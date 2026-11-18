import json

import pytest

import exec_login
import exec_register
import exec_tamper
import key_gen
import password_hash

KEY_PASSWORD = "senha-apenas-para-teste"
PASSWORD = "senha-de-teste-longa-1"
WRONG_PASSWORD = "senha-de-teste-errada-2"

@pytest.fixture
def users_path(tmp_path, monkeypatch):
    monkeypatch.setattr(key_gen, "KEYS_DIR", tmp_path / "keys")
    monkeypatch.setenv("KEY_PASSWORD", KEY_PASSWORD)
    monkeypatch.setattr(password_hash, "ITERATIONS", 1_000)
    return tmp_path / "data" / "usuarios.json"

@pytest.fixture
def typed(monkeypatch):
    answers = []
    monkeypatch.setattr("getpass.getpass", lambda prompt="": answers.pop(0))
    return answers

def register(path, typed, username="alice", password=PASSWORD, confirmation=None):
    typed[:] = [password, password if confirmation is None else confirmation]
    exec_register.main([username, "--file", str(path)])

def login(path, typed, username="alice", password=PASSWORD):
    typed[:] = [password]
    exec_login.main([username, "--file", str(path)])

def test_correct_login_is_accepted(users_path, typed, capsys):
    register(users_path, typed)
    login(users_path, typed)
    assert "Login realizado: alice" in capsys.readouterr().out

def test_wrong_password_is_rejected(users_path, typed):
    register(users_path, typed)
    with pytest.raises(SystemExit, match="usuário ou senha incorretos"):
        login(users_path, typed, password=WRONG_PASSWORD)

def test_unknown_user_gets_the_same_message(users_path, typed):
    register(users_path, typed)
    with pytest.raises(SystemExit) as error:
        login(users_path, typed, username="bob")
    assert error.value.code == exec_login.INVALID_LOGIN

def test_login_without_users_file_is_rejected(users_path, typed):
    key_gen.ensure_keys()
    with pytest.raises(SystemExit, match="usuário ou senha incorretos"):
        login(users_path, typed)

def test_login_without_keys_is_reported(users_path, typed):
    with pytest.raises(SystemExit, match="Erro"):
        login(users_path, typed)

def test_username_is_normalized(users_path, typed, capsys):
    register(users_path, typed, username="Alice")
    login(users_path, typed, username=" ALICE ")
    assert "Login realizado: alice" in capsys.readouterr().out

def test_file_stores_salt_and_hash_but_not_password(users_path, typed):
    register(users_path, typed)
    content = users_path.read_text()
    record = json.loads(content)["users"]["alice"]
    assert PASSWORD not in content
    assert record["algorithm"] == "pbkdf2-sha256"
    assert set(record) == {"algorithm", "iterations", "salt", "hash"}
    assert "signature" in json.loads(content)

def test_two_users_with_same_password_get_different_hashes(users_path, typed):
    register(users_path, typed, username="alice")
    register(users_path, typed, username="bob")
    users = json.loads(users_path.read_text())["users"]
    assert users["alice"]["salt"] != users["bob"]["salt"]
    assert users["alice"]["hash"] != users["bob"]["hash"]

def test_duplicate_user_is_rejected(users_path, typed):
    register(users_path, typed)
    with pytest.raises(SystemExit, match="já existe"):
        register(users_path, typed)

@pytest.mark.parametrize("password", ["curta", "x" * 65])
def test_password_length_is_enforced(users_path, typed, password):
    with pytest.raises(SystemExit, match="de 15 a 64 caracteres"):
        register(users_path, typed, password=password)
    assert not users_path.exists()

def test_confirmation_must_match(users_path, typed):
    with pytest.raises(SystemExit, match="não conferem"):
        register(users_path, typed, confirmation=WRONG_PASSWORD)

@pytest.mark.parametrize("username", ["ab", "a" * 33, "alice bob", "alice;drop"])
def test_invalid_username_is_rejected(users_path, username):
    with pytest.raises(SystemExit) as error:
        exec_register.main([username, "--file", str(users_path)])
    assert error.value.code == 2

def test_login_does_not_need_key_password(users_path, typed, monkeypatch, capsys):
    register(users_path, typed)
    monkeypatch.delenv("KEY_PASSWORD")
    login(users_path, typed)
    assert "Login realizado" in capsys.readouterr().out

def test_register_needs_key_password(users_path, typed, monkeypatch):
    monkeypatch.delenv("KEY_PASSWORD")
    with pytest.raises(SystemExit, match="KEY_PASSWORD"):
        register(users_path, typed)

def test_swapped_hash_is_detected(users_path, typed):
    register(users_path, typed)
    exec_tamper.main(["alice", "--file", str(users_path)])
    with pytest.raises(SystemExit, match="alterado fora da aplicação"):
        login(users_path, typed, password=exec_tamper.ATTACKER_PASSWORD)
    with pytest.raises(SystemExit, match="alterado fora da aplicação"):
        login(users_path, typed)

def test_register_refuses_tampered_file(users_path, typed):
    register(users_path, typed)
    exec_tamper.main(["alice", "--file", str(users_path)])
    with pytest.raises(SystemExit, match="alterado fora da aplicação"):
        register(users_path, typed, username="bob")

@pytest.mark.parametrize("field, value", [("iterations", 1), ("algorithm", "sha256")])
def test_any_edited_field_is_detected(users_path, typed, field, value):
    register(users_path, typed)
    data = json.loads(users_path.read_text())
    data["users"]["alice"][field] = value
    users_path.write_text(json.dumps(data))
    with pytest.raises(SystemExit, match="alterado fora da aplicação"):
        login(users_path, typed)

def test_removed_user_is_detected(users_path, typed):
    register(users_path, typed, username="alice")
    register(users_path, typed, username="bob")
    data = json.loads(users_path.read_text())
    del data["users"]["bob"]
    users_path.write_text(json.dumps(data))
    with pytest.raises(SystemExit, match="alterado fora da aplicação"):
        login(users_path, typed)

def test_invalid_file_is_reported(users_path, typed):
    users_path.parent.mkdir(parents=True)
    users_path.write_text("isto não é um cadastro")
    with pytest.raises(SystemExit, match="Erro"):
        login(users_path, typed)

def test_tamper_unknown_user_is_reported(users_path, typed):
    register(users_path, typed)
    with pytest.raises(SystemExit, match="não está cadastrado"):
        exec_tamper.main(["bob", "--file", str(users_path)])
