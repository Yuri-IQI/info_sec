import json

import pytest

import exec_cypher
import exec_decypher
import key_gen
from package_file import load_package, tamper_package

PASSWORD = "senha-apenas-para-teste"

@pytest.fixture
def package_path(tmp_path, monkeypatch):
    monkeypatch.setattr(key_gen, "KEYS_DIR", tmp_path / "keys")
    monkeypatch.setenv("KEY_PASSWORD", PASSWORD)
    return tmp_path / "data" / "mensagem.json"

def run_cypher(path, *args):
    exec_cypher.main([*args, "--file", str(path)])

def run_decypher(path, *args):
    exec_decypher.main([*args, "--file", str(path)])

def test_unsigned_message_is_restored_with_warning(package_path, capsys):
    run_cypher(package_path, "ação é ótima")
    run_decypher(package_path)
    output = capsys.readouterr().out
    assert "Aviso: mensagem sem assinatura" in output
    assert "Mensagem decifrada: ação é ótima" in output

def test_file_does_not_contain_plain_message(package_path):
    run_cypher(package_path, "mensagem secreta")
    assert "mensagem secreta" not in package_path.read_text()

def test_signed_message_is_verified_and_restored(package_path, capsys):
    run_cypher(package_path, "mensagem de teste", "--sign")
    run_decypher(package_path, "--require-signature")
    output = capsys.readouterr().out
    assert "Assinatura válida" in output
    assert "Mensagem decifrada: mensagem de teste" in output

def test_tamper_on_existing_unsigned_message_is_detected(package_path):
    run_cypher(package_path, "mensagem de teste")
    run_cypher(package_path, "--tamper")
    with pytest.raises(SystemExit, match="adulteração detectada"):
        run_decypher(package_path)

def test_tamper_on_existing_signed_message_is_detected(package_path):
    run_cypher(package_path, "mensagem de teste", "--sign")
    run_cypher(package_path, "--tamper")
    with pytest.raises(SystemExit, match="assinatura inválida"):
        run_decypher(package_path)

def test_tamper_together_with_message_is_detected(package_path):
    run_cypher(package_path, "mensagem de teste", "--sign", "--tamper")
    with pytest.raises(SystemExit, match="assinatura inválida"):
        run_decypher(package_path)

@pytest.mark.parametrize("field", ["cyphered_key", "nonce", "signature"])
def test_any_changed_signed_field_is_rejected(package_path, field):
    run_cypher(package_path, "mensagem de teste", "--sign")
    data = json.loads(package_path.read_text())
    other = data["cyphered_key"] if field == "nonce" else data["nonce"]
    data[field] = other
    package_path.write_text(json.dumps(data))
    with pytest.raises(SystemExit, match="assinatura inválida"):
        run_decypher(package_path)

def test_removed_signature_is_rejected_when_required(package_path):
    run_cypher(package_path, "mensagem de teste", "--sign")
    data = json.loads(package_path.read_text())
    del data["signature"]
    package_path.write_text(json.dumps(data))
    with pytest.raises(SystemExit, match="não tem assinatura"):
        run_decypher(package_path, "--require-signature")

def test_tamper_changes_only_the_cyphered_content(package_path):
    run_cypher(package_path, "mensagem de teste", "--sign")
    before = load_package(package_path)
    tamper_package(package_path)
    after = load_package(package_path)
    assert after["cyphered"] != before["cyphered"]
    assert {key: value for key, value in after.items() if key != "cyphered"} == {
        key: value for key, value in before.items() if key != "cyphered"
    }

def test_tamper_without_file_is_reported(package_path):
    with pytest.raises(SystemExit, match="Erro"):
        run_cypher(package_path, "--tamper")

def test_decypher_does_not_generate_keys(package_path):
    run_cypher(package_path, "mensagem de teste")
    for name in key_gen.KEY_NAMES:
        for path in key_gen.key_paths(name):
            path.unlink()
    with pytest.raises(SystemExit, match="Erro"):
        run_decypher(package_path)
    assert not key_gen.key_paths("rsa")[0].exists()

def test_cypher_without_signature_does_not_need_password(package_path, monkeypatch):
    run_cypher(package_path, "primeira")
    monkeypatch.delenv("KEY_PASSWORD")
    run_cypher(package_path, "segunda")

def test_wrong_password_is_reported(package_path, monkeypatch):
    run_cypher(package_path, "mensagem de teste")
    monkeypatch.setenv("KEY_PASSWORD", "senha-incorreta")
    with pytest.raises(SystemExit, match="Erro"):
        run_decypher(package_path)

def test_invalid_file_is_reported(package_path):
    package_path.parent.mkdir(parents=True)
    package_path.write_text("isto não é um pacote")
    with pytest.raises(SystemExit, match="Erro"):
        run_decypher(package_path)

@pytest.mark.parametrize("args", [[], [""], ["--sign"], ["--sign", "--tamper"]])
def test_invalid_arguments_are_rejected(package_path, args):
    with pytest.raises(SystemExit) as error:
        exec_cypher.main(args)
    assert error.value.code == 2
