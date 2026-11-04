import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization

import key_gen
from encrypt import cypher, decypher
from signature import sign, verify

MSG = b"mensagem de teste"
PASSWORD = "senha-apenas-para-teste"

@pytest.fixture(scope="module")
def keys():
    return key_gen.generate_keys()

@pytest.fixture(scope="module")
def other_keys():
    return key_gen.generate_keys()

@pytest.fixture
def keys_dir(tmp_path, monkeypatch):
    path = tmp_path / "pasta" / "keys"
    monkeypatch.setattr(key_gen, "KEYS_DIR", path)
    monkeypatch.setenv("KEY_PASSWORD", PASSWORD)
    return path

def flip_bit(data: bytes) -> bytes:
    tampered = bytearray(data)
    tampered[0] ^= 1
    return bytes(tampered)

def test_decypher_returns_original_message(keys):
    package = cypher(MSG, keys["rsa"]["public_key"])
    assert package["cyphered"] != MSG
    assert decypher(package, keys["rsa"]["private_key"]) == MSG

def test_each_message_uses_new_key_and_nonce(keys):
    first = cypher(MSG, keys["rsa"]["public_key"])
    second = cypher(MSG, keys["rsa"]["public_key"])
    assert first["nonce"] != second["nonce"]
    assert first["cyphered_key"] != second["cyphered_key"]
    assert first["cyphered"] != second["cyphered"]

@pytest.mark.parametrize("field", ["cyphered", "nonce"])
def test_tampered_content_is_rejected(keys, field):
    package = cypher(MSG, keys["rsa"]["public_key"])
    package[field] = flip_bit(package[field])
    with pytest.raises(InvalidTag):
        decypher(package, keys["rsa"]["private_key"])

def test_tampered_wrapped_key_is_rejected(keys):
    package = cypher(MSG, keys["rsa"]["public_key"])
    package["cyphered_key"] = flip_bit(package["cyphered_key"])
    with pytest.raises(ValueError):
        decypher(package, keys["rsa"]["private_key"])

def test_wrong_private_key_cannot_decypher(keys, other_keys):
    package = cypher(MSG, keys["rsa"]["public_key"])
    with pytest.raises(ValueError):
        decypher(package, other_keys["rsa"]["private_key"])

def test_valid_signature_is_accepted(keys):
    signature = sign(MSG, keys["ed25519"]["private_key"])
    verify(signature, MSG, keys["ed25519"]["public_key"])

def test_tampered_message_is_rejected(keys):
    signature = sign(MSG, keys["ed25519"]["private_key"])
    with pytest.raises(InvalidSignature):
        verify(signature, b"mensagem adulterada", keys["ed25519"]["public_key"])

def test_tampered_signature_is_rejected(keys):
    signature = sign(MSG, keys["ed25519"]["private_key"])
    with pytest.raises(InvalidSignature):
        verify(flip_bit(signature), MSG, keys["ed25519"]["public_key"])

def test_wrong_public_key_is_rejected(keys, other_keys):
    signature = sign(MSG, keys["ed25519"]["private_key"])
    with pytest.raises(InvalidSignature):
        verify(signature, MSG, other_keys["ed25519"]["public_key"])

def test_generates_all_files_when_folder_does_not_exist(keys_dir):
    key_gen.load_or_generate_keys()
    assert sorted(path.name for path in keys_dir.iterdir()) == [
        "private_ed25519_key.pem",
        "private_rsa_key.pem",
        "public_ed25519_key.pem",
        "public_rsa_key.pem",
    ]

def test_reuses_existing_keys(keys_dir):
    key_gen.load_or_generate_keys()
    before = {path.name: path.read_bytes() for path in keys_dir.iterdir()}
    keys = key_gen.load_or_generate_keys()
    after = {path.name: path.read_bytes() for path in keys_dir.iterdir()}
    assert before == after
    signature = sign(MSG, keys["ed25519"]["private_key"])
    verify(signature, MSG, keys["ed25519"]["public_key"])

def test_private_keys_are_protected_by_password(keys_dir):
    key_gen.load_or_generate_keys()
    for name in key_gen.KEY_NAMES:
        data = key_gen.key_paths(name)[0].read_bytes()
        assert data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        with pytest.raises(TypeError):
            serialization.load_pem_private_key(data, None)
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(data, b"senha-errada")

def test_saving_does_not_overwrite_keys(keys_dir, keys):
    key_gen.save_keys_to_file(keys)
    before = key_gen.key_paths("rsa")[0].read_bytes()
    with pytest.raises(FileExistsError):
        key_gen.save_keys_to_file(keys)
    assert key_gen.key_paths("rsa")[0].read_bytes() == before

def test_incomplete_key_set_is_reported(keys_dir, keys):
    key_gen.save_keys_to_file(keys)
    key_gen.key_paths("ed25519")[1].unlink()
    with pytest.raises(FileNotFoundError, match="public_ed25519_key.pem"):
        key_gen.load_or_generate_keys()

@pytest.mark.parametrize("password", [None, "", "curta"])
def test_missing_or_short_password_is_rejected(keys_dir, monkeypatch, password):
    if password is None:
        monkeypatch.delenv("KEY_PASSWORD")
    else:
        monkeypatch.setenv("KEY_PASSWORD", password)
    with pytest.raises(ValueError, match="KEY_PASSWORD"):
        key_gen.load_or_generate_keys()
    assert not keys_dir.exists()
