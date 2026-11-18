import hashlib

import pytest

import password_hash
from password_hash import ALGORITHM, HASH_SIZE, ITERATIONS, SALT_SIZE, hash_password, verify_password

PASSWORD = "senha-de-teste-longa-1"
WRONG_PASSWORD = "senha-de-teste-errada-2"

@pytest.fixture(scope="module")
def record():
    return hash_password(PASSWORD)

def flip_bit(data: bytes) -> bytes:
    tampered = bytearray(data)
    tampered[0] ^= 1
    return bytes(tampered)

def test_record_uses_pbkdf2_parameters(record):
    assert record["algorithm"] == ALGORITHM
    assert record["iterations"] == ITERATIONS >= 600_000
    assert len(record["salt"]) == SALT_SIZE
    assert len(record["hash"]) == HASH_SIZE

def test_record_does_not_contain_password(record):
    assert PASSWORD.encode() not in record["hash"] + record["salt"]

def test_correct_password_is_accepted(record):
    assert verify_password(record, PASSWORD)

def test_wrong_password_is_rejected(record):
    assert not verify_password(record, WRONG_PASSWORD)

def test_same_password_gets_new_salt_and_hash(record):
    other = hash_password(PASSWORD)
    assert other["salt"] != record["salt"]
    assert other["hash"] != record["hash"]

def test_hash_is_not_plain_sha256(record):
    assert record["hash"] != hashlib.sha256(PASSWORD.encode()).digest()

def test_unknown_user_is_rejected():
    assert not verify_password(None, PASSWORD)

def test_unknown_user_still_runs_pbkdf2(monkeypatch):
    calls = []
    original = password_hash.new_kdf

    def spy(salt, iterations):
        calls.append(iterations)
        return original(salt, iterations)

    monkeypatch.setattr(password_hash, "new_kdf", spy)
    verify_password(None, PASSWORD)
    assert calls == [ITERATIONS]

@pytest.mark.parametrize("field", ["salt", "hash"])
def test_tampered_record_is_rejected(record, field):
    assert not verify_password({**record, field: flip_bit(record[field])}, PASSWORD)

def test_changed_iterations_are_rejected(record):
    assert not verify_password({**record, "iterations": ITERATIONS - 1}, PASSWORD)

def test_unknown_algorithm_is_rejected(record):
    assert not verify_password({**record, "algorithm": "sha256"}, PASSWORD)
