from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

ALGORITHM = "pbkdf2-sha256"
ITERATIONS = 600_000
SALT_SIZE = 16
HASH_SIZE = 32

def new_kdf(salt: bytes, iterations: int) -> PBKDF2HMAC:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=HASH_SIZE, salt=salt, iterations=iterations)

def hash_password(password: str) -> dict:
    salt = os.urandom(SALT_SIZE)
    return {
        "algorithm": ALGORITHM,
        "iterations": ITERATIONS,
        "salt": salt,
        "hash": new_kdf(salt, ITERATIONS).derive(password.encode()),
    }

def verify_password(record: dict | None, password: str) -> bool:
    stored = record or {
            "algorithm": ALGORITHM, 
            "iterations": ITERATIONS, 
            "salt": bytes(SALT_SIZE), 
            "hash": bytes(HASH_SIZE)
        }

    if stored["algorithm"] != ALGORITHM:
        return False

    try:
        new_kdf(stored["salt"], stored["iterations"]).verify(password.encode(), stored["hash"])
    except InvalidKey:
        return False

    return record is not None
