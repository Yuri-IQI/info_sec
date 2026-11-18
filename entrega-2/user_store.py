from base64 import b64decode
from pathlib import Path
import argparse
import json
import re

from entrega1 import encode_field, sign, verify

DEFAULT_PATH = Path(__file__).parent / "data" / "usuarios.json"
USERNAME_PATTERN = re.compile(r"[a-z0-9_.-]{3,32}")

def parse_username(value: str) -> str:
    username = value.strip().lower()
    if not USERNAME_PATTERN.fullmatch(username):
        raise argparse.ArgumentTypeError("use de 3 a 32 caracteres: letras minúsculas, números, '.', '_' ou '-'.")

    return username

def encode_record(record: dict) -> dict:
    return {
        "algorithm": record["algorithm"],
        "iterations": record["iterations"],
        "salt": encode_field(record["salt"]),
        "hash": encode_field(record["hash"]),
    }

def decode_record(data: dict) -> dict:
    return {
        "algorithm": str(data["algorithm"]),
        "iterations": int(data["iterations"]),
        "salt": b64decode(data["salt"], validate=True),
        "hash": b64decode(data["hash"], validate=True),
    }

def signed_bytes(users: dict) -> bytes:
    return json.dumps({name: encode_record(record) for name, record in users.items()}, sort_keys=True).encode()

def write_users_file(users: dict, signature: bytes, path=DEFAULT_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "users": {name: encode_record(record) for name, record in users.items()},
        "signature": encode_field(signature),
    }
    path.write_text(json.dumps(data, indent=2))

def read_users_file(path=DEFAULT_PATH) -> tuple[dict, bytes]:
    try:
        data = json.loads(Path(path).read_text())
        users = {name: decode_record(record) for name, record in data["users"].items()}
        signature = b64decode(data["signature"], validate=True)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ValueError(f"O arquivo {path} não contém um cadastro válido.") from error

    return users, signature

def save_users(users: dict, private_key, path=DEFAULT_PATH) -> None:
    write_users_file(users, sign(signed_bytes(users), private_key), path)

def load_users(public_key, path=DEFAULT_PATH) -> dict:
    if not Path(path).exists():
        return {}

    users, signature = read_users_file(path)
    verify(signature, signed_bytes(users), public_key)
    return users

def tamper_user(username: str, record: dict, path=DEFAULT_PATH) -> None:
    users, signature = read_users_file(path)

    if username not in users:
        raise ValueError(f"O usuário {username} não está cadastrado.")

    users[username] = record
    write_users_file(users, signature, path)
