from base64 import b64decode, b64encode
from pathlib import Path
import json
import secrets

DEFAULT_PATH = Path(__file__).parent / "data" / "mensagem.json"
PACKAGE_FIELDS = ("cyphered_key", "nonce", "cyphered")

def encode_field(value: bytes) -> str:
    return b64encode(value).decode()

def signed_bytes(pkg: dict) -> bytes:
    return json.dumps({field: encode_field(pkg[field]) for field in PACKAGE_FIELDS}, sort_keys=True).encode()

def save_package(pkg: dict, path=DEFAULT_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({field: encode_field(value) for field, value in pkg.items()}, indent=2))

def load_package(path=DEFAULT_PATH) -> dict:
    try:
        data = json.loads(Path(path).read_text())
        pkg = {field: b64decode(data[field], validate=True) for field in PACKAGE_FIELDS}
        if "signature" in data:
            pkg["signature"] = b64decode(data["signature"], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"O arquivo {path} não contém um pacote válido.") from error

    return pkg

def tamper_package(path=DEFAULT_PATH) -> None:
    pkg = load_package(path)
    tampered = bytearray(pkg["cyphered"])
    tampered[secrets.randbelow(len(tampered))] ^= 1 << secrets.randbelow(8)
    pkg["cyphered"] = bytes(tampered)
    save_package(pkg, path)
