from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import os

KEYS_DIR = Path(__file__).parent / "keys"
MIN_PASSWORD_LENGTH = 8
KEY_NAMES = ("rsa", "ed25519")

def generate_keys(save_to_file=False):
    private_rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_ed25519_key = ed25519.Ed25519PrivateKey.generate()

    keys = {
        "rsa": {
            "private_key": private_rsa_key,
            "public_key": private_rsa_key.public_key()
        },
        "ed25519": {
            "private_key": private_ed25519_key,
            "public_key": private_ed25519_key.public_key()
        }
    }

    if save_to_file:
        save_keys_to_file(keys)

    return keys

def load_or_generate_keys():
    paths = [path for name in KEY_NAMES for path in key_paths(name)]
    existing = [path for path in paths if path.exists()]

    if not existing:
        return generate_keys(save_to_file=True)

    if len(existing) < len(paths):
        missing = [path.name for path in paths if not path.exists()]
        raise FileNotFoundError(f"Conjunto de chaves incompleto em {KEYS_DIR}. Faltam: {', '.join(missing)}")

    return load_keys()

def load_keys():
    password = get_key_password()
    keys = {}

    for name in KEY_NAMES:
        private_path, public_path = key_paths(name)
        keys[name] = {
            "private_key": serialization.load_pem_private_key(private_path.read_bytes(), password),
            "public_key": serialization.load_pem_public_key(public_path.read_bytes())
        }

    return keys

def save_keys_to_file(keys):
    password = get_key_password()

    for name in keys:
        for path in key_paths(name):
            if path.exists():
                raise FileExistsError(f"A chave {path} já existe e não será sobrescrita.")

    KEYS_DIR.mkdir(exist_ok=True)

    for name, pair in keys.items():
        save_key_pair(name, pair["private_key"], pair["public_key"], password)

def get_key_password():
    password = os.environ.get("KEY_PASSWORD", "")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Defina KEY_PASSWORD com pelo menos {MIN_PASSWORD_LENGTH} caracteres.")

    return password.encode()

def key_paths(name):
    return KEYS_DIR / f"private_{name}_key.pem", KEYS_DIR / f"public_{name}_key.pem"

def save_key_pair(name, private_key, public_key, password):
    private_path, public_path = key_paths(name)

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_path, "xb") as f:
        f.write(pem_private)

    with open(public_path, "xb") as f:
        f.write(pem_public)

if __name__ == "__main__":
    try:
        generate_keys(save_to_file=True)
    except (ValueError, FileExistsError) as error:
        raise SystemExit(f"Erro: {error}")

    print(f"Chaves salvas em {KEYS_DIR}")
