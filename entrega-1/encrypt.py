import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

def cypher(msg: bytes, public_key) -> dict:
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return {
        "cyphered_key": public_key.encrypt(aes_key, OAEP),
        "nonce": nonce,
        "cyphered": AESGCM(aes_key).encrypt(nonce, msg, None),
    }

def decypher(pkg: dict, private_key) -> bytes:
    aes_key = private_key.decrypt(pkg["cyphered_key"], OAEP)
    return AESGCM(aes_key).decrypt(pkg["nonce"], pkg["cyphered"], None)