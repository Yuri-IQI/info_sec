def sign(msg: bytes, private_key) -> bytes:
    return private_key.sign(msg)

def verify(signature: bytes, msg: bytes, public_key) -> None:
    public_key.verify(signature, msg)
