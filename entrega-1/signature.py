from key_gen import load_or_generate_keys
from cryptography.exceptions import InvalidSignature

try:
    keys = load_or_generate_keys()
except (ValueError, FileNotFoundError) as error:
    raise SystemExit(f"Erro: {error}")

ed25519_private_key = keys["ed25519"]["private_key"]
ed25519_public_key = keys["ed25519"]["public_key"]

msg = b"mensagem de teste"
signature = ed25519_private_key.sign(msg)

ed25519_public_key.verify(signature, msg)
print("Assinatura válida")

try:
    ed25519_public_key.verify(signature, b"mensagem adulterada")
except InvalidSignature:
    print("Falha: assinatura inválida")
else:
    raise SystemExit("Erro: adulteração não detectada")
