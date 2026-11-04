from encrypt import cypher, decypher
from key_gen import load_or_generate_keys
from cryptography.exceptions import InvalidTag

try:
    keys = load_or_generate_keys()
except (ValueError, FileNotFoundError) as error:
    raise SystemExit(f"Erro: {error}")

rsa_public_key = keys["rsa"]["public_key"]
rsa_private_key = keys["rsa"]["private_key"]

package = cypher(b"mensagem de teste", rsa_public_key)
print(decypher(package, rsa_private_key))

tampered = bytearray(package["cyphered"])
tampered[0] ^= 1
package["cyphered"] = bytes(tampered)

try:
    decypher(package, rsa_private_key)
except InvalidTag:
    print("Falha: adulteração detectada")
