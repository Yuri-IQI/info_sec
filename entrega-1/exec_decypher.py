from encrypt import decypher
from key_gen import load_private_key, load_public_key
from package_file import DEFAULT_PATH, load_package, signed_bytes
from signature import verify
from cryptography.exceptions import InvalidSignature, InvalidTag
import argparse

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Verifica e decifra um pacote salvo por exec_cypher.py.")
    parser.add_argument("--require-signature", action="store_true", help="rejeita mensagens sem assinatura")
    parser.add_argument("--file", default=DEFAULT_PATH, help="arquivo do pacote cifrado")
    return parser.parse_args(argv)

def main(argv=None):
    args = parse_args(argv)

    try:
        pkg = load_package(args.file)
        rsa_private_key = load_private_key("rsa")
        ed25519_public_key = load_public_key("ed25519")
    except (ValueError, FileNotFoundError) as error:
        raise SystemExit(f"Erro: {error}")

    if "signature" in pkg:
        try:
            verify(pkg["signature"], signed_bytes(pkg), ed25519_public_key)
        except InvalidSignature:
            raise SystemExit("Falha: assinatura inválida; o pacote foi alterado ou não veio deste remetente.")
        print("Assinatura válida")
    elif args.require_signature:
        raise SystemExit("Falha: a mensagem não tem assinatura.")
    else:
        print("Aviso: mensagem sem assinatura; a origem não foi verificada.")

    try:
        print(f"Mensagem decifrada: {decypher(pkg, rsa_private_key).decode()}")
    except InvalidTag:
        raise SystemExit("Falha: adulteração detectada no conteúdo cifrado.")
    except ValueError:
        raise SystemExit("Falha: a mensagem não pôde ser decifrada com esta chave privada.")

if __name__ == "__main__":
    main()
