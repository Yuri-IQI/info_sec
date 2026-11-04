from encrypt import cypher
from key_gen import ensure_keys, load_private_key, load_public_key
from package_file import DEFAULT_PATH, save_package, signed_bytes, tamper_package
from signature import sign
import argparse

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Cifra uma mensagem em arquivo ou adultera um arquivo já cifrado.")
    parser.add_argument("message", nargs="?", help="mensagem a cifrar; omita para adulterar um arquivo existente com --tamper")
    parser.add_argument("--sign", action="store_true", help="assina o pacote cifrado com Ed25519")
    parser.add_argument("--tamper", action="store_true", help="altera um bit do conteúdo cifrado no arquivo")
    parser.add_argument("--file", default=DEFAULT_PATH, help="arquivo do pacote cifrado")
    args = parser.parse_args(argv)

    if args.message is None and not args.tamper:
        parser.error("informe a mensagem ou use --tamper.")
    if args.message == "":
        parser.error("a mensagem não pode ser vazia.")
    if args.sign and args.message is None:
        parser.error("--sign exige uma mensagem.")

    return args

def main(argv=None):
    args = parse_args(argv)

    try:
        if args.message is not None:
            ensure_keys()
            pkg = cypher(args.message.encode(), load_public_key("rsa"))
            if args.sign:
                pkg["signature"] = sign(signed_bytes(pkg), load_private_key("ed25519"))
            save_package(pkg, args.file)
            print(f"Mensagem cifrada{' e assinada' if args.sign else ''} em {args.file}")

        if args.tamper:
            tamper_package(args.file)
            print(f"Conteúdo cifrado adulterado em {args.file}")
            
    except (ValueError, FileNotFoundError) as error:
        raise SystemExit(f"Erro: {error}")

if __name__ == "__main__":
    main()
