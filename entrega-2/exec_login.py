from entrega1 import load_public_key
from password_hash import verify_password
from user_store import DEFAULT_PATH, load_users, parse_username
from cryptography.exceptions import InvalidSignature
import argparse
import getpass

INVALID_LOGIN = "Falha: usuário ou senha incorretos."

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Verifica o login de um usuário cadastrado.")
    parser.add_argument("username", type=parse_username, help="nome do usuário")
    parser.add_argument("--file", default=DEFAULT_PATH, help="arquivo de usuários")
    return parser.parse_args(argv)

def main(argv=None):
    args = parse_args(argv)

    try:
        users = load_users(load_public_key("ed25519"), args.file)
    except InvalidSignature:
        raise SystemExit("Falha: o arquivo de usuários foi alterado fora da aplicação.")
    except (ValueError, FileNotFoundError) as error:
        raise SystemExit(f"Erro: {error}")

    if not verify_password(users.get(args.username), getpass.getpass("Senha: ")):
        raise SystemExit(INVALID_LOGIN)

    print(f"Login realizado: {args.username}")

if __name__ == "__main__":
    main()
