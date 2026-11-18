from entrega1 import ensure_keys, load_private_key, load_public_key
from password_hash import hash_password
from user_store import DEFAULT_PATH, load_users, parse_username, save_users
from cryptography.exceptions import InvalidSignature
import argparse
import getpass

MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 64

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Cadastra um usuário com a senha protegida por PBKDF2.")
    parser.add_argument("username", type=parse_username, help="nome do usuário")
    parser.add_argument("--file", default=DEFAULT_PATH, help="arquivo de usuários")
    return parser.parse_args(argv)

def read_new_password() -> str:
    password = getpass.getpass("Senha: ")

    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise ValueError(f"A senha deve ter de {MIN_PASSWORD_LENGTH} a {MAX_PASSWORD_LENGTH} caracteres.")
    if getpass.getpass("Confirme a senha: ") != password:
        raise ValueError("As senhas não conferem.")

    return password

def main(argv=None):
    args = parse_args(argv)

    try:
        ensure_keys()
        private_key = load_private_key("ed25519")
        users = load_users(load_public_key("ed25519"), args.file)

        if args.username in users:
            raise ValueError(f"O usuário {args.username} já existe.")

        users[args.username] = hash_password(read_new_password())
        save_users(users, private_key, args.file)
    except InvalidSignature:
        raise SystemExit("Falha: o arquivo de usuários foi alterado fora da aplicação.")
    except (ValueError, FileNotFoundError) as error:
        raise SystemExit(f"Erro: {error}")

    print(f"Usuário {args.username} cadastrado em {args.file}")

if __name__ == "__main__":
    main()
