from password_hash import hash_password
from user_store import DEFAULT_PATH, parse_username, tamper_user
import argparse

ATTACKER_PASSWORD = "senha-do-atacante-123"

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Simula um atacante que troca o hash de um usuário sem ter a chave privada de assinatura."
    )
    parser.add_argument("username", type=parse_username, help="usuário a adulterar")
    parser.add_argument("--password", default=ATTACKER_PASSWORD, help="senha conhecida pelo atacante")
    parser.add_argument("--file", default=DEFAULT_PATH, help="arquivo de usuários")
    return parser.parse_args(argv)

def main(argv=None):
    args = parse_args(argv)

    try:
        tamper_user(args.username, hash_password(args.password), args.file)
    except (ValueError, FileNotFoundError) as error:
        raise SystemExit(f"Erro: {error}")

    print(f"Hash de {args.username} trocado pelo da senha '{args.password}' em {args.file}")

if __name__ == "__main__":
    main()
