from password_hash import ITERATIONS, hash_password
import hashlib
import time

PASSWORD = "senha-de-teste-longa-1"
SHA_DURATION_SECONDS = 1.0
PBKDF2_SAMPLES = 5

def sha256_per_second() -> float:
    count = 0
    start = time.perf_counter()

    while (elapsed := time.perf_counter() - start) < SHA_DURATION_SECONDS:
        hashlib.sha256(PASSWORD.encode()).digest()
        count += 1

    return count / elapsed

def pbkdf2_per_second() -> float:
    start = time.perf_counter()

    for _ in range(PBKDF2_SAMPLES):
        hash_password(PASSWORD)

    return PBKDF2_SAMPLES / (time.perf_counter() - start)

def main():
    sha_rate = sha256_per_second()
    pbkdf2_rate = pbkdf2_per_second()

    print("Velocidade em uma senha de teste")
    print(f" SHA-256: {sha_rate:,.0f} hashes")
    print(f" PBKDF2-SHA256: {pbkdf2_rate:,.1f} hashes ({ITERATIONS:,} iterações)")
    print(f" O SHA-256 foi {sha_rate / pbkdf2_rate:,.0f} vezes mais rápido nesta máquina")
    print()
    print("Mesma senha, duas vezes")
    for _ in range(2):
        print(f"  SHA-256: {hashlib.sha256(PASSWORD.encode()).hexdigest()}")
    for _ in range(2):
        record = hash_password(PASSWORD)
        print(f"  PBKDF2:  salt={record['salt'].hex()} hash={record['hash'].hex()}")

if __name__ == "__main__":
    main()
