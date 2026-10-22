"""
CENÁRIO 03 · Quebra de senhas com hash fraco (MD5 sem salt)
Semana 09 (Criptografia) · CIA: Confidencialidade.

Os hashes extraídos no cenário 02 são MD5 sem salt. Como MD5 é rápido e não tem
salt, um ataque de dicionário recupera as senhas: basta calcular o MD5 de cada
palavra de uma lista e comparar. Mostra, na prática, por que a aula recomenda
bcrypt/argon2 com salt.
"""
import hashlib
from config import titulo

# Lista de senhas comuns (dicionário de brinquedo para o laboratório):
DICIONARIO = [
    "123456", "senha", "admin", "admin123", "102030", "primavera",
    "qwerty", "password", "102030", "12345678", "iloveyou", "goiania",
]


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def main():
    titulo("03", "Quebra de hash MD5 sem salt", "Semana 09 - Criptografia")

    # Para o laboratório, recalculamos os hashes reais dos usuários-semente:
    alvos = {
        "admin": md5("admin123"),
        "ana": md5("primavera"),
        "bruno": md5("102030"),
        "carla": md5("senha"),
    }
    print("\nHashes-alvo (como viriam do cenário 02):")
    for u, h in alvos.items():
        print(f"  {u:6} -> {h}")

    tabela = {md5(p): p for p in DICIONARIO}  # rainbow table de brinquedo
    print(f"\nDicionário com {len(set(DICIONARIO))} palavras. Comparando...\n")
    for u, h in alvos.items():
        achou = tabela.get(h)
        print(f"  {u:6} : {'SENHA = ' + achou if achou else 'não quebrada'}")

    print("\nTempo para calcular todas: desprezível — é esse o problema do MD5.")
    print("CORREÇÃO: bcrypt/argon2/scrypt (lentos de propósito) + salt por usuário,")
    print("          de modo que hashes iguais não revelem senhas iguais.")


if __name__ == "__main__":
    main()
