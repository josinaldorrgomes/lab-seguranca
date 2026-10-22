"""
Executa todos os cenários do LabSeg em sequência, contra o alvo local.
Uso:  python run_all.py
(Requer o alvo rodando: python ../alvo/app.py)
"""
import importlib
import sys
from config import checar_escopo

ALVO = checar_escopo()

MODULOS = [
    "01_sqli_login", "02_sqli_union", "03_quebra_hash", "04_jwt_none",
    "05_idor", "06_xss", "07_http_texto_claro", "08_prompt_injection",
]


def main():
    print(f"\n### LabSeg · executando {len(MODULOS)} cenários contra {ALVO} ###\n")
    for nome in MODULOS:
        try:
            mod = importlib.import_module(nome)
            mod.main()
        except Exception as e:  # um cenário falhar não derruba os demais
            print(f"  [ERRO em {nome}] {type(e).__name__}: {e}")
        print()
    print("### Fim. Veja o roteiro em ../roteiro/roteiro-laboratorio.md ###")


if __name__ == "__main__":
    sys.exit(main())
