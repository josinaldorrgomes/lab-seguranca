"""
CENÁRIO 06 · XSS — Cross-Site Scripting (refletido e armazenado)
Camada de aplicação · CIA: Integridade (e roubo de sessão -> Confidencialidade).

- Refletido: /busca?q=... devolve o termo no HTML sem escapar. Um link malicioso
  executa script no navegador da vítima.
- Armazenado: um comentário com <script> fica salvo e dispara em todo visitante.
Este script só DETECTA que o payload volta sem escape (não abre navegador).
"""
from config import checar_escopo, titulo, sessao

ALVO = checar_escopo()

PAYLOAD = "<script>alert('XSS-LabSeg')</script>"


def main():
    titulo("06", "XSS refletido e armazenado", "Aplicação / Integridade")

    print("\n(1) XSS REFLETIDO em /busca?q=")
    r = sessao.get(f"{ALVO}/busca", params={"q": PAYLOAD})
    if PAYLOAD in r.text:
        print("  VULNERÁVEL: o payload voltou intacto (sem escape) no HTML.")
        print(f"  Trecho: ...{r.text[r.text.find('Resultados'):][:70]}...")
    else:
        print("  Protegido: o payload foi escapado.")

    print("\n(2) XSS ARMAZENADO em /comentarios")
    marca = "<script>document.title='LabSeg'</script>"
    sessao.post(f"{ALVO}/comentarios", data={"autor": "pentest", "texto": marca})
    r = sessao.get(f"{ALVO}/")
    if marca in r.text:
        print("  VULNERÁVEL: o comentário foi salvo e é servido sem escape (|safe).")
        print("  Todo visitante da home passa a executar esse script.")
    else:
        print("  Protegido: o comentário foi escapado.")

    print("\nCORREÇÃO: escapar a saída (deixar o autoescape do Jinja agir; não usar")
    print("          |safe), validar entradas e aplicar Content-Security-Policy.")


if __name__ == "__main__":
    main()
