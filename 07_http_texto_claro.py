"""
CENÁRIO 07 · Dados em trânsito em HTTP (texto claro) + má configuração
Camada de transporte / Semana 10 (TLS) · CIA: Confidencialidade.

O alvo roda em HTTP (porta 80/5000), sem TLS. Quem estiver no caminho (Wi-Fi,
proxy) lê usuário, senha e token em texto claro — exatamente o que o HTTPS
resolve (aula de Certificados/SSL/TLS). Aqui simulamos o "grampo" mostrando o
corpo da requisição que trafegaria aberto, e conferimos a ausência de TLS/HSTS.
"""
from urllib.parse import urlparse
from config import checar_escopo, titulo, sessao

ALVO = checar_escopo()


def main():
    titulo("07", "Credenciais em HTTP + sem HSTS", "Transporte / Semana 10 - TLS")

    u = urlparse(ALVO)
    print(f"\nEsquema do alvo: {u.scheme}  (porta {u.port})")
    if u.scheme == "http":
        print("  SEM TLS: tudo trafega em texto claro.")

    print("\n(1) O que um sniffer veria no login (bytes que saem na rede):")
    corpo = "usuario=ana&senha=primavera"
    requisicao = (
        f"POST /login HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(corpo)}\r\n\r\n{corpo}"
    )
    print("  " + requisicao.replace("\r\n", "\n  "))
    print("  <- usuário e senha legíveis a olho nu.")

    print("\n(2) Fazendo o login de verdade e observando o token no claro:")
    r = sessao.post(f"{ALVO}/login", data={"usuario": "ana", "senha": "primavera"})
    if r.ok and r.json().get("ok"):
        print(f"  token recebido em texto claro: {r.json()['token'][:40]}...")

    print("\n(3) Cabeçalho HSTS presente? (deveria existir para forçar HTTPS)")
    print(f"  Strict-Transport-Security: {r.headers.get('Strict-Transport-Security', 'AUSENTE')}")

    print("\nCORREÇÃO: servir só por HTTPS (TLS 1.2/1.3) com certificado válido,")
    print("          redirecionar 80->443 e enviar HSTS (Semana 10).")


if __name__ == "__main__":
    main()
