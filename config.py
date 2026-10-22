"""
Configuração + TRAVA DE ESCOPO do kit de pentest do LabSeg.

Princípio didático (autorização e escopo): só se testa o que se tem permissão
para testar. Por isso os scripts SÓ rodam contra:

  1. o alvo local do laboratório (127.0.0.1 / localhost); OU
  2. um servidor da REDE-LAB ISOLADA, declarado explicitamente pelo instrutor
     na variável LABSEG_REDE_LAB (uma faixa CIDR privada — RFC 1918).

Qualquer host público continua BLOQUEADO, mesmo que apontado à força. Testar
sistemas de terceiros sem autorização é crime (Lei 12.737/2012).

Exemplos de uso:
  # Modo local (cada estação ataca a si mesma) — padrão, nada a configurar:
  python run_all.py

  # Modo rede-lab (estação atacante -> servidor na sub-rede isolada):
  export LABSEG_REDE_LAB=10.13.37.0/24
  export LABSEG_ALVO=http://10.13.37.10:5001
  python run_all.py
"""
import ipaddress
import os
import random
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

ALVO = os.environ.get("LABSEG_ALVO", "http://127.0.0.1:5001")

# Hosts locais sempre permitidos (modo "cada estação ataca a si mesma").
_LOCAIS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}

# Faixa CIDR da rede-lab isolada, declarada pelo instrutor. Só faixas privadas
# (RFC 1918 / reservadas) são aceitas — nunca endereços públicos.
_REDE_LAB = os.environ.get("LABSEG_REDE_LAB", "").strip()


def _rede_lab_permitida():
    """Devolve a rede-lab como objeto de rede se for válida e privada; senão None."""
    if not _REDE_LAB:
        return None
    try:
        rede = ipaddress.ip_network(_REDE_LAB, strict=False)
    except ValueError:
        sys.exit(
            f"\n[ESCOPO] LABSEG_REDE_LAB='{_REDE_LAB}' não é uma faixa CIDR válida.\n"
            f"         Ex.: export LABSEG_REDE_LAB=10.13.37.0/24\n"
        )
    if not rede.is_private:
        sys.exit(
            f"\n[ESCOPO] A rede-lab '{rede}' NÃO é privada. Por segurança e por lei,\n"
            f"         o laboratório só opera em faixas privadas (RFC 1918):\n"
            f"         10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.\n"
        )
    return rede


def checar_escopo():
    host = (urlparse(ALVO).hostname or "").lower()

    # 1) Alvo local — sempre liberado.
    if host in _LOCAIS:
        return ALVO

    # 2) Alvo na rede-lab isolada declarada pelo instrutor.
    rede = _rede_lab_permitida()
    if rede is not None:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and ip in rede:
            return ALVO

    # 3) Qualquer outra coisa é fora de escopo.
    dica = (
        "         Para o modo rede-lab, declare a sub-rede isolada e aponte o alvo:\n"
        "           export LABSEG_REDE_LAB=10.13.37.0/24\n"
        "           export LABSEG_ALVO=http://10.13.37.10:5001\n"
        if not _REDE_LAB
        else f"         O alvo '{host}' está fora da rede-lab declarada ({_REDE_LAB}).\n"
    )
    sys.exit(
        f"\n[ESCOPO] Alvo '{host}' fora de escopo. Este kit é didático e só roda\n"
        f"         contra o laboratório local ({' / '.join(sorted(_LOCAIS))}) ou\n"
        f"         contra um servidor da rede-lab isolada (faixa privada).\n"
        f"{dica}"
        f"         Testar sistemas de terceiros sem autorização é crime "
        f"(Lei 12.737/2012).\n"
    )


# ----------------------------------------------- identidade da estação -------
# Cada estação que roda o kit ganha um NICKNAME aleatório, gravado em disco para
# se manter o mesmo entre execuções. É assim que o painel do alvo mostra QUEM
# está atacando. Pode ser fixado manualmente com a variável LABSEG_NICK.
_ADJETIVOS = [
    "veloz", "furtivo", "sombrio", "neon", "quantico", "fantasma", "cifrado",
    "oculto", "turbo", "glacial", "rubro", "binario", "astuto", "nitido",
    "sonico", "letal", "zero", "prisma", "vortex", "obsidiana",
]
_NOMES = [
    "lobo", "corvo", "cobra", "falcao", "raposa", "tubarao", "escorpiao",
    "pantera", "aguia", "dragao", "hidra", "basilisco", "lince", "coruja",
    "polvo", "mamba", "chacal", "grifo", "kraken", "fenix",
]


def _gerar_nick() -> str:
    return (f"{random.choice(_ADJETIVOS)}-{random.choice(_NOMES)}-"
            f"{random.randint(10, 99)}")


def _nick_da_estacao() -> str:
    forcado = os.environ.get("LABSEG_NICK", "").strip()
    if forcado:
        return forcado
    arquivo = Path.home() / ".labseg_nick"
    try:
        salvo = arquivo.read_text(encoding="utf-8").strip()
        if salvo:
            return salvo
    except OSError:
        pass
    novo = _gerar_nick()
    try:
        arquivo.write_text(novo, encoding="utf-8")
    except OSError:
        pass  # sem permissão de escrita: usa o nick só nesta execução
    return novo


NICK = _nick_da_estacao()

# Sessão única: toda requisição do kit leva o nick no cabeçalho, para o painel
# atribuir cada ataque à estação certa.
sessao = requests.Session()
sessao.headers.update({"X-LabSeg-Pentester": NICK})


def beacon(cenario, nome):
    """Avisa o painel do alvo que esta estação começou um cenário (inclui os
    ataques offline, que não tocam os endpoints vulneráveis). Falha em silêncio:
    se o painel não responder, o ataque continua normalmente."""
    try:
        sessao.post(f"{ALVO}/labseg/beacon",
                    json={"nick": NICK, "cenario": str(cenario), "titulo": nome},
                    timeout=1.5)
    except requests.RequestException:
        pass


def titulo(num, nome, camada):
    print("=" * 74)
    print(f"  CENÁRIO {num} · {nome}")
    print(f"  Camada/tema: {camada}")
    print(f"  Alvo: {ALVO}   |   Estação: {NICK}")
    print("=" * 74)
    beacon(num, nome)
