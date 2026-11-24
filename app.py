#!/usr/bin/env python3
"""
Monitor de Aplicações
=====================

Monitora sites/domínios (públicos ou internos via VPN), mostra o status em uma
tela web e envia notificação quando um site cai ou volta.

Uso:
    python3 app.py                 # sobe o servidor
    python3 app.py senha           # define/altere a senha de acesso
    python3 app.py ajuda           # mostra esta ajuda

Somente biblioteca padrão do Python 3.9+.
"""

from __future__ import annotations

import getpass
import gzip
import hashlib
import hmac
import json
import os
import re
import secrets as pysecrets
import smtplib
import socket
import ssl
import sqlite3
import sys
import threading
import time
import traceback
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# --------------------------------------------------------------------------- #
# Caminhos e constantes
# --------------------------------------------------------------------------- #

BASE = Path(__file__).resolve().parent
ARQ_SITES = BASE / "sites.json"
ARQ_CONFIG = BASE / "config.json"
ARQ_SEGREDOS = BASE / "secrets.json"
ARQ_BANCO = BASE / "monitor.db"
ARQ_HTML = BASE / "index.html"

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

MARCAS_BLOQUEIO = (
    "just a moment",
    "cf-chl",
    "attention required",
    "checking your browser",
    "enable javascript and cookies",
    "ddos protection by",
    "captcha",
)

CONFIG_PADRAO = {
    "host": "0.0.0.0",
    "porta": 8090,
    "exigir_login": True,
    "intervalo_padrao_s": 60,
    "timeout_padrao_s": 10,
    "limiar_lento_ms": 5000,
    "retencao_dias": 7,
    "cooldown_min": 5,
    "ca_bundle": "",
    "url_publica": "",
    "canais_ativos": {"telegram": True, "google_chat": False, "webhook": False, "email": False},
}

SEGREDOS_PADRAO = {
    "senha_hash": "",
    "senha_salt": "",
    "telegram_token": "",
    "telegram_chat_id": "",
    "google_chat_urls": [],
    "google_chat_thread": False,
    "webhook_url": "",
    "smtp": {
        "host": "",
        "porta": 587,
        "tls": True,
        "usuario": "",
        "senha": "",
        "de": "",
        "para": "",
    },
}

ESTADOS = ("no_ar", "degradado", "instavel", "fora_do_ar", "pausado", "desconhecido")

SERIE_MAX = 60          # pontos mantidos em memória para o gráfico
COOKIE = "mon_sid"
SESSAO_SEGUNDOS = 12 * 3600


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #


def log(msg: str) -> None:
    print(f"[{time.strftime('%d/%m/%Y %H:%M:%S')}] {msg}", flush=True)


def agora() -> int:
    return int(time.time())


def slug(texto: str) -> str:
    normal = unicodedata.normalize("NFKD", texto or "")
    normal = normal.encode("ascii", "ignore").decode("ascii").lower()
    normal = re.sub(r"[^a-z0-9]+", "-", normal).strip("-")
    return normal or "site"


def ler_json(caminho: Path, padrao: dict) -> dict:
    try:
        with caminho.open("r", encoding="utf-8") as fh:
            dados = json.load(fh)
        if isinstance(dados, dict):
            return dados
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError) as exc:
        log(f"AVISO: não consegui ler {caminho.name} ({exc}); usando padrões.")
    return json.loads(json.dumps(padrao))


def escrever_json(caminho: Path, dados: dict, privado: bool = False) -> None:
    temporario = caminho.with_name(caminho.name + ".tmp")
    texto = json.dumps(dados, indent=2, ensure_ascii=False) + "\n"
    fd = os.open(temporario, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if privado else 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(texto)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporario, caminho)
    finally:
        if temporario.exists():
            try:
                temporario.unlink()
            except OSError:
                pass


def mtime(caminho: Path) -> float:
    try:
        return caminho.stat().st_mtime
    except OSError:
        return 0.0


def resolver_caminho(valor: str) -> Path:
    caminho = Path(str(valor)).expanduser()
    return caminho if caminho.is_absolute() else (BASE / caminho)


def _booleano(valor, padrao: bool = False) -> bool:
    """Aceita true/false do JSON e também 'true'/'1'/'sim' escritos à mão."""
    if valor is None:
        return padrao
    if isinstance(valor, bool):
        return valor
    if isinstance(valor, (int, float)):
        return bool(valor)
    texto = str(valor).strip().lower()
    if texto in ("1", "true", "sim", "s", "yes", "y", "on"):
        return True
    if texto in ("0", "false", "nao", "não", "n", "no", "off"):
        return False
    return padrao


# --------------------------------------------------------------------------- #
# Repositório de configuração (arquivos JSON)
# --------------------------------------------------------------------------- #


class ErroValidacao(Exception):
    pass


class Repositorio:
    """Mantém sites.json / config.json / secrets.json com recarga automática."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        if not ARQ_CONFIG.exists():
            escrever_json(ARQ_CONFIG, CONFIG_PADRAO)
        if not ARQ_SEGREDOS.exists():
            escrever_json(ARQ_SEGREDOS, SEGREDOS_PADRAO, privado=True)
        if not ARQ_SITES.exists():
            escrever_json(ARQ_SITES, {"editar_pela_tela": True, "sites": []})

        self.config = ler_json(ARQ_CONFIG, CONFIG_PADRAO)
        self.segredos = ler_json(ARQ_SEGREDOS, SEGREDOS_PADRAO)
        self._sites_doc = ler_json(ARQ_SITES, {"editar_pela_tela": True, "sites": []})
        self._sites_mtime = mtime(ARQ_SITES)
        self._segredos_mtime = mtime(ARQ_SEGREDOS)
        self._config_mtime = mtime(ARQ_CONFIG)

    # -- sites ------------------------------------------------------------- #

    def sites(self) -> list[dict]:
        """Devolve os sites normalizados, tolerando edições manuais no JSON."""
        with self.lock:
            saida = []
            for bruto in self._sites_doc.get("sites", []):
                if not isinstance(bruto, dict):
                    continue
                url = str(bruto.get("url") or "").strip()
                if not url:
                    continue
                nome = str(bruto.get("nome") or url).strip() or url
                try:
                    intervalo = max(10, min(3600, int(bruto.get("intervalo_s") or 60)))
                except (TypeError, ValueError):
                    intervalo = 60
                try:
                    timeout = max(1, min(60, int(bruto.get("timeout_s") or 10)))
                except (TypeError, ValueError):
                    timeout = 10
                try:
                    falhas = max(1, min(10, int(bruto.get("falhas_para_alerta") or 2)))
                except (TypeError, ValueError):
                    falhas = 2
                esperados = bruto.get("status_esperado") or [200]
                if not isinstance(esperados, list):
                    esperados = [200]
                codigos = []
                for item in esperados:
                    try:
                        codigos.append(int(item))
                    except (TypeError, ValueError):
                        continue
                saida.append(
                    {
                        "id": str(bruto.get("id") or slug(nome)),
                        "nome": nome,
                        "url": url,
                        "rede": "interno"
                        if str(bruto.get("rede") or "").lower().startswith("intern")
                        else "publico",
                        "intervalo_s": intervalo,
                        "timeout_s": timeout,
                        "status_esperado": codigos or [200],
                        "palavra_chave": (str(bruto.get("palavra_chave")).strip() or None)
                        if bruto.get("palavra_chave")
                        else None,
                        "falhas_para_alerta": falhas,
                        "ignorar_certificado": _booleano(bruto.get("ignorar_certificado"), False),
                        "ativo": _booleano(bruto.get("ativo"), True),
                        "notificar": _booleano(bruto.get("notificar"), True),
                    }
                )
            return saida

    def editar_pela_tela(self) -> bool:
        with self.lock:
            return bool(self._sites_doc.get("editar_pela_tela", True))

    def recarregar_se_mudou(self) -> bool:
        """Relê os JSONs se foram alterados por fora (ex.: edição via SSH)."""
        mudou = False
        with self.lock:
            atual = mtime(ARQ_SITES)
            if atual != self._sites_mtime:
                self._sites_mtime = atual
                self._sites_doc = ler_json(ARQ_SITES, {"editar_pela_tela": True, "sites": []})
                mudou = True
                log(f"sites.json recarregado ({len(self._sites_doc.get('sites', []))} site(s)).")
            if mtime(ARQ_CONFIG) != self._config_mtime:
                self._config_mtime = mtime(ARQ_CONFIG)
                self.config = ler_json(ARQ_CONFIG, CONFIG_PADRAO)
                mudou = True
            if mtime(ARQ_SEGREDOS) != self._segredos_mtime:
                self._segredos_mtime = mtime(ARQ_SEGREDOS)
                self.segredos = ler_json(ARQ_SEGREDOS, SEGREDOS_PADRAO)
                mudou = True
        return mudou

    def salvar_sites(self, sites: list[dict], editar_pela_tela: bool | None = None) -> None:
        with self.lock:
            if editar_pela_tela is None:
                editar_pela_tela = bool(self._sites_doc.get("editar_pela_tela", True))
            doc = {"editar_pela_tela": editar_pela_tela, "sites": sites}
            escrever_json(ARQ_SITES, doc)
            self._sites_doc = doc
            self._sites_mtime = mtime(ARQ_SITES)

    def salvar_config(self, novo: dict) -> None:
        with self.lock:
            self.config = novo
            escrever_json(ARQ_CONFIG, novo)
            self._config_mtime = mtime(ARQ_CONFIG)

    def salvar_segredos(self, novo: dict) -> None:
        with self.lock:
            self.segredos = novo
            escrever_json(ARQ_SEGREDOS, novo, privado=True)
            self._segredos_mtime = mtime(ARQ_SEGREDOS)

    # -- autenticação ------------------------------------------------------ #

    def tem_senha(self) -> bool:
        return bool(self.segredos.get("senha_hash"))

    def definir_senha(self, senha: str) -> None:
        salt = pysecrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt.encode(), 200_000).hex()
        segredos = dict(self.segredos)
        segredos["senha_salt"] = salt
        segredos["senha_hash"] = digest
        self.salvar_segredos(segredos)

    def conferir_senha(self, senha: str) -> bool:
        segredos = self.segredos
        if not segredos.get("senha_hash"):
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", senha.encode(), segredos.get("senha_salt", "").encode(), 200_000
        ).hex()
        return hmac.compare_digest(digest, segredos["senha_hash"])

    # -- visão pública ----------------------------------------------------- #

    def modo_somente_leitura(self) -> bool:
        return bool(self.config.get("exigir_login", True)) and not self.tem_senha()

    def config_publica(self) -> dict:
        cfg = dict(self.config)
        seg = self.segredos
        smtp = dict(seg.get("smtp") or {})
        return {
            "config": cfg,
            "editar_pela_tela": self.editar_pela_tela(),
            "modo_somente_leitura": self.modo_somente_leitura(),
            "tem_senha": self.tem_senha(),
            "segredos": {
                "telegram_configurado": bool(seg.get("telegram_token") and seg.get("telegram_chat_id")),
                "telegram_chat_id": seg.get("telegram_chat_id", ""),
                "google_chat_configurado": bool(seg.get("google_chat_urls")),
                "google_chat_qtd": len(seg.get("google_chat_urls") or []),
                "google_chat_thread": bool(seg.get("google_chat_thread", True)),
                "webhook_configurado": bool(seg.get("webhook_url")),
                "email_configurado": bool(smtp.get("host") and smtp.get("para")),
                "smtp": {
                    "host": smtp.get("host", ""),
                    "porta": smtp.get("porta", 587),
                    "tls": bool(smtp.get("tls", True)),
                    "usuario": smtp.get("usuario", ""),
                    "de": smtp.get("de", ""),
                    "para": smtp.get("para", ""),
                },
            },
        }


# --------------------------------------------------------------------------- #
# Banco de dados (histórico)
# --------------------------------------------------------------------------- #


class Banco:
    def __init__(self, caminho: Path) -> None:
        self.lock = threading.RLock()
        self.con = sqlite3.connect(str(caminho), check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        with self.lock, self.con:
            self.con.execute("PRAGMA journal_mode=WAL")
            self.con.executescript(
                """
                CREATE TABLE IF NOT EXISTS checagens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    ok INTEGER NOT NULL,
                    status_code INTEGER,
                    latencia_ms INTEGER,
                    erro TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_checagens_site_ts
                    ON checagens(site_id, ts);
                CREATE TABLE IF NOT EXISTS incidentes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id TEXT NOT NULL,
                    inicio INTEGER NOT NULL,
                    fim INTEGER,
                    motivo TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_incidentes_site
                    ON incidentes(site_id, inicio);
                """
            )

    def registrar(self, site_id: str, ok: bool, status_code, latencia_ms, erro) -> None:
        with self.lock, self.con:
            self.con.execute(
                "INSERT INTO checagens (site_id, ts, ok, status_code, latencia_ms, erro)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (site_id, agora(), 1 if ok else 0, status_code, latencia_ms, erro),
            )

    def abrir_incidente(self, site_id: str, motivo: str | None) -> int:
        with self.lock, self.con:
            cur = self.con.execute(
                "INSERT INTO incidentes (site_id, inicio, motivo) VALUES (?, ?, ?)",
                (site_id, agora(), motivo),
            )
            return int(cur.lastrowid)

    def fechar_incidente(self, incidente_id: int) -> None:
        with self.lock, self.con:
            self.con.execute(
                "UPDATE incidentes SET fim = ? WHERE id = ? AND fim IS NULL",
                (agora(), incidente_id),
            )

    def uptime(self, site_id: str, desde: int) -> tuple[int, int]:
        with self.lock:
            linha = self.con.execute(
                "SELECT COUNT(*) AS total, COALESCE(SUM(ok), 0) AS bons"
                " FROM checagens WHERE site_id = ? AND ts >= ?",
                (site_id, desde),
            ).fetchone()
        return int(linha["total"]), int(linha["bons"])

    def incidentes(self, limite: int = 30) -> list[dict]:
        with self.lock:
            linhas = self.con.execute(
                "SELECT * FROM incidentes ORDER BY inicio DESC LIMIT ?", (limite,)
            ).fetchall()
        return [dict(l) for l in linhas]

    def limpar(self, dias: int) -> int:
        corte = agora() - max(1, dias) * 86400
        with self.lock, self.con:
            cur = self.con.execute("DELETE FROM checagens WHERE ts < ?", (corte,))
            return cur.rowcount

    def apagar_site(self, site_id: str) -> None:
        with self.lock, self.con:
            self.con.execute("DELETE FROM checagens WHERE site_id = ?", (site_id,))
            self.con.execute("DELETE FROM incidentes WHERE site_id = ?", (site_id,))


# --------------------------------------------------------------------------- #
# Checagem HTTP
# --------------------------------------------------------------------------- #


def _corpo(resp, limite: int = 262_144) -> bytes:
    try:
        bruto = resp.read(limite)
    except Exception:
        return b""
    codificacao = (resp.headers.get("Content-Encoding") or "").lower()
    try:
        if "gzip" in codificacao:
            return gzip.decompress(bruto)
        if "deflate" in codificacao:
            return zlib.decompress(bruto)
    except Exception:
        pass
    return bruto


def _texto(bruto: bytes) -> str:
    for codificacao in ("utf-8", "latin-1"):
        try:
            return bruto.decode(codificacao)
        except UnicodeDecodeError:
            continue
    return ""


def checar_site(site: dict, ca_bundle: str | None = None) -> dict:
    """Faz uma checagem e devolve ok/status/latência/erro."""
    url = site["url"]
    timeout = float(site.get("timeout_s") or 10)
    esperados = site.get("status_esperado") or [200]
    palavra = (site.get("palavra_chave") or "").strip()

    contexto = None
    if url.lower().startswith("https"):
        contexto = ssl.create_default_context()
        if site.get("ignorar_certificado"):
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE
        elif ca_bundle:
            caminho_ca = resolver_caminho(ca_bundle)
            if caminho_ca.exists():
                try:
                    contexto.load_verify_locations(cafile=str(caminho_ca))
                except ssl.SSLError as exc:
                    log(f"AVISO: ca_bundle inválido ({caminho_ca}): {exc}")

    pedido = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "Upgrade-Insecure-Requests": "1",
        },
    )

    inicio = time.monotonic()
    codigo = None
    corpo = b""
    erro = None
    servidor = ""
    try:
        with urllib.request.urlopen(pedido, timeout=timeout, context=contexto) as resp:
            codigo = getattr(resp, "status", None) or resp.getcode()
            servidor = (resp.headers.get("Server") or "").lower()
            if palavra or codigo in (403, 429, 503):
                corpo = _corpo(resp, 65536 if codigo in (403, 429, 503) else 262144)
    except urllib.error.HTTPError as exc:
        codigo = exc.code
        servidor = ((exc.headers.get("Server") if exc.headers else "") or "").lower()
        if palavra or codigo in (403, 429, 503):
            corpo = _corpo(exc, 65536)
        exc.close()
    except (socket.timeout, TimeoutError):
        erro = f"timeout após {timeout:g}s"
    except urllib.error.URLError as exc:
        razao = exc.reason
        if isinstance(razao, ssl.SSLCertVerificationError):
            erro = (
                "certificado TLS não validado (cadeia incompleta ou CA desconhecida). "
                "Marque 'Ignorar certificado' neste site ou configure o ca_bundle nos Ajustes."
            )
        elif isinstance(razao, socket.gaierror):
            erro = "DNS não resolveu o domínio"
        elif isinstance(razao, ssl.SSLError):
            erro = f"erro de TLS: {razao}"
        elif isinstance(razao, (socket.timeout, TimeoutError)):
            erro = f"timeout após {timeout:g}s"
        else:
            erro = f"conexão falhou: {razao}"
    except ssl.SSLCertVerificationError:
        erro = (
            "certificado TLS não validado (cadeia incompleta ou CA desconhecida). "
            "Marque 'Ignorar certificado' neste site ou configure o ca_bundle nos Ajustes."
        )
    except ssl.SSLError as exc:
        erro = f"erro de TLS: {exc}"
    except ConnectionError as exc:
        erro = f"conexão encerrada: {exc}"
    except Exception as exc:  # noqa: BLE001 - queremos registrar qualquer falha
        erro = f"falha: {exc.__class__.__name__}: {exc}"

    latencia = int((time.monotonic() - inicio) * 1000)

    if erro:
        return {
            "ok": False,
            "bloqueio": False,
            "status_code": codigo,
            "latencia_ms": latencia,
            "erro": erro,
        }

    if codigo in (403, 429, 503):
        texto = _texto(corpo).lower()
        if "cloudflare" in servidor or any(m in texto for m in MARCAS_BLOQUEIO):
            return {
                "ok": False,
                "bloqueio": True,
                "status_code": codigo,
                "latencia_ms": latencia,
                "erro": (
                    f"HTTP {codigo}: desafio anti-bot (proteção do site). "
                    "O site está no ar, mas bloqueia a checagem automática."
                ),
            }

    ok_status = codigo in esperados
    ok_palavra = True
    if palavra:
        ok_palavra = palavra.lower() in _texto(corpo).lower()

    if not ok_status:
        erro = f"HTTP {codigo} (esperado {', '.join(str(c) for c in esperados)})"
    elif not ok_palavra:
        erro = f"palavra-chave não encontrada: \"{palavra}\""

    return {
        "ok": ok_status and ok_palavra,
        "bloqueio": False,
        "status_code": codigo,
        "latencia_ms": latencia,
        "erro": erro,
    }


# --------------------------------------------------------------------------- #
# Notificações
# --------------------------------------------------------------------------- #


class Notificador:
    def __init__(self, repo: Repositorio) -> None:
        self.repo = repo
        self.lock = threading.Lock()
        self.ultimo = {"ts": None, "ok": None, "detalhe": "nenhuma notificação enviada ainda"}

    def _registrar(self, resultados: list[dict]) -> None:
        if not resultados:
            detalhe = "nenhum canal ativo/configurado"
            ok = None
        else:
            ok = all(r["ok"] for r in resultados)
            partes = []
            for r in resultados:
                if r["ok"]:
                    partes.append(f"{r['canal']}: ok")
                else:
                    erro = r.get("erro")
                    partes.append(f"{r['canal']}: falhou" + (f" ({erro})" if erro else ""))
            detalhe = "; ".join(partes)
        with self.lock:
            self.ultimo = {"ts": agora(), "ok": ok, "detalhe": detalhe}
        log(f"notificação -> {detalhe}")

    def enviar(
        self,
        titulo: str,
        texto: str,
        chave_thread: str | None = None,
        cartao: dict | None = None,
    ) -> list[dict]:
        seg = self.repo.segredos
        canais = self.repo.config.get("canais_ativos", {})
        resultados: list[dict] = []

        if canais.get("telegram"):
            token = (seg.get("telegram_token") or "").strip()
            chat = (seg.get("telegram_chat_id") or "").strip()
            if token and chat:
                resultados.append(
                    self._telegram(token, chat, f"<b>{_html(titulo)}</b>\n{_html(texto)}")
                )
            else:
                resultados.append({"canal": "telegram", "ok": False, "erro": "não configurado"})

        if canais.get("google_chat"):
            urls = [u for u in (seg.get("google_chat_urls") or []) if u]
            if urls:
                for url in urls:
                    item = self._google_chat(url, titulo, texto, chave_thread, seg, cartao)
                    if len(urls) > 1:
                        item["canal"] = f"google_chat[{urls.index(url) + 1}]"
                    resultados.append(item)
            else:
                resultados.append({"canal": "google_chat", "ok": False, "erro": "não configurado"})

        if canais.get("webhook"):
            url = (seg.get("webhook_url") or "").strip()
            if url:
                resultados.append(self._webhook(url, f"**{titulo}**\n\n{texto}"))
            else:
                resultados.append({"canal": "webhook", "ok": False, "erro": "não configurado"})

        if canais.get("email"):
            smtp = seg.get("smtp") or {}
            if smtp.get("host") and smtp.get("para"):
                resultados.append(self._email(smtp, titulo, texto))
            else:
                resultados.append({"canal": "email", "ok": False, "erro": "não configurado"})

        self._registrar(resultados)
        return resultados

    # -- canais ------------------------------------------------------------ #

    def _telegram(self, token: str, chat: str, mensagem: str) -> dict:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        dados = urllib.parse.urlencode(
            {"chat_id": chat, "text": mensagem, "parse_mode": "HTML", "disable_web_page_preview": "true"}
        ).encode()
        try:
            pedido = urllib.request.Request(url, data=dados, method="POST")
            with urllib.request.urlopen(pedido, timeout=15) as resp:
                resp.read()
            return {"canal": "telegram", "ok": True}
        except Exception as exc:  # noqa: BLE001
            return {"canal": "telegram", "ok": False, "erro": str(exc)}

    def _google_chat(
        self,
        url: str,
        titulo: str,
        texto: str,
        chave_thread: str | None,
        seg: dict,
        cartao: dict | None = None,
    ) -> dict:
        destino = url
        if seg.get("google_chat_thread", True) and chave_thread:
            separador = "&" if "?" in destino else "?"
            destino += (
                f"{separador}threadKey={urllib.parse.quote(slug(chave_thread))}"
                "&messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
            )
        if cartao:
            payload = {"cardsV2": [cartao]}
        else:
            payload = {"text": f"*{titulo}*\n\n{texto}"}
        corpo = json.dumps(payload).encode("utf-8")
        try:
            pedido = urllib.request.Request(
                destino,
                data=corpo,
                method="POST",
                headers={"Content-Type": "application/json; charset=UTF-8"},
            )
            with urllib.request.urlopen(pedido, timeout=15) as resp:
                resp.read()
            return {"canal": "google_chat", "ok": True}
        except urllib.error.HTTPError as exc:
            detalhe = ""
            try:
                bruto = exc.read(4000).decode("utf-8", "replace")
                try:
                    dados = json.loads(bruto)
                    detalhe = (dados.get("error") or {}).get("message") or bruto
                except json.JSONDecodeError:
                    detalhe = bruto
            except Exception:  # noqa: BLE001
                pass
            detalhe = " ".join(str(detalhe).split())[:200]
            return {
                "canal": "google_chat",
                "ok": False,
                "erro": f"HTTP {exc.code}: {detalhe}" if detalhe else f"HTTP {exc.code}",
            }
        except Exception as exc:  # noqa: BLE001
            return {"canal": "google_chat", "ok": False, "erro": str(exc)}

    def _webhook(self, url: str, mensagem: str) -> dict:
        corpo = json.dumps({"text": mensagem, "content": mensagem}).encode()
        try:
            pedido = urllib.request.Request(
                url, data=corpo, method="POST", headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(pedido, timeout=15) as resp:
                resp.read()
            return {"canal": "webhook", "ok": True}
        except Exception as exc:  # noqa: BLE001
            return {"canal": "webhook", "ok": False, "erro": str(exc)}

    def _email(self, smtp: dict, titulo: str, texto: str) -> dict:
        try:
            msg = EmailMessage()
            msg["Subject"] = titulo
            msg["From"] = smtp.get("de") or smtp.get("usuario") or "monitor@localhost"
            msg["To"] = smtp.get("para")
            msg.set_content(texto)

            host = smtp.get("host")
            porta = int(smtp.get("porta") or 587)
            if int(porta) == 465:
                cliente = smtplib.SMTP_SSL(host, porta, timeout=15)
            else:
                cliente = smtplib.SMTP(host, porta, timeout=15)
                if smtp.get("tls", True):
                    cliente.starttls()
            if smtp.get("usuario"):
                cliente.login(smtp["usuario"], smtp.get("senha", ""))
            cliente.send_message(msg)
            cliente.quit()
            return {"canal": "email", "ok": True}
        except Exception as exc:  # noqa: BLE001
            return {"canal": "email", "ok": False, "erro": str(exc)}


def _html(texto: str) -> str:
    return (
        str(texto)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# --------------------------------------------------------------------------- #
# Monitor (agendador + estado)
# --------------------------------------------------------------------------- #


def estado_vazio() -> dict:
    return {
        "estado": "desconhecido",
        "desde": None,
        "latencia_ms": None,
        "status_code": None,
        "erro": None,
        "ultima_checagem": None,
        "falhas": 0,
        "serie": [],
        "incidente_id": None,
    }


class Monitor:
    def __init__(self, repo: Repositorio, banco: Banco, notificador: Notificador) -> None:
        self.repo = repo
        self.banco = banco
        self.notificador = notificador
        self.lock = threading.RLock()
        self.estados: dict[str, dict] = {}
        self.proximo: dict[str, float] = {}
        self.avisado: dict[str, float] = {}
        self.vpn_suspeita = False
        self.vpn_avisada = False
        self._parar = threading.Event()
        self._ultima_limpeza = 0.0
        self._thread: threading.Thread | None = None

    # -- ciclo de vida ----------------------------------------------------- #

    def iniciar(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="monitor", daemon=True)
        self._thread.start()

    def parar(self) -> None:
        self._parar.set()

    def _loop(self) -> None:
        pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="checagem")
        try:
            while not self._parar.is_set():
                try:
                    self.repo.recarregar_se_mudou()
                    self._sincronizar()
                    momento = time.time()
                    for site in self._sites_ativos():
                        if self.proximo.get(site["id"], 0) <= momento:
                            self.proximo[site["id"]] = momento + max(10, int(site["intervalo_s"]))
                            pool.submit(self._executar, site)
                    self._avaliar_vpn()
                    self._limpeza_diaria()
                except Exception:  # noqa: BLE001
                    log("ERRO no agendador:\n" + traceback.format_exc())
                self._parar.wait(1)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def _sites_ativos(self) -> list[dict]:
        return [s for s in self.repo.sites() if s.get("ativo", True)]

    def _sincronizar(self) -> None:
        """Ajusta o dicionário de estados à lista atual de sites."""
        with self.lock:
            ids = {s["id"] for s in self.repo.sites()}
            for site_id in list(self.estados):
                if site_id not in ids:
                    self.estados.pop(site_id, None)
                    self.proximo.pop(site_id, None)
                    self.avisado.pop(site_id, None)
            for site in self.repo.sites():
                st = self.estados.setdefault(site["id"], estado_vazio())
                if not site.get("ativo", True):
                    if st["estado"] != "pausado":
                        st["estado"] = "pausado"
                        st["desde"] = agora()
                elif st["estado"] == "pausado":
                    st["estado"] = "desconhecido"
                    st["desde"] = agora()

    # -- execução de uma checagem ------------------------------------------ #

    def _executar(self, site: dict) -> None:
        try:
            resultado = checar_site(site, self.repo.config.get("ca_bundle"))
        except Exception:  # noqa: BLE001
            log(f"ERRO ao checar {site.get('url')}:\n" + traceback.format_exc())
            resultado = {"ok": False, "status_code": None, "latencia_ms": None, "erro": "erro interno"}
        try:
            self._aplicar(site, resultado)
        except Exception:  # noqa: BLE001
            log("ERRO ao aplicar resultado:\n" + traceback.format_exc())

    def _aplicar(self, site: dict, resultado: dict) -> None:
        limiar = int(self.repo.config.get("limiar_lento_ms", 5000))
        falhas_alerta = max(1, int(site.get("falhas_para_alerta", 2)))
        evento = None
        incidente_aberto = None
        incidente_fechado = None

        with self.lock:
            st = self.estados.setdefault(site["id"], estado_vazio())
            anterior = st["estado"]
            anterior_desde = st["desde"]
            st["ultima_checagem"] = agora()
            st["status_code"] = resultado.get("status_code")
            st["latencia_ms"] = resultado.get("latencia_ms")
            st["erro"] = resultado.get("erro")
            st["serie"].append(
                {
                    "ts": agora(),
                    "latencia_ms": resultado.get("latencia_ms"),
                    "ok": bool(resultado.get("ok")) or bool(resultado.get("bloqueio")),
                }
            )
            del st["serie"][:-SERIE_MAX]

            bloqueado = bool(resultado.get("bloqueio"))
            if bloqueado:
                st["falhas"] = 0
                st["estado"] = "bloqueado"
            elif resultado.get("ok"):
                st["falhas"] = 0
                latencia = resultado.get("latencia_ms") or 0
                st["estado"] = "degradado" if latencia > limiar else "no_ar"
            else:
                st["falhas"] += 1
                st["estado"] = "fora_do_ar" if st["falhas"] >= falhas_alerta else "instavel"

            if st["estado"] != anterior:
                st["estado_anterior_desde"] = anterior_desde
                st["desde"] = agora()

            if st["estado"] == "fora_do_ar" and anterior != "fora_do_ar":
                evento = "queda"
            elif anterior == "fora_do_ar" and st["estado"] in ("no_ar", "degradado"):
                evento = "recuperacao"
            elif st["estado"] == "bloqueado" and anterior != "bloqueado":
                evento = "bloqueio"

        self.banco.registrar(
            site["id"],
            bool(resultado.get("ok")) or bool(resultado.get("bloqueio")),
            resultado.get("status_code"),
            resultado.get("latencia_ms"),
            resultado.get("erro"),
        )

        if evento == "queda":
            with self.lock:
                incidente_aberto = st["incidente_id"] = self.banco.abrir_incidente(
                    site["id"], resultado.get("erro")
                )
        elif evento == "recuperacao":
            with self.lock:
                incidente_fechado = st["incidente_id"]
                st["incidente_id"] = None
            if incidente_fechado:
                self.banco.fechar_incidente(int(incidente_fechado))

        if evento:
            self._notificar_evento(site, evento, resultado, incidente_aberto)

    # -- notificações de eventos ------------------------------------------- #

    def _botao(self, texto: str, url: str) -> dict:
        return {"text": texto, "onClick": {"openLink": {"url": url}}}

    def _linha(self, rotulo: str, valor: str) -> dict:
        return {"decoratedText": {"topLabel": rotulo, "text": valor, "wrapText": True}}

    def _botoes(self, site: dict | None = None) -> list[dict]:
        botoes = []
        if site and str(site.get("url", "")).startswith(("http://", "https://")):
            botoes.append(self._botao("Abrir site", site["url"]))
        publica = str(self.repo.config.get("url_publica") or "").strip()
        if publica.startswith(("http://", "https://")):
            botoes.append(self._botao("Abrir monitor", publica))
        return botoes

    def _cartao_evento(self, site: dict, evento: str, resultado: dict) -> dict:
        st = self.estados.get(site["id"], {})
        url = _html(site["url"])
        endereco = f'<a href="{url}">{url}</a>'

        if evento == "queda":
            cabecalho = {
                "title": f"🔴 {site['nome']} está fora do ar",
                "subtitle": "Monitor de Aplicações · indisponibilidade",
            }
            destaque = (
                f'<font color="#d93025"><b>FORA DO AR</b></font>'
                f" · detectado às {time.strftime('%H:%M')}"
            )
            detalhes = [
                ("Endereço", endereco),
                ("Motivo", _html(resultado.get("erro") or "sem resposta")),
                ("Falhas seguidas", str(st.get("falhas", "?"))),
                ("Detectado em", time.strftime("%d/%m/%Y %H:%M:%S")),
            ]
        elif evento == "bloqueio":
            cabecalho = {
                "title": f"🟡 {site['nome']} — monitor bloqueado",
                "subtitle": "Monitor de Aplicações · proteção anti-bot",
            }
            destaque = (
                f'<font color="#b06000"><b>DESAFIO ANTI-BOT</b></font>'
                " · o site recusou a checagem automática"
            )
            detalhes = [
                ("Endereço", endereco),
                ("Resposta", _html(resultado.get("erro") or "desafio anti-bot")),
                (
                    "O que fazer",
                    "Use uma URL de health check sem proteção de bot "
                    "ou aumente o intervalo de checagem.",
                ),
                ("Detectado em", time.strftime("%d/%m/%Y %H:%M:%S")),
            ]
        else:
            desde = st.get("estado_anterior_desde") or st.get("desde") or agora()
            duracao = _duracao(max(0, agora() - int(desde)))
            cabecalho = {
                "title": f"🟢 {site['nome']} voltou ao ar",
                "subtitle": "Monitor de Aplicações · recuperação",
            }
            destaque = (
                f'<font color="#188038"><b>NO AR</b></font>'
                f" · normalizado às {time.strftime('%H:%M')}"
            )
            detalhes = [
                ("Endereço", endereco),
                ("Latência agora", f"{resultado.get('latencia_ms') or 0} ms"),
                ("Indisponível por", duracao),
                ("Recuperado em", time.strftime("%d/%m/%Y %H:%M:%S")),
            ]

        secoes = [
            {"widgets": [{"textParagraph": {"text": destaque}}]},
            {"header": "Detalhes", "widgets": [self._linha(r, v) for r, v in detalhes]},
        ]
        botoes = self._botoes(site)
        if botoes:
            secoes.append({"widgets": [{"buttonList": {"buttons": botoes}}]})

        return {
            "cardId": f"monitor-{slug(site['id'])}-{int(time.time())}",
            "card": {"header": cabecalho, "sections": secoes},
        }

    def _cartao_vpn(self, nomes: str) -> dict:
        secoes = [
            {
                "widgets": [
                    {
                        "textParagraph": {
                            "text": '<font color="#b06000"><b>ATENÇÃO</b></font> — '
                            "todos os sites internos estão inacessíveis, mas os públicos "
                            "continuam respondendo."
                        }
                    }
                ]
            },
            {
                "header": "Diagnóstico",
                "widgets": [
                    self._linha("Internos afetados", _html(nomes)),
                    self._linha("Hipótese", "Perda de VPN ou de rota para a rede interna"),
                    self._linha("Verificado em", time.strftime("%d/%m/%Y %H:%M:%S")),
                ],
            },
        ]
        botoes = self._botoes()
        if botoes:
            secoes.append({"widgets": [{"buttonList": {"buttons": botoes}}]})

        return {
            "cardId": f"monitor-vpn-{int(time.time())}",
            "card": {
                "header": {
                    "title": "⚠️ Possível perda de VPN/rede local",
                    "subtitle": "Monitor de Aplicações · aviso de rede",
                },
                "sections": secoes,
            },
        }

    def _notificar_evento(self, site: dict, evento: str, resultado: dict, incidente_id) -> None:
        if not site.get("notificar", True):
            return

        # Se a VPN parece ter caído, o alerta agregado já cobre os internos.
        if evento == "queda" and site.get("rede") == "interno" and self._vpn_caida_agora():
            log(f"alerta individual de '{site['nome']}' suprimido (suspeita de VPN caída).")
            return

        cooldown = int(self.repo.config.get("cooldown_min", 5)) * 60
        if evento == "bloqueio":
            cooldown = 24 * 3600  # avisa no máximo uma vez por dia
        chave = f"{site['id']}:{evento}"
        ultimo = self.avisado.get(chave, 0)
        if evento in ("queda", "bloqueio") and agora() - ultimo < cooldown:
            log(f"alerta de '{site['nome']}' ({evento}) em cooldown; não reenviado.")
            return
        self.avisado[chave] = agora()

        if evento == "queda":
            titulo = f"🔴 {site['nome']} está fora do ar"
            linhas = [
                f"Site: {site['nome']}",
                f"URL: {site['url']}",
                f"Motivo: {resultado.get('erro') or 'sem resposta'}",
                f"Falhas seguidas: {self.estados.get(site['id'], {}).get('falhas', '?')}",
                f"Detectado em: {time.strftime('%d/%m/%Y %H:%M:%S')}",
            ]
        elif evento == "bloqueio":
            titulo = f"🟡 {site['nome']}: monitor bloqueado pelo site"
            linhas = [
                f"Site: {site['nome']}",
                f"URL: {site['url']}",
                f"Resposta: {resultado.get('erro') or 'desafio anti-bot'}",
                "O site está no ar, mas recusa a checagem automática.",
                "Sugestão: use uma URL de health check sem proteção de bot "
                "ou ajuste o intervalo de checagem.",
            ]
        else:
            st = self.estados.get(site["id"], {})
            desde = st.get("estado_anterior_desde") or st.get("desde") or agora()
            duracao = max(0, agora() - int(desde))
            titulo = f"🟢 {site['nome']} voltou ao ar"
            linhas = [
                f"Site: {site['nome']}",
                f"URL: {site['url']}",
                f"Latência agora: {resultado.get('latencia_ms')} ms",
                f"Indisponível por: {_duracao(duracao)}",
                f"Recuperado em: {time.strftime('%d/%m/%Y %H:%M:%S')}",
            ]

        self.notificador.enviar(
            titulo,
            "\n".join(linhas),
            chave_thread=site["id"],
            cartao=self._cartao_evento(site, evento, resultado),
        )

    def _vpn_caida_agora(self) -> bool:
        sites = [s for s in self.repo.sites() if s.get("ativo", True)]
        internos = [s for s in sites if s.get("rede") == "interno"]
        publicos = [s for s in sites if s.get("rede") != "interno"]
        if not internos or not publicos:
            return False
        with self.lock:
            if not all(
                self.estados.get(s["id"], {}).get("estado") == "fora_do_ar" for s in internos
            ):
                return False
            return any(
                self.estados.get(s["id"], {}).get("estado") in ("no_ar", "degradado")
                for s in publicos
            )

    def _avaliar_vpn(self) -> None:
        novo = self._vpn_caida_agora()

        if novo and not self.vpn_suspeita:
            log("suspeita de perda de VPN/rede local (internos caídos, públicos no ar).")
            if not self.vpn_avisada:
                self.vpn_avisada = True
                internos = [
                    s for s in self.repo.sites() if s.get("rede") == "interno" and s.get("ativo", True)
                ]
                nomes = ", ".join(s["nome"] for s in internos)
                self.notificador.enviar(
                    "⚠️ Possível perda de VPN/rede local",
                    "Todos os sites internos estão inacessíveis, mas os públicos respondem.\n"
                    f"Internos afetados: {nomes}\n"
                    "Verifique sua conexão VPN antes de tratar como queda dos serviços.",
                    chave_thread="vpn",
                    cartao=self._cartao_vpn(nomes),
                )
        if not novo:
            self.vpn_avisada = False
        self.vpn_suspeita = novo

    def _limpeza_diaria(self) -> None:
        if time.time() - self._ultima_limpeza < 86400:
            return
        self._ultima_limpeza = time.time()
        removidas = self.banco.limpar(int(self.repo.config.get("retencao_dias", 7)))
        if removidas:
            log(f"limpeza: {removidas} checagens antigas removidas.")

    # -- leitura ----------------------------------------------------------- #

    def status(self) -> dict:
        self._sincronizar()
        agora_ts = agora()
        dia = agora_ts - 86400
        semana = agora_ts - 7 * 86400
        resumo = {
            "total": 0,
            "no_ar": 0,
            "lento": 0,
            "instavel": 0,
            "fora_do_ar": 0,
            "bloqueado": 0,
            "pausado": 0,
            "aguardando": 0,
        }

        with self.lock:
            lista = []
            for site in self.repo.sites():
                st = self.estados.get(site["id"], estado_vazio())
                total24, bons24 = self.banco.uptime(site["id"], dia)
                total7, bons7 = self.banco.uptime(site["id"], semana)
                estado = st["estado"] if site.get("ativo", True) else "pausado"

                resumo["total"] += 1
                if estado == "no_ar":
                    resumo["no_ar"] += 1
                elif estado == "degradado":
                    resumo["lento"] += 1
                elif estado == "instavel":
                    resumo["instavel"] += 1
                elif estado == "fora_do_ar":
                    resumo["fora_do_ar"] += 1
                elif estado == "bloqueado":
                    resumo["bloqueado"] += 1
                elif estado == "pausado":
                    resumo["pausado"] += 1
                else:
                    resumo["aguardando"] += 1

                lista.append(
                    {
                        **{k: site.get(k) for k in (
                            "id", "nome", "url", "rede", "intervalo_s", "timeout_s",
                            "palavra_chave", "ignorar_certificado", "status_esperado",
                            "falhas_para_alerta", "ativo", "notificar",
                        )},
                        "estado": estado,
                        "estado_desde": st["desde"],
                        "latencia_ms": st["latencia_ms"],
                        "status_code": st["status_code"],
                        "erro": st["erro"],
                        "ultima_checagem": st["ultima_checagem"],
                        "falhas": st["falhas"],
                        "serie": list(st["serie"]),
                        "uptime_24h": round(bons24 / total24 * 100, 2) if total24 else None,
                        "uptime_7d": round(bons7 / total7 * 100, 2) if total7 else None,
                    }
                )

            return {
                "agora": agora_ts,
                "alerta_rede": self.vpn_suspeita,
                "resumo": resumo,
                "sites": lista,
                "ultima_notificacao": dict(self.notificador.ultimo),
            }

    def incidentes(self, limite: int = 30) -> list[dict]:
        nomes = {s["id"]: s["nome"] for s in self.repo.sites()}
        saida = []
        for item in self.banco.incidentes(limite):
            fim = item.get("fim")
            saida.append(
                {
                    "site_id": item["site_id"],
                    "nome": nomes.get(item["site_id"], item["site_id"]),
                    "inicio": item["inicio"],
                    "fim": fim,
                    "duracao_s": (int(fim) - int(item["inicio"])) if fim else agora() - int(item["inicio"]),
                    "aberto": fim is None,
                    "motivo": item.get("motivo"),
                }
            )
        return saida


def _duracao(segundos: int) -> str:
    segundos = max(0, int(segundos))
    if segundos < 60:
        return f"{segundos}s"
    if segundos < 3600:
        return f"{segundos // 60} min"
    horas, resto = divmod(segundos, 3600)
    minutos = resto // 60
    if horas < 24:
        return f"{horas}h {minutos}min"
    dias, horas = divmod(horas, 24)
    return f"{dias}d {horas}h"


# --------------------------------------------------------------------------- #
# Validação de sites
# --------------------------------------------------------------------------- #


def validar_site(dados: dict, config: dict, existente: dict | None = None) -> dict:
    site = dict(existente or {})

    nome = str(dados.get("nome", site.get("nome", ""))).strip()
    if not nome:
        raise ErroValidacao("Informe o nome do site.")
    if len(nome) > 80:
        raise ErroValidacao("O nome deve ter no máximo 80 caracteres.")
    site["nome"] = nome

    url = str(dados.get("url", site.get("url", ""))).strip()
    partes = urllib.parse.urlparse(url)
    if partes.scheme not in ("http", "https"):
        raise ErroValidacao("A URL deve começar com http:// ou https://.")
    if not partes.netloc:
        raise ErroValidacao("A URL não tem um domínio válido.")
    if partes.username or partes.password:
        raise ErroValidacao("Não coloque usuário/senha na URL.")
    if " " in url:
        raise ErroValidacao("A URL não pode conter espaços.")
    site["url"] = url

    rede = str(dados.get("rede", site.get("rede", "publico"))).strip().lower()
    site["rede"] = "interno" if rede.startswith("intern") else "publico"

    site["intervalo_s"] = _inteiro(
        dados.get("intervalo_s", site.get("intervalo_s", config.get("intervalo_padrao_s", 60))),
        10, 3600, "Intervalo",
    )
    site["timeout_s"] = _inteiro(
        dados.get("timeout_s", site.get("timeout_s", config.get("timeout_padrao_s", 10))),
        1, 60, "Timeout",
    )
    site["falhas_para_alerta"] = _inteiro(
        dados.get("falhas_para_alerta", site.get("falhas_para_alerta", 2)),
        1, 10, "Falhas para alertar",
    )

    esperados = dados.get("status_esperado", site.get("status_esperado", [200]))
    if isinstance(esperados, str):
        esperados = [p.strip() for p in esperados.split(",") if p.strip()]
    if not isinstance(esperados, list) or not esperados:
        raise ErroValidacao("Informe ao menos um status HTTP esperado.")
    codigos = []
    for item in esperados:
        try:
            codigo = int(item)
        except (TypeError, ValueError):
            raise ErroValidacao(f"Status HTTP inválido: {item!r}")
        if not 100 <= codigo <= 599:
            raise ErroValidacao(f"Status HTTP fora de faixa: {codigo}")
        codigos.append(codigo)
    site["status_esperado"] = sorted(set(codigos))

    palavra = dados.get("palavra_chave", site.get("palavra_chave"))
    palavra = (str(palavra).strip() if palavra is not None else "") or None
    if palavra and len(palavra) > 200:
        raise ErroValidacao("A palavra-chave deve ter no máximo 200 caracteres.")
    site["palavra_chave"] = palavra

    site["ignorar_certificado"] = bool(
        dados.get("ignorar_certificado", site.get("ignorar_certificado", False))
    )
    site["ativo"] = bool(dados.get("ativo", site.get("ativo", True)))
    site["notificar"] = bool(dados.get("notificar", site.get("notificar", True)))

    return site


def _inteiro(valor, minimo: int, maximo: int, rotulo: str) -> int:
    try:
        numero = int(valor)
    except (TypeError, ValueError):
        raise ErroValidacao(f"{rotulo}: informe um número inteiro.")
    if not minimo <= numero <= maximo:
        raise ErroValidacao(f"{rotulo}: use um valor entre {minimo} e {maximo}.")
    return numero


# --------------------------------------------------------------------------- #
# Servidor HTTP
# --------------------------------------------------------------------------- #


class ErroHTTP(Exception):
    def __init__(self, codigo: int, mensagem: str) -> None:
        super().__init__(mensagem)
        self.codigo = codigo


class ServidorHTTP(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, endereco, handler, repo, banco, monitor, notificador):
        super().__init__(endereco, handler)
        self.repo = repo
        self.banco = banco
        self.monitor = monitor
        self.notificador = notificador
        self.sessoes: dict[str, float] = {}
        self.sessoes_lock = threading.Lock()
        self.tentativas: dict[str, list[float]] = {}


class Handler(BaseHTTPRequestHandler):
    server_version = "MonitorAplicacoes/1.0"
    protocol_version = "HTTP/1.1"

    # -- infraestrutura ---------------------------------------------------- #

    def log_message(self, formato, *args):  # silencia log padrão de acesso
        pass

    @property
    def repo(self) -> Repositorio:
        return self.server.repo  # type: ignore[attr-defined]

    @property
    def banco(self) -> Banco:
        return self.server.banco  # type: ignore[attr-defined]

    @property
    def monitor(self) -> Monitor:
        return self.server.monitor  # type: ignore[attr-defined]

    @property
    def notificador(self) -> Notificador:
        return self.server.notificador  # type: ignore[attr-defined]

    def _corpo(self) -> dict:
        tamanho = int(self.headers.get("Content-Length") or 0)
        if tamanho <= 0:
            return {}
        if tamanho > 1_000_000:
            raise ErroHTTP(413, "Corpo grande demais.")
        bruto = self.rfile.read(tamanho)
        try:
            dados = json.loads(bruto.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ErroHTTP(400, "JSON inválido.")
        if not isinstance(dados, dict):
            raise ErroHTTP(400, "Esperado um objeto JSON.")
        return dados

    def _responder(
        self,
        codigo: int,
        dados,
        tipo: str = "application/json; charset=utf-8",
        cookie: str | None = None,
    ) -> None:
        if isinstance(dados, (dict, list)):
            corpo = json.dumps(dados, ensure_ascii=False).encode("utf-8")
        elif isinstance(dados, str):
            corpo = dados.encode("utf-8")
        else:
            corpo = b""
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie:
            self.send_header(
                "Set-Cookie",
                f"{COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSAO_SEGUNDOS}",
            )
        self.end_headers()
        if corpo:
            self.wfile.write(corpo)

    # -- autenticação ------------------------------------------------------ #

    def _cookie(self) -> str | None:
        bruto = self.headers.get("Cookie") or ""
        for parte in bruto.split(";"):
            if "=" in parte:
                nome, valor = parte.strip().split("=", 1)
                if nome == COOKIE:
                    return valor
        return None

    def _sessao_valida(self) -> bool:
        token = self._cookie()
        if not token:
            return False
        with self.server.sessoes_lock:  # type: ignore[attr-defined]
            expira = self.server.sessoes.get(token)  # type: ignore[attr-defined]
            if not expira:
                return False
            if expira < time.time():
                self.server.sessoes.pop(token, None)  # type: ignore[attr-defined]
                return False
        return True

    def _exigir_acesso(self, escrita: bool) -> None:
        if not self.repo.config.get("exigir_login", True):
            return
        if self.repo.modo_somente_leitura():
            if escrita:
                raise ErroHTTP(
                    403,
                    "Modo somente leitura: defina a senha com 'python3 app.py senha' "
                    "para liberar alterações.",
                )
            return
        if not self._sessao_valida():
            raise ErroHTTP(401, "Faça login para continuar.")

    # -- roteamento -------------------------------------------------------- #

    def do_GET(self):
        self._despachar("GET")

    def do_POST(self):
        self._despachar("POST")

    def do_PUT(self):
        self._despachar("PUT")

    def do_DELETE(self):
        self._despachar("DELETE")

    def _despachar(self, metodo: str) -> None:
        try:
            caminho = urllib.parse.urlparse(self.path).path
            partes = [p for p in caminho.split("/") if p]

            if metodo == "GET" and not partes:
                return self._pagina()
            if metodo == "GET" and partes == ["index.html"]:
                return self._pagina()

            if not partes or partes[0] != "api":
                raise ErroHTTP(404, "Não encontrado.")

            escrita = metodo in ("POST", "PUT", "DELETE")
            rota_publica = partes[1:] in (["sessao"], ["login"])
            if not rota_publica:
                self._exigir_acesso(escrita)
            self._api(metodo, partes[1:])
        except ErroHTTP as exc:
            self._responder(exc.codigo, {"erro": str(exc)})
        except ErroValidacao as exc:
            self._responder(400, {"erro": str(exc)})
        except BrokenPipeError:
            pass
        except Exception:  # noqa: BLE001
            log("ERRO na requisição:\n" + traceback.format_exc())
            try:
                self._responder(500, {"erro": "Erro interno do servidor."})
            except Exception:  # noqa: BLE001
                pass

    def _pagina(self) -> None:
        if not ARQ_HTML.exists():
            return self._responder(500, {"erro": "index.html não encontrado."})
        self._responder(200, ARQ_HTML.read_text(encoding="utf-8"), "text/html; charset=utf-8")

    def _api(self, metodo: str, partes: list[str]) -> None:
        # GET -----------------------------------------------------------------
        if metodo == "GET":
            if partes == ["sessao"]:
                return self._responder(
                    200,
                    {
                        "autenticado": self._sessao_valida()
                        or not self.repo.config.get("exigir_login", True),
                        "exigir_login": bool(self.repo.config.get("exigir_login", True)),
                        "modo_somente_leitura": self.repo.modo_somente_leitura(),
                        "editar_pela_tela": self.repo.editar_pela_tela(),
                        "tem_senha": self.repo.tem_senha(),
                    },
                )
            if partes == ["status"]:
                return self._responder(200, self.monitor.status())
            if partes == ["incidentes"]:
                return self._responder(200, {"incidentes": self.monitor.incidentes(40)})
            if partes == ["ajustes"]:
                return self._responder(200, self.repo.config_publica())
            raise ErroHTTP(404, "Rota não encontrada.")

        # POST ----------------------------------------------------------------
        if metodo == "POST":
            if partes == ["login"]:
                return self._login()
            if partes == ["logout"]:
                return self._logout()
            if partes == ["sites"]:
                return self._criar_site()
            if partes == ["sites", "teste"]:
                return self._testar_avulso()
            if len(partes) == 3 and partes[0] == "sites" and partes[2] == "teste":
                return self._testar_site(partes[1])
            if partes == ["notificacoes", "teste"]:
                return self._testar_notificacoes()
            if partes == ["internos", "pausar"]:
                return self._pausar_internos()
            raise ErroHTTP(404, "Rota não encontrada.")

        # PUT -----------------------------------------------------------------
        if metodo == "PUT":
            if len(partes) == 2 and partes[0] == "sites":
                return self._atualizar_site(partes[1])
            if partes == ["ajustes"]:
                return self._salvar_ajustes()
            raise ErroHTTP(404, "Rota não encontrada.")

        # DELETE --------------------------------------------------------------
        if metodo == "DELETE":
            if len(partes) == 2 and partes[0] == "sites":
                return self._remover_site(partes[1])
            raise ErroHTTP(404, "Rota não encontrada.")

        raise ErroHTTP(405, "Método não permitido.")

    # -- sessão ------------------------------------------------------------ #

    def _login(self) -> None:
        ip = self.client_address[0]
        agora_ts = time.time()
        with self.server.sessoes_lock:  # type: ignore[attr-defined]
            historico = [t for t in self.server.tentativas.get(ip, []) if agora_ts - t < 300]  # type: ignore[attr-defined]
            if len(historico) >= 8:
                raise ErroHTTP(429, "Muitas tentativas. Aguarde alguns minutos.")
            historico.append(agora_ts)
            self.server.tentativas[ip] = historico  # type: ignore[attr-defined]

        dados = self._corpo()
        senha = str(dados.get("senha", ""))
        if not self.repo.tem_senha():
            raise ErroHTTP(
                400, "Nenhuma senha definida. Rode 'python3 app.py senha' no servidor."
            )
        if not senha or not self.repo.conferir_senha(senha):
            time.sleep(0.4)
            raise ErroHTTP(401, "Senha incorreta.")

        token = pysecrets.token_urlsafe(32)
        with self.server.sessoes_lock:  # type: ignore[attr-defined]
            self.server.sessoes[token] = time.time() + SESSAO_SEGUNDOS  # type: ignore[attr-defined]
            self.server.tentativas.pop(ip, None)  # type: ignore[attr-defined]

        corpo = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header(
            "Set-Cookie",
            f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSAO_SEGUNDOS}",
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(corpo)

    def _logout(self) -> None:
        token = self._cookie()
        if token:
            with self.server.sessoes_lock:  # type: ignore[attr-defined]
                self.server.sessoes.pop(token, None)  # type: ignore[attr-defined]
        corpo = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Set-Cookie", f"{COOKIE}=; Path=/; HttpOnly; Max-Age=0")
        self.end_headers()
        self.wfile.write(corpo)

    # -- CRUD de sites ----------------------------------------------------- #

    def _exigir_edicao(self) -> None:
        if not self.repo.editar_pela_tela():
            raise ErroHTTP(
                403,
                "A edição pela tela está desativada (sites.json: editar_pela_tela=false).",
            )

    def _criar_site(self) -> None:
        self._exigir_edicao()
        dados = self._corpo()
        sites = self.repo.sites()
        site = validar_site(dados, self.repo.config)
        base = slug(site["nome"])
        existentes = {s["id"] for s in sites}
        identificador = base
        contador = 2
        while identificador in existentes:
            identificador = f"{base}-{contador}"
            contador += 1
        site = {"id": identificador, **site}
        sites.append(site)
        self.repo.salvar_sites(sites)
        log(f"site adicionado: {site['nome']} ({site['url']})")
        self._responder(201, {"site": site})

    def _atualizar_site(self, site_id: str) -> None:
        self._exigir_edicao()
        dados = self._corpo()
        sites = self.repo.sites()
        for indice, atual in enumerate(sites):
            if atual["id"] == site_id:
                novo = validar_site(dados, self.repo.config, existente=atual)
                novo["id"] = site_id
                sites[indice] = novo
                self.repo.salvar_sites(sites)
                return self._responder(200, {"site": novo})
        raise ErroHTTP(404, "Site não encontrado.")

    def _remover_site(self, site_id: str) -> None:
        self._exigir_edicao()
        sites = self.repo.sites()
        restantes = [s for s in sites if s["id"] != site_id]
        if len(restantes) == len(sites):
            raise ErroHTTP(404, "Site não encontrado.")
        self.repo.salvar_sites(restantes)
        self.banco.apagar_site(site_id)
        log(f"site removido: {site_id}")
        self._responder(200, {"ok": True})

    def _testar_site(self, site_id: str) -> None:
        for site in self.repo.sites():
            if site["id"] == site_id:
                return self._responder(
                    200, checar_site(site, self.repo.config.get("ca_bundle"))
                )
        raise ErroHTTP(404, "Site não encontrado.")

    def _testar_avulso(self) -> None:
        dados = self._corpo()
        site = validar_site(dados, self.repo.config)
        self._responder(200, checar_site(site, self.repo.config.get("ca_bundle")))

    def _pausar_internos(self) -> None:
        self._exigir_edicao()
        dados = self._corpo()
        pausar = bool(dados.get("pausar", True))
        sites = self.repo.sites()
        alterados = 0
        for site in sites:
            if site.get("rede") == "interno":
                novo_ativo = not pausar
                if site.get("ativo", True) != novo_ativo:
                    site["ativo"] = novo_ativo
                    alterados += 1
        if alterados:
            self.repo.salvar_sites(sites)
            log(f"sites internos {'pausados' if pausar else 'reativados'} ({alterados}).")
        self._responder(200, {"ok": True, "alterados": alterados, "pausados": pausar})

    # -- ajustes ----------------------------------------------------------- #

    def _salvar_ajustes(self) -> None:
        dados = self._corpo()
        config = dict(self.repo.config)

        if "config" in dados and isinstance(dados["config"], dict):
            permitidos = {
                "exigir_login": bool,
                "intervalo_padrao_s": (int, 10, 3600),
                "timeout_padrao_s": (int, 1, 60),
                "limiar_lento_ms": (int, 500, 120000),
                "retencao_dias": (int, 1, 365),
                "cooldown_min": (int, 1, 1440),
            }
            for chave, regra in permitidos.items():
                if chave not in dados["config"]:
                    continue
                valor = dados["config"][chave]
                if isinstance(regra, tuple):
                    minimo, maximo = regra[1], regra[2]
                    try:
                        numero = int(valor)
                    except (TypeError, ValueError):
                        raise ErroValidacao(f"{chave}: valor inválido.")
                    if not minimo <= numero <= maximo:
                        raise ErroValidacao(f"{chave}: use entre {minimo} e {maximo}.")
                    config[chave] = numero
                else:
                    config[chave] = bool(valor)

            canais = dados["config"].get("canais_ativos")
            if isinstance(canais, dict):
                config["canais_ativos"] = {
                    "telegram": bool(canais.get("telegram", False)),
                    "google_chat": bool(canais.get("google_chat", False)),
                    "webhook": bool(canais.get("webhook", False)),
                    "email": bool(canais.get("email", False)),
                }

            if "ca_bundle" in dados["config"]:
                caminho_ca = str(dados["config"]["ca_bundle"] or "").strip()
                if caminho_ca and not resolver_caminho(caminho_ca).exists():
                    raise ErroValidacao(f"Arquivo de CA não encontrado: {caminho_ca}")
                config["ca_bundle"] = caminho_ca

            if "url_publica" in dados["config"]:
                publica = str(dados["config"]["url_publica"] or "").strip()
                if publica and not publica.startswith(("http://", "https://")):
                    raise ErroValidacao(
                        "A URL pública do monitor deve começar com http:// ou https://"
                    )
                config["url_publica"] = publica

            if "porta" in dados["config"]:
                porta = _inteiro(dados["config"]["porta"], 1, 65535, "Porta")
                config["porta"] = porta

            if "host" in dados["config"]:
                host = str(dados["config"]["host"]).strip() or "0.0.0.0"
                config["host"] = host

        self.repo.salvar_config(config)

        segredos = dict(self.repo.segredos)
        novos = dados.get("segredos") or {}
        nova_senha = ""
        if isinstance(novos, dict):
            limpar = {str(x) for x in (dados.get("limpar") or [])}
            # Campo em branco mantém o valor atual; use "limpar" para apagar.
            for chave in ("telegram_token", "webhook_url"):
                if chave in novos:
                    valor = str(novos[chave] or "").strip()
                    if valor:
                        segredos[chave] = valor
                    elif chave in limpar:
                        segredos[chave] = ""
            if "telegram_chat_id" in novos:
                segredos["telegram_chat_id"] = str(novos["telegram_chat_id"] or "").strip()

            if "google_chat_urls" in novos:
                brutas = novos["google_chat_urls"]
                if isinstance(brutas, str):
                    brutas = brutas.splitlines()
                lista = [str(u).strip() for u in (brutas or []) if str(u).strip()]
                for item in lista:
                    if not item.startswith("https://chat.googleapis.com/"):
                        raise ErroValidacao(
                            "A URL do Google Chat deve começar com https://chat.googleapis.com/"
                        )
                if lista:
                    segredos["google_chat_urls"] = lista
                elif "google_chat_urls" in limpar:
                    segredos["google_chat_urls"] = []

            if "google_chat_thread" in novos:
                segredos["google_chat_thread"] = _booleano(novos["google_chat_thread"], True)

            if isinstance(novos.get("smtp"), dict):
                smtp = dict(segredos.get("smtp") or {})
                for chave in ("host", "usuario", "de", "para"):
                    if chave in novos["smtp"]:
                        smtp[chave] = str(novos["smtp"][chave] or "").strip()
                if "senha" in novos["smtp"] and str(novos["smtp"]["senha"] or ""):
                    smtp["senha"] = str(novos["smtp"]["senha"])
                if "porta" in novos["smtp"]:
                    smtp["porta"] = _inteiro(novos["smtp"]["porta"], 1, 65535, "Porta SMTP")
                if "tls" in novos["smtp"]:
                    smtp["tls"] = bool(novos["smtp"]["tls"])
                segredos["smtp"] = smtp

            nova_senha = str(novos.get("senha") or "")
            if nova_senha:
                if len(nova_senha) < 6:
                    raise ErroValidacao("A senha deve ter ao menos 6 caracteres.")
                salt = pysecrets.token_hex(16)
                segredos["senha_salt"] = salt
                segredos["senha_hash"] = hashlib.pbkdf2_hmac(
                    "sha256", nova_senha.encode(), salt.encode(), 200_000
                ).hex()

        self.repo.salvar_segredos(segredos)

        if isinstance(dados.get("sites_doc_editar"), bool):
            self.repo.salvar_sites(
                self.repo.sites(), editar_pela_tela=dados["sites_doc_editar"]
            )

        token = None
        if nova_senha and self.repo.config.get("exigir_login", True):
            token = pysecrets.token_urlsafe(32)
            with self.server.sessoes_lock:  # type: ignore[attr-defined]
                self.server.sessoes[token] = time.time() + SESSAO_SEGUNDOS  # type: ignore[attr-defined]

        self._responder(200, {"ok": True, **self.repo.config_publica()}, cookie=token)

    def _testar_notificacoes(self) -> None:
        secoes = [
            {
                "widgets": [
                    {
                        "textParagraph": {
                            "text": "Se você recebeu esta mensagem, o canal está "
                            "configurado corretamente."
                        }
                    }
                ]
            },
            {
                "header": "Servidor",
                "widgets": [
                    {
                        "decoratedText": {
                            "topLabel": "Máquina",
                            "text": _html(socket.gethostname()),
                        }
                    },
                    {
                        "decoratedText": {
                            "topLabel": "Horário",
                            "text": time.strftime("%d/%m/%Y %H:%M:%S"),
                        }
                    },
                ],
            },
        ]
        botoes = self.monitor._botoes()
        if botoes:
            secoes.append({"widgets": [{"buttonList": {"buttons": botoes}}]})

        cartao = {
            "cardId": f"monitor-teste-{int(time.time())}",
            "card": {
                "header": {
                    "title": "✅ Monitor de Aplicações",
                    "subtitle": "Teste de notificação",
                },
                "sections": secoes,
            },
        }

        resultados = self.notificador.enviar(
            "✅ Teste do Monitor de Aplicações",
            "Se você recebeu esta mensagem, a notificação está configurada corretamente.\n"
            f"Servidor: {socket.gethostname()} · {time.strftime('%d/%m/%Y %H:%M:%S')}",
            chave_thread="teste",
            cartao=cartao,
        )
        self._responder(200, {"resultados": resultados, "ultimo": self.notificador.ultimo})


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def definir_senha() -> None:
    repo = Repositorio()
    print("Definindo senha de acesso ao monitor.")
    senha = getpass.getpass("Nova senha: ")
    if len(senha) < 6:
        print("A senha precisa ter pelo menos 6 caracteres.")
        return
    confirmacao = getpass.getpass("Repita a senha: ")
    if senha != confirmacao:
        print("As senhas não conferem.")
        return
    repo.definir_senha(senha)
    print(f"Senha definida em {ARQ_SEGREDOS}")


def principal(argv: list[str]) -> int:
    if argv and argv[0] in ("senha", "definir-senha", "password"):
        definir_senha()
        return 0
    if argv and argv[0] in ("ajuda", "-h", "--help", "help"):
        print(__doc__)
        return 0

    repo = Repositorio()
    banco = Banco(ARQ_BANCO)
    notificador = Notificador(repo)
    monitor = Monitor(repo, banco, notificador)

    host = str(repo.config.get("host", "0.0.0.0"))
    porta = int(repo.config.get("porta", 8090))

    monitor.iniciar()
    servidor = ServidorHTTP((host, porta), Handler, repo, banco, monitor, notificador)

    total = len(repo.sites())
    log(f"Monitor de Aplicações no ar em http://{host}:{porta} ({total} site(s) cadastrado(s))")
    if repo.modo_somente_leitura():
        log("MODO SOMENTE LEITURA: nenhuma senha definida.")
        log("Defina com: python3 app.py senha")
    if not repo.sites():
        log("Nenhum site cadastrado ainda — abra a tela e clique em 'Adicionar site'.")

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        log("Encerrando...")
    finally:
        monitor.parar()
        servidor.server_close()
        banco.con.close()
    return 0


if __name__ == "__main__":
    sys.exit(principal(sys.argv[1:]))
