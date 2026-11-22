#!/usr/bin/env python3
"""canaryd - NAS fals (honeypot) + capcana TCP pentru reteaua locala.

Ruleaza pe un host dedicat, cu IP propriu, pe care NICIUN serviciu real nu exista.
Orice conexiune catre el este, prin definitie, o scanare.

- asculta pe porturile reale si atractive (21, 22, 23, 80, 139, 445, 3306, 5000, ...)
- se da drept Synology DiskStation: bannere, dialoguri de login, pagina web DSM falsa
- captureaza ce trimite scanerul: utilizator, parola, comenzi (Redis, Docker, RTSP)
- il ține apoi agatat intr-o capcana TCP (picurare lenta) pana la 15 minute
- se anunta singur in retea: mDNS (avahi), NetBIOS (UDP 137), SSDP/UPnP (UDP 1900)
- trimite alerta pe webhook catre Home Assistant, cu anti-spam per IP sursa
- scrie tot in /var/log/canary/events.jsonl, chiar si ce nu alerteaza

Doar biblioteca standard Python. Configurare: /etc/canary/config.json
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

CONFIG_PATH = os.environ.get("CANARY_CONFIG", "/etc/canary/config.json")

DEFAULTS = {
    "webhook_url": "",
    "hostname": "DiskStation",
    "model": "DS920+",
    "dsm_version": "DSM 7.2-64570 Update 3",
    "cooldown": 300,
    "ignore_nets": ["127.0.0.0/8"],
    "tarpit_minutes": 15,
    "drip_seconds": 10,
    "max_sockets": 128,
    "log_file": "/var/log/canary/events.jsonl",
    "hosts_file": "/etc/canary/hosts.json",
    "advertise_nbns": True,
    "advertise_ssdp": True,
    "http_ports": [80, 5000, 8080],
    "ports": {
        "21": "ftp",
        "22": "ssh",
        "23": "telnet",
        "25": "smtp",
        "80": "http",
        "139": "smb",
        "443": "tls",
        "445": "smb",
        "554": "rtsp",
        "1433": "mssql",
        "2375": "docker",
        "3306": "mysql",
        "3389": "rdp",
        "5000": "http",
        "5001": "tls",
        "5555": "adb",
        "5900": "vnc",
        "6379": "redis",
        "7547": "http",
        "8080": "http",
        "9200": "elastic",
        "27017": "mongo",
    },
}

SERVICE_NAMES = {
    "ftp": "FTP",
    "ssh": "SSH",
    "telnet": "Telnet",
    "http": "DSM web",
    "smb": "SMB / fisiere",
    "tls": "HTTPS",
    "rtsp": "RTSP camera",
    "mssql": "MSSQL",
    "docker": "Docker API",
    "mysql": "MySQL/MariaDB",
    "rdp": "RDP",
    "adb": "Android ADB",
    "vnc": "VNC",
    "redis": "Redis",
    "elastic": "Elasticsearch",
    "mongo": "MongoDB",
    "smtp": "SMTP (releu deschis)",
    "token": "Fisier momeala deschis",
}

# imagine 1x1 transparenta, raspunsul pentru fisierele-far (beacon)
PIXEL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=="
)

try:  # rezerva pe Telegram, pentru cand HA nu raspunde (opționala)
    import telegram_fallback as telegram
except Exception:  # noqa: BLE001
    telegram = None

# IP-ul local pe care a intrat conexiunea (poate fi un IP fantoma)
DST_IP: contextvars.ContextVar[str] = contextvars.ContextVar("dst_ip", default="")

log = logging.getLogger("canaryd")


def load_config() -> dict:
    conf = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            conf.update(json.load(fh))
    except FileNotFoundError:
        log.warning("Fara %s, folosesc valorile implicite", CONFIG_PATH)
    except Exception as err:
        log.error("Config invalid (%s), folosesc valorile implicite: %s", CONFIG_PATH, err)
    conf["ports"] = {int(k): v for k, v in conf["ports"].items()}
    nets = []
    for item in conf.get("ignore_nets", []):
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log.error("ignore_nets: '%s' nu e IP/CIDR valid", item)
    conf["_ignore_nets"] = nets
    return conf


def textline(data: bytes, limit: int = 120) -> str:
    """Prima linie lizibila, curata - pentru comenzi si credentiale."""
    text = data.decode("utf-8", errors="replace").replace("\x00", "")
    out = []
    for ch in text:
        if ch in "\r\n":
            break
        if 32 <= ord(ch) < 127:
            out.append(ch)
    return "".join(out).strip()[:limit]


def printable(data: bytes, limit: int = 160) -> str:
    text = data.decode("utf-8", errors="replace")
    out = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    out = re.sub(r"\.{4,}", "...", out).strip()
    return out[:limit]


class Canary:
    def __init__(self, conf: dict) -> None:
        self.conf = conf
        self.cooldown: int = int(conf["cooldown"])
        self.drip: float = float(conf["drip_seconds"])
        self.tarpit_steps = max(1, int(float(conf["tarpit_minutes"]) * 60 / self.drip))
        self.max_sockets = int(conf["max_sockets"])
        self.hostname: str = conf["hostname"]
        self.model: str = conf["model"]
        self.dsm_version: str = conf["dsm_version"]
        self.webhook: str = conf["webhook_url"]
        self.ignore_nets = conf["_ignore_nets"]
        self.quarantine_url: str = conf.get("quarantine_url", "")
        self.quarantine_token: str = ""
        cale_token = conf.get("quarantine_token_file", "")
        if self.quarantine_url and cale_token:
            try:
                with open(cale_token, "r", encoding="utf-8") as fh:
                    self.quarantine_token = fh.read().strip()
            except Exception as err:
                log.error("nu pot citi tokenul de carantina: %s", err)
        self.log_path = Path(conf["log_file"])
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self.held: set[asyncio.StreamWriter] = set()
        self._last_alert: dict[str, float] = {}
        self._suppressed: dict[str, int] = defaultdict(int)
        self._host_cache: dict[str, str] = {}
        self._hosts_map: dict[str, str] = {}
        self._hosts_mtime: float = -1.0
        self.stats = defaultdict(int)

    # ---------------- utilitare ----------------

    def ignored(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.ignore_nets)

    def load_hosts_map(self) -> dict[str, str]:
        """Harta IP -> nume, luata din comentariile leaseurilor din router."""
        path = self.conf.get("hosts_file")
        if not path:
            return {}
        try:
            stat = os.stat(path)
        except OSError:
            return self._hosts_map
        if stat.st_mtime != self._hosts_mtime:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    self._hosts_map = {str(k): str(v) for k, v in json.load(fh).items()}
                self._hosts_mtime = stat.st_mtime
                log.info("harta de nume reincarcata: %d intrari", len(self._hosts_map))
            except Exception as err:
                log.error("harta de nume invalida (%s): %s", path, err)
        return self._hosts_map

    async def resolve(self, ip: str) -> str:
        mapped = self.load_hosts_map().get(ip)
        if mapped:
            return mapped
        if ip in self._host_cache:
            return self._host_cache[ip]
        name = "necunoscut"
        try:
            loop = asyncio.get_running_loop()
            res = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=2.0
            )
            name = res[0].split(".")[0]
        except Exception:
            name = "necunoscut"
        self._host_cache[ip] = name
        return name

    def write_log(self, record: dict) -> None:
        try:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as err:
            log.error("Nu pot scrie in jurnal: %s", err)

    async def alert(
        self,
        ip: str,
        port: int,
        persona: str,
        note: str = "",
        payload: bytes | str = b"",
        creds: list[dict] | None = None,
        urgent: bool = False,
        silent: bool = False,
    ) -> None:
        """Scrie evenimentul in jurnal si, daca nu e in cooldown, il trimite in HA."""
        host = await self.resolve(ip)
        service = SERVICE_NAMES.get(persona, persona)
        text = payload if isinstance(payload, str) else printable(payload)
        # Pe ce IP local a aterizat: daca nu e cel principal, a fost lovit un IP
        # fantoma, ceea ce inseamna o scanare a subretelei, nu o greseala de adresa.
        dst = DST_IP.get()
        if dst and dst != self.conf.get("ip"):
            note = f"[IP fantoma {dst}] {note}".strip()
        now = time.monotonic()
        # Doua clase de alerte, cu ferestre separate: o simpla atingere de port
        # ("plain") si ceva interesant - parole incercate, exploit ("urgent").
        # Separate, ca alerta de conectare sa nu inghita alerta cu parola; si cu
        # fereastra, ca un brute-force sa nu trimita 1000 de notificari.
        klass = "urgent" if (creds or urgent) else "plain"
        key = f"{ip}|{klass}"
        last = self._last_alert.get(key, 0.0)
        window = min(60, self.cooldown) if klass == "urgent" else self.cooldown
        must_alert = (now - last) >= window and not silent

        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "src_ip": ip,
            "src_host": host,
            "port": port,
            "service": service,
            "persona": persona,
            "note": note,
            "dst_ip": dst or self.conf.get("ip", ""),
            "payload": text,
            "creds": creds or [],
            "held": len(self.held),
            "alerted": must_alert,
        }
        self.write_log(record)
        self.stats["sonde"] += 1
        log.log(
            logging.INFO if silent else logging.WARNING,
            "%s %s (%s) -> %s :%d %s%s",
            "descoperire" if silent else "SONDA",
            ip,
            host,
            service,
            port,
            note,
            f" creds={creds}" if creds else "",
        )

        if not must_alert:
            if not silent:
                self._suppressed[ip] += 1
            return

        record["suppressed"] = self._suppressed.pop(ip, 0)
        # ATENTIE: cheia trebuie sa fie aceeasi la citire si la scriere (ip|clasa).
        # Cand aici scria doar `ip`, fereastra de anti-spam nu se aplica niciodata
        # si o singura unealta care pipaie porturile trimitea zeci de notificari.
        self._last_alert[key] = now
        self.stats["alerte"] += 1
        await self.send_webhook(record)
        # Carantina se cere doar pentru clasa "urgenta" (parola incercata, exploit,
        # fisier citit) - o simpla atingere de port nu merita blocat un aparat.
        if klass == "urgent":
            await self.cere_carantina(ip, note)

    async def send_webhook(self, record: dict) -> None:
        if not self.webhook:
            return
        body = json.dumps(record, ensure_ascii=False).encode("utf-8")

        def _post() -> int:
            req = urllib.request.Request(
                self.webhook,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "canaryd/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                return resp.status

        try:
            loop = asyncio.get_running_loop()
            status = await loop.run_in_executor(None, _post)
            if status < 300:
                return
            log.error("Webhook HA a raspuns %s", status)
        except Exception as err:
            log.error("Webhook HA a eșuat: %s", err)
        await self.rezerva_telegram(record)

    async def rezerva_telegram(self, record: dict) -> None:
        """HA nu a primit alerta -> o trimitem direct pe Telegram."""
        if telegram is None or not telegram.disponibil():
            return
        creds = record.get("creds") or []
        text = (
            "🕸️ CANARY (HA nu raspunde)\n"
            f"{record.get('src_ip')} ({record.get('src_host')}) -> "
            f"{record.get('service')} :{record.get('port')}\n"
            f"{record.get('note', '')}"
        )
        if creds:
            text += "\nA incercat: " + ", ".join(
                f"{c.get('user')} / {c.get('pass')}" for c in creds
            )
        loop = asyncio.get_running_loop()
        ok, motiv = await loop.run_in_executor(
            None,
            lambda: telegram.trimite(
                text, cheie=f"alerta:{record.get('src_ip')}", interval=self.cooldown
            ),
        )
        log.warning("rezerva Telegram: %s (%s)", "trimis" if ok else "netrimis", motiv)

    async def cere_carantina(self, ip: str, motiv: str) -> None:
        """Cere serviciului de pe CT117 sa puna IP-ul in carantina.

        Honeypot-ul nu atinge niciodata firewallul: doar *cere*. Validarea,
        lista protejata si plafonul sunt in afara lui, iar routerul isi citeste
        singur lista si o valideaza din nou.
        """
        if not self.quarantine_url:
            return
        corp = json.dumps(
            {"ip": ip, "motiv": motiv[:200], "token": self.quarantine_token}
        ).encode()

        def _post() -> tuple[int, str]:
            req = urllib.request.Request(
                self.quarantine_url,
                data=corp,
                headers={"Content-Type": "application/json", "User-Agent": "canaryd/1.0"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=6) as resp:
                    return resp.status, resp.read(200).decode("utf-8", "replace").strip()
            except urllib.error.HTTPError as err:
                return err.code, err.read(200).decode("utf-8", "replace").strip()

        try:
            loop = asyncio.get_running_loop()
            status, raspuns = await loop.run_in_executor(None, _post)
            log.warning("carantina pentru %s: HTTP %s - %s", ip, status, raspuns)
        except Exception as err:
            log.error("nu am putut cere carantina pentru %s: %s", ip, err)

    # ---------------- capcana ----------------

    async def tarpit(self, writer: asyncio.StreamWriter, persona: str) -> None:
        """Picurare lenta, ca scanerul sa stea agatat cat mai mult."""
        if len(self.held) >= self.max_sockets:
            return
        self.held.add(writer)
        try:
            for step in range(1, self.tarpit_steps + 1):
                await asyncio.sleep(self.drip)
                if writer.is_closing():
                    return
                if persona == "ftp":
                    data = f"220-Verificare RAID {min(step, 99)}%...\r\n".encode()
                elif persona == "ssh":
                    data = f"{self.hostname}-KeyCheck-{step}: wait\r\n".encode()
                elif persona == "http":
                    data = f"X-Syno-Auth-Wait-{step}: {step * int(self.drip)}\r\n".encode()
                elif persona in ("smb", "mssql", "mongo", "adb", "rdp", "tls"):
                    data = b"\x00"
                else:
                    data = b"\x00"
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as err:
            log.debug("capcana incheiata: %s", err)
        finally:
            self.held.discard(writer)

    async def release_all(self) -> int:
        n = len(self.held)
        for w in list(self.held):
            try:
                w.close()
            except Exception:
                pass
        self.held.clear()
        self._last_alert.clear()
        return n

    # ---------------- personaje ----------------

    async def read_some(self, reader, limit=2048, timeout=2.0) -> bytes:
        try:
            return await asyncio.wait_for(reader.read(limit), timeout=timeout)
        except (asyncio.TimeoutError, ConnectionResetError):
            return b""

    async def p_ftp(self, reader, writer, ip, port):
        writer.write(f"220 {self.hostname} FTP server ready.\r\n".encode())
        await writer.drain()
        user = passwd = None
        seen: list[str] = []
        announced = False
        for _ in range(6):
            line = await self.read_some(reader, 512, 8.0)
            if not line:
                break
            cmd = textline(line, 80)
            seen.append(cmd)
            if not announced:
                announced = True
                await self.alert(ip, port, "ftp", f"dialog FTP: {cmd[:40]}")
            upper = cmd.upper()
            if upper.startswith("USER"):
                user = cmd[5:].strip()
                writer.write(f"331 Password required for {user}.\r\n".encode())
            elif upper.startswith("PASS"):
                passwd = cmd[5:].strip()
                writer.write(b"530 Login incorrect.\r\n")
            elif upper.startswith(("AUTH", "FEAT")):
                writer.write(b"500 Command not understood.\r\n")
            elif upper.startswith("SYST"):
                writer.write(b"215 UNIX Type: L8\r\n")
            else:
                writer.write(b"530 Please login with USER and PASS.\r\n")
            await writer.drain()
            if user and passwd:
                break
        creds = [{"user": user, "pass": passwd}] if (user or passwd) else []
        if creds or not announced:
            await self.alert(
                ip,
                port,
                "ftp",
                "a incercat login FTP" if creds else "s-a conectat si a tacut",
                " | ".join(seen),
                creds,
                urgent=bool(creds),
            )
        await self.tarpit(writer, "ftp")

    async def p_ssh(self, reader, writer, ip, port):
        # RFC 4253 §4.2: oricate linii inainte de "SSH-2.0-" => scanerul asteapta la infinit
        writer.write(f"{self.hostname}-SSH-Guard: verificare cheie gazda...\r\n".encode())
        await writer.drain()
        data = await self.read_some(reader, 512, 3.0)
        await self.alert(ip, port, "ssh", "a cerut handshake SSH", data)
        await self.tarpit(writer, "ssh")

    async def p_telnet(self, reader, writer, ip, port):
        writer.write(f"\r\n{self.hostname} login: ".encode())
        await writer.drain()
        user = await self.read_some(reader, 128, 10.0)
        await self.alert(
            ip, port, "telnet", f"prompt de login, a scris '{textline(user, 30)}'"
        )
        writer.write(b"Password: ")
        await writer.drain()
        passwd = await self.read_some(reader, 128, 10.0)
        creds = []
        if user or passwd:
            creds = [{"user": textline(user, 40), "pass": textline(passwd, 40)}]
        writer.write(b"\r\nLogin incorrect\r\n")
        await writer.drain()
        if creds:
            await self.alert(
                ip, port, "telnet", "a incercat login Telnet", b"", creds, urgent=True
            )
        await self.tarpit(writer, "telnet")

    async def p_http(self, reader, writer, ip, port):
        raw = await self.read_some(reader, 8192, 5.0)
        if not raw:
            await self.alert(ip, port, "http", "a deschis portul web fara cerere")
            await self.tarpit(writer, "http")
            return
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.decode("utf-8", errors="replace").split("\r\n")
        request = lines[0] if lines else ""
        method, path = "GET", "/"
        parts = request.split()
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        agent = headers.get("user-agent", "")

        creds = self.extract_http_creds(path, body, headers)

        # /token/<nume> = un fisier momeala (docx, html, .url) a fost DESCHIS.
        # Nu e o scanare de porturi: cineva a umblat prin fisierele furate.
        if path.startswith("/token/"):
            nume = path.split("/token/", 1)[1].split("?")[0][:60]
            await self.alert(
                ip,
                port,
                "token",
                f"FISIER MOMEALA DESCHIS: {nume}",
                agent[:120],
                urgent=True,
            )
            self.http_reply(writer, "200 OK", "image/png", PIXEL_PNG)
            await writer.drain()
            return

        note = f"{method} {path[:60]}"
        if agent:
            note += f" [{agent[:40]}]"
        # /desc.xml e descrierea UPnP pe care o cer chiar dispozitivele carora
        # ne-am facut reclama prin SSDP (TV-uri, HA, Windows). Se scrie in jurnal,
        # dar nu trimite notificare - altfel ne-am alerta singuri.
        await self.alert(
            ip,
            port,
            "http",
            note,
            body[:200] if body else b"",
            creds,
            silent=path.startswith("/desc.xml") and not creds,
        )

        # Paginile momeala primesc un raspuns complet (asa pare un NAS adevarat
        # si merita fotografiat de scanerele care fac fingerprint).
        if path.startswith("/desc.xml"):
            payload = self.upnp_description().encode()
            self.http_reply(writer, "200 OK", "text/xml; charset=utf-8", payload)
            await writer.drain()
            return
        if creds:
            payload = json.dumps({"success": False, "error": {"code": 400}}).encode()
            self.http_reply(writer, "200 OK", "application/json", payload)
            await writer.drain()
            return
        if path.split("?")[0] in (
            "/",
            "/index.html",
            "/login.html",
            "/webman/",
            "/webman/index.cgi",
            "/webapi/auth.cgi",
        ):
            payload = self.dsm_login_page().encode()
            self.http_reply(writer, "200 OK", "text/html; charset=utf-8", payload)
            await writer.drain()
            return
        # Orice altceva (/.env, /shell, /manager/html, /cgi-bin/...) = scaner:
        # antete care nu se termina niciodata (Slowloris invers).
        await self.http_drip(writer)

    async def http_drip(self, writer) -> None:
        """Trimite antete fara CRLF CRLF final, apoi picura la infinit."""
        writer.write(
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\n"
            b"Cache-Control: no-store\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
        )
        await writer.drain()
        await self.tarpit(writer, "http")

    def extract_http_creds(self, path: str, body: bytes, headers: dict) -> list[dict]:
        found: list[dict] = []
        fields: dict[str, str] = {}
        query = urllib.parse.urlparse(path).query
        for blob in (query, body.decode("utf-8", errors="replace")):
            if not blob:
                continue
            try:
                for k, v in urllib.parse.parse_qsl(blob, keep_blank_values=True):
                    fields[k.lower()] = v
            except Exception:
                pass
        user = fields.get("username") or fields.get("user") or fields.get("login")
        passwd = fields.get("passwd") or fields.get("password") or fields.get("pass")
        if user or passwd:
            found.append({"user": (user or "")[:60], "pass": (passwd or "")[:60]})
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            import base64

            try:
                decoded = base64.b64decode(auth.split(None, 1)[1]).decode("utf-8", "replace")
                u, _, p = decoded.partition(":")
                found.append({"user": u[:60], "pass": p[:60], "via": "basic-auth"})
            except Exception:
                pass
        return found

    def http_reply(self, writer, status: str, ctype: str, payload: bytes) -> None:
        head = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: nginx\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"X-Syno-Model: {self.model}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        writer.write(head + payload)

    def dsm_login_page(self) -> str:
        return f"""<!doctype html>
<html lang="ro"><head><meta charset="utf-8">
<title>{self.hostname} - Autentificare</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 :root {{ color-scheme: dark; }}
 body {{ margin:0; font-family:-apple-system,"Segoe UI",Roboto,sans-serif;
   background:#1b2838 radial-gradient(circle at 50% 30%, #2a4a6b, #10161f 70%);
   min-height:100vh; display:flex; align-items:center; justify-content:center; color:#eef3f8; }}
 .box {{ background:rgba(16,22,31,.82); padding:36px 34px; border-radius:10px;
   width:320px; box-shadow:0 18px 48px rgba(0,0,0,.55); }}
 h1 {{ font-size:19px; font-weight:500; margin:0 0 4px; text-align:center; }}
 .sub {{ font-size:12px; color:#9fb3c8; text-align:center; margin-bottom:22px; }}
 label {{ display:block; font-size:12px; color:#9fb3c8; margin:12px 0 4px; }}
 input {{ width:100%; box-sizing:border-box; padding:10px; border-radius:5px;
   border:1px solid #38506b; background:#0d131b; color:#eef3f8; font-size:14px; }}
 button {{ width:100%; margin-top:20px; padding:10px; border:0; border-radius:5px;
   background:#2e7cd6; color:#fff; font-size:14px; cursor:pointer; }}
 .foot {{ margin-top:18px; font-size:11px; color:#6d8299; text-align:center; }}
</style></head>
<body>
 <form class="box" method="post" action="/webapi/auth.cgi">
  <h1>{self.hostname}</h1>
  <div class="sub">{self.model} &middot; {self.dsm_version}</div>
  <label for="username">Utilizator</label>
  <input id="username" name="username" autocomplete="username">
  <label for="passwd">Parola</label>
  <input id="passwd" name="passwd" type="password" autocomplete="current-password">
  <button type="submit">Conectare</button>
  <div class="foot">Sesiunea expira dupa 15 minute de inactivitate.</div>
 </form>
</body></html>"""

    def upnp_description(self) -> str:
        return f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <specVersion><major>1</major><minor>0</minor></specVersion>
 <device>
  <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
  <friendlyName>{self.hostname}</friendlyName>
  <manufacturer>Synology</manufacturer>
  <modelName>{self.model}</modelName>
  <modelDescription>Network Attached Storage</modelDescription>
  <UDN>uuid:{self.conf.get('uuid', '4c3f2b10-0000-1000-8000-001132000060')}</UDN>
  <presentationURL>http://{self.conf.get('ip', '')}:5000/</presentationURL>
 </device>
</root>"""

    async def p_smb(self, reader, writer, ip, port):
        data = await self.read_some(reader, 1024, 4.0)
        note = "a cerut SMB"
        if b"SMB" in data:
            dialect = "SMB2/3" if b"\xfeSMB" in data else "SMB1"
            note = f"negociere {dialect}"
            if b"\xffSMB" in data:
                note += " (SMB1! scaner de ransomware/EternalBlue)"
        await self.alert(ip, port, "smb", note, data[:120])
        await self.tarpit(writer, "smb")

    async def p_mysql(self, reader, writer, ip, port):
        greeting = (
            b"\x4a\x00\x00\x00\x0a" + b"5.5.68-MariaDB-Synology\x00"
            b"\x01\x00\x00\x00" + os.urandom(8) + b"\x00"
            b"\x0f\xa2\x21\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + os.urandom(12) + b"\x00mysql_native_password\x00"
        )
        writer.write(greeting)
        await writer.drain()
        data = await self.read_some(reader, 1024, 4.0)
        user = ""
        if len(data) > 36:
            tail = data[36:]
            user = textline(tail.split(b"\x00")[0], 40)
        creds = [{"user": user, "pass": "(hash)"}] if user else []
        writer.write(b"\x17\x00\x00\x02\xff\x15\x04#28000Access denied")
        await writer.drain()
        await self.alert(ip, port, "mysql", "a incercat login MySQL", data[:80], creds)
        await self.tarpit(writer, "mysql")

    async def p_redis(self, reader, writer, ip, port):
        cmds: list[str] = []
        announced = False
        for _ in range(8):
            data = await self.read_some(reader, 2048, 6.0)
            if not data:
                break
            text = printable(data, 200)
            cmds.append(text)
            if not announced:
                announced = True
                await self.alert(ip, port, "redis", f"comanda Redis: {text[:40]}", text)
            upper = text.upper()
            if "PING" in upper:
                writer.write(b"+PONG\r\n")
            elif "INFO" in upper:
                info = (
                    f"# Server\r\nredis_version:6.2.14\r\nos:Linux 4.4.302+ x86_64\r\n"
                    f"# Keyspace\r\ndb0:keys=1423,expires=12\r\n"
                ).encode()
                writer.write(b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n")
            elif "CONFIG" in upper:
                writer.write(b"*2\r\n$3\r\ndir\r\n$10\r\n/var/lib/r\r\n")
            elif "AUTH" in upper:
                writer.write(b"-ERR invalid password\r\n")
            else:
                writer.write(b"+OK\r\n")
            await writer.drain()
        exploit = any(
            key in c.upper()
            for c in cmds
            for key in ("CONFIG", "SLAVEOF", "REPLICAOF", "MODULE", "EVAL", "SAVE")
        )
        if exploit:
            await self.alert(
                ip,
                port,
                "redis",
                "incearca exploit Redis (CONFIG/SET/MODULE/SLAVEOF)",
                " | ".join(cmds),
                urgent=True,
            )
        await self.tarpit(writer, "redis")

    async def p_docker(self, reader, writer, ip, port):
        raw = await self.read_some(reader, 8192, 4.0)
        head, _, body = raw.partition(b"\r\n\r\n")
        request = head.decode("utf-8", errors="replace").split("\r\n")[0]
        note = f"Docker API: {request[:70]}"
        if b"/containers/create" in head or b"Image" in body:
            note += " - incearca sa porneasca un container (miner?)"
        payload = json.dumps(
            {
                "Version": "24.0.7",
                "ApiVersion": "1.43",
                "Os": "linux",
                "Arch": "amd64",
                "KernelVersion": "4.4.302+",
            }
        ).encode()
        self.http_reply(writer, "200 OK", "application/json", payload)
        await writer.drain()
        await self.alert(ip, port, "docker", note, body[:300] if body else head[:200])

    async def p_rtsp(self, reader, writer, ip, port):
        data = await self.read_some(reader, 2048, 4.0)
        text = printable(data, 120)
        writer.write(
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n"
            b'WWW-Authenticate: Digest realm="IPCamera", nonce="7f3c1a"\r\n'
            b"Server: Synology/SurveillanceStation\r\n\r\n"
        )
        await writer.drain()
        creds = []
        m = re.search(r'username="([^"]*)"', text)
        if m:
            creds = [{"user": m.group(1)[:40], "pass": "(digest)"}]
        await self.alert(ip, port, "rtsp", "cerere RTSP", text, creds)
        await self.tarpit(writer, "rtsp")

    async def p_vnc(self, reader, writer, ip, port):
        writer.write(b"RFB 003.008\n")
        await writer.drain()
        data = await self.read_some(reader, 64, 4.0)
        if data:
            writer.write(b"\x01\x02")  # o metoda de securitate: VNC auth
            await writer.drain()
        await self.alert(ip, port, "vnc", "handshake VNC", data)
        await self.tarpit(writer, "vnc")

    # ---------------- dispecer ----------------

    def handler_for(self, persona: str):
        table = {
            "ftp": self.p_ftp,
            "ssh": self.p_ssh,
            "telnet": self.p_telnet,
            "http": self.p_http,
            "smb": self.p_smb,
            "mysql": self.p_mysql,
            "redis": self.p_redis,
            "docker": self.p_docker,
            "rtsp": self.p_rtsp,
            "vnc": self.p_vnc,
        }
        if persona in table:
            return table[persona]

        banners = {
            "smtp": f"220 {self.hostname} ESMTP Postfix (Debian)\r\n".encode(),
            "mssql": None,
            "mongo": None,
            "rdp": None,
            "adb": None,
            "tls": None,
            "elastic": None,
        }

        async def generic(reader, writer, ip, port, _p=persona, _b=banners.get(persona)):
            if _p == "elastic":
                body = json.dumps(
                    {
                        "name": self.hostname,
                        "cluster_name": "nas-cluster",
                        "version": {"number": "7.10.2"},
                        "tagline": "You Know, for Search",
                    }
                ).encode()
                data = await self.read_some(reader, 2048, 3.0)
                self.http_reply(writer, "200 OK", "application/json", body)
                await writer.drain()
                await self.alert(ip, port, _p, "interogare Elasticsearch", data)
                return
            if _b:
                writer.write(_b)
                await writer.drain()
            data = await self.read_some(reader, 2048, 3.0)
            await self.alert(ip, port, _p, "conexiune", data)
            await self.tarpit(writer, _p)

        return generic

    async def serve(self, port: int, persona: str) -> None:
        handler = self.handler_for(persona)

        async def on_client(reader, writer):
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else "necunoscut"
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            local = writer.get_extra_info("sockname")
            DST_IP.set(local[0] if local else "")

            try:
                if self.ignored(ip):
                    return
                await handler(reader, writer, ip, port)
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            except Exception as err:
                log.debug("eroare pe :%d de la %s: %s", port, ip, err)
            finally:
                self.held.discard(writer)
                try:
                    writer.close()
                except Exception:
                    pass

        try:
            server = await asyncio.start_server(on_client, host="0.0.0.0", port=port)
            log.info("ascult pe :%d (%s)", port, persona)
            return server
        except OSError as err:
            log.error("nu pot deschide :%d (%s): %s", port, persona, err)
            return None


# ---------------- anunturi in retea ----------------


class NBNSResponder(asyncio.DatagramProtocol):
    """Raspunde la interogari NetBIOS doar pentru numele nostru (UDP 137)."""

    def __init__(self, name: str, ip: str) -> None:
        self.name = name.upper()[:15]
        self.ip = ip

    def connection_made(self, transport):
        self.transport = transport

    @staticmethod
    def decode_netbios(encoded: bytes) -> str:
        out = []
        for i in range(0, len(encoded) - 1, 2):
            hi, lo = encoded[i] - 0x41, encoded[i + 1] - 0x41
            out.append(chr((hi << 4) | lo))
        return "".join(out).strip()

    @staticmethod
    def encode_netbios(name: str, suffix: int = 0x20) -> bytes:
        padded = name.upper().ljust(15)[:15].encode("ascii", "replace") + bytes([suffix])
        out = bytearray()
        for byte in padded:
            out.append(0x41 + (byte >> 4))
            out.append(0x41 + (byte & 0x0F))
        return bytes(out)

    def datagram_received(self, data, addr):
        try:
            if len(data) < 12:
                return
            tid = data[:2]
            flags = struct.unpack("!H", data[2:4])[0]
            if flags & 0x8000:  # deja un raspuns
                return
            qlen = data[12]
            qname = data[13 : 13 + qlen]
            asked = self.decode_netbios(qname)
            if asked.rstrip("\x00").strip() not in (self.name, "*"):
                return
            resp = bytearray()
            resp += tid
            resp += struct.pack("!H", 0x8500)  # raspuns autoritar
            resp += struct.pack("!HHHH", 0, 1, 0, 0)
            resp += bytes([qlen]) + qname + b"\x00"
            resp += struct.pack("!HH", 0x0020, 0x0001)  # NB, IN
            resp += struct.pack("!I", 300)
            resp += struct.pack("!H", 6)
            resp += struct.pack("!H", 0x4000)  # B-node, unic
            resp += socket.inet_aton(self.ip)
            self.transport.sendto(bytes(resp), addr)
        except Exception:
            pass


class SSDPResponder(asyncio.DatagramProtocol):
    """Raspunde la M-SEARCH si se anunta periodic (UDP 1900)."""

    def __init__(self, canary: Canary, ip: str) -> None:
        self.canary = canary
        self.ip = ip
        self.usn = "uuid:4c3f2b10-0000-1000-8000-001132000060"
        self.location = f"http://{ip}:5000/desc.xml"

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        try:
            mreq = struct.pack("4s4s", socket.inet_aton("239.255.255.250"), socket.inet_aton(self.ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as err:
            log.error("SSDP: nu pot intra in grupul multicast: %s", err)

    def datagram_received(self, data, addr):
        try:
            text = data.decode("utf-8", errors="replace")
            if not text.upper().startswith("M-SEARCH"):
                return
            st_match = re.search(r"(?im)^ST:\s*(.+)$", text)
            st = st_match.group(1).strip() if st_match else "ssdp:all"
            wanted = ("ssdp:all", "upnp:rootdevice", "urn:schemas-upnp-org:device:Basic:1")
            if st not in wanted:
                return
            reply = (
                "HTTP/1.1 200 OK\r\n"
                "CACHE-CONTROL: max-age=1800\r\n"
                f"LOCATION: {self.location}\r\n"
                "SERVER: Linux/4.4 UPnP/1.0 Synology/DSM\r\n"
                f"ST: {st if st != 'ssdp:all' else 'upnp:rootdevice'}\r\n"
                f"USN: {self.usn}::upnp:rootdevice\r\n"
                "EXT:\r\n\r\n"
            ).encode()
            self.transport.sendto(reply, addr)
        except Exception:
            pass

    async def announce_loop(self) -> None:
        while True:
            try:
                notify = (
                    "NOTIFY * HTTP/1.1\r\n"
                    "HOST: 239.255.255.250:1900\r\n"
                    "CACHE-CONTROL: max-age=1800\r\n"
                    f"LOCATION: {self.location}\r\n"
                    "NT: upnp:rootdevice\r\n"
                    "NTS: ssdp:alive\r\n"
                    "SERVER: Linux/4.4 UPnP/1.0 Synology/DSM\r\n"
                    f"USN: {self.usn}::upnp:rootdevice\r\n\r\n"
                ).encode()
                self.transport.sendto(notify, ("239.255.255.250", 1900))
            except Exception as err:
                log.debug("SSDP notify: %s", err)
            await asyncio.sleep(900)


def local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.168.1.1", 9))
        return sock.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        sock.close()


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    conf = load_config()
    ip = conf.get("ip") or local_ip()
    conf["ip"] = ip
    canary = Canary(conf)
    log.info("canaryd porneste ca '%s' (%s) pe %s", canary.hostname, canary.model, ip)

    servers = []
    for port, persona in sorted(conf["ports"].items()):
        srv = await canary.serve(port, persona)
        if srv:
            servers.append(srv)
    log.info("%d porturi momeala active", len(servers))

    loop = asyncio.get_running_loop()
    if conf.get("advertise_nbns", True):
        try:
            await loop.create_datagram_endpoint(
                lambda: NBNSResponder(canary.hostname, ip),
                local_addr=("0.0.0.0", 137),
                allow_broadcast=True,
            )
            log.info("NetBIOS: anunt numele '%s' pe UDP 137", canary.hostname.upper())
        except OSError as err:
            log.error("NetBIOS indisponibil: %s", err)

    if conf.get("advertise_ssdp", True):
        try:
            transport, proto = await loop.create_datagram_endpoint(
                lambda: SSDPResponder(canary, ip),
                local_addr=("0.0.0.0", 1900),
                allow_broadcast=True,
                reuse_port=True,
            )
            asyncio.ensure_future(proto.announce_loop())
            log.info("SSDP/UPnP: ma anunt pe UDP 1900")
        except OSError as err:
            log.error("SSDP indisponibil: %s", err)

    while True:
        await asyncio.sleep(3600)
        log.info(
            "stare: %d sonde, %d alerte, %d socketuri in capcana",
            canary.stats["sonde"],
            canary.stats["alerte"],
            len(canary.held),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
