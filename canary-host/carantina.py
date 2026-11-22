#!/usr/bin/env python3
"""Serviciul de carantina - ruleaza pe CT117 (gazda de incredere), nu pe honeypot.

De ce aici si nu pe canary: honeypot-ul este, prin definitie, cutia pe care se
sparge cineva. Daca el ar putea comanda direct firewallul, un atacator ar putea
sa-ti blocheze toata casa. Asa, canary-ul doar *cere* o carantina, iar decizia
si validarea stau in afara lui. Routerul, la rândul lui, nu primeste comenzi:
el citeste periodic lista de la /carantina.txt si o aplica cu `timeout=15m`,
validand din nou fiecare adresa in scriptul lui.

API:
  POST /carantina  {"ip": "192.168.1.77", "motiv": "...", "token": "..."}
  GET  /carantina.txt   -> "192.168.1.77,192.168.1.88"  (pentru router)
  GET  /stare           -> JSON cu ce e in carantina si de ce

Configurare: /etc/carantina/config.json
Doar biblioteca standard.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("CARANTINA_CONFIG", "/etc/carantina/config.json")

DEFAULTS = {
    "bind": "0.0.0.0",
    "port": 8099,
    "durata_minute": 15,
    "maxim_simultan": 3,
    "reteaua": "192.168.1.0/24",
    # Nu se pune NICIODATA in carantina (infrastructura + echipamentele mele)
    "protejate": [
        "192.168.1.1",    # router
        "192.168.1.2",    # AP magazin
        "192.168.1.4",    # Proxmox
        "192.168.1.6",    # media server
        "192.168.1.7",    # switch Cisco
        "192.168.1.10",   # Home Assistant
        "192.168.1.124",  # CT117 (eu insumi)
        "192.168.1.130",  # AP Atelier
        "192.168.1.132",  # HA Mirel
        "192.168.1.174",  # AP Baie
    ],
    "protejate_reteaua": ["192.168.1.60/29", "192.168.192.0/24"],
    "token_file": "/etc/carantina/token",
    "ha_webhook": "",
    "log_file": "/var/log/carantina.jsonl",
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("carantina")


def load_config() -> dict:
    conf = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            conf.update(json.load(fh))
    except FileNotFoundError:
        log.warning("fara %s, folosesc valorile implicite", CONFIG_PATH)
    except Exception as err:
        log.error("config invalid: %s", err)
    return conf


class Carantina:
    def __init__(self, conf: dict) -> None:
        self.conf = conf
        self.durata = int(conf["durata_minute"]) * 60
        self.maxim = int(conf["maxim_simultan"])
        self.reteaua = ipaddress.ip_network(conf["reteaua"], strict=False)
        self.protejate = set(conf["protejate"])
        self.protejate_reteaua = [
            ipaddress.ip_network(n, strict=False) for n in conf["protejate_reteaua"]
        ]
        self.token = ""
        try:
            with open(conf["token_file"], "r", encoding="utf-8") as fh:
                self.token = fh.read().strip()
        except Exception:
            log.warning("fara token: accept cereri doar din reteaua locala")
        self.activi: dict[str, dict] = {}
        self._lock = threading.Lock()

    def curata(self) -> None:
        acum = time.time()
        with self._lock:
            for ip in [k for k, v in self.activi.items() if v["expira"] <= acum]:
                log.info("carantina expirata pentru %s", ip)
                self.activi.pop(ip, None)

    def motiv_refuz(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "nu e adresa IP"
        if addr not in self.reteaua:
            return f"nu e in {self.reteaua}"
        if ip in self.protejate:
            return "e pe lista protejata (infrastructura)"
        if any(addr in net for net in self.protejate_reteaua):
            return "e in subreteaua protejata"
        self.curata()
        with self._lock:
            if ip in self.activi:
                return "deja in carantina"
            if len(self.activi) >= self.maxim:
                return f"plafon atins ({self.maxim} simultan)"
        return None

    def adauga(self, ip: str, motiv: str) -> tuple[bool, str]:
        refuz = self.motiv_refuz(ip)
        if refuz:
            log.warning("REFUZ carantina pentru %s: %s", ip, refuz)
            return False, refuz
        acum = time.time()
        with self._lock:
            self.activi[ip] = {
                "motiv": motiv[:200],
                "de_la": acum,
                "expira": acum + self.durata,
            }
        log.warning("CARANTINA %s pentru %d minute: %s", ip, self.durata // 60, motiv)
        self.jurnal({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "ip": ip, "motiv": motiv})
        self.anunta_ha(ip, motiv)
        return True, "pus in carantina"

    def scoate(self, ip: str) -> bool:
        with self._lock:
            return self.activi.pop(ip, None) is not None

    def lista(self) -> list[str]:
        self.curata()
        with self._lock:
            return sorted(self.activi)

    def jurnal(self, record: dict) -> None:
        try:
            with open(self.conf["log_file"], "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as err:
            log.error("nu pot scrie jurnalul: %s", err)

    def anunta_ha(self, ip: str, motiv: str) -> None:
        url = self.conf.get("ha_webhook", "")
        if not url:
            return
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "src_ip": ip,
            "src_host": "carantina",
            "port": 0,
            "service": "CARANTINA",
            "persona": "carantina",
            "note": f"IP pus in carantina {self.durata // 60} min (internet + acces la router): {motiv}",
            "payload": "",
            "creds": [],
            "held": 0,
            "alerted": True,
            "suppressed": 0,
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(record, ensure_ascii=False).encode(),
                headers={"Content-Type": "application/json", "User-Agent": "carantina/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status >= 300:
                    log.error("HA a raspuns %s", resp.status)
        except Exception as err:
            log.error("nu am putut anunta HA: %s", err)


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    carantina: Carantina

    def _raspunde(self, cod: int, corp: bytes, ctype: str = "text/plain; charset=utf-8") -> None:
        self.send_response(cod)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(corp)))
        self.end_headers()
        self.wfile.write(corp)

    def do_GET(self) -> None:
        cale = self.path.split("?")[0]
        if cale == "/carantina.txt":
            # formatul cu virgule e cerut de RouterOS: `:toarray` sparge pe virgula
            self._raspunde(200, ",".join(self.carantina.lista()).encode())
        elif cale == "/stare":
            self.carantina.curata()
            corp = json.dumps(
                {
                    "activi": self.carantina.activi,
                    "durata_minute": self.carantina.durata // 60,
                    "maxim": self.carantina.maxim,
                },
                ensure_ascii=False,
                default=str,
            ).encode()
            self._raspunde(200, corp, "application/json")
        else:
            self._raspunde(404, b"nu exista\n")

    def do_POST(self) -> None:
        cale = self.path.split("?")[0]
        lungime = int(self.headers.get("content-length", 0) or 0)
        corp = self.rfile.read(min(lungime, 8192)) if lungime else b"{}"
        try:
            date = json.loads(corp.decode("utf-8", "replace"))
        except Exception:
            self._raspunde(400, b"json invalid\n")
            return

        token_cerut = self.carantina.token
        if token_cerut and str(date.get("token", "")) != token_cerut:
            log.warning("cerere respinsa (token invalid) de la %s", self.client_address[0])
            self._raspunde(403, b"token invalid\n")
            return

        ip = str(date.get("ip", "")).strip()
        if cale == "/carantina":
            ok, mesaj = self.carantina.adauga(ip, str(date.get("motiv", "fara motiv")))
            self._raspunde(200 if ok else 409, (mesaj + "\n").encode())
        elif cale == "/eliberare":
            scos = self.carantina.scoate(ip)
            log.warning("eliberare pentru %s: %s", ip, "da" if scos else "nu era in lista")
            self._raspunde(200, b"eliberat\n" if scos else b"nu era in lista\n")
        else:
            self._raspunde(404, b"nu exista\n")

    def log_message(self, *args) -> None:  # noqa: D102
        pass


def main() -> None:
    conf = load_config()
    Handler.carantina = Carantina(conf)
    srv = ThreadingHTTPServer((conf["bind"], int(conf["port"])), Handler)
    log.info(
        "carantina pe %s:%s, %d minute, maxim %s simultan",
        conf["bind"], conf["port"], Handler.carantina.durata // 60, conf["maxim_simultan"],
    )
    srv.serve_forever()


if __name__ == "__main__":
    main()
