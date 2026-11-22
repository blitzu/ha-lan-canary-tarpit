#!/usr/bin/env python3
"""Duce in Home Assistant fiecare citire din share-ul SMB cu momeli.

Samba scrie prin `vfs objects = full_audit` in syslog (facility local5), deci
journald le are. Urmarim fluxul si trimitem pe acelasi webhook ca restul:
cineva care deschide `Parole_router_si_camere.kdbx` de pe un share care nu are
nimic real pe el nu poate fi o greseala.

Formatul liniei (prefixul e setat in smb.conf ca %I|%u|%S):
    smbd_audit: 192.168.1.33|nobody|Backup|pread|ok|Parole_router.kdbx
Doar biblioteca standard. Configurare: /etc/canary/config.json.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import subprocess
import time
import urllib.request
from collections import defaultdict

CONFIG_PATH = os.environ.get("CANARY_CONFIG", "/etc/canary/config.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("samba-audit")

try:
    import telegram_fallback as telegram
except Exception:  # noqa: BLE001
    telegram = None

# ce operatii conteaza: deschiderea si citirea unui fisier
OPERATII = {"open", "pread", "read", "openat"}
# zgomot: directoare si fisiere pe care Windows le atinge singur la navigare
IGNORA_FISIERE = {".", "..", "desktop.ini", "autorun.inf", "folder.jpg", "thumbs.db"}


class Forwarder:
    def __init__(self) -> None:
        conf = {}
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                conf = json.load(fh)
        except Exception as err:
            log.error("nu pot citi %s: %s", CONFIG_PATH, err)
        self.webhook = conf.get("webhook_url", "")
        self.cooldown = int(conf.get("cooldown", 300))
        self.hosts_file = conf.get("hosts_file", "")
        self.nets = []
        for item in conf.get("ignore_nets", []):
            try:
                self.nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                pass
        self._last: dict[str, float] = {}
        self._suprimate: dict[str, int] = defaultdict(int)
        self._hosts: dict[str, str] = {}
        self._hosts_mtime = -1.0

    def ignorat(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(addr in net for net in self.nets)

    def nume(self, ip: str) -> str:
        if self.hosts_file:
            try:
                mtime = os.stat(self.hosts_file).st_mtime
                if mtime != self._hosts_mtime:
                    with open(self.hosts_file, "r", encoding="utf-8") as fh:
                        self._hosts = json.load(fh)
                    self._hosts_mtime = mtime
            except Exception:
                pass
        return self._hosts.get(ip, "necunoscut")

    def alerta(self, ip: str, share: str, fisier: str, user: str) -> None:
        # un fisier citit de pe share-ul momeala e mereu interesant, dar tot
        # punem o fereastra per (IP, fisier), ca o copiere sa nu trimita 200 de mesaje
        cheie = f"{ip}|{fisier}"
        acum = time.monotonic()
        if acum - self._last.get(cheie, 0.0) < min(60, self.cooldown):
            self._suprimate[ip] += 1
            return
        self._last[cheie] = acum

        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "src_ip": ip,
            "src_host": self.nume(ip),
            "port": 445,
            "service": "SMB momeala",
            "persona": "smb_audit",
            "note": f"A CITIT fisierul momeala '{fisier}' din \\\\DiskStation\\{share}",
            "payload": f"utilizator SMB: {user}",
            "creds": [],
            "held": 0,
            "alerted": True,
            "suppressed": self._suprimate.pop(ip, 0),
        }
        log.warning("ALERTA %s a citit %s/%s", ip, share, fisier)

        ajuns = False
        if self.webhook:
            try:
                req = urllib.request.Request(
                    self.webhook,
                    data=json.dumps(record, ensure_ascii=False).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "samba-audit-forward/1.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=6) as resp:
                    ajuns = resp.status < 300
            except Exception as err:
                log.error("webhook HA a eșuat: %s", err)

        if not ajuns and telegram is not None and telegram.disponibil():
            ok, motiv = telegram.trimite(
                "🕸️ CANARY / share momeala (HA nu raspunde)\n"
                f"{ip} ({record['src_host']}) a citit '{fisier}' din {share}",
                cheie=f"smb:{ip}",
                interval=self.cooldown,
            )
            log.warning("rezerva Telegram: %s (%s)", "trimis" if ok else "netrimis", motiv)

    def linie(self, text: str) -> None:
        # Cu `journalctl -o cat` eticheta "smbd_audit:" nu mai apare, deci nu o
        # cerem. Samba pune intre rezultat si cale si modul de deschidere ("r"),
        # asa ca luam calea de la sfarsit, nu de pe o poziție fixa:
        #   IP|utilizator|share|operatie|rezultat[|mod]|/cale/fisier
        corp = text.split("smbd_audit:", 1)[-1].strip()
        parti = [p.strip() for p in corp.split("|")]
        if len(parti) < 6:
            return
        ip, user, share, operatie, rezultat = parti[:5]
        cale = parti[-1]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return
        if operatie not in OPERATII or rezultat != "ok":
            return
        fisier = os.path.basename(cale.rstrip("/"))
        # directoarele apar si ele (navigarea prin share): ne interesează fisierele
        if not fisier or "." not in fisier or fisier.lower() in IGNORA_FISIERE:
            return
        if self.ignorat(ip):
            return
        self.alerta(ip, share, fisier, user)

    def urmareste(self) -> None:
        cmd = [
            "journalctl", "-f", "-n", "0", "--facility=local5",
            "-o", "cat", "--no-pager",
        ]
        log.info("urmaresc auditul Samba (local5), trimit catre %s", self.webhook or "-")
        while True:
            try:
                # bufsize=1 + readline(): `for linie in proc.stdout` citeste in
                # blocuri si ar tine alertele in buffer pana se umple 8 KB.
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, text=True, bufsize=1
                )
                assert proc.stdout is not None
                while True:
                    linie = proc.stdout.readline()
                    if not linie:
                        break
                    self.linie(linie.rstrip("\n"))
                log.error("journalctl s-a inchis, reiau in 5 s")
            except Exception as err:
                log.error("eroare la urmarire: %s", err)
            time.sleep(5)


if __name__ == "__main__":
    Forwarder().urmareste()
