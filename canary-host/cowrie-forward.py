#!/usr/bin/env python3
"""Duce evenimentele Cowrie in Home Assistant, pe acelasi webhook ca canaryd.

Citeste la coada `cowrie.json` (jsonl) si trimite doar ce conteaza:
  - sesiune noua                  -> alerta normala (fereastra `cooldown` per IP)
  - parola incercata / acceptata  -> alerta urgenta (fereastra de 60 s per IP)
  - prima comanda din shell       -> alerta urgenta
  - fisier descarcat / urcat      -> alerta urgenta (asta e premiul: URL + hash)
  - sesiune incheiata             -> rezumat cu toate comenzile, daca a scris ceva

Foloseste aceeasi configurare ca canaryd (/etc/canary/config.json): webhook_url,
cooldown, ignore_nets, hosts_file. Doar biblioteca standard.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
import urllib.request
from collections import defaultdict

CONFIG_PATH = os.environ.get("CANARY_CONFIG", "/etc/canary/config.json")
COWRIE_LOG = os.environ.get(
    "COWRIE_JSON", "/opt/cowrie/var/log/cowrie/cowrie.json"
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("cowrie-forward")

INTERESANTE = {
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
    "cowrie.session.closed",
}


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
        self._suppressed: dict[str, int] = defaultdict(int)
        self._cmds: dict[str, list[str]] = defaultdict(list)
        self._hosts: dict[str, str] = {}
        self._hosts_mtime = -1.0

    # ---------- utilitare ----------

    def ignored(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.nets)

    def host_name(self, ip: str) -> str:
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

    def send(
        self,
        ip: str,
        port: int,
        proto: str,
        note: str,
        payload: str = "",
        creds: list[dict] | None = None,
        urgent: bool = False,
        klass: str | None = None,
    ) -> None:
        # Clase separate = ferestre separate de anti-spam. Un fisier descarcat
        # (clasa "file") e cea mai valoroasa informatie si nu trebuie inghitita
        # de alerta de login din aceeasi sesiune.
        klass = klass or ("urgent" if (creds or urgent) else "plain")
        key = f"{ip}|{klass}"
        now = time.monotonic()
        window = min(60, self.cooldown) if klass == "urgent" else self.cooldown
        if now - self._last.get(key, 0.0) < window:
            self._suppressed[ip] += 1
            log.info("suprimat (%s): %s %s", klass, ip, note)
            return
        self._last[key] = now

        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "src_ip": ip,
            "src_host": self.host_name(ip),
            "port": port,
            "service": f"Cowrie {proto.upper()} (shell fals)",
            "persona": "cowrie",
            "note": note,
            "payload": payload[:200],
            "creds": creds or [],
            "held": 0,
            "alerted": True,
            "suppressed": self._suppressed.pop(ip, 0),
        }
        log.warning("ALERTA %s :%d %s %s", ip, port, note, creds or "")
        if not self.webhook:
            return
        body = json.dumps(record, ensure_ascii=False).encode()
        try:
            req = urllib.request.Request(
                self.webhook,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "cowrie-forward/1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status >= 300:
                    log.error("webhook HA a raspuns %s", resp.status)
        except Exception as err:
            log.error("webhook HA a eșuat: %s", err)

    # ---------- evenimente ----------

    def handle(self, ev: dict) -> None:
        eid = ev.get("eventid", "")
        if eid not in INTERESANTE:
            return
        ip = ev.get("src_ip") or ""
        if not ip or self.ignored(ip):
            return
        proto = ev.get("protocol") or "ssh"
        port = int(ev.get("dst_port") or (23 if proto == "telnet" else 22))
        sess = ev.get("session") or ip

        if eid == "cowrie.session.connect":
            self.send(ip, port, proto, "sesiune noua pe shell-ul fals")
        elif eid == "cowrie.login.failed":
            self.send(
                ip, port, proto, "parola respinsa",
                creds=[{"user": ev.get("username", ""), "pass": ev.get("password", "")}],
            )
        elif eid == "cowrie.login.success":
            self.send(
                ip, port, proto, "A INTRAT in shell-ul fals",
                creds=[{"user": ev.get("username", ""), "pass": ev.get("password", "")}],
                urgent=True,
            )
        elif eid == "cowrie.command.input":
            cmd = (ev.get("input") or "").strip()
            first = not self._cmds[sess]
            self._cmds[sess].append(cmd)
            if first:
                self.send(
                    ip, port, proto, f"ruleaza comenzi: {cmd[:60]}", cmd, urgent=True
                )
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            what = "a descarcat" if eid.endswith("download") else "a urcat"
            url = ev.get("url") or ev.get("filename") or ev.get("outfile") or ""
            self.send(
                ip, port, proto,
                f"{what} un fisier in shell-ul fals",
                f"{url} sha256={(ev.get('shasum') or '')[:16]}",
                urgent=True,
                klass="file",
            )
        elif eid == "cowrie.session.closed":
            cmds = self._cmds.pop(sess, [])
            if len(cmds) > 1:
                self.send(
                    ip, port, proto,
                    f"sesiune incheiata, {len(cmds)} comenzi",
                    " ; ".join(cmds)[:200],
                    urgent=True,
                )

    # ---------- urmarirea jurnalului ----------

    def follow(self, path: str) -> None:
        log.info("urmaresc %s, trimit catre %s", path, self.webhook or "(fara webhook)")
        fh = None
        inode = None
        while True:
            try:
                if fh is None:
                    if not os.path.exists(path):
                        time.sleep(2)
                        continue
                    fh = open(path, "r", encoding="utf-8", errors="replace")
                    fh.seek(0, os.SEEK_END)
                    inode = os.fstat(fh.fileno()).st_ino
                line = fh.readline()
                if not line:
                    # rotatie?
                    try:
                        if os.stat(path).st_ino != inode:
                            fh.close()
                            fh = None
                            continue
                    except OSError:
                        fh.close()
                        fh = None
                        continue
                    time.sleep(0.5)
                    continue
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    self.handle(json.loads(line))
                except Exception as err:
                    log.error("linie invalida: %s", err)
            except Exception as err:
                log.error("eroare la urmarire: %s", err)
                if fh:
                    try:
                        fh.close()
                    except Exception:
                        pass
                fh = None
                time.sleep(2)


if __name__ == "__main__":
    Forwarder().follow(COWRIE_LOG)
