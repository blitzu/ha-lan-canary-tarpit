#!/usr/bin/env python3
"""Autoverificare + puls pentru hostul canary.

Rulat de un timer systemd la fiecare 5 minute:
  1. verifica serviciile (canaryd, cowrie, cowrie-forward, avahi-daemon)
  2. se conecteaza local pe FIECARE port momeala si vede ca cineva raspunde
     (127.0.0.1 e in `ignore_nets`, deci nu se alerteaza singur)
  3. trimite un puls in Home Assistant pe `heartbeat_url`
  4. daca ceva e picat, trimite si o alerta normala pe `webhook_url`

Daca pulsul nu mai ajunge, cronometrul de veghe din HA suna singur - asa aflam
ca honeypot-ul a murit, nu doar ca nimeni nu l-a atins.
Doar biblioteca standard.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.request

CONFIG_PATH = os.environ.get("CANARY_CONFIG", "/etc/canary/config.json")
SERVICII = ["canaryd", "cowrie", "cowrie-forward", "avahi-daemon"]
# porturile pe care le tine Cowrie, nu canaryd, cu ce trebuie sa raspunda
COWRIE_PORTS = {22: b"SSH-2.0", 23: b"login"}
TIMEOUT = 4.0


def conf() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def serviciu_activ(nume: str) -> bool:
    try:
        out = subprocess.run(
            ["systemctl", "is-active", nume],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() == "active"
    except Exception:
        return False


def port_viu(port: int, ateptat: bytes | None = None) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as s:
            if ateptat is None:
                return True
            s.settimeout(TIMEOUT)
            data = b""
            capat = time.time() + TIMEOUT
            while time.time() < capat:
                try:
                    bucata = s.recv(256)
                except socket.timeout:
                    break
                if not bucata:
                    break
                data += bucata
                if ateptat.lower() in data.lower():
                    return True
            return ateptat.lower() in data.lower()
    except Exception:
        return False


def trimite(url: str, payload: dict) -> bool:
    if not url:
        return False
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "canary-healthcheck/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status < 300
    except Exception as err:
        print("nu am putut trimite catre HA: %s" % err)
        return False


def main() -> int:
    c = conf()
    porturi = {int(p): n for p, n in c.get("ports", {}).items()}

    servicii_moarte = [s for s in SERVICII if not serviciu_activ(s)]

    # IP-urile fantoma trebuie sa fie in continuare pe interfata
    fantome_lipsa = []
    dark = c.get("dark_ips", [])
    if dark:
        try:
            out = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "dev", c.get("dev", "eth0")],
                capture_output=True, text=True, timeout=10,
            ).stdout
            prezente = {w.split("/")[0] for w in out.split() if w.count(".") == 3}
            fantome_lipsa = [ip for ip in dark if ip not in prezente]
        except Exception:
            fantome_lipsa = []
    if fantome_lipsa:
        servicii_moarte.append("ip-uri fantoma lipsa: " + ",".join(fantome_lipsa))
    porturi_moarte = [p for p in sorted(porturi) if not port_viu(p)]
    porturi_moarte += [
        p for p, semn in COWRIE_PORTS.items() if not port_viu(p, semn)
    ]
    porturi_moarte.sort()

    ok = not servicii_moarte and not porturi_moarte
    puls = {
        "status": "ok" if ok else "degradat",
        "gazda": c.get("hostname", "canary"),
        "ip": c.get("ip", ""),
        "porturi_ok": len(porturi) + len(COWRIE_PORTS) - len(porturi_moarte),
        "porturi_total": len(porturi) + len(COWRIE_PORTS),
        "porturi_moarte": porturi_moarte,
        "servicii_moarte": servicii_moarte,
        "ip_uri_fantoma": len(c.get("dark_ips", [])),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    print(json.dumps(puls, ensure_ascii=False))

    pulsul_a_ajuns = trimite(c.get("heartbeat_url", ""), puls)

    # Daca HA nu primeste pulsul, cronometrul de veghe de acolo nu ne mai poate
    # ajuta (poate HA e cel picat). Atunci anuntam direct pe Telegram, o data pe ora.
    if not pulsul_a_ajuns:
        try:
            import telegram_fallback as telegram
        except Exception:
            telegram = None
        if telegram is not None and telegram.disponibil():
            text = (
                "⚠️ CANARY: Home Assistant nu primeste pulsul\n"
                f"Capcana de pe {c.get('ip', '?')} e {puls['status']} "
                f"({puls['porturi_ok']}/{puls['porturi_total']} porturi)."
            )
            if porturi_moarte or servicii_moarte:
                text += (
                    f"\nPorturi moarte: {porturi_moarte or '-'}"
                    f"\nServicii picate: {servicii_moarte or '-'}"
                )
            ok, motiv = telegram.trimite(text, cheie="ha_fara_puls", interval=3600)
            print("rezerva Telegram: %s (%s)" % ("trimis" if ok else "netrimis", motiv))

    if not ok:
        # Nu trimitem si pe webhook-ul de intruziune: pulsul duce deja `status`
        # si detaliile, iar automatizarea "puls primit" din HA notifica. Altfel
        # am aprinde alerta de INTRUS si am umfla contorul de sonde pentru o
        # defectiune proprie.
        print("DEGRADAT: servicii=%s porturi=%s" % (servicii_moarte, porturi_moarte))

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
