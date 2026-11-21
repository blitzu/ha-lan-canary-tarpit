#!/usr/bin/env python3
"""Rezerva pe Telegram, pentru cand Home Assistant nu raspunde.

Tokenul NU se afla in acest fisier si nu se scrie niciodata in jurnal: se
citeste din /etc/canary/telegram.json (0600), pe care il completeaza omul:

    {"bot_token": "...", "chat_id": "..."}

Daca fisierul lipseste, rezerva e pur si simplu dezactivata.
Are propriul anti-spam, pe cheie, ca o cadere lunga de HA sa nu trimita o mie
de mesaje. Test: `python3 telegram_fallback.py --test`.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

CRED_PATH = os.environ.get("CANARY_TELEGRAM", "/etc/canary/telegram.json")
STATE_PATH = os.environ.get(
    "CANARY_TELEGRAM_STATE", "/var/lib/canary/telegram-state.json"
)
API = "https://api.telegram.org/bot%s/sendMessage"


def _creds() -> tuple[str, str] | None:
    try:
        with open(CRED_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        token = str(data.get("bot_token", "")).strip()
        chat = str(data.get("chat_id", "")).strip()
        if token and chat:
            return token, chat
    except FileNotFoundError:
        return None
    except Exception:
        return None
    return None


def disponibil() -> bool:
    return _creds() is not None


def _state() -> dict:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
    except Exception:
        pass


def _curat(mesaj: str, token: str) -> str:
    """Nu lasa niciodata tokenul sa ajunga in jurnal."""
    return mesaj.replace(token, "***") if token else mesaj


def trimite(text: str, cheie: str | None = None, interval: int = 0) -> tuple[bool, str]:
    """Trimite pe Telegram. Returneaza (reusit, motiv_pe_scurt)."""
    cred = _creds()
    if cred is None:
        return False, "rezerva Telegram nu e configurata"
    token, chat = cred

    if cheie and interval > 0:
        state = _state()
        acum = time.time()
        ultim = float(state.get(cheie, 0))
        if acum - ultim < interval:
            return False, "anti-spam (trimis acum %d s)" % int(acum - ultim)
        state[cheie] = acum
        _save_state(state)

    body = urllib.parse.urlencode(
        {"chat_id": chat, "text": text[:3900], "disable_web_page_preview": "true"}
    ).encode()
    try:
        req = urllib.request.Request(
            API % token,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status < 300, "HTTP %s" % resp.status
    except Exception as err:
        return False, _curat(str(err)[:160], token)


if __name__ == "__main__":
    import sys

    if "--test" in sys.argv:
        if not disponibil():
            print("NU e configurata: lipseste sau e incompleta " + CRED_PATH)
            raise SystemExit(2)
        ok, motiv = trimite(
            "Test din canary (%s): rezerva pe Telegram functioneaza."
            % os.uname().nodename
        )
        print("trimis" if ok else "eșuat: " + motiv)
        raise SystemExit(0 if ok else 1)
    print("configurata" if disponibil() else "neconfigurata")
