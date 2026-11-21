#!/usr/bin/env python3
"""Reface /etc/canary/hosts.json din leaseurile DHCP ale routerului.

Rulare de pe Mac:  python3 refresh-hosts.py         (citeste routerul prin ssh)
Numele vine din comentariul leaseului (routerul are ~100 comentarii),
altfel din host-name-ul raportat de dispozitiv.
"""
import base64
import json
import re
import subprocess

STATICE = {
    # "192.168.1.10": "Home Assistant",  # IP-urile statice, completate manual
}

SSH = [
    "ssh", "-i", "~/.ssh/id_ed25519", "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
]


def leases() -> dict:
    out = subprocess.run(
        SSH + ["<user>@<router>", "/ip dhcp-server lease print terse"],
        capture_output=True, text=True, timeout=30, check=True,
    ).stdout
    found = {}
    for line in out.splitlines():
        m_ip = re.search(r"\baddress=(192\.168\.1\.\d+)", line)
        if not m_ip:
            continue
        ip = m_ip.group(1)
        m_c = re.search(r"\bcomment=(.*?)\s+(?:address|mac-address)=", line)
        m_h = re.search(r"\bhost-name=(\S+)", line)
        name = (m_c.group(1).strip() if m_c else "") or (m_h.group(1) if m_h else "")
        if name:
            found[ip] = name[:60]
    return found


def main() -> None:
    harta = {**leases(), **STATICE}
    blob = json.dumps(harta, indent=1, ensure_ascii=False, sort_keys=True)
    print(f"{len(harta)} nume")
    payload = base64.b64encode((blob + "\n").encode()).decode()
    script = "base64 -d > /etc/canary/hosts.json <<'B64'\n" + "\n".join(
        payload[i:i + 120] for i in range(0, len(payload), 120)
    ) + "\nB64\necho scris: $(wc -c < /etc/canary/hosts.json) octeti\n"
    res = subprocess.run(
        SSH + ["root@<proxmox>", "pct exec <VMID> -- bash -s"],
        input=script, capture_output=True, text=True, timeout=60,
    )
    print(res.stdout.strip() or res.stderr.strip())


if __name__ == "__main__":
    main()
