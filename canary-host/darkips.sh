#!/bin/bash
# Adauga/scoate "IP-urile fantoma" pe eth0: adrese libere din LAN pe care nimeni
# nu are ce sa le caute. Containerul raspunde ARP pentru ele, deci orice scanare
# a subretelei aterizeaza pe honeypot, nu doar pe IP-ul lui principal.
# Lista vine din /etc/canary/config.json -> "dark_ips".
set -u
CONFIG="${CANARY_CONFIG:-/etc/canary/config.json}"
DEV="${CANARY_DEV:-eth0}"

lista() {
  python3 -c "import json,sys; print(' '.join(json.load(open('$CONFIG')).get('dark_ips', [])))"
}

case "${1:-add}" in
  add)
    for ip in $(lista); do
      ip addr add "$ip/24" dev "$DEV" 2>/dev/null && echo "adaugat $ip" || echo "deja exista $ip"
    done
    ;;
  del)
    for ip in $(lista); do
      ip addr del "$ip/24" dev "$DEV" 2>/dev/null && echo "scos $ip"
    done
    ;;
  list)
    ip -4 -o addr show dev "$DEV" | awk '{print $4}'
    ;;
  *)
    echo "folosire: darkips.sh [add|del|list]" >&2; exit 2 ;;
esac
