# canaryd - NAS fals pe host dedicat

Varianta "miere mai atractiva" a capcanei din acest repo: in loc de porturi
nestandard (`:2121`, `:2222`) pe cutia de Home Assistant, un **host dedicat**
cu IP propriu, care nu ruleaza nimic real si se da drept un NAS Synology
pe **porturile adevarate**.

Orice pachet catre acest IP este, prin definitie, o scanare: nimeni n-are
treaba cu el. Si, in plus, **se lauda singur in retea**, ca sa fie gasit
inainte de celelalte aparate.

## Ce face

| Ce | Detalii |
| --- | --- |
| 22 porturi momeala | 21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 80/5000/8080/7547 web, 139/445 SMB, 443/5001 TLS, 554 RTSP, 1433 MSSQL, 2375 Docker API, 3306 MySQL, 3389 RDP, 5555 ADB, 5900 VNC, 6379 Redis, 9200 Elasticsearch, 27017 MongoDB |
| Dialoguri reale, nu doar bannere | FTP cere `USER`/`PASS`, Telnet are prompt de login, pagina web e un login DSM, Redis raspunde la `PING`/`INFO`/`CONFIG`, Docker API da o versiune falsa, RTSP cere Digest |
| Captureaza ce incearca | utilizator + parola (FTP, Telnet, formular web, Basic-Auth, MySQL), comenzile Redis, imaginea pe care vrea sa o porneasca prin Docker, dialectul SMB (un `SMB1` = scaner de ransomware) |
| Capcana TCP | dupa ce a fost prins, picurare lenta pana la 15 minute (plafon de socketuri, ca sa nu-l doboare nimeni cu conexiuni) |
| Se anunta in retea | mDNS/Bonjour prin avahi (apare in *Network* din Finder), NetBIOS pe UDP 137 (apare in *Network* din Windows), SSDP/UPnP pe UDP 1900 (`NOTIFY ssdp:alive` la 15 min) |
| Alerta | webhook catre Home Assistant, cu anti-spam: o alerta per IP la `cooldown` secunde, dar **parolele si exploit-urile au fereastra proprie, scurta**, ca sa nu fie inghitite de alerta de conectare |
| Jurnal | `/var/log/canary/events.jsonl` - tot, inclusiv ce nu a alertat (`"alerted": false`) |
| Nume citibile | `hosts.json` (IP -> nume), ca alerta sa spuna "PC Windows din birou", nu "necunoscut" |

Doar biblioteca standard Python 3 + `avahi-daemon` pentru mDNS.

## Containerul (Proxmox LXC)

```bash
pct create <VMID> local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
  --hostname diskstation --cores 1 --memory 512 --swap 512 \
  --rootfs local-lvm:3 \
  --net0 name=eth0,bridge=vmbr0,hwaddr=00:11:32:2A:7B:60,ip=<IP>/24,gw=<GW>,type=veth \
  --nameserver <DNS> --onboot 1 --unprivileged 1 --ostype debian \
  --tags 'canary;honeypot' --start 1
```

`hwaddr` incepe cu `00:11:32` = OUI Synology, deci si in tabelul routerului
si in ntopng apare ca "Synology Incorporated".

**Nu lasa SSH-ul containerului pornit**: portul 22 e momeala.
Administrarea se face din gazda, cu `pct exec <VMID> -- ...`:

```bash
systemctl disable --now ssh.socket ssh.service postfix
systemctl mask ssh.socket ssh.service
```

## Instalare

```bash
apt-get install -y avahi-daemon avahi-utils
mkdir -p /opt/canary /etc/canary /var/log/canary /etc/avahi/services
install -m755 canaryd.py            /opt/canary/canaryd.py
install -m640 config.example.json   /etc/canary/config.json   # completeaza webhook_url + ip
install -m644 canaryd.service       /etc/systemd/system/canaryd.service
install -m644 avahi-nas.service     /etc/avahi/services/nas.service
install -m644 logrotate.canary      /etc/logrotate.d/canary
systemctl daemon-reload
systemctl enable --now avahi-daemon canaryd
```

## Cowrie pe 22 si 23 (shell fals)

Porturile SSH si Telnet sunt date lui [Cowrie](https://github.com/cowrie/cowrie):
acolo nu vrem doar sa agatam scanerul, vrem sa-l lasam sa creada ca a intrat.
`canaryd` renunta la 22 si 23 (le scoți din `ports` in config), restul porturilor
rămân ale lui.

Ce da Cowrie in plus: accepta login-ul doar pentru o **lista scurta de parole**
(`userdb.txt`: `root`/`admin` cu `admin`, `synology`, `123456`, `password`...), deci
botii cu dictionar clasic intra, iar restul sunt respinsi - un om care incearca o parola
inventata vede "Login incorrect", ca pe un NAS adevarat. Mai departe:
prezinta un shell fals cu prompt `root@DiskStation:~#`, raspunde la `uname -a`,
`cat /proc/cpuinfo`, `wget`..., **inregistreaza fiecare comanda**, descarca si
pastreaza fisierele pe care botul incearca sa le aduca (`var/lib/cowrie/downloads`,
cu sha256) si salveaza sesiunea ca inregistrare TTY, care se poate reda:

```bash
/opt/cowrie/cowrie-env/bin/python -m cowrie.scripts.playlog var/lib/cowrie/tty/<hash>
```

Instalare (Debian 13, in containerul canary):

```bash
apt-get install -y git python3-venv python3-dev libffi-dev
adduser --disabled-password --gecos "" --home /opt/cowrie cowrie
git clone --depth 1 https://github.com/cowrie/cowrie.git /opt/cowrie   # sau clona si copiaza
runuser -u cowrie -- bash -c 'cd /opt/cowrie && python3 -m venv cowrie-env &&
  source cowrie-env/bin/activate && pip install -r requirements.txt && pip install -e .'
install -m644 cowrie.cfg  /opt/cowrie/etc/cowrie.cfg
install -m644 userdb.txt  /opt/cowrie/etc/userdb.txt
install -m644 cowrie.service /etc/systemd/system/
install -m755 cowrie-forward.py /opt/canary/
install -m644 cowrie-forward.service /etc/systemd/system/
install -m644 logrotate.cowrie /etc/logrotate.d/cowrie
systemctl daemon-reload && systemctl enable --now cowrie cowrie-forward
```

`cowrie-forward.py` citeste la coada `cowrie.json` si trimite in HA, pe acelasi
webhook, cu **clase separate de anti-spam**: conectare (fereastra `cooldown`),
parola/comenzi (60 s) si **fisier descarcat, care are clasa proprie** - altfel
alerta cu URL-ul malware-ului ar fi inghitita de alerta de login din aceeasi sesiune.
O sesiune completa de bot = 2-3 notificari, iar tot restul e in `cowrie.json`.

Nu ruleaza ca root: unitatea systemd ii da doar `CAP_NET_BIND_SERVICE` ca sa poata
lega 22 si 23.

## Partea de Home Assistant

Automatizare cu declansator `webhook` (`local_only: true`) pe `webhook_id`-ul
din `webhook_url`. JSON-ul primit:

```json
{"ts":"...","src_ip":"192.168.1.33","src_host":"PC birou","port":23,
 "service":"Telnet","persona":"telnet","note":"a incercat login Telnet",
 "payload":"","creds":[{"user":"root","pass":"xc3511"}],
 "held":2,"alerted":true,"suppressed":4}
```

`suppressed` = cate sonde de la acelasi IP au fost inghitite de anti-spam
de la ultima alerta.

## Ca sa nu moara in liniste

Un honeypot mort tace exact ca unul neatins, deci are nevoie de puls, nu doar de
`Restart=always`. Trei straturi:

1. **systemd + `onboot`** - `canaryd`, `cowrie` si `cowrie-forward` au `Restart=always`,
   iar containerul porneste la boot-ul gazdei. Acopera crash-urile si repornirile.
2. **Autoverificare la 5 minute** (`canary-healthcheck.py` + `canary-healthcheck.timer`):
   verifica serviciile *si* se conecteaza local pe fiecare port momeala (plus bannerul
   SSH si promptul Telnet ale lui Cowrie), apoi trimite un puls pe `heartbeat_url`.
   `127.0.0.1` e in `ignore_nets`, deci verificarea nu se alerteaza singura. Daca un
   port nu raspunde, pulsul pleaca cu `"status": "degradat"` si lista porturilor moarte.
3. **Dead-man's switch in Home Assistant**: fiecare puls scrie `input_datetime` si
   rearmeaza un `timer` de 15 minute. Daca pulsul nu mai vine, `timer.finished`
   declanseaza o notificare critica ("capcana nu mai raspunde"), se repeta la ~45 min
   si se rearmeaza si la pornirea HA, ca o capcana moarta inainte de un restart sa nu
   treaca neobservata.

Asa afli si cand moare tot hostul (nu mai vine puls), si cand moare doar o parte
(pulsul spune `degradat`). Testat prin oprirea lui Cowrie - pulsul a raportat imediat
`porturi_moarte: [22, 23]`, `servicii_moarte: ["cowrie"]` - si prin oprirea pulsului,
caz in care HA a sunat singur.

## Capcane de care sa ții cont

- **Te alertezi singur prin SSDP**: dupa ce te anunti, televizoarele, PC-urile
  Windows si Home Assistant cer `GET /desc.xml`. Acele cereri se scriu in
  jurnal, dar nu trimit notificare.
- **Monitorizarea proprie**: daca ai Uptime Kuma / Zabbix care verifica porturi,
  pune-i IP-ul (sau subreteaua VPN-ului) in `ignore_nets`, altfel suna la fiecare verificare.
- **Home Assistant va "descoperi" NAS-ul** prin SSDP si va propune integrarea
  Synology DSM. Ignora sugestia.
- **`userdb.txt` se citeste strict ca ASCII** (`read_text(encoding="ascii")` in
  `src/cowrie/core/auth.py`). Un singur caracter cu diacritice intr-un comentariu si
  fisierul nu se incarca, iar **toate** loginurile sunt respinse, fara nicio eroare
  vizibila in jurnal. Scrie-l fara diacritice.
- NetBIOS raspunde **doar** pentru numele propriu, niciodata pentru alte nume:
  altfel ai deturna rezolvarea de nume in toata reteaua.
