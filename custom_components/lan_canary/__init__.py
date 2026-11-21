"""LAN Canary - honeypot intern + capcana TCP activa (tarpit) pentru Home Assistant.

Adaptare a https://github.com/robainbinder/ha-lan-canary-tarpit pentru reteaua
de acasa: texte in romana, lista alba de IP-uri, anti-spam pe notificari
(un singur alert per IP in fereastra de cooldown) si un eveniment HA
(`lan_canary_hit`) pe care se leaga automatizarile.

Configurare in configuration.yaml:

    lan_canary:
      cooldown: 300            # secunde intre doua notificari de la acelasi IP
      ignore_ips:              # IP-uri care nu declanseaza nimic (scanere proprii)
        - 192.168.1.218
      ports: [2121, 2222, 2323, 3306, 5900, 8088]   # opțional, subset
      tarpit_minutes: 15
      max_sockets: 64
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv
from homeassistant.util import dt as dt_util

_LOGGER = logging.getLogger(__name__)

DOMAIN = "lan_canary"
EVENT_HIT = "lan_canary_hit"

# Entitati din HA (helperi creati separat, in storage mode)
ENT_ALERT = "input_boolean.canary_alerta_intruziune"
ENT_LAST = "input_text.canary_ultimul_eveniment"
ENT_COUNT = "input_number.canary_numar_hituri"

# Bannerele initiale, per protocol:
# - FTP (2121): "220-" cu cratima (RFC 959, salut pe mai multe linii) -> scanerul
#   asteapta la infinit linia finala "220 "
# - SSH (2222): RFC 4253 §4.2 permite oricate linii inainte de "SSH-2.0-" (stil Endlessh)
# - Telnet (2323): prompt fals de DiskStation + picurare de octeti
# - MySQL (3306): antet parțial de handshake MariaDB
# - VNC (5900): handshake RFB 003.008 tinut deschis
# - DSM HTTP (8088): Slowloris inversat - antete fara \r\n\r\n final
DECOYS: dict[int, tuple[str, bytes | None]] = {
    2121: ("FTP", b"220-DiskStation FTP server (Synology DSM 7.2) initializing...\r\n"),
    2222: ("SSH", b"Synology-DSM-7.2-Security-Banner: verifying host key...\r\n"),
    2323: ("Telnet", b"\r\nDiskStation-NAS login: "),
    3306: ("MySQL", b"\x4a\x00\x00\x00\x0a5.5.68-MariaDB-Synology\x00"),
    5900: ("VNC", b"RFB 003.008\n"),
    8088: ("Synology-DSM-HTTP", None),
}

DRIP_INTERVAL_SEC = 10.0
DEFAULT_COOLDOWN = 300
DEFAULT_TARPIT_MINUTES = 15
DEFAULT_MAX_SOCKETS = 64

CONF_COOLDOWN = "cooldown"
CONF_IGNORE_IPS = "ignore_ips"
CONF_PORTS = "ports"
CONF_TARPIT_MINUTES = "tarpit_minutes"
CONF_MAX_SOCKETS = "max_sockets"

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Optional(CONF_COOLDOWN, default=DEFAULT_COOLDOWN): cv.positive_int,
                vol.Optional(CONF_IGNORE_IPS, default=[]): vol.All(
                    cv.ensure_list, [cv.string]
                ),
                vol.Optional(CONF_PORTS, default=list(DECOYS)): vol.All(
                    cv.ensure_list, [vol.In(list(DECOYS))]
                ),
                vol.Optional(
                    CONF_TARPIT_MINUTES, default=DEFAULT_TARPIT_MINUTES
                ): cv.positive_int,
                vol.Optional(
                    CONF_MAX_SOCKETS, default=DEFAULT_MAX_SOCKETS
                ): cv.positive_int,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)

ALWAYS_IGNORED = {"127.0.0.1", "::1", "unknown"}


def _resolve_host(ip: str) -> str:
    """Reverse-DNS, rulat in executor (poate bloca)."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.replace(".lan", "").replace(".local", "")
    except Exception:  # noqa: BLE001 - orice eroare DNS = nume necunoscut
        return "necunoscut"


def _clean_payload(payload: bytes) -> str:
    """Primul rand lizibil din ce a trimis scanerul (max 40 caractere)."""
    if not payload:
        return ""
    lines = payload.decode("utf-8", errors="ignore").strip().splitlines()
    if not lines:
        return ""
    snippet = "".join(ch for ch in lines[0] if 32 <= ord(ch) < 127)[:40].strip()
    return snippet


class CanaryRuntime:
    """Starea componentei: servere, socketuri prinse, anti-spam."""

    def __init__(self, hass: HomeAssistant, conf: dict) -> None:
        self.hass = hass
        self.cooldown: int = conf[CONF_COOLDOWN]
        self.ignore_ips: set[str] = set(conf[CONF_IGNORE_IPS]) | ALWAYS_IGNORED
        self.ports: list[int] = list(conf[CONF_PORTS])
        self.tarpit_seconds: float = conf[CONF_TARPIT_MINUTES] * 60.0
        self.max_sockets: int = conf[CONF_MAX_SOCKETS]
        self.servers: dict[int, asyncio.AbstractServer] = {}
        self.writers: set[asyncio.StreamWriter] = set()
        self._last_notify: dict[str, float] = {}
        self._warned_missing: set[str] = set()

    # ---------- anti-spam ----------

    def should_notify(self, ip: str) -> bool:
        now = time.monotonic()
        last = self._last_notify.get(ip, 0.0)
        if now - last < self.cooldown:
            return False
        self._last_notify[ip] = now
        return True

    def clear_cooldowns(self) -> None:
        self._last_notify.clear()

    # ---------- scriere in HA ----------

    async def _set_helper(self, domain: str, service: str, data: dict) -> None:
        entity = data.get("entity_id", "")
        if entity and self.hass.states.get(entity) is None:
            if entity not in self._warned_missing:
                self._warned_missing.add(entity)
                _LOGGER.warning(
                    "LAN Canary: helperul %s nu exista, sar peste actualizare", entity
                )
            return
        try:
            await self.hass.services.async_call(domain, service, data, blocking=True)
        except Exception as err:  # noqa: BLE001
            _LOGGER.error("LAN Canary: nu am putut apela %s.%s: %s", domain, service, err)

    async def record_hit(
        self, src_ip: str, svc: str, port: int, payload: bytes, trapped: int
    ) -> None:
        """Scrie evenimentul in HA si il anunta pe bus."""
        try:
            host = await asyncio.wait_for(
                self.hass.async_add_executor_job(_resolve_host, src_ip), timeout=2.5
            )
        except Exception:  # noqa: BLE001 - timeout sau eroare DNS
            host = "necunoscut"

        snippet = _clean_payload(payload)
        notify = self.should_notify(src_ip)
        now_str = dt_util.now().strftime("%H:%M:%S")
        msg = (
            f"{now_str} - {src_ip} ({host}) prins pe {svc} :{port}"
            f"{f' [{snippet}]' if snippet else ''} ({trapped} in capcana)"
        )[:250]

        _LOGGER.warning("LAN CANARY: %s", msg)

        await self._set_helper(
            "input_text", "set_value", {"entity_id": ENT_LAST, "value": msg}
        )
        await self._set_helper("input_number", "increment", {"entity_id": ENT_COUNT})

        self.hass.bus.async_fire(
            EVENT_HIT,
            {
                "ip": src_ip,
                "host": host,
                "port": port,
                "service": svc,
                "payload": snippet,
                "trapped": trapped,
                "message": msg,
                "notify": notify,
            },
        )

        alert = self.hass.states.get(ENT_ALERT)
        if alert is not None and alert.state != "on":
            await self._set_helper(
                "input_boolean", "turn_on", {"entity_id": ENT_ALERT}
            )

    # ---------- serverele momeala ----------

    async def start(self) -> None:
        for port in self.ports:
            if port in self.servers:
                continue
            svc_name, banner = DECOYS[port]
            handler = self._make_handler(port, svc_name, banner)
            try:
                srv = await asyncio.start_server(handler, host="0.0.0.0", port=port)
            except Exception as err:  # noqa: BLE001
                _LOGGER.error(
                    "LAN Canary: nu pot deschide portul %d (%s): %s", port, svc_name, err
                )
                continue
            self.servers[port] = srv
            _LOGGER.info("LAN Canary: capcana activa pe 0.0.0.0:%d (%s)", port, svc_name)

    def _make_handler(self, port: int, svc: str, banner: bytes | None):
        async def _handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            peer = writer.get_extra_info("peername")
            src_ip = peer[0] if peer else "unknown"
            payload = b""
            trapped = False
            try:
                if banner is not None:
                    writer.write(banner)
                    await writer.drain()
                try:
                    payload = await asyncio.wait_for(reader.read(512), timeout=1.2)
                except asyncio.TimeoutError:
                    payload = b""

                if b"CANARY_HEALTHCHECK" in payload:
                    writer.write(b"CANARY_TARPIT_OK\n")
                    await writer.drain()
                    return

                if src_ip in self.ignore_ips:
                    _LOGGER.debug(
                        "LAN Canary: ignor %s (lista alba) pe :%d", src_ip, port
                    )
                    return

                if len(self.writers) >= self.max_sockets:
                    _LOGGER.warning(
                        "LAN Canary: plafon de %d socketuri atins, inchid conexiunea de la %s",
                        self.max_sockets,
                        src_ip,
                    )
                    await self.record_hit(src_ip, svc, port, payload, len(self.writers))
                    return

                self.writers.add(writer)
                trapped = True

                # Notificarea pleaca inainte de bucla de picurare
                self.hass.async_create_task(
                    self.record_hit(src_ip, svc, port, payload, len(self.writers))
                )

                if port == 8088:
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Server: nginx (Synology DSM 7.2)\r\n"
                        b"Cache-Control: no-cache, no-store\r\n"
                    )
                    await writer.drain()

                steps = int(self.tarpit_seconds // DRIP_INTERVAL_SEC)
                for step in range(steps):
                    await asyncio.sleep(DRIP_INTERVAL_SEC)
                    if writer.is_closing():
                        break
                    if port == 2121:
                        drip = f"220-DiskStation RAID check {step + 1}%...\r\n".encode()
                    elif port == 2222:
                        drip = f"Synology-DSM-KeyCheck-{step + 1}: wait\r\n".encode()
                    elif port == 8088:
                        drip = f"X-Synology-Auth-Wait-{step + 1}: {step * 10}\r\n".encode()
                    else:
                        drip = b"\x00"
                    writer.write(drip)
                    await writer.drain()
            except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("LAN Canary: conexiune incheiata (%s): %s", src_ip, err)
            finally:
                if trapped:
                    self.writers.discard(writer)
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass

        return _handle

    async def release(self) -> int:
        """Taie toate socketurile prinse. Returneaza cate au fost."""
        released = len(self.writers)
        for w in list(self.writers):
            try:
                w.close()
            except Exception:  # noqa: BLE001
                pass
        self.writers.clear()
        self.clear_cooldowns()
        return released


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Porneste componenta."""
    conf = config.get(DOMAIN) or {}
    conf = CONFIG_SCHEMA({DOMAIN: conf})[DOMAIN]

    runtime = CanaryRuntime(hass, conf)
    hass.data[DOMAIN] = runtime
    await runtime.start()

    async def handle_start(call: ServiceCall) -> None:
        await runtime.start()

    async def handle_reset(call: ServiceCall) -> None:
        released = await runtime.release()
        now_str = dt_util.now().strftime("%d.%m %H:%M")
        if hass.states.get(ENT_ALERT) is not None:
            await hass.services.async_call(
                "input_boolean", "turn_off", {"entity_id": ENT_ALERT}, blocking=True
            )
        if hass.states.get(ENT_LAST) is not None:
            await hass.services.async_call(
                "input_text",
                "set_value",
                {
                    "entity_id": ENT_LAST,
                    "value": (
                        f"Armat, capcana pregatita - rearmat {now_str} "
                        f"({released} socketuri eliberate)"
                    ),
                },
                blocking=True,
            )
        _LOGGER.info("LAN Canary: rearmat, %d socketuri eliberate", released)

    hass.services.async_register(DOMAIN, "start_canary", handle_start)
    hass.services.async_register(DOMAIN, "reset_canary", handle_reset)

    async def _stop(event) -> None:
        for srv in runtime.servers.values():
            srv.close()
        await runtime.release()

    hass.bus.async_listen_once("homeassistant_stop", _stop)
    return True
