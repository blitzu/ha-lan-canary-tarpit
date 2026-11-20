"""Home Assistant LAN Canary Honeypot & Active TCP Tarpit."""
import asyncio
import logging
import socket
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.util import dt as dt_util

_LOGGER = logging.getLogger(__name__)

DOMAIN = "lan_canary"

# Protocol-specific initial tarpit banners:
# - FTP (2121): "220-" with hyphen (RFC 959 multi-line greeting) forces FTP scanners to wait for "220 " forever
# - SSH (2222): RFC 4253 sec 4.2 allows unlimited pre-identification lines before "SSH-2.0-" (Endlessh style)
# - Telnet (2323): Fake Synology DiskStation login prompt + slow byte drip
# - MySQL (3306): Partial MariaDB handshake header + slow byte drip
# - VNC (5900): RFB 003.008 handshake + slow byte drip
# - Synology-DSM-HTTP (8088): Reverse Slowloris HTTP header drip (never sends final \r\n\r\n)
CANARY_DECOYS = {
    2121: ("FTP", b"220-DiskStation FTP server (Synology DSM 7.2) initializing...\r\n"),
    2222: ("SSH", b"Synology-DSM-7.2-Security-Banner: verifying host key...\r\n"),
    2323: ("Telnet", b"\r\nDiskStation-NAS login: "),
    3306: ("MySQL", b"\x4a\x00\x00\x00\x0a5.5.68-MariaDB-Synology\x00"),
    5900: ("VNC", b"RFB 003.008\n"),
    8088: ("Synology-DSM-HTTP", None),
}

MAX_CONCURRENT_TARPITS = 64
TARPIT_DRIP_INTERVAL_SEC = 10.0
TARPIT_MAX_DURATION_SEC = 900.0  # 15 minutes per trapped scanner thread


def _resolve_host(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.replace(".lan", "").replace(".local", "")
    except Exception:
        return "Unknown-Host"


async def _record_canary_hit(
    hass: HomeAssistant,
    src_ip: str,
    svc: str,
    port: int,
    payload_raw: bytes,
    active_tarpits: int,
):
    host = await hass.async_add_executor_job(_resolve_host, src_ip)
    clean_payload = ""
    if payload_raw:
        first_line = payload_raw.decode("utf-8", errors="ignore").strip().splitlines()
        if first_line:
            snippet = "".join(ch for ch in first_line[0] if 32 <= ord(ch) < 127)[:40].strip()
            if snippet:
                clean_payload = f" [{snippet}]"

    now_str = dt_util.now().strftime("%H:%M:%S")
    event_msg = (
        f"{now_str} — {src_ip} ({host}) TARPITTED on {svc} :{port}"
        f"{clean_payload} ({active_tarpits} trapped)"
    )[:250]
    _LOGGER.warning("LAN CANARY TARPIT ENGAGED: %s", event_msg)

    try:
        await hass.services.async_call(
            "input_text",
            "set_value",
            {"entity_id": "input_text.canary_last_event", "value": event_msg},
            blocking=True,
        )
        await hass.services.async_call(
            "input_number",
            "increment",
            {"entity_id": "input_number.canary_hit_count"},
            blocking=True,
        )
        cur_alert = hass.states.get("input_boolean.canary_intrusion_alert")
        if cur_alert and cur_alert.state == "on":
            await hass.services.async_call(
                "input_boolean",
                "turn_off",
                {"entity_id": "input_boolean.canary_intrusion_alert"},
                blocking=True,
            )
        await hass.services.async_call(
            "input_boolean",
            "turn_on",
            {"entity_id": "input_boolean.canary_intrusion_alert"},
            blocking=True,
        )
    except Exception as err:
        _LOGGER.error("Failed to update LAN Canary entities: %s", err)


async def _start_canary_listeners(hass: HomeAssistant):
    servers = hass.data.setdefault(f"{DOMAIN}_servers", {})
    tarpit_writers = hass.data.setdefault(f"{DOMAIN}_tarpit_writers", set())

    for port, (svc_name, banner) in CANARY_DECOYS.items():
        if port in servers:
            continue

        async def _handle_client(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            p=port,
            svc=svc_name,
            bnr=banner,
        ):
            peer = writer.get_extra_info("peername")
            src_ip = peer[0] if peer else "unknown"
            payload_raw = b""
            try:
                if bnr is not None:
                    writer.write(bnr)
                    await writer.drain()
                    try:
                        payload_raw = await asyncio.wait_for(reader.read(256), timeout=1.2)
                    except asyncio.TimeoutError:
                        payload_raw = b""
                else:
                    try:
                        payload_raw = await asyncio.wait_for(reader.read(512), timeout=1.2)
                    except asyncio.TimeoutError:
                        payload_raw = b""

                if b"CANARY_HEALTHCHECK" in payload_raw:
                    writer.write(b"CANARY_TARPIT_OK\n")
                    await writer.drain()
                    return

                if src_ip in ("127.0.0.1", "::1"):
                    return

                tarpit_writers.add(writer)

                # Fire the push notification & dashboard update immediately before holding the socket
                hass.async_create_task(
                    _record_canary_hit(hass, src_ip, svc, p, payload_raw, len(tarpit_writers))
                )

                if p == 8088:
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Server: nginx (Synology DSM 7.2)\r\n"
                        b"Cache-Control: no-cache, no-store\r\n"
                    )
                    await writer.drain()

                # Hold scanner thread in a slow-drip TCP tarpit (1 drip every 10s for up to 15 min)
                if len(tarpit_writers) <= MAX_CONCURRENT_TARPITS:
                    steps = int(TARPIT_MAX_DURATION_SEC // TARPIT_DRIP_INTERVAL_SEC)
                    for step in range(steps):
                        await asyncio.sleep(TARPIT_DRIP_INTERVAL_SEC)
                        if writer.is_closing():
                            break
                        if p == 2121:
                            drip = f"220-DiskStation RAID check {step + 1}%...\r\n".encode("ascii")
                        elif p == 2222:
                            drip = f"Synology-DSM-KeyCheck-{step + 1}: wait\r\n".encode("ascii")
                        elif p == 8088:
                            drip = f"X-Synology-Auth-Wait-{step + 1}: {step * 10}\r\n".encode("ascii")
                        else:
                            drip = b"\x00"
                        writer.write(drip)
                        await writer.drain()
            except Exception:
                pass
            finally:
                tarpit_writers.discard(writer)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        try:
            srv = await asyncio.start_server(_handle_client, host="0.0.0.0", port=port)
            servers[port] = srv
            _LOGGER.warning("LAN Canary Active TCP Tarpit bound on 0.0.0.0:%d (%s)", port, svc_name)
        except Exception as err:
            _LOGGER.error("Could not bind LAN Canary Tarpit port %d (%s): %s", port, svc_name, err)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    await _start_canary_listeners(hass)

    async def handle_start(call: ServiceCall):
        await _start_canary_listeners(hass)

    async def handle_reset(call: ServiceCall):
        tarpit_writers = hass.data.get(f"{DOMAIN}_tarpit_writers", set())
        released = len(tarpit_writers)
        for w in list(tarpit_writers):
            try:
                w.close()
            except Exception:
                pass
        tarpit_writers.clear()

        now_str = dt_util.now().strftime("%b %d %I:%M %p")
        await hass.services.async_call(
            "input_boolean",
            "turn_off",
            {"entity_id": "input_boolean.canary_intrusion_alert"},
            blocking=True,
        )
        await hass.services.async_call(
            "input_text",
            "set_value",
            {
                "entity_id": "input_text.canary_last_event",
                "value": f"Armed & Tarpit Ready — Re-armed {now_str} (Released {released} sockets)",
            },
            blocking=True,
        )

    hass.services.async_register(DOMAIN, "start_canary", handle_start)
    hass.services.async_register(DOMAIN, "reset_canary", handle_reset)
    return True
