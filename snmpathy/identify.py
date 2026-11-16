"""Ask a device who made it and what model it is, without SNMP.

Two quick probes that most home and small-office gear answers out of the box:

* **Ubiquiti discovery** (UDP 10001): UniFi access points and switches, airMAX radios and
  EdgeRouters reply with their model ("U6-Lite"), firmware, hostname and MAC.
* **UPnP / SSDP** (UDP 1900): routers, TVs, speakers, printers, NAS boxes and media players
  answer an M-SEARCH with the address of an XML description naming their manufacturer and
  model ("NETGEAR", "Nighthawk R7000").

Both are unicast to one address, so they work across routers and from remote collectors.
``identify(ip)`` runs them together and returns what it learned (empty fields if nothing).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import struct
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Any
from xml.etree import ElementTree

log = logging.getLogger(__name__)

UBNT_PORT = 10001
SSDP_PORT = 1900
MAX_DESCRIPTION = 64 * 1024


@dataclass
class Identity:
    vendor: str = ""
    model: str = ""
    firmware: str = ""
    name: str = ""
    source: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- UDP helper
class _Collector(asyncio.DatagramProtocol):
    def __init__(self, host: str):
        self.host = host
        self.replies: asyncio.Queue[bytes] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr) -> None:
        if addr and addr[0] == self.host:
            self.replies.put_nowait(data)

    def error_received(self, exc: Exception) -> None:  # e.g. ICMP port unreachable
        pass


async def _udp_exchange(host: str, port: int, payload: bytes, timeout: float, many: bool = False) -> list[bytes]:
    """Send one datagram and collect the replies from ``host`` for up to ``timeout`` seconds."""
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    transport, proto = await loop.create_datagram_endpoint(lambda: _Collector(host), family=family,
                                                           local_addr=("::" if family == socket.AF_INET6 else "0.0.0.0", 0))
    out: list[bytes] = []
    try:
        transport.sendto(payload, (host, port))
        deadline = loop.time() + timeout
        while True:
            left = deadline - loop.time()
            if left <= 0:
                break
            try:
                out.append(await asyncio.wait_for(proto.replies.get(), left))
            except asyncio.TimeoutError:
                break
            if not many:
                break
    finally:
        transport.close()
    return out


# --------------------------------------------------------------------------- Ubiquiti
UBNT_REQUEST = b"\x01\x00\x00\x00"


def parse_ubnt(data: bytes) -> Identity | None:
    """A Ubiquiti discovery reply (v1 or v2): header, then type / 16-bit length / value fields."""
    if len(data) < 4 or data[0] not in (1, 2):
        return None
    fields: dict[int, bytes] = {}
    pos = 4
    while pos + 3 <= len(data):
        kind = data[pos]
        (length,) = struct.unpack(">H", data[pos + 1:pos + 3])
        value = data[pos + 3:pos + 3 + length]
        if len(value) < length:
            break
        fields.setdefault(kind, value)
        pos += 3 + length
    if not fields:
        return None

    def text(kind: int) -> str:
        raw = fields.get(kind, b"")
        return raw.decode("utf-8", errors="replace").strip("\x00 ").strip() if raw else ""

    model = text(0x14) or text(0x15) or text(0x0C)
    firmware = text(0x03)
    if not (model or firmware or text(0x0B)):
        return None
    return Identity(vendor="Ubiquiti", model=model[:80], firmware=firmware[:120], name=text(0x0B)[:120],
                    source="ubiquiti")


async def ubiquiti(host: str, timeout: float = 1.5, port: int = UBNT_PORT) -> Identity | None:
    try:
        replies = await _udp_exchange(host, port, UBNT_REQUEST, timeout)
    except OSError as exc:
        log.debug("Ubiquiti discovery of %s failed: %s", host, exc)
        return None
    for reply in replies:
        found = parse_ubnt(reply)
        if found:
            return found
    return None


# --------------------------------------------------------------------------- UPnP
def msearch(host: str) -> bytes:
    return ("M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {host}:{SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            "ST: upnp:rootdevice\r\n"
            "\r\n").encode()


def ssdp_location(reply: bytes) -> str:
    match = re.search(rb"^location:\s*(\S+)", reply, re.I | re.M)
    return match.group(1).decode("latin-1") if match else ""


def location_allowed(url: str, host: str) -> bool:
    """Only fetch a description from the device itself, over http(s)."""
    try:
        parts = urllib.parse.urlsplit(url)
        return parts.scheme in ("http", "https") and parts.hostname is not None and \
            ipaddress.ip_address(parts.hostname) == ipaddress.ip_address(host)
    except ValueError:
        return False


def parse_description(xml: bytes | str) -> Identity | None:
    """UPnP device description: the root device's manufacturer, model and friendly name."""
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return None
    device = next((el for el in root.iter() if el.tag.split("}")[-1] == "device"), None)
    if device is None:
        return None
    values: dict[str, str] = {}
    for child in device:
        key = child.tag.split("}")[-1]
        if child.text and key not in values:
            values[key] = " ".join(child.text.split())
    model = values.get("modelName", "")
    number = values.get("modelNumber", "")
    if number and number.lower() not in model.lower():
        model = f"{model} {number}".strip()
    found = Identity(vendor=values.get("manufacturer", "")[:120], model=model[:80],
                     name=values.get("friendlyName", "")[:120], source="upnp")
    return found if (found.vendor or found.model) else None


async def _fetch(url: str, timeout: float) -> bytes:
    import httpx

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
        async with client.stream("GET", url, headers={"User-Agent": "SNMPathy UPnP/1.0"}) as resp:
            if resp.status_code != 200:
                return b""
            body = b""
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > MAX_DESCRIPTION:
                    return b""
            return body


async def upnp(host: str, timeout: float = 1.5, port: int = SSDP_PORT) -> Identity | None:
    try:
        replies = await _udp_exchange(host, port, msearch(host), timeout, many=True)
    except OSError as exc:
        log.debug("SSDP query of %s failed: %s", host, exc)
        return None
    seen = set()
    for reply in replies:
        url = ssdp_location(reply)
        if not url or url in seen or not location_allowed(url, host):
            continue
        seen.add(url)
        try:
            body = await _fetch(url, max(timeout, 3.0))
        except Exception as exc:  # a broken web server on the device
            log.debug("UPnP description %s failed: %s", url, exc)
            continue
        found = parse_description(body) if body else None
        if found:
            return found
    return None


# --------------------------------------------------------------------------- both
async def identify(host: str, timeout: float = 1.5) -> Identity:
    """Ubiquiti discovery and UPnP together; Ubiquiti's answer wins when both reply."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return Identity()
    results = await asyncio.gather(ubiquiti(host, timeout), upnp(host, timeout), return_exceptions=True)
    ubnt, up = (r if isinstance(r, Identity) else None for r in results)
    out = Identity()
    for found in (ubnt, up):
        if not found:
            continue
        out.vendor = out.vendor or found.vendor
        out.model = out.model or found.model
        out.firmware = out.firmware or found.firmware
        out.name = out.name or found.name
        out.source = out.source or found.source
    return out
