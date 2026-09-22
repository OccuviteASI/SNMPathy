"""Availability probes: ICMP ping, TCP connect, HTTP(S) and SNMP.

ICMP is implemented natively where the OS allows it and falls back to the
system ``ping`` binary otherwise, so it works unprivileged on:

* Linux   - raw socket as root / CAP_NET_RAW, unprivileged ICMP datagram
            socket when ``net.ipv4.ping_group_range`` allows, else ``ping``
* macOS   - unprivileged ICMP datagram socket (always allowed)
* Windows - raw socket as Administrator, else ``ping.exe``
* Docker  - raw socket (containers get CAP_NET_RAW by default)
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import re
import shutil
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any

IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"


@dataclass
class ProbeResult:
    ok: bool
    latency_ms: float | None = None
    message: str = ""


# ---------------------------------------------------------------- helpers
async def resolve(host: str, family: int = socket.AF_UNSPEC) -> tuple[int, str]:
    """Resolve ``host`` to ``(family, address)``, preferring IPv4."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return (socket.AF_INET6 if ip.version == 6 else socket.AF_INET), str(ip)
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"cannot resolve {host}")
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    fam, _, _, _, addr = infos[0]
    return fam, addr[0]


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


# ------------------------------------------------------------------- ICMP
_ICMP_MODE: str | None = None  # "raw" | "dgram" | "exec" | "tcp"


def detect_icmp_mode() -> str:
    """Work out (once) which ICMP implementation this process can use."""
    global _ICMP_MODE
    if _ICMP_MODE is not None:
        return _ICMP_MODE
    forced = os.environ.get("SNMPATHY_ICMP_MODE", "").strip().lower()
    if forced in {"raw", "dgram", "exec", "tcp"}:
        _ICMP_MODE = forced
        return forced
    if IS_WINDOWS:
        # ping.exe needs no elevation and is always present; raw sockets need Administrator
        # and behave inconsistently under the Proactor event loop.
        _ICMP_MODE = "exec" if shutil.which("ping") else "tcp"
        return _ICMP_MODE
    for mode, sock_type in (("raw", socket.SOCK_RAW), ("dgram", socket.SOCK_DGRAM)):
        try:
            s = socket.socket(socket.AF_INET, sock_type, socket.IPPROTO_ICMP)
            s.close()
            _ICMP_MODE = mode
            return mode
        except (PermissionError, OSError):
            continue
    _ICMP_MODE = "exec" if shutil.which("ping") else "tcp"
    return _ICMP_MODE


import errno as _errno

_UNREACHABLE_ERRNOS = {
    getattr(_errno, name) for name in ("EHOSTUNREACH", "ENETUNREACH", "EHOSTDOWN", "ENETDOWN")
    if hasattr(_errno, name)
}


def _set_icmp_mode(mode: str) -> None:
    global _ICMP_MODE
    _ICMP_MODE = mode


async def ping(host: str, timeout: float = 2.0, count: int = 1) -> ProbeResult:
    try:
        family, address = await resolve(host)
    except OSError as exc:
        return ProbeResult(False, None, f"DNS lookup failed: {exc}")
    mode = detect_icmp_mode()
    if family == socket.AF_INET6 and mode in {"raw", "dgram"}:
        mode = "exec" if shutil.which("ping") else "tcp"
    last = ProbeResult(False, None, "no reply")
    for _ in range(max(1, count)):
        if mode in {"raw", "dgram"}:
            try:
                last = await _ping_socket(address, timeout, raw=(mode == "raw"))
            except OSError as exc:
                if getattr(exc, "errno", None) in _UNREACHABLE_ERRNOS:
                    last = ProbeResult(False, None, f"ICMP error: {exc.strerror or exc}")
                else:
                    # The socket mode is not usable on this system after all (e.g. a
                    # sandbox or an OS quirk): switch to the ping command for good.
                    _set_icmp_mode("exec" if shutil.which("ping") else "tcp")
                    mode = _ICMP_MODE or "tcp"
                    last = await (_ping_exec(address, timeout, family) if mode == "exec" else _tcp_ping(address, timeout))
        elif mode == "exec":
            last = await _ping_exec(address, timeout, family)
        else:
            last = await _tcp_ping(address, timeout)
        if last.ok:
            return last
    return last


async def _ping_socket(address: str, timeout: float, raw: bool) -> ProbeResult:
    loop = asyncio.get_running_loop()
    sock_type = socket.SOCK_RAW if raw else socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_INET, sock_type, socket.IPPROTO_ICMP)
    sock.setblocking(False)
    ident = random.randint(0, 0xFFFF)
    seq = random.randint(0, 0xFFFF)
    payload = struct.pack("!d", time.time()) + b"snmpathy-ping".ljust(48, b".")
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    packet = struct.pack("!BBHHH", 8, 0, _checksum(header + payload), ident, seq) + payload
    try:
        # connect() on a raw/datagram socket only sets the peer, it never blocks.
        # (loop.sock_connect would try getaddrinfo, which rejects SOCK_RAW.)
        sock.connect((address, 0))
        start = time.perf_counter()
        await loop.sock_sendall(sock, packet)
        deadline = start + timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return ProbeResult(False, None, f"timeout after {timeout:.1f}s")
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 2048), remaining)
            except asyncio.TimeoutError:
                return ProbeResult(False, None, f"timeout after {timeout:.1f}s")
            elapsed = (time.perf_counter() - start) * 1000
            # Raw sockets (and macOS datagram sockets) include the IP header.
            if len(data) >= 20 and (data[0] >> 4) == 4:
                # Raw sockets see every ICMP packet for the host: only accept the target's replies.
                if raw and socket.inet_ntoa(data[12:16]) != address:
                    continue
                data = data[(data[0] & 0x0F) * 4 :]
            if len(data) < 8:
                continue
            icmp_type, _code, _csum, r_ident, r_seq = struct.unpack("!BBHHH", data[:8])
            if icmp_type == 0 and r_seq == seq and (not raw or r_ident == ident):
                return ProbeResult(True, elapsed, "echo reply")
            if icmp_type == 3:
                return ProbeResult(False, None, "destination unreachable")
            if icmp_type == 11:
                return ProbeResult(False, None, "TTL exceeded")
    finally:
        sock.close()


_RTT_RE = re.compile(r"(?:time|zeit|temps|tiempo|durata|время)[=<]\s*([\d.,]+)\s*ms", re.IGNORECASE)


def ping_command(address: str, timeout: float, family: int = socket.AF_INET, platform: str | None = None) -> list[str]:
    platform = platform or sys.platform
    exe = shutil.which("ping") or "ping"
    if platform.startswith("win"):
        cmd = [exe, "-n", "1", "-w", str(max(1, int(timeout * 1000)))]
        if family == socket.AF_INET6:
            cmd.append("-6")
        return cmd + [address]
    if platform == "darwin":
        # macOS: -W is the per-packet wait in milliseconds, -t the overall timeout in seconds.
        cmd = [exe, "-c", "1", "-W", str(max(1, int(timeout * 1000))), "-t", str(max(1, int(round(timeout + 0.5))))]
        if family == socket.AF_INET6:
            cmd = [shutil.which("ping6") or "ping6", "-c", "1"]
        return cmd + [address]
    cmd = [exe, "-c", "1", "-W", str(max(1, int(round(timeout + 0.49))))]
    if family == socket.AF_INET6:
        cmd.append("-6")
    return cmd + [address]


def parse_ping_output(output: str, returncode: int) -> ProbeResult:
    """Parse the output of the system ``ping`` on Linux, macOS or Windows."""
    match = _RTT_RE.search(output)
    # Windows returns 0 even for "Destination host unreachable"; require a TTL= in replies.
    success = returncode == 0 and (match is not None or "ttl=" in output.lower())
    if success:
        latency = None
        if match:
            try:
                latency = float(match.group(1).replace(",", "."))
            except ValueError:
                latency = None
        return ProbeResult(True, latency, "echo reply")
    lowered = output.lower()
    if "unreachable" in lowered:
        return ProbeResult(False, None, "destination unreachable")
    if "unknown host" in lowered or "could not find host" in lowered or "name or service not known" in lowered:
        return ProbeResult(False, None, "unknown host")
    return ProbeResult(False, None, "request timed out")


async def _ping_exec(address: str, timeout: float, family: int) -> ProbeResult:
    cmd = ping_command(address, timeout, family)
    kwargs: dict[str, Any] = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0)
    start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, **kwargs
        )
    except (FileNotFoundError, NotImplementedError, OSError):
        # NotImplementedError: a SelectorEventLoop on Windows cannot spawn subprocesses.
        return await _tcp_ping(address, timeout)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout + 3)
    except asyncio.TimeoutError:
        proc.kill()
        return ProbeResult(False, None, f"timeout after {timeout:.1f}s")
    result = parse_ping_output(out.decode(errors="replace"), proc.returncode or 0)
    if result.ok and result.latency_ms is None:
        result.latency_ms = (time.perf_counter() - start) * 1000
    return result


async def _tcp_ping(address: str, timeout: float) -> ProbeResult:
    """Last-resort reachability test: a TCP connect to a common port.

    A refused connection still proves the host is up.
    """
    for port in (80, 443, 22, 3389):
        result = await tcp_check(address, port, timeout, refused_is_up=True)
        if result.ok:
            result.message = f"host reachable (tcp/{port})"
            return result
    return ProbeResult(False, None, "no response (TCP fallback)")


# -------------------------------------------------------------------- TCP
async def tcp_check(host: str, port: int, timeout: float = 5.0, refused_is_up: bool = False) -> ProbeResult:
    start = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return ProbeResult(False, None, f"tcp/{port} timeout after {timeout:.1f}s")
    except ConnectionRefusedError:
        if refused_is_up:
            return ProbeResult(True, (time.perf_counter() - start) * 1000, f"tcp/{port} refused")
        return ProbeResult(False, None, f"tcp/{port} connection refused")
    except OSError as exc:
        return ProbeResult(False, None, f"tcp/{port} {exc.strerror or exc}")
    latency = (time.perf_counter() - start) * 1000
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (asyncio.TimeoutError, OSError):
        pass
    return ProbeResult(True, latency, f"tcp/{port} open")


# ------------------------------------------------------------------- HTTP
async def http_check(url: str, timeout: float = 10.0, options: dict[str, Any] | None = None) -> ProbeResult:
    import httpx

    options = options or {}
    method = str(options.get("method") or "GET").upper()
    expected = options.get("expected_status") or "200-399"
    keyword = options.get("keyword") or ""
    invert = bool(options.get("keyword_absent"))
    verify = bool(options.get("verify_tls", True))
    headers = options.get("headers") or {}
    cert_days = options.get("cert_expiry_days")
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(verify=verify, timeout=timeout, follow_redirects=bool(options.get("follow_redirects", True))) as client:
            resp = await client.request(method, url, headers=headers, content=options.get("body"))
    except httpx.TimeoutException:
        return ProbeResult(False, None, f"timeout after {timeout:.1f}s")
    except httpx.HTTPError as exc:
        return ProbeResult(False, None, f"{type(exc).__name__}: {exc}"[:300])
    latency = (time.perf_counter() - start) * 1000
    if not status_matches(resp.status_code, expected):
        return ProbeResult(False, latency, f"HTTP {resp.status_code} (expected {expected})")
    if keyword:
        found = keyword in resp.text
        if found == invert:
            what = "present" if invert else "missing"
            return ProbeResult(False, latency, f"keyword {keyword!r} {what}")
    message = f"HTTP {resp.status_code}"
    if cert_days and url.lower().startswith("https://"):
        days = await cert_days_remaining(url, timeout)
        if days is not None:
            message += f", certificate expires in {days:.0f}d"
            if days < float(cert_days):
                return ProbeResult(False, latency, message)
    return ProbeResult(True, latency, message)


def status_matches(code: int, spec: Any) -> bool:
    """``spec`` is e.g. ``200``, ``"200,204"`` or ``"200-399"``."""
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            if int(lo) <= code <= int(hi):
                return True
        elif part.endswith("xx") and part[0].isdigit():
            if code // 100 == int(part[0]):
                return True
        elif int(part) == code:
            return True
    return False


async def cert_days_remaining(url: str, timeout: float) -> float | None:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return None
    port = parts.port or 443
    ctx = ssl.create_default_context()
    try:
        _r, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    try:
        cert = writer.get_extra_info("peercert")
        if not cert or "notAfter" not in cert:
            return None
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        return (expires - time.time()) / 86400
    finally:
        writer.close()


# ------------------------------------------------------------------- SNMP
async def snmp_check(host: str, creds: Any, timeout: float = 2.0) -> ProbeResult:
    from ..snmp.client import PySnmpClient, SnmpError
    from ..snmp import mibs

    client = PySnmpClient(host, creds, timeout=timeout, retries=0)
    start = time.perf_counter()
    try:
        values = await client.get([mibs.SYS_UPTIME])
    except SnmpError as exc:
        return ProbeResult(False, None, f"SNMP: {exc}")
    finally:
        client.close()
    if values.get(mibs.SYS_UPTIME) is None:
        return ProbeResult(False, None, "SNMP: no sysUpTime")
    return ProbeResult(True, (time.perf_counter() - start) * 1000, "SNMP agent responding")
