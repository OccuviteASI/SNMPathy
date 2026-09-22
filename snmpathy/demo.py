"""Demo mode: simulated SNMP agents, availability checks and syslog traffic.

``snmpathy demo`` creates a handful of fake devices (hostnames ending in
``.demo``), back-fills a few days of history through the real poller,
check state machine and syslog storage code paths, and then keeps
generating live data. Real devices can be added alongside the demo ones.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import random
import socket
import time
from typing import Any, Callable

from .checks.probes import ProbeResult
from .checks.runner import record_result, run_probe
from .config import Settings
from .db import Database
from .monitor import default_snmp_factory
from .services import create_check, create_device
from .snmp import mibs
from .snmp.client import FakeSnmpClient, SnmpClient, SnmpError, normalize_oid
from .snmp.discovery import apply_discovery, discover
from .snmp.poller import poll_device
from .storage import rollup
from .syslog.parser import parse
from .syslog.server import message_row, store_messages

log = logging.getLogger(__name__)

GBIT = 1_000_000_000

DEMO_DEVICES: list[dict[str, Any]] = [
    {"name": "core-sw01", "vendor_oid": "1.3.6.1.4.1.9.1.2494", "descr": "Cisco IOS Software, Catalyst 9300 Software (CAT9K_IOSXE), Version 17.9.4",
     "ports": 24, "uplinks": 4, "speed": GBIT, "uplink_speed": 10 * GBIT, "cpus": 2, "load": 18,
     "location": "HQ / MDF rack A1", "tags": ["core", "hq"]},
    {"name": "dist-sw02", "vendor_oid": "1.3.6.1.4.1.30065.1.3011.7048", "descr": "Arista Networks EOS version 4.31.2F running on an Arista DCS-7050SX3-48YC8",
     "ports": 16, "uplinks": 2, "speed": 10 * GBIT, "uplink_speed": 100 * GBIT, "cpus": 4, "load": 12,
     "location": "HQ / IDF 2", "tags": ["distribution", "hq"]},
    {"name": "edge-fw01", "vendor_oid": "1.3.6.1.4.1.12356.101.1.10004", "descr": "FortiGate-100F v7.4.3,build2573",
     "ports": 6, "uplinks": 2, "speed": GBIT, "uplink_speed": GBIT, "cpus": 2, "load": 35,
     "location": "HQ / MDF rack A2", "tags": ["firewall", "hq"]},
    {"name": "linux-web01", "vendor_oid": "1.3.6.1.4.1.8072.3.2.10", "descr": "Linux web01 6.8.0-45-generic #45-Ubuntu SMP x86_64",
     "ports": 1, "uplinks": 1, "speed": 10 * GBIT, "uplink_speed": 10 * GBIT, "cpus": 8, "load": 45,
     "disks": [("/", 200), ("/var", 500)], "ucd": True, "location": "DC1 / rack 12", "tags": ["server", "dc1"]},
    {"name": "nas01", "vendor_oid": "1.3.6.1.4.1.6574.1", "descr": "Linux nas01 5.10.55+ #72806 SMP synology_r1000_ds923+",
     "ports": 2, "uplinks": 0, "speed": GBIT, "uplink_speed": GBIT, "cpus": 4, "load": 22,
     "disks": [("/volume1", 16000), ("/volume2", 8000)], "ucd": True, "location": "HQ / MDF rack A1", "tags": ["storage", "hq"]},
    {"name": "branch-rtr01", "vendor_oid": "1.3.6.1.4.1.2636.1.1.1.2.137", "descr": "Juniper Networks, Inc. srx340 internet router, kernel JUNOS 22.4R3",
     "ports": 4, "uplinks": 1, "speed": GBIT, "uplink_speed": 100_000_000, "cpus": 1, "load": 25,
     "location": "Branch office Denver", "tags": ["branch", "wan"], "flaky": True},
    {"name": "ap-lobby", "vendor_oid": "1.3.6.1.4.1.41112.1.6", "descr": "UniFi U6-Pro 6.6.55",
     "ports": 1, "uplinks": 0, "speed": GBIT, "uplink_speed": GBIT, "cpus": 1, "load": 8,
     "location": "HQ / lobby ceiling", "tags": ["wireless", "hq"]},
]

DEMO_CHECKS: list[dict[str, Any]] = [
    {"name": "Company website", "type": "http", "target": "https://www.example.demo/", "interval": 60, "public": 1,
     "options": {"expected_status": "200-299", "keyword": "Welcome"}},
    {"name": "Customer portal API", "type": "http", "target": "https://api.example.demo/health", "interval": 30, "public": 1},
    {"name": "Mail server SMTP", "type": "tcp", "target": "mail.example.demo", "port": 25, "interval": 60, "public": 1},
    {"name": "VPN gateway", "type": "tcp", "target": "vpn.example.demo", "port": 443, "interval": 60, "public": 1},
    {"name": "DNS resolution", "type": "dns", "target": "example.demo", "interval": 120},
]


# ------------------------------------------------------------------ helpers
def _h(*parts: Any) -> int:
    return int(hashlib.md5("|".join(map(str, parts)).encode()).hexdigest()[:8], 16)


def outage_at(name: str, t: float, rate: int = 180) -> bool:
    """Deterministic, rare outages: roughly one short outage per ``rate`` hours."""
    hour = int(t // 3600)
    if _h(name, hour) % rate != 0:
        return False
    minute = (t % 3600) / 60
    length = 5 + _h(name, hour, "len") % 35
    return minute < length


def _diurnal(t: float, phase: float) -> float:
    """Business-hours shaped load between ~0.15 and 1.0."""
    local = time.localtime(t)
    hour = local.tm_hour + local.tm_min / 60
    day = 0.55 - 0.45 * math.cos((hour - 2 + phase) / 24 * 2 * math.pi)
    weekend = 0.55 if local.tm_wday >= 5 else 1.0
    return max(0.12, day * weekend)


def _rate_integral(t: float, base: float, phase: float) -> float:
    """Exact integral of ``base * (0.55 + 0.4 sin(daily) + 0.08 sin(hourly))``.

    The rate never drops below ``0.07 * base`` so the counter is strictly
    increasing and the poller sees realistic, smoothly varying traffic.
    """
    day = 2 * math.pi / 86400
    hour = 2 * math.pi / 3600
    utcoff = -time.timezone if not time.localtime(t).tm_isdst else -time.altzone
    # Peak traffic at ~14:00 local time (+/- a per-port phase shift).
    phi = day * (utcoff - (14 + phase) * 3600) + math.pi / 2
    return base * (0.55 * t - 0.4 / day * math.cos(day * t + phi) - 0.08 / hour * math.cos(hour * t + phase))


class DemoAgent(FakeSnmpClient):
    """Simulated SNMP agent whose values evolve with (possibly simulated) time."""

    def __init__(self, spec: dict[str, Any], clock: Callable[[], float] = time.time):
        super().__init__({})
        self.spec = spec
        self.clock = clock
        self.boot = 1_700_000_000 + _h(spec["name"]) % 5_000_000
        self._build_static()

    def _build_static(self) -> None:
        s = self.spec
        d: dict[str, Any] = {
            mibs.SYS_DESCR: s["descr"],
            mibs.SYS_OBJECT_ID: s["vendor_oid"],
            mibs.SYS_NAME: s["name"],
            mibs.SYS_LOCATION: s.get("location", ""),
            mibs.SYS_CONTACT: "noc@example.demo",
        }
        self.ifaces = []
        total = s["ports"] + s["uplinks"]
        for i in range(1, total + 1):
            uplink = i > s["ports"]
            if s["name"].startswith("linux") or s["name"].startswith("nas"):
                name = f"eth{i - 1}"
            elif s["vendor_oid"].startswith("1.3.6.1.4.1.9."):
                name = f"Te1/1/{i - s['ports']}" if uplink else f"Gi1/0/{i}"
            elif s["vendor_oid"].startswith("1.3.6.1.4.1.2636."):
                name = f"ge-0/0/{i - 1}"
            else:
                name = f"port{i}"
            speed = s["uplink_speed"] if uplink else s["speed"]
            connected = uplink or _h(s["name"], i) % 10 < 7
            self.ifaces.append({"idx": i, "name": name, "speed": speed, "uplink": uplink, "connected": connected,
                                "alias": ("Uplink to core" if uplink else (f"User port {i}" if connected else ""))})
            d[f"{mibs.IF_DESCR}.{i}"] = name
            d[f"{mibs.IF_NAME}.{i}"] = name
            d[f"{mibs.IF_ALIAS}.{i}"] = self.ifaces[-1]["alias"]
            d[f"{mibs.IF_TYPE}.{i}"] = 6
            d[f"{mibs.IF_MTU}.{i}"] = 1500 if not uplink else 9216
            d[f"{mibs.IF_SPEED}.{i}"] = min(speed, 4_294_967_295)
            d[f"{mibs.IF_HIGH_SPEED}.{i}"] = int(speed / 1_000_000)
            d[f"{mibs.IF_PHYS_ADDRESS}.{i}"] = bytes([0x00, 0x1B, 0x54, _h(s["name"]) % 256, i // 256, i % 256])
            d[f"{mibs.IF_ADMIN_STATUS}.{i}"] = 1
            d[f"{mibs.IF_LAST_CHANGE}.{i}"] = 0
        for c in range(1, s["cpus"] + 1):
            d[f"{mibs.HR_PROCESSOR_LOAD}.{196607 + c}"] = 0
        storage_idx = 1
        d[f"{mibs.HR_STORAGE_TYPE}.{storage_idx}"] = mibs.HR_STORAGE_RAM
        d[f"{mibs.HR_STORAGE_DESCR}.{storage_idx}"] = "Physical memory"
        d[f"{mibs.HR_STORAGE_ALLOC}.{storage_idx}"] = 1024
        d[f"{mibs.HR_STORAGE_SIZE}.{storage_idx}"] = 16 * 1024 * 1024
        self.disks = []
        for n, (mount, gb) in enumerate(s.get("disks", []), start=31):
            d[f"{mibs.HR_STORAGE_TYPE}.{n}"] = mibs.HR_STORAGE_FIXED_DISK
            d[f"{mibs.HR_STORAGE_DESCR}.{n}"] = mount
            d[f"{mibs.HR_STORAGE_ALLOC}.{n}"] = 4096
            d[f"{mibs.HR_STORAGE_SIZE}.{n}"] = gb * 1024 * 1024 * 1024 // 4096
            self.disks.append((n, gb))
        if s.get("ucd"):
            d[mibs.UCD_MEM_TOTAL_REAL] = 16 * 1024 * 1024
        self.static = {normalize_oid(k): v for k, v in d.items()}

    def _value(self, oid: str, t: float) -> Any:
        s = self.spec
        name = s["name"]
        if oid in self.static and not oid.startswith(mibs.HR_PROCESSOR_LOAD):
            return self.static[oid]
        if oid == mibs.SYS_UPTIME:
            return int((t - self.boot) * 100) % (2**32)
        for base, direction in ((mibs.IF_HC_IN_OCTETS, "in"), (mibs.IF_HC_OUT_OCTETS, "out"),
                                (mibs.IF_IN_OCTETS, "in32"), (mibs.IF_OUT_OCTETS, "out32")):
            if oid.startswith(base + "."):
                i = int(oid.rsplit(".", 1)[1])
                iface = self.ifaces[i - 1] if 0 < i <= len(self.ifaces) else None
                if not iface or not iface["connected"]:
                    return 0
                share = (0.35 if iface["uplink"] else 0.04 + (_h(name, i) % 20) / 100)
                base_bps = iface["speed"] * share * (1.3 if direction.startswith("in") else 0.7)
                octets = _rate_integral(t, base_bps / 8, (_h(name, i) % 6) - 3)
                if direction.endswith("32"):
                    return int(octets) % (2**32)
                return int(octets)
        for base, per_sec in ((mibs.IF_IN_ERRORS, 0.02), (mibs.IF_OUT_ERRORS, 0.005),
                              (mibs.IF_IN_DISCARDS, 0.05), (mibs.IF_OUT_DISCARDS, 0.08)):
            if oid.startswith(base + "."):
                i = int(oid.rsplit(".", 1)[1])
                noisy = _h(name, i, "err") % 17 == 0
                return int((t - self.boot) * per_sec * (40 if noisy else 1)) % (2**32)
        if oid.startswith(mibs.IF_OPER_STATUS + "."):
            i = int(oid.rsplit(".", 1)[1])
            iface = self.ifaces[i - 1] if 0 < i <= len(self.ifaces) else None
            if not iface:
                return None
            if iface["connected"] and not iface["uplink"] and outage_at(f"{name}/{i}", t, rate=90):
                return 2
            return 1 if iface["connected"] else 2
        if oid.startswith(mibs.HR_PROCESSOR_LOAD + "."):
            core = int(oid.rsplit(".", 1)[1])
            jitter = (_h(name, core, int(t // 60)) % 1000) / 1000
            return int(min(100, s["load"] * (0.5 + _diurnal(t, core)) + jitter * 15))
        if oid == f"{mibs.HR_STORAGE_USED}.1":
            size = 16 * 1024 * 1024
            return int(size * (0.55 + 0.2 * _diurnal(t, 1)))
        for n, gb in self.disks:
            if oid == f"{mibs.HR_STORAGE_USED}.{n}":
                blocks = gb * 1024 * 1024 * 1024 // 4096
                # Slowly filling disks that get cleaned up every 60 days.
                fill = 0.45 + (_h(name, n) % 40) / 100 + ((t - self.boot) / 86400 % 60) * 0.002
                return int(blocks * min(0.97, fill))
        if s.get("ucd"):
            if oid == mibs.UCD_MEM_AVAIL_REAL:
                return int(16 * 1024 * 1024 * (0.6 - 0.35 * _diurnal(t, 2)))
            if oid in (mibs.UCD_LOAD_1, mibs.UCD_LOAD_5, mibs.UCD_LOAD_15):
                return f"{s['cpus'] * s['load'] / 100 * (0.4 + _diurnal(t, 0)):.2f}"
        return self.static.get(oid)

    def _check(self) -> None:
        if self.spec.get("flaky") and outage_at(self.spec["name"], self.clock(), rate=60):
            raise SnmpError("No SNMP response received before timeout")

    async def get(self, oids: list[str]) -> dict[str, Any]:
        self._check()
        t = self.clock()
        if self.clock is time.time:  # simulate network latency only for live polls
            await asyncio.sleep(0.005 + (_h(self.spec["name"], int(t)) % 30) / 1000)
        return {normalize_oid(o): self._value(normalize_oid(o), t) for o in oids}

    async def walk(self, oid: str) -> dict[str, Any]:
        self._check()
        t = self.clock()
        prefix = normalize_oid(oid) + "."
        keys = [k for k in self.static if k.startswith(prefix)]
        if normalize_oid(oid) in (mibs.HR_PROCESSOR_LOAD, "1.3.6.1.2.1.25.2.3.1", mibs.IF_OPER_STATUS,
                                  mibs.IF_HC_IN_OCTETS):
            extra = []
            if normalize_oid(oid) == mibs.IF_OPER_STATUS or normalize_oid(oid) == mibs.IF_HC_IN_OCTETS:
                extra = [f"{normalize_oid(oid)}.{i['idx']}" for i in self.ifaces]
            elif normalize_oid(oid) == "1.3.6.1.2.1.25.2.3.1":
                extra = [f"{mibs.HR_STORAGE_USED}.1"] + [f"{mibs.HR_STORAGE_USED}.{n}" for n, _ in self.disks]
            keys = sorted(set(keys + extra))
        from .snmp.client import oid_sort_key

        return {k: self._value(k, t) for k in sorted(keys, key=oid_sort_key)}


_AGENTS: dict[str, dict[str, Any]] = {f"{d['name']}.demo": d for d in DEMO_DEVICES}


def demo_snmp_factory(device: dict[str, Any], settings: Settings) -> SnmpClient:
    spec = _AGENTS.get(device["hostname"])
    if spec is None:
        return default_snmp_factory(device, settings)
    return DemoAgent(spec)


def _demo_probe_result(check: dict[str, Any], t: float) -> ProbeResult:
    name = check["target"]
    spec = next((d for d in DEMO_DEVICES if f"{d['name']}.demo" == name), None)
    rate = 60 if spec and spec.get("flaky") else (240 if check["type"] == "http" else 400)
    if outage_at(name, t, rate=rate):
        msg = {"http": "HTTP 503 (expected 200-399)", "tcp": f"tcp/{check.get('port')} timeout after 5.0s",
               "dns": "Name or service not known"}.get(check["type"], "timeout after 2.0s")
        return ProbeResult(False, None, msg)
    base = {"icmp": 0.8, "tcp": 12, "http": 140, "dns": 9}.get(check["type"], 5)
    if spec and spec.get("flaky"):
        base = 38
    jitter = (_h(name, int(t // 30)) % 1000) / 1000
    latency = base * (0.8 + 0.6 * jitter) * (1 + 0.4 * _diurnal(t, 0))
    msg = {"icmp": "echo reply", "tcp": f"tcp/{check.get('port')} open", "http": "HTTP 200",
           "dns": "93.184.216.34"}.get(check["type"], "ok")
    return ProbeResult(True, latency, msg)


async def demo_probe(check: dict[str, Any], device: dict[str, Any] | None = None) -> ProbeResult:
    if not str(check["target"]).split("/")[2 if "://" in check["target"] else 0].split(":")[0].endswith(".demo"):
        return await run_probe(check, device)
    await asyncio.sleep(0.01)
    return _demo_probe_result(check, time.time())


# ----------------------------------------------------------------- syslog
SYSLOG_TEMPLATES: dict[str, list[tuple[int, int, str, str]]] = {
    # (facility, severity, app, message)
    "cisco": [
        (23, 5, "%SYS-5-CONFIG_I", "Configured from console by admin on vty0 (10.0.10.25)"),
        (23, 3, "%LINK-3-UPDOWN", "Interface {iface}, changed state to down"),
        (23, 3, "%LINK-3-UPDOWN", "Interface {iface}, changed state to up"),
        (23, 5, "%LINEPROTO-5-UPDOWN", "Line protocol on Interface {iface}, changed state to up"),
        (23, 4, "%SW_MATM-4-MACFLAP_NOTIF", "Host 001b.54a2.33f1 in vlan 20 is flapping between port {iface} and port Te1/1/1"),
        (23, 6, "%SEC_LOGIN-5-LOGIN_SUCCESS", "Login Success [user: netops] [Source: 10.0.10.25] [localport: 22]"),
        (23, 4, "%SEC_LOGIN-4-LOGIN_FAILED", "Login failed [user: admin] [Source: 185.220.101.4] [localport: 22] [Reason: Login Authentication Failed]"),
    ],
    "fortinet": [
        (16, 6, "fortigate", 'type="traffic" subtype="forward" action="accept" srcip=10.0.20.{n} dstip=142.250.72.{n} dstport=443 proto=6 service="HTTPS"'),
        (16, 4, "fortigate", 'type="traffic" subtype="forward" action="deny" srcip=45.155.205.{n} dstip=203.0.113.10 dstport=3389 proto=6 policyid=0'),
        (16, 2, "fortigate", 'type="event" subtype="system" level="critical" msg="Power supply 2 failure"'),
        (16, 5, "fortigate", 'type="event" subtype="vpn" action="tunnel-up" remip=198.51.100.7 tunnelid=1044'),
        (16, 1, "fortigate", 'type="utm" subtype="ips" level="alert" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" srcip=45.155.205.{n}'),
    ],
    "linux": [
        (4, 6, "sshd", "Accepted publickey for deploy from 10.0.10.{n} port 5{n}22 ssh2: ED25519 SHA256:q8x"),
        (10, 5, "sshd", "Failed password for invalid user oracle from 185.220.101.{n} port 4{n}11 ssh2"),
        (3, 6, "systemd", "Started Daily apt download activities."),
        (3, 6, "nginx", '10.0.20.{n} - - "GET /api/v1/orders HTTP/1.1" 200 5123 "-" "Mozilla/5.0"'),
        (3, 3, "nginx", "upstream timed out (110: Connection timed out) while reading response header from upstream"),
        (0, 4, "kernel", "TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies."),
        (9, 6, "CRON", "(root) CMD (/usr/local/bin/backup.sh >/dev/null 2>&1)"),
        (0, 2, "kernel", "EXT4-fs error (device sdb1): ext4_find_entry:1455: inode #2: comm rsync: reading directory lblock 0"),
    ],
    "juniper": [
        (23, 4, "rpd", "BGP_IO_ERROR_CLOSE_SESSION: BGP peer 198.51.100.1 (External AS 64500): Error event Operation timed out(60) for I/O session"),
        (23, 5, "mgd", "UI_COMMIT: User 'netops' requested 'commit' operation (comment: none)"),
        (23, 3, "kernel", "SNMP_TRAP_LINK_DOWN: ifIndex 518, ifAdminStatus up(1), ifOperStatus down(2), ifName ge-0/0/1"),
    ],
    "generic": [
        (1, 6, "hostapd", "wlan0: STA 3c:22:fb:{n:02x}:10:aa IEEE 802.11: associated"),
        (1, 6, "hostapd", "wlan0: STA 3c:22:fb:{n:02x}:10:aa IEEE 802.11: disassociated"),
        (1, 4, "mcad", "Radio ra0 channel utilisation 87% exceeds threshold"),
    ],
}


def _family(spec: dict[str, Any]) -> str:
    oid = spec["vendor_oid"]
    if ".9." in oid:
        return "cisco"
    if ".12356." in oid:
        return "fortinet"
    if ".2636." in oid:
        return "juniper"
    if ".8072." in oid or ".6574." in oid:
        return "linux"
    return "generic"


def make_syslog(spec: dict[str, Any], t: float, rng: random.Random) -> bytes:
    facility, severity, app, text = rng.choice(SYSLOG_TEMPLATES[_family(spec)])
    iface = f"GigabitEthernet1/0/{rng.randint(1, spec['ports'])}"
    text = text.format(iface=iface, n=rng.randint(2, 250))
    lt = time.localtime(t)
    month = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()[lt.tm_mon - 1]
    stamp = f"{month} {lt.tm_mday:>2} {lt.tm_hour:02d}:{lt.tm_min:02d}:{lt.tm_sec:02d}"
    pri = facility * 8 + severity
    if app.startswith("%"):
        return f"<{pri}>{rng.randint(1000, 99999)}: {spec['name']}: {stamp}: {app}: {text}".encode()
    pid = f"[{rng.randint(300, 40000)}]" if app not in {"fortigate", "kernel"} else ""
    return f"<{pri}>{stamp} {spec['name']} {app}{pid}: {text}".encode()


async def demo_syslog_sender(settings: Settings, interval: float = 6.0) -> None:
    """Continuously send simulated syslog to our own UDP listener."""
    await asyncio.sleep(3)
    port = settings.syslog_udp_port
    if not port:
        return
    rng = random.Random()
    host = "127.0.0.1" if settings.syslog_host in ("0.0.0.0", "", "::") else settings.syslog_host
    sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while True:
            for _ in range(rng.randint(0, 2)):
                spec = rng.choice(DEMO_DEVICES)
                try:
                    sock.sendto(make_syslog(spec, time.time(), rng), (host, port))
                except OSError:
                    pass
            await asyncio.sleep(interval)
    finally:
        sock.close()


# --------------------------------------------------------------- back-fill
async def populate_demo(db: Database, settings: Settings, days: int = 7) -> None:
    if db.get_meta("demo_populated"):
        return
    started = time.time()
    log.info("generating %s days of demo history (this takes a few seconds)...", days)
    await _populate(db, days)
    db.set_meta("demo_populated", str(time.time()))
    log.info("demo data ready in %.1fs", time.time() - started)


async def _populate(db: Database, days: int) -> None:
    now = time.time()
    start = now - days * 86400
    step = 300 if days <= 2 else 900
    rng = random.Random(42)

    devices = []
    for spec in DEMO_DEVICES:
        if db.one("SELECT 1 FROM devices WHERE name = ?", (spec["name"],)):
            continue
        device = create_device(db, {
            "name": spec["name"], "hostname": f"{spec['name']}.demo", "snmp_community": "public",
            "poll_interval": 60, "location": spec["location"], "tags": spec["tags"],
        })
        db.execute("UPDATE devices SET created_at = ?, updated_at = ? WHERE id = ?", (start, start, device["id"]))
        devices.append((spec, device))
    for c in DEMO_CHECKS:
        create_check(db, c)
    db.execute("UPDATE checks SET created_at = ?", (start,))

    clock = {"t": start}
    for spec, device in devices:
        agent = DemoAgent(spec, clock=lambda: clock["t"])
        clock["t"] = start
        apply_discovery(db, device["id"], await discover(agent), now=start)
        t = start
        # One transaction per device: thousands of small commits are slow on some disks.
        with db.transaction():
            while t < now - 60:
                clock["t"] = t
                row = db.one("SELECT * FROM devices WHERE id = ?", (device["id"],))
                await poll_device(db, agent, row, now=t)
                t += step
        db.execute("UPDATE devices SET last_discovered = ? WHERE id = ?", (now, device["id"]))

    hb_step = 300
    for check in db.query("SELECT * FROM checks"):
        t = start
        current = check
        with db.transaction():
            while t < now - 30:
                current = record_result(db, current, _demo_probe_result(current, t), now=t)
                # Probe faster around failures so outages get realistic start/end times.
                t += 60 if current.get("fail_count") or current.get("transition") else hb_step

    rows = []
    t = start
    while t < now:
        spec = rng.choice(DEMO_DEVICES)
        msg = parse(make_syslog(spec, t, rng), source_ip=f"10.0.0.{DEMO_DEVICES.index(spec) + 10}", received_at=t)
        rows.append(message_row(msg, {}))
        t += rng.expovariate(1 / 45) * (2.2 - _diurnal(t, 0))
    store_messages(db, rows)
    db.execute(
        "UPDATE syslog SET device_id = (SELECT id FROM devices WHERE devices.name = syslog.host) WHERE device_id IS NULL"
    )
    rollup(db, now)
