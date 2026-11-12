"""Vendor-specific discovery: private MIB metrics for particular device families.

Each vendor contributes identity (model / serial / firmware), metrics (as
:class:`MetricSpec`) and, where the MIB has one, a wireless-peer table that
feeds the network map. Vendors are matched on sysObjectID; devices that report
a generic sysObjectID (e.g. Net-SNMP) are also probed once for a vendor
identity OID.

OIDs were taken from the vendors' MIB files and checked against real device
walks:

* **Rajant** BreadCrumb (RAJANT-CORPORATION-MIB, enterprise 34861). Scalars are
  served *without* the usual ``.0`` instance. The MIB has no per-peer table.
* **Tachyon Networks** TNA-30x radios / TNS switches (TACHYON-MIB, enterprise
  57344). Tables are indexed 1..n in practice; scalars use ``.0``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .client import SnmpClient, SnmpError, as_text, format_mac, index_of

log = logging.getLogger(__name__)

ENT = "1.3.6.1.4.1"

# ------------------------------------------------------------------ Rajant
RAJANT = f"{ENT}.34861"
RAJANT_SERIAL = f"{RAJANT}.1.1"          # no .0
RAJANT_TEMPERATURE = f"{RAJANT}.1.2"     # Integer32, hundredths of a degree C
RAJANT_FREE_MEMORY = f"{RAJANT}.1.3"     # Gauge32, KiB
RAJANT_IDLE = f"{RAJANT}.1.4"            # TimeTicks, cumulative idle (centiseconds)
RAJANT_UPTIME = f"{RAJANT}.1.5"          # TimeTicks
RAJANT_MESH = f"{RAJANT}.2"
RAJANT_MESH_COUNTERS = {                 # Counter64, packets
    "rajant.mesh.rx_pps": (9, "InstaMesh packets received"),
    "rajant.mesh.tx_pps": (10, "InstaMesh packets sent"),
    "rajant.mesh.dropped_pps": (7, "InstaMesh packets dropped"),
    "rajant.mesh.floods_dropped_pps": (6, "InstaMesh floods dropped"),
}
RAJANT_RADIOS = f"{RAJANT}.3"            # .3.{n}.1 name, .2 frequency MHz, .3 noise dBm (wlan0..wlan3)
RAJANT_GPS = f"{RAJANT}.4"               # .3 longitude, .4 latitude, .5 altitude, .7 satellites, .8 valid

# ----------------------------------------------------------------- Tachyon
TACHYON = f"{ENT}.57344"
TACHYON_MODEL = f"{TACHYON}.1.3.1.0"
TACHYON_SERIAL = f"{TACHYON}.1.3.2.0"
TACHYON_CPU_TEMP = f"{TACHYON}.1.3.3.0"  # deg C
TACHYON_FIRMWARE = f"{TACHYON}.1.3.4.0"
TACHYON_CPU = f"{TACHYON}.1.3.6.0"       # %
TACHYON_MEMORY = f"{TACHYON}.1.3.7.0"    # %
TACHYON_PEER_COUNT = f"{TACHYON}.1.2.5.0"
TACHYON_RADIO_TABLE = f"{TACHYON}.1.2.2.1"   # .2 name .3 tx power dBm .5 freq MHz .6 width MHz .10 modem temp .11 radio temp
TACHYON_PEER_TABLE = f"{TACHYON}.1.2.6.1"


@dataclass
class VendorResult:
    vendor: str = ""
    system: dict[str, Any] = field(default_factory=dict)   # hw_model / hw_serial / firmware
    metrics: list[Any] = field(default_factory=list)        # MetricSpec
    neighbors: list[dict[str, Any]] = field(default_factory=list)


async def _get(client: SnmpClient, oids: list[str]) -> dict[str, Any]:
    try:
        return await client.get(oids)
    except SnmpError:
        return {}


async def _walk(client: SnmpClient, oid: str) -> dict[str, Any]:
    try:
        return await client.walk(oid)
    except SnmpError:
        return {}


def _col(table: dict[str, Any], base: str, column: int) -> dict[str, Any]:
    prefix = f"{base}.{column}"
    return {index_of(oid, prefix): v for oid, v in table.items() if oid.startswith(prefix + ".")}


def _num(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def vendor_of(sys_object_id: str) -> str:
    oid = (sys_object_id or "").lstrip(".")
    if oid == RAJANT or oid.startswith(RAJANT + "."):
        return "rajant"
    if oid == TACHYON or oid.startswith(TACHYON + "."):
        return "tachyon"
    return ""


async def detect(client: SnmpClient, sys_object_id: str, sys_descr: str = "") -> str:
    vendor = vendor_of(sys_object_id)
    if vendor:
        return vendor
    oid = (sys_object_id or "").lstrip(".")
    generic = not oid or oid.startswith(("1.3.6.1.4.1.8072.", "1.3.6.1.4.1.2021.")) or oid == "0.0"
    if not generic and "rajant" not in (sys_descr or "").lower():
        return ""
    # Some firmware reports a generic (e.g. Net-SNMP) sysObjectID: probe the identity OIDs once.
    values = await _get(client, [RAJANT_SERIAL, TACHYON_MODEL])
    if as_text(values.get(TACHYON_MODEL)).strip():
        return "tachyon"
    if as_text(values.get(RAJANT_SERIAL)).strip() or "rajant" in (sys_descr or "").lower():
        return "rajant"
    return ""


async def discover_vendor(client: SnmpClient, sys_object_id: str, sys_descr: str = "",
                          have_cpu: bool = False, have_memory: bool = False) -> VendorResult:
    vendor = await detect(client, sys_object_id, sys_descr)
    if vendor == "rajant":
        return await _rajant(client, sys_descr, have_cpu, have_memory)
    if vendor == "tachyon":
        return await _tachyon(client, have_cpu, have_memory)
    return VendorResult()


# ------------------------------------------------------------------ Rajant
def _rajant_identity(sys_descr: str, serial: str) -> dict[str, str]:
    # sysDescr: "<hostname> <firmware> <model>-<serial> <mesh name...>", e.g. "bc1 11.27.0 ME4-2450R-12345 Mesh"
    parts = (sys_descr or "").split()
    info = {"hw_serial": serial}
    if len(parts) >= 3:
        info["firmware"] = parts[1]
        model = parts[2]
        if serial and model.endswith("-" + serial.rsplit("-", 1)[-1]) and "-" in model:
            model = model.rsplit("-", 1)[0]
        info["hw_model"] = model
    return {k: v for k, v in info.items() if v}


async def _rajant(client: SnmpClient, sys_descr: str, have_cpu: bool, have_memory: bool) -> VendorResult:
    from .discovery import MetricSpec

    res = VendorResult(vendor="Rajant")
    values = await _get(client, [RAJANT_SERIAL, RAJANT_TEMPERATURE, RAJANT_FREE_MEMORY, RAJANT_IDLE])
    res.system = _rajant_identity(sys_descr, as_text(values.get(RAJANT_SERIAL)).strip())
    m = res.metrics
    if _num(values.get(RAJANT_TEMPERATURE)) is not None:
        m.append(MetricSpec("hw.temperature", "system", "System", "gauge", RAJANT_TEMPERATURE, unit="°C", scale=0.01))
    if _num(values.get(RAJANT_FREE_MEMORY)) is not None:
        m.append(MetricSpec("mem.free_bytes", "", "Free memory", "gauge", RAJANT_FREE_MEMORY, unit="B", scale=1024.0))
    if not have_cpu and _num(values.get(RAJANT_IDLE)) is not None:
        # Cumulative idle centiseconds per second = idle %; the poller reports 100 - idle.
        m.append(MetricSpec("cpu.load", "0", "CPU", "idle_counter", RAJANT_IDLE, unit="%", counter_bits=32))
        m.append(MetricSpec("cpu.avg", kind="derived", unit="%"))
    mesh = await _walk(client, RAJANT_MESH)
    for key, (column, label) in RAJANT_MESH_COUNTERS.items():
        oid = f"{RAJANT_MESH}.{column}"
        if oid in mesh or any(k.startswith(oid + ".") for k in mesh):
            actual = oid if oid in mesh else next(k for k in mesh if k.startswith(oid + "."))
            m.append(MetricSpec(key, "", label, "counter", actual, unit="pps", counter_bits=64))
    radios = await _walk(client, RAJANT_RADIOS)
    for n in range(1, 5):
        base = f"{RAJANT_RADIOS}.{n}"
        name_oid = next((k for k in radios if k == f"{base}.1" or k.startswith(f"{base}.1.")), None)
        if name_oid is None:
            continue
        name = as_text(radios[name_oid]).strip() or f"wlan{n - 1}"
        for column, key, unit in ((2, "radio.frequency", "MHz"), (3, "radio.noise", "dBm")):
            oid = next((k for k in radios if k == f"{base}.{column}" or k.startswith(f"{base}.{column}.")), None)
            if oid is not None:
                m.append(MetricSpec(key, name, name, "gauge", oid, unit=unit))
    gps = await _walk(client, RAJANT_GPS)
    for column, key, unit in ((4, "gps.latitude", "°"), (3, "gps.longitude", "°"), (5, "gps.altitude", "m"),
                              (7, "gps.satellites", "")):
        oid = next((k for k in gps if k == f"{RAJANT_GPS}.{column}" or k.startswith(f"{RAJANT_GPS}.{column}.")), None)
        if oid is not None and _num(gps[oid]) is not None:
            m.append(MetricSpec(key, "", key.split(".")[1].title(), "gauge", oid, unit=unit))
    return res


# ----------------------------------------------------------------- Tachyon
async def _tachyon(client: SnmpClient, have_cpu: bool, have_memory: bool) -> VendorResult:
    from .discovery import MetricSpec

    res = VendorResult(vendor="Tachyon Networks")
    values = await _get(client, [TACHYON_MODEL, TACHYON_SERIAL, TACHYON_FIRMWARE, TACHYON_CPU_TEMP, TACHYON_CPU,
                                 TACHYON_MEMORY, TACHYON_PEER_COUNT])
    res.system = {k: as_text(values.get(o)).strip() for k, o in
                  (("hw_model", TACHYON_MODEL), ("hw_serial", TACHYON_SERIAL), ("firmware", TACHYON_FIRMWARE))
                  if as_text(values.get(o)).strip()}
    m = res.metrics
    if _num(values.get(TACHYON_CPU_TEMP)) is not None:
        m.append(MetricSpec("hw.temperature", "cpu", "CPU", "gauge", TACHYON_CPU_TEMP, unit="°C"))
    if not have_cpu and _num(values.get(TACHYON_CPU)) is not None:
        m.append(MetricSpec("cpu.load", "0", "CPU", "gauge", TACHYON_CPU, unit="%"))
        m.append(MetricSpec("cpu.avg", kind="derived", unit="%"))
    if not have_memory and _num(values.get(TACHYON_MEMORY)) is not None:
        m.append(MetricSpec("mem.used_pct", "", "Memory", "gauge", TACHYON_MEMORY, unit="%"))
    if _num(values.get(TACHYON_PEER_COUNT)) is not None:
        m.append(MetricSpec("wireless.peers", "", "Wireless peers", "gauge", TACHYON_PEER_COUNT))

    radios = await _walk(client, TACHYON_RADIO_TABLE)
    names = _col(radios, TACHYON_RADIO_TABLE, 2)
    for idx in sorted(names, key=lambda i: [int(p) if p.isdigit() else 0 for p in i.split(".")]):
        name = as_text(names[idx]).strip() or f"radio {idx}"
        for column, key, unit, inst, label in (
            (3, "radio.tx_power", "dBm", name, name), (5, "radio.frequency", "MHz", name, name),
            (6, "radio.channel_width", "MHz", name, name),
            (10, "hw.temperature", "°C", f"modem {name}", f"Modem {name}"),
            (11, "hw.temperature", "°C", f"radio {name}", f"Radio {name}"),
        ):
            oid = f"{TACHYON_RADIO_TABLE}.{column}.{idx}"
            if oid in radios and _num(radios[oid]) is not None:
                m.append(MetricSpec(key, inst, label, "gauge", oid, unit=unit))

    peers = await _walk(client, TACHYON_PEER_TABLE)
    macs = _col(peers, TACHYON_PEER_TABLE, 1)
    for idx in sorted(macs, key=lambda i: [int(p) if p.isdigit() else 0 for p in i.split(".")]):
        mac = as_text(macs[idx]).strip()
        name = as_text(peers.get(f"{TACHYON_PEER_TABLE}.20.{idx}")).strip()
        label = f"{name} ({mac})" if name and mac else (name or mac or f"peer {idx}")
        inst = mac.lower() if mac else f"peer{idx}"
        for column, key, kind, unit, scale, bits in (
            (6, "wireless.rssi", "gauge", "dBm", 1.0, 32),
            (8, "wireless.snr", "gauge", "dB", 1.0, 32),
            (7, "wireless.tx_rate", "gauge", "bps", 1e6, 32),
            (9, "wireless.rx_rate", "gauge", "bps", 1e6, 32),
            (10, "wireless.tx_mcs", "gauge", "", 1.0, 32),
            (11, "wireless.rx_mcs", "gauge", "", 1.0, 32),
            (12, "wireless.link_uptime", "gauge", "s", 1.0, 32),
            (13, "wireless.distance", "gauge", "m", 1.0, 32),
            (14, "wireless.rx_bps", "counter", "bps", 8.0, 64),
            (15, "wireless.tx_bps", "counter", "bps", 8.0, 64),
        ):
            oid = f"{TACHYON_PEER_TABLE}.{column}.{idx}"
            if oid in peers:
                m.append(MetricSpec(key, inst, label, kind, oid, unit=unit, scale=scale, counter_bits=bits))
        ip = as_text(peers.get(f"{TACHYON_PEER_TABLE}.23.{idx}")).strip()
        res.neighbors.append({
            "protocol": "wireless", "if_index": None, "local_port": "wireless",
            "remote_name": name or mac, "remote_port": "", "remote_ip": ip if ip not in ("0.0.0.0",) else "",
            "remote_chassis": _mac_text(macs[idx]),
            "remote_platform": as_text(peers.get(f"{TACHYON_PEER_TABLE}.18.{idx}")).strip(),
        })
    return res


def _mac_text(value: Any) -> str:
    if isinstance(value, bytes) and len(value) == 6:
        return format_mac(value)
    return as_text(value).strip().lower().replace("-", ":")


async def wireless_neighbors(client: SnmpClient) -> list[dict[str, Any]]:
    """Wireless peers as map neighbours (Tachyon only; the Rajant MIB has no peer table)."""
    values = await _get(client, [TACHYON_MODEL])
    if not as_text(values.get(TACHYON_MODEL)).strip():
        return []
    return (await _tachyon(client, True, True)).neighbors
