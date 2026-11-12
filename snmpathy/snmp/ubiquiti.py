"""Ubiquiti private-MIB discovery: airMAX, UniFi, airFiber, LTU, airFiber 60 / Wave,
EdgeMAX (EdgeRouter, UFiber / UISP Fiber OLT, EdgePower) and FASTPATH switches
(EdgeSwitch and first-generation UniFi switches).

OIDs come from Ubiquiti's MIB files (UBNT-AirMAX-MIB, UBNT-UniFi-MIB,
UBNT-AirFIBER-MIB, UBNT-AFLTU-MIB, UI-AF60-MIB, UBNT-EdgeMAX-MIB,
EdgeSwitch-BOXSERVICES-PRIVATE-MIB) and were checked against real device walks.
Where devices disagree with the MIB the code follows the devices:

* airFiber 60 / Wave "scalars" end in ``.1`` (not ``.0``) and station rows carry
  a trailing ``.1`` after the MAC.
* LTU station distance is in metres (the MIB says km).
* airMAX firmware 8.7.4-8.7.6 reports the host temperature multiplied by 10^7.
* airFiber classic frequencies are sometimes reported in kHz.
* EdgeMAX temperatures are milli-degrees on most units, whole degrees on newer OLTs.
* The FASTPATH CPU figure is a text string ("5 Secs ( 31.11%) 60 Secs ...").

Many of these devices share the generic Frogfoot sysObjectID (1.3.6.1.4.1.10002.1),
so the family is found by probing one identity OID per MIB.
"""

from __future__ import annotations

import re
from typing import Any

from .client import SnmpClient, SnmpError, as_text

U = "1.3.6.1.4.1.41112"
FROGFOOT_MEM_TOTAL = "1.3.6.1.4.1.10002.1.1.1.1.1.0"   # KiB
FROGFOOT_MEM_FREE = "1.3.6.1.4.1.10002.1.1.1.1.2.0"    # KiB
DOT11_PRODUCT_NAME = "1.2.840.10036.3.1.2.1.3"
DOT11_PRODUCT_VERSION = "1.2.840.10036.3.1.2.1.4"

# Identity probes, in the order families are tested.
PROBES: list[tuple[str, str]] = [
    ("af60", f"{U}.1.11.1.2.4.1"),       # af60FirmwareVersion
    ("ltu", f"{U}.1.10.1.3.4.0"),        # afLTUFirmwareVersion
    ("airfiber", f"{U}.1.3.2.1.40.1"),   # fwVersion
    ("unifi", f"{U}.1.6.3.3.0"),         # unifiApSystemModel
    ("airmax", f"{U}.1.4.1.1.4.1"),      # ubntRadioFreq
    ("edgemax", f"{U}.1.5.1.1.0"),       # ubntModel
    ("fastpath", "1.3.6.1.4.1.4413.1.1.1.1.4.9.0"),  # agentSwitchCpuProcessTotalUtilization
]
FAMILY_NAMES = {
    "af60": "airFiber 60 / Wave", "ltu": "LTU", "airfiber": "airFiber", "unifi": "UniFi",
    "airmax": "airMAX", "edgemax": "EdgeMAX", "fastpath": "EdgeSwitch",
}

# sysObjectIDs worth probing for a Ubiquiti family.
PROBE_PREFIXES = ("1.3.6.1.4.1.41112", "1.3.6.1.4.1.10002", "1.3.6.1.4.1.4413", "1.3.6.1.4.1.8072",
                  "1.3.6.1.4.1.27282")
DESCR_HINTS = re.compile(r"^(UAP|U6|U7|E7|UK|U-LTE|USW|US[ -]|US\d|UBNT|UniFi|Ubiquiti|EdgeSwitch|EdgePoint|EdgeOS|"
                         r"EdgeRouter|UISP|UFiber)", re.I)


def worth_probing(sys_object_id: str, sys_descr: str) -> bool:
    oid = (sys_object_id or "").lstrip(".")
    return (not oid or oid in ("1.3.6.1.4.1", "0.0") or oid.startswith(PROBE_PREFIXES)
            or bool(DESCR_HINTS.match((sys_descr or "").strip())))


async def detect_family(client: SnmpClient, sys_object_id: str, sys_descr: str) -> str:
    if not worth_probing(sys_object_id, sys_descr):
        return ""
    try:
        values = await client.get([oid for _, oid in PROBES])
    except SnmpError:
        return ""
    for family, oid in PROBES:
        value = values.get(oid)
        if value is not None and as_text(value).strip() != "":
            return family
    return ""


# ------------------------------------------------------------------ helpers
async def _walk(client: SnmpClient, oid: str) -> dict[str, Any]:
    try:
        return await client.walk(oid)
    except SnmpError:
        return {}


async def _get(client: SnmpClient, oids: list[str]) -> dict[str, Any]:
    try:
        return await client.get(oids)
    except SnmpError:
        return {}


def _num(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _rows(table: dict[str, Any], base: str) -> dict[str, dict[int, Any]]:
    """{row index: {column: value}} for a table walked at ``base`` (entry OID)."""
    rows: dict[str, dict[int, Any]] = {}
    prefix = base + "."
    for oid, value in table.items():
        if not oid.startswith(prefix):
            continue
        column, _, index = oid[len(prefix):].partition(".")
        if column.isdigit() and index:
            rows.setdefault(index, {})[int(column)] = value
    return rows


def _mac_from_index(index: str, skip: int = 0) -> str:
    parts = index.split(".")[skip:skip + 6]
    if len(parts) == 6 and all(p.isdigit() and int(p) < 256 for p in parts):
        return ":".join(f"{int(p):02x}" for p in parts)
    return ""


def _text(value: Any) -> str:
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join(f"{b:02x}" for b in value)
    return as_text(value).strip()


def _peer_label(name: str, mac: str) -> str:
    return f"{name} ({mac})" if name and mac else (name or mac)


def _memory(res: Any, values: dict[str, Any], have_memory: bool) -> None:
    from .discovery import MetricSpec

    if not have_memory and _num(values.get(FROGFOOT_MEM_TOTAL)) and _num(values.get(FROGFOOT_MEM_FREE)) is not None:
        res.metrics.append(MetricSpec("mem.used_pct", "", "Memory", "ratio_free", FROGFOOT_MEM_FREE,
                                      FROGFOOT_MEM_TOTAL, "%"))


def _station_metrics(res: Any, instance: str, label: str, table: str, index: str, rows: dict[int, Any],
                     columns: list[tuple[int, str, str, str, float, int]]) -> None:
    from .discovery import MetricSpec

    for column, key, kind, unit, scale, bits in columns:
        if column in rows and (kind == "counter" or _num(rows[column]) is not None):
            res.metrics.append(MetricSpec(key, instance, label, kind, f"{table}.{column}.{index}", unit=unit,
                                          scale=scale, counter_bits=bits))


def _neighbor(name: str, mac: str, ip: str, platform: str = "", local_port: str = "wireless") -> dict[str, Any]:
    return {"protocol": "wireless", "if_index": None, "local_port": local_port, "remote_name": name or mac,
            "remote_port": "", "remote_ip": "" if ip in ("", "0.0.0.0") else ip, "remote_chassis": mac,
            "remote_platform": platform}


# ------------------------------------------------------------------ families
async def discover(client: SnmpClient, family: str, have_cpu: bool, have_memory: bool) -> Any:
    from .vendors import VendorResult

    res = VendorResult(vendor="Ubiquiti")
    handler = {"airmax": _airmax, "unifi": _unifi, "airfiber": _airfiber, "ltu": _ltu, "af60": _af60,
               "edgemax": _edgemax, "fastpath": _fastpath}[family]
    await handler(client, res, have_cpu, have_memory)
    res.system.setdefault("hw_model", FAMILY_NAMES[family])
    return res


async def _dot11_identity(client: SnmpClient) -> dict[str, str]:
    info: dict[str, str] = {}
    names = await _walk(client, DOT11_PRODUCT_NAME)
    versions = await _walk(client, DOT11_PRODUCT_VERSION)
    name = next((as_text(v).strip() for v in names.values() if as_text(v).strip()), "")
    version = next((as_text(v).strip() for v in versions.values() if as_text(v).strip()), "")
    if name:
        info["hw_model"] = name
    if version:
        m = re.search(r"\.v(\d+\.\d+(?:\.\d+)?)", version)
        info["firmware"] = m.group(1) if m else version
    return info


AIRMAX_STA = f"{U}.1.4.7.1"


async def _airmax(client: SnmpClient, res: Any, have_cpu: bool, have_memory: bool) -> None:
    from .discovery import MetricSpec

    res.system.update(await _dot11_identity(client))
    base = f"{U}.1.4"
    oids = {
        "freq": f"{base}.1.1.4.1", "txpower": f"{base}.1.1.6.1", "distance": f"{base}.1.1.7.1",
        "signal": f"{base}.5.1.5.1", "ccq": f"{base}.5.1.7.1", "noise": f"{base}.5.1.8.1",
        "txrate": f"{base}.5.1.9.1", "rxrate": f"{base}.5.1.10.1", "stations": f"{base}.5.1.15.1",
        "quality": f"{base}.6.1.3.1", "capacity": f"{base}.6.1.4.1", "airtime": f"{base}.6.1.7.1",
        "temp": f"{base}.8.4.0", "mem_total": FROGFOOT_MEM_TOTAL, "mem_free": FROGFOOT_MEM_FREE,
    }
    v = await _get(client, list(oids.values()))
    m = res.metrics
    for key, oid_key, unit, scale, label in (
        ("radio.frequency", "freq", "MHz", 1.0, "Radio"), ("radio.tx_power", "txpower", "dBm", 1.0, "Radio"),
        ("wireless.distance", "distance", "m", 1.0, "Link"), ("wireless.signal", "signal", "dBm", 1.0, "Signal"),
        ("wireless.ccq", "ccq", "%", 1.0, "CCQ"), ("radio.noise", "noise", "dBm", 1.0, "Radio"),
        ("wireless.tx_rate", "txrate", "bps", 1.0, "Link"), ("wireless.rx_rate", "rxrate", "bps", 1.0, "Link"),
        ("wireless.peers", "stations", "", 1.0, "Stations"),
        ("wireless.airmax_quality", "quality", "%", 1.0, "airMAX quality"),
        ("wireless.airmax_capacity", "capacity", "%", 1.0, "airMAX capacity"),
        ("wireless.airtime", "airtime", "%", 0.1, "Airtime"),
    ):
        if _num(v.get(oids[oid_key])) is not None:
            instance = "radio" if key.startswith("radio.") else ("link" if label == "Link" else "")
            m.append(MetricSpec(key, instance, label, "gauge", oids[oid_key], unit=unit, scale=scale))
    temp = _num(v.get(oids["temp"]))
    if temp is not None:
        # airOS 8.7.4-8.7.6 report the temperature multiplied by 10^7.
        scale = 1e-7 if abs(temp) > 1e5 else 1.0
        m.append(MetricSpec("hw.temperature", "system", "System", "gauge", oids["temp"], unit="°C", scale=scale))
    _memory(res, v, have_memory)
    stations = _rows(await _walk(client, AIRMAX_STA), AIRMAX_STA)
    for index, row in sorted(stations.items()):
        mac = _mac_from_index(index, skip=1)
        if not mac:
            continue
        name = _text(row.get(2))
        label = _peer_label(name, mac)
        _station_metrics(res, mac, label, AIRMAX_STA, index, row, [
            (3, "wireless.rssi", "gauge", "dBm", 1.0, 32), (6, "wireless.ccq", "gauge", "%", 1.0, 32),
            (5, "wireless.distance", "gauge", "m", 1.0, 32),
            (8, "wireless.airmax_quality", "gauge", "%", 1.0, 32), (9, "wireless.airmax_capacity", "gauge", "%", 1.0, 32),
            (11, "wireless.tx_rate", "gauge", "bps", 1.0, 32), (12, "wireless.rx_rate", "gauge", "bps", 1.0, 32),
            (17, "wireless.tx_capacity", "gauge", "bps", 1000.0, 32), (18, "wireless.rx_capacity", "gauge", "bps", 1000.0, 32),
            (13, "wireless.tx_bps", "counter", "bps", 8.0, 64), (14, "wireless.rx_bps", "counter", "bps", 8.0, 64),
            (21, "wireless.latency", "gauge", "ms", 1.0, 32),
        ])
        res.neighbors.append(_neighbor(name, mac, _text(row.get(10))))


UNIFI_RADIO = f"{U}.1.6.1.1.1"
UNIFI_VAP = f"{U}.1.6.1.2.1"
BANDS = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz", "ax": "6 GHz"}


async def _unifi(client: SnmpClient, res: Any, have_cpu: bool, have_memory: bool) -> None:
    from .discovery import MetricSpec

    v = await _get(client, [f"{U}.1.6.3.3.0", f"{U}.1.6.3.6.0", FROGFOOT_MEM_TOTAL, FROGFOOT_MEM_FREE])
    model, version = as_text(v.get(f"{U}.1.6.3.3.0")).strip(), as_text(v.get(f"{U}.1.6.3.6.0")).strip()
    res.system.update({k: val for k, val in (("hw_model", model), ("firmware", version)) if val})
    _memory(res, v, have_memory)
    m = res.metrics
    for index, row in sorted(_rows(await _walk(client, UNIFI_RADIO), UNIFI_RADIO).items()):
        band = BANDS.get(_text(row.get(3)).lower(), _text(row.get(3)))
        name = _text(row.get(2)) or f"radio {index}"
        label = f"{band} ({name})" if band else name
        for column, key, lbl in ((6, "radio.channel_util", "Channel utilisation"),
                                 (7, "radio.util_self_rx", "Own RX airtime"), (8, "radio.util_self_tx", "Own TX airtime"),
                                 (9, "radio.util_other_bss", "Other networks' airtime")):
            if _num(row.get(column)) is not None:
                m.append(MetricSpec(key, name, f"{label}: {lbl}", "gauge", f"{UNIFI_RADIO}.{column}.{index}", unit="%"))
    seen_radio_power: set[str] = set()
    for index, row in sorted(_rows(await _walk(client, UNIFI_VAP), UNIFI_VAP).items()):
        essid = _text(row.get(6))
        if not essid or essid.startswith("vwire"):
            continue  # wireless uplink / mesh VAPs
        band = BANDS.get(_text(row.get(9)).lower(), _text(row.get(9)))
        instance = f"{essid} {band}".strip()
        label = f"{essid} ({band})" if band else essid
        for column, key, kind, unit, scale, bits in (
            (8, "wireless.clients", "gauge", "", 1.0, 32), (3, "wireless.ccq", "gauge", "%", 0.1, 32),
            (10, "wireless.rx_bps", "counter", "bps", 8.0, 32), (16, "wireless.tx_bps", "counter", "bps", 8.0, 32),
        ):
            if column in row:
                m.append(MetricSpec(key, instance, label, kind, f"{UNIFI_VAP}.{column}.{index}", unit=unit,
                                    scale=scale, counter_bits=bits))
        if band and band not in seen_radio_power:
            seen_radio_power.add(band)
            for column, key, unit in ((4, "radio.channel", ""), (21, "radio.tx_power", "dBm")):
                if _num(row.get(column)) is not None:
                    m.append(MetricSpec(key, band, band, "gauge", f"{UNIFI_VAP}.{column}.{index}", unit=unit))


AF = f"{U}.1.3"


async def _airfiber(client: SnmpClient, res: Any, have_cpu: bool, have_memory: bool) -> None:
    from .discovery import MetricSpec

    cfg, st, stats = f"{AF}.1.1", f"{AF}.2.1", f"{AF}.3.1"
    oids = {
        "txfreq": f"{cfg}.5.1", "rxfreq": f"{cfg}.6.1", "txpower": f"{cfg}.9.1", "name": f"{cfg}.14.1",
        "dist": f"{st}.4.1", "rxcap": f"{st}.5.1", "txcap": f"{st}.6.1", "t0": f"{st}.8.1", "t1": f"{st}.10.1",
        "rx0": f"{st}.11.1", "rx1": f"{st}.14.1", "rrx0": f"{st}.19.1", "rrx1": f"{st}.22.1", "link": f"{st}.26.1",
        "uptime": f"{st}.44.1", "fw": f"{st}.40.1", "rmac": f"{st}.45.1", "rip": f"{st}.46.1",
        "txoct": f"{stats}.64.1", "rxoct": f"{stats}.66.1",
        "mem_total": FROGFOOT_MEM_TOTAL, "mem_free": FROGFOOT_MEM_FREE,
    }
    v = await _get(client, list(oids.values()))
    res.system["firmware"] = as_text(v.get(oids["fw"])).strip().lstrip("v")
    m = res.metrics
    for key, which in (("txfreq", "tx"), ("rxfreq", "rx")):
        freq = _num(v.get(oids[key]))
        if freq is not None:
            m.append(MetricSpec("radio.frequency", which, f"{which.upper()} frequency", "gauge", oids[key],
                                unit="MHz", scale=0.001 if freq > 100_000 else 1.0))
    for key, metric, inst, label, unit, scale in (
        ("txpower", "radio.tx_power", "radio", "Radio", "dBm", 1.0),
        ("dist", "wireless.distance", "link", "Link", "m", 1.0),
        ("rxcap", "wireless.rx_capacity", "link", "Link", "bps", 1.0),
        ("txcap", "wireless.tx_capacity", "link", "Link", "bps", 1.0),
        ("t0", "hw.temperature", "radio0", "Radio 0", "°C", 1.0), ("t1", "hw.temperature", "radio1", "Radio 1", "°C", 1.0),
        ("rx0", "wireless.rssi", "chain0", "Local chain 0", "dBm", 1.0),
        ("rx1", "wireless.rssi", "chain1", "Local chain 1", "dBm", 1.0),
        ("rrx0", "wireless.remote_rssi", "chain0", "Remote chain 0", "dBm", 1.0),
        ("rrx1", "wireless.remote_rssi", "chain1", "Remote chain 1", "dBm", 1.0),
        ("link", "wireless.link_up", "link", "Radio link up", "", 1.0),
        ("uptime", "wireless.link_uptime", "link", "Link", "s", 1.0),
    ):
        if _num(v.get(oids[key])) is not None:
            m.append(MetricSpec(metric, inst, label, "gauge", oids[key], unit=unit, scale=scale))
    for key, metric in (("txoct", "wireless.tx_bps"), ("rxoct", "wireless.rx_bps")):
        if v.get(oids[key]) is not None:
            m.append(MetricSpec(metric, "link", "RF link", "counter", oids[key], unit="bps", scale=8.0, counter_bits=64))
    _memory(res, v, have_memory)
    remote = _text(v.get(oids["rmac"])).lower()
    if remote:
        res.neighbors.append(_neighbor(_text(v.get(oids["name"])), remote, _text(v.get(oids["rip"]))))


LTU = f"{U}.1.10.1"
LTU_STA = f"{LTU}.4.1"


async def _ltu(client: SnmpClient, res: Any, have_cpu: bool, have_memory: bool) -> None:
    from .discovery import MetricSpec

    oids = {"freq": f"{LTU}.2.2.0", "eirp": f"{LTU}.2.6.0", "model": f"{LTU}.3.2.0", "fw": f"{LTU}.3.4.0",
            "mem": f"{LTU}.3.5.0", "cpu": f"{LTU}.3.6.0", "tx": f"{LTU}.5.1.0", "rx": f"{LTU}.5.3.0",
            "up": f"{LTU}.5.5.0"}
    v = await _get(client, list(oids.values()))
    res.system.update({k: val for k, val in (("hw_model", _text(v.get(oids["model"]))),
                                             ("firmware", _text(v.get(oids["fw"])).lstrip("v"))) if val})
    m = res.metrics
    if not have_cpu and _num(v.get(oids["cpu"])) is not None:
        m += [MetricSpec("cpu.load", "0", "CPU", "gauge", oids["cpu"], unit="%"), MetricSpec("cpu.avg", kind="derived", unit="%")]
    if not have_memory and _num(v.get(oids["mem"])) is not None:
        m.append(MetricSpec("mem.used_pct", "", "Memory", "gauge", oids["mem"], unit="%"))
    for key, metric, unit, label in (("freq", "radio.frequency", "MHz", "Radio"), ("eirp", "radio.tx_power", "dBm", "EIRP"),
                                     ("up", "wireless.link_up", "", "Wireless connected")):
        if _num(v.get(oids[key])) is not None:
            m.append(MetricSpec(metric, "radio" if metric.startswith("radio.") else "link", label, "gauge", oids[key], unit=unit))
    for key, metric in (("tx", "wireless.tx_bps"), ("rx", "wireless.rx_bps")):
        if v.get(oids[key]) is not None:
            m.append(MetricSpec(metric, "link", "Wireless", "counter", oids[key], unit="bps", scale=8.0, counter_bits=64))
    for index, row in sorted(_rows(await _walk(client, LTU_STA), LTU_STA).items()):
        mac = _mac_from_index(index) or _text(row.get(11)).lower()
        if not mac:
            continue
        name = _text(row.get(13))
        _station_metrics(res, mac, _peer_label(name, mac), LTU_STA, index, row, [
            (3, "wireless.tx_capacity", "gauge", "bps", 1000.0, 32), (4, "wireless.rx_capacity", "gauge", "bps", 1000.0, 32),
            (5, "wireless.rssi", "gauge", "dBm", 1.0, 32), (16, "wireless.remote_rssi", "gauge", "dBm", 1.0, 32),
            (22, "wireless.latency", "gauge", "ms", 1.0, 32), (23, "wireless.distance", "gauge", "m", 1.0, 32),
        ])
        res.neighbors.append(_neighbor(name, mac, _text(row.get(25)), _text(row.get(12))))


AF60 = f"{U}.1.11.1"
AF60_STA = f"{AF60}.3.1"


async def _af60(client: SnmpClient, res: Any, have_cpu: bool, have_memory: bool) -> None:
    from .discovery import MetricSpec

    # Scalars on these devices end in .1, not .0.
    oids = {"freq": f"{AF60}.1.2.1", "model": f"{AF60}.2.2.1", "fw": f"{AF60}.2.4.1", "mem": f"{AF60}.2.5.1",
            "cpu": f"{AF60}.2.6.1"}
    v = await _get(client, list(oids.values()))
    res.system.update({k: val for k, val in (("hw_model", _text(v.get(oids["model"]))),
                                             ("firmware", _text(v.get(oids["fw"])))) if val})
    m = res.metrics
    if not have_cpu and _num(v.get(oids["cpu"])) is not None:
        m += [MetricSpec("cpu.load", "0", "CPU", "gauge", oids["cpu"], unit="%"), MetricSpec("cpu.avg", kind="derived", unit="%")]
    if not have_memory and _num(v.get(oids["mem"])) is not None:
        m.append(MetricSpec("mem.used_pct", "", "Memory", "gauge", oids["mem"], unit="%"))
    if _num(v.get(oids["freq"])) is not None:
        m.append(MetricSpec("radio.frequency", "radio", "Radio", "gauge", oids["freq"], unit="MHz"))
    for index, row in sorted(_rows(await _walk(client, AF60_STA), AF60_STA).items()):
        mac = _mac_from_index(index)
        if not mac:
            continue
        name = _text(row.get(14))
        link = _text(row.get(2))
        label = _peer_label(name, mac) + (f" [{link}]" if link and link != "main" else "")
        _station_metrics(res, mac, label, AF60_STA, index, row, [
            (3, "wireless.rssi", "gauge", "dBm", 1.0, 32), (4, "wireless.snr", "gauge", "dB", 1.0, 32),
            (18, "wireless.remote_rssi", "gauge", "dBm", 1.0, 32), (19, "wireless.remote_snr", "gauge", "dB", 1.0, 32),
            (5, "wireless.tx_mcs", "gauge", "", 1.0, 32), (6, "wireless.rx_mcs", "gauge", "", 1.0, 32),
            (7, "wireless.tx_capacity", "gauge", "bps", 1000.0, 32), (8, "wireless.rx_capacity", "gauge", "bps", 1000.0, 32),
            (9, "wireless.tx_bps", "counter", "bps", 8.0, 64), (10, "wireless.rx_bps", "counter", "bps", 8.0, 64),
            (15, "wireless.distance", "gauge", "m", 1.0, 32),
        ])
        res.neighbors.append(_neighbor(name, mac, _text(row.get(20)), _text(row.get(13))))


EDGEMAX = f"{U}.1.5"


async def _edgemax(client: SnmpClient, res: Any, have_cpu: bool, have_memory: bool) -> None:
    from .discovery import MetricSpec

    v = await _get(client, [f"{EDGEMAX}.1.1.0", f"{EDGEMAX}.1.2.0", f"{EDGEMAX}.1.3.0"])
    res.system.update({k: _text(v.get(o)) for k, o in (("hw_model", f"{EDGEMAX}.1.1.0"), ("hw_serial", f"{EDGEMAX}.1.2.0"),
                                                       ("firmware", f"{EDGEMAX}.1.3.0")) if _text(v.get(o))})
    m = res.metrics
    therm_types = {1: "other", 2: "board", 3: "cpu", 4: "power"}
    for index, row in sorted(_rows(await _walk(client, f"{EDGEMAX}.4.2.1"), f"{EDGEMAX}.4.2.1").items()):
        value = _num(row.get(3))
        if value is None:
            continue
        kind = therm_types.get(int(_num(row.get(2)) or 1), "sensor")
        # Milli-degrees on most units; newer OLTs report whole degrees.
        m.append(MetricSpec("hw.temperature", f"{kind} {index}", f"{kind.title()} {index}", "gauge",
                            f"{EDGEMAX}.4.2.1.3.{index}", unit="°C", scale=0.001 if abs(value) > 1000 else 1.0))
    for index, row in sorted(_rows(await _walk(client, f"{EDGEMAX}.5.2.1"), f"{EDGEMAX}.5.2.1").items()):
        if _num(row.get(3)) is not None:
            m.append(MetricSpec("hw.fan_rpm", f"fan {index}", f"Fan {index}", "gauge", f"{EDGEMAX}.5.2.1.3.{index}", unit="rpm"))
    for index, row in sorted(_rows(await _walk(client, f"{EDGEMAX}.2.2.1"), f"{EDGEMAX}.2.2.1").items()):
        if _num(row.get(4)) is not None:
            m.append(MetricSpec("poe.output_w", index, f"Output {index}", "gauge", f"{EDGEMAX}.2.2.1.4.{index}",
                                unit="W", scale=0.001))


FP = "1.3.6.1.4.1.4413.1.1"


async def _fastpath(client: SnmpClient, res: Any, have_cpu: bool, have_memory: bool) -> None:
    from .discovery import MetricSpec

    ident = {"hw_model": f"{FP}.1.1.1.3.0", "hw_serial": f"{FP}.1.1.1.4.0", "firmware": f"{FP}.1.1.1.13.0"}
    mem_free, mem_total, cpu = f"{FP}.1.1.4.1.0", f"{FP}.1.1.4.2.0", f"{FP}.1.1.4.9.0"
    v = await _get(client, [*ident.values(), mem_free, mem_total, cpu])
    res.system.update({k: _text(v.get(o)) for k, o in ident.items() if _text(v.get(o))})
    m = res.metrics
    if not have_cpu and v.get(cpu) is not None:
        m += [MetricSpec("cpu.load", "0", "CPU", "pct_text", cpu, unit="%"), MetricSpec("cpu.avg", kind="derived", unit="%")]
    if not have_memory and _num(v.get(mem_total)) and _num(v.get(mem_free)) is not None:
        m.append(MetricSpec("mem.used_pct", "", "Memory", "ratio_free", mem_free, mem_total, "%"))
    box = f"{FP}.43.1"
    for index, row in sorted(_rows(await _walk(client, f"{box}.8.1"), f"{box}.8.1").items()):
        if _num(row.get(5)) is not None and _num(row.get(4)) not in (5.0, 6.0):  # not present / not operational
            m.append(MetricSpec("hw.temperature", f"sensor {index}", f"Sensor {index}", "gauge", f"{box}.8.1.5.{index}", unit="°C"))
    for index, row in sorted(_rows(await _walk(client, f"{box}.6.1"), f"{box}.6.1").items()):
        if _num(row.get(3)) == 1.0:
            continue  # not present
        m.append(MetricSpec("hw.fan_state", f"fan {index}", f"Fan {index} (2 = operational)", "gauge", f"{box}.6.1.3.{index}"))
        if _num(row.get(4)) is not None:
            m.append(MetricSpec("hw.fan_rpm", f"fan {index}", f"Fan {index}", "gauge", f"{box}.6.1.4.{index}", unit="rpm"))
    for index, row in sorted(_rows(await _walk(client, f"{box}.7.1"), f"{box}.7.1").items()):
        if _num(row.get(3)) not in (None, 1.0):
            m.append(MetricSpec("hw.psu_state", f"psu {index}", f"Power supply {index} (2 = operational)", "gauge",
                                f"{box}.7.1.3.{index}"))


# ----------------------------------------------------------------- PoE (standard)
PETH_MAIN = "1.3.6.1.2.1.105.1.3.1.1"


async def discover_poe(client: SnmpClient) -> list[Any]:
    """POWER-ETHERNET-MIB budget and consumption per PSE group (any vendor)."""
    from .discovery import MetricSpec

    out = []
    for index, row in sorted(_rows(await _walk(client, PETH_MAIN), PETH_MAIN).items()):
        if _num(row.get(2)) is not None:
            out.append(MetricSpec("poe.budget_w", index, f"PoE group {index}", "gauge", f"{PETH_MAIN}.2.{index}", unit="W"))
        if _num(row.get(4)) is not None:
            out.append(MetricSpec("poe.consumption_w", index, f"PoE group {index}", "gauge", f"{PETH_MAIN}.4.{index}", unit="W"))
    return out
