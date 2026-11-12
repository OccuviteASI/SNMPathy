"""Read-side helpers over the minute-aggregated ``flows`` table: totals, time series and top-N."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any, Sequence

from ..db import Database
from ..syslog.search import parse_duration

PROTO_NAMES: dict[int, str] = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6", 46: "RSVP",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP",
    115: "L2TP", 132: "SCTP", 137: "MPLS-in-IP",
}

SERVICE_NAMES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 49: "tacacs", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "isakmp", 514: "syslog", 515: "printer", 520: "rip", 546: "dhcpv6",
    547: "dhcpv6", 554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 853: "dns-over-tls",
    873: "rsync", 993: "imaps", 995: "pop3s", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1645: "radius", 1812: "radius", 1813: "radius-acct", 1883: "mqtt", 2049: "nfs", 2055: "netflow",
    3268: "ldap-gc", 3306: "mysql", 3389: "rdp", 3478: "stun", 4500: "ipsec-nat-t", 4739: "ipfix",
    5060: "sip", 5061: "sips", 5222: "xmpp", 5432: "postgres", 5900: "vnc", 5985: "winrm",
    5986: "winrm-https", 6343: "sflow", 6379: "redis", 6443: "kubernetes", 8080: "http-alt",
    8443: "https-alt", 8883: "mqtts", 9000: "http-alt", 9092: "kafka", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 51820: "wireguard",
}

GROUPS = (None, "src", "dst", "dport", "proto", "source")
TOP_BY = ("src", "dst", "conversation", "app", "dport", "proto", "source", "in_if", "out_if")

_KNOWN_PORTS_SQL = ", ".join(str(p) for p in sorted(SERVICE_NAMES))
# Application port: dport when well-known, else a well-known sport (server -> client), else dport.
_APP_PORT_SQL = (
    f"CASE WHEN dport < 1024 OR dport IN ({_KNOWN_PORTS_SQL}) THEN dport "
    f"WHEN sport < 1024 OR sport IN ({_KNOWN_PORTS_SQL}) THEN sport ELSE dport END"
)


def proto_name(proto: int | None) -> str:
    if proto is None:
        return ""
    return PROTO_NAMES.get(int(proto), str(proto))


def _well_known(port: int) -> bool:
    return port < 1024 or port in SERVICE_NAMES


def app_port(sport: int, dport: int) -> int:
    """The port that identifies the application of a flow (see module rules)."""
    if _well_known(dport):
        return dport
    if _well_known(sport):
        return sport
    return dport


def service_name(proto: int, port: int) -> str:
    """``"https"`` for a known port, ``"ICMP"`` for ICMP, else ``"tcp/8123"``."""
    if proto in (1, 58):
        return proto_name(proto)
    name = SERVICE_NAMES.get(port)
    if name:
        return name
    return f"{proto_name(proto).lower()}/{port}"


def app_name(proto: int, sport: int, dport: int) -> str:
    """Human name of the application a flow belongs to, e.g. ``app_name(6, 51000, 443) == "https"``."""
    return service_name(proto, app_port(sport, dport))


@dataclass
class FlowFilter:
    """Time range plus optional filters shared by all queries.

    ``ip`` matches src or dst, ``port`` matches sport or dport, ``cidr`` matches when src or dst is
    inside the network (evaluated in Python).
    """

    start: float | None = None
    end: float | None = None
    source_id: int | None = None
    ip: str = ""
    src: str = ""
    dst: str = ""
    port: int | None = None
    proto: int | None = None
    cidr: str = ""

    def bounds(self) -> tuple[float, float]:
        end = self.end if self.end is not None else time.time()
        start = self.start if self.start is not None else end - 3600
        if start >= end:
            start = end - 60
        return float(start), float(end)

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> "FlowFilter":
        """Build a filter from query-string style parameters (``since=6h`` is accepted)."""

        def num(name: str, conv=float):
            value = params.get(name)
            if value in (None, ""):
                return None
            try:
                return conv(value)
            except (TypeError, ValueError):
                return None

        proto = params.get("proto")
        if isinstance(proto, str) and not proto.isdigit():
            lookup = {v.lower(): k for k, v in PROTO_NAMES.items()}
            proto = lookup.get(proto.strip().lower())
        else:
            proto = num("proto", int)
        start, end = num("start"), num("end")
        since = params.get("since")
        if since and start is None:
            start = (end or time.time()) - parse_duration(str(since))
        return cls(
            start=start,
            end=end,
            source_id=num("source_id", int),
            ip=str(params.get("ip") or "").strip(),
            src=str(params.get("src") or "").strip(),
            dst=str(params.get("dst") or "").strip(),
            port=num("port", int),
            proto=proto,
            cidr=str(params.get("cidr") or "").strip(),
        )


def _where(f: FlowFilter) -> tuple[str, list[Any]]:
    start, end = f.bounds()
    clauses = ["bucket >= ?", "bucket <= ?"]
    params: list[Any] = [int(start) // 60 * 60, end]
    if f.source_id is not None:
        clauses.append("source_id = ?")
        params.append(f.source_id)
    if f.ip:
        clauses.append("(src = ? OR dst = ?)")
        params.extend([f.ip, f.ip])
    if f.src:
        clauses.append("src = ?")
        params.append(f.src)
    if f.dst:
        clauses.append("dst = ?")
        params.append(f.dst)
    if f.port is not None:
        clauses.append("(sport = ? OR dport = ?)")
        params.extend([f.port, f.port])
    if f.proto is not None:
        clauses.append("proto = ?")
        params.append(f.proto)
    return "WHERE " + " AND ".join(clauses), params


def _grouped(db: Database, f: FlowFilter, cols: Sequence[tuple[str, str]]) -> list[dict[str, Any]]:
    """Sum bytes/packets/flows grouped by ``cols`` (``(alias, sql expression)`` pairs).

    Without a CIDR filter this is a single SQL GROUP BY. With one, rows are pre-aggregated per
    (cols, src, dst) in SQL, filtered by network membership in Python and re-aggregated.
    """
    where, params = _where(f)
    sums = "SUM(bytes) AS bytes, SUM(packets) AS packets, SUM(flows) AS flows"
    if not f.cidr:
        select = ", ".join(f"{expr} AS {alias}" for alias, expr in cols)
        group = (" GROUP BY " + ", ".join(alias for alias, _ in cols)) if cols else ""
        rows = db.query(f"SELECT {select + ', ' if select else ''}{sums} FROM flows {where}{group}", params)
        if cols:
            return rows
        return [{k: (v or 0) for k, v in rows[0].items()}]

    try:
        net = ipaddress.ip_network(f.cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR {f.cidr!r}") from exc
    aliases = [alias for alias, _ in cols]
    extra = [(c, c) for c in ("src", "dst") if c not in aliases]
    allcols = list(cols) + extra
    select = ", ".join(f"{expr} AS {alias}" for alias, expr in allcols)
    group = ", ".join(alias for alias, _ in allcols)
    member: dict[str, bool] = {}

    def inside(addr: str) -> bool:
        hit = member.get(addr)
        if hit is None:
            try:
                hit = ipaddress.ip_address(addr) in net
            except ValueError:
                hit = False
            member[addr] = hit
        return hit

    out: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in db.query(f"SELECT {select}, {sums} FROM flows {where} GROUP BY {group}", params):
        if not (inside(row["src"]) or inside(row["dst"])):
            continue
        key = tuple(row[a] for a in aliases)
        acc = out.get(key)
        if acc is None:
            acc = out[key] = {**{a: row[a] for a in aliases}, "bytes": 0, "packets": 0, "flows": 0}
        acc["bytes"] += row["bytes"] or 0
        acc["packets"] += row["packets"] or 0
        acc["flows"] += row["flows"] or 0
    if not cols:
        return list(out.values()) or [{"bytes": 0, "packets": 0, "flows": 0}]
    return list(out.values())


def totals(db: Database, f: FlowFilter) -> dict[str, Any]:
    """Overall ``{bytes, packets, flows, bps_avg}`` for the filter's time range."""
    row = _grouped(db, f, ())[0]
    start, end = f.bounds()
    b = int(row["bytes"] or 0)
    return {
        "bytes": b,
        "packets": int(row["packets"] or 0),
        "flows": int(row["flows"] or 0),
        "bps_avg": b * 8 / max(1.0, end - start),
    }


def auto_step(span: float) -> int:
    if span <= 6 * 3600:
        return 60
    if span <= 2 * 86400:
        return 300
    return 3600


_GROUP_COLS = {"src": "src", "dst": "dst", "dport": "dport", "proto": "proto", "source": "source_id"}


def _source_names(db: Database) -> dict[int, str]:
    return {r["id"]: (r["name"] or r["address"]) for r in db.query("SELECT id, name, address FROM flow_sources")}


def _label(group: str, value: Any, names: dict[int, str] | None = None) -> str:
    if group == "proto":
        return proto_name(value)
    if group == "dport":
        name = SERVICE_NAMES.get(int(value or 0))
        return f"{value} ({name})" if name else str(value)
    if group == "source":
        return (names or {}).get(value, str(value))
    return str(value)


def timeseries(
    db: Database, f: FlowFilter, step: int | None = None, group: str | None = None, limit: int = 6
) -> dict[str, Any]:
    """Bits-per-second series: one ``Total`` series, or the top-``limit`` groups plus ``Other``.

    Returns ``{"step": s, "series": [{"name", "key", "points": [[ts, bps], ...]}]}`` with every step
    of the range present (zero-filled).
    """
    if group not in GROUPS:
        raise ValueError(f"unknown group {group!r}")
    start, end = f.bounds()
    step = int(step) if step else auto_step(end - start)
    step = max(60, step // 60 * 60)
    while (end - start) / step > 2000:  # keep the payload bounded
        step *= 2
    first = int(start) // step * step
    stamps = list(range(first, int(end) + 1, step))
    index = {t: i for i, t in enumerate(stamps)}
    bucket_expr = f"(bucket / {step}) * {step}"

    def points(values: dict[int, int]) -> list[list[float]]:
        return [[t, values.get(t, 0) * 8 / step] for t in stamps]

    if group is None:
        rows = _grouped(db, f, (("t", bucket_expr),))
        values = {r["t"]: r["bytes"] or 0 for r in rows if r["t"] in index}
        return {"step": step, "series": [{"name": "Total", "key": None, "points": points(values)}]}

    col = _GROUP_COLS[group]
    rows = _grouped(db, f, (("t", bucket_expr), ("g", col)))
    per_group: dict[Any, int] = {}
    for r in rows:
        per_group[r["g"]] = per_group.get(r["g"], 0) + (r["bytes"] or 0)
    ranked = sorted(per_group, key=lambda g: (-per_group[g], str(g)))
    top_keys = ranked[:max(0, limit)]
    chosen = set(top_keys)
    series_values: dict[Any, dict[int, int]] = {g: {} for g in top_keys}
    other: dict[int, int] = {}
    for r in rows:
        if r["t"] not in index:
            continue
        target = series_values[r["g"]] if r["g"] in chosen else other
        target[r["t"]] = target.get(r["t"], 0) + (r["bytes"] or 0)
    names = _source_names(db) if group == "source" else None
    series = [{"name": _label(group, g, names), "key": g, "points": points(series_values[g])} for g in top_keys]
    if len(ranked) > len(top_keys) and any(other.values()):
        series.append({"name": "Other", "key": None, "points": points(other)})
    return {"step": step, "series": series}


_TOP_COLS: dict[str, tuple[tuple[str, str], ...]] = {
    "src": (("src", "src"),),
    "dst": (("dst", "dst"),),
    "conversation": (("src", "src"), ("dst", "dst")),
    "app": (("proto", "proto"), ("port", _APP_PORT_SQL)),
    "dport": (("proto", "proto"), ("dport", "dport")),
    "proto": (("proto", "proto"),),
    "source": (("source_id", "source_id"),),
    "in_if": (("source_id", "source_id"), ("in_if", "in_if")),
    "out_if": (("source_id", "source_id"), ("out_if", "out_if")),
}


def top(db: Database, f: FlowFilter, by: str, limit: int = 10) -> list[dict[str, Any]]:
    """Top-N rows by bytes for ``by`` in :data:`TOP_BY`.

    Each row holds its key fields plus ``bytes``, ``packets``, ``flows`` and ``pct`` (share of the
    filter's total bytes); ``app``/``dport`` rows add ``service``, rows with a protocol add
    ``proto_name``, rows with a source add ``source_name``.
    """
    if by not in _TOP_COLS:
        raise ValueError(f"unknown top-N dimension {by!r}")
    limit = max(1, min(int(limit), 1000))
    rows = _grouped(db, f, _TOP_COLS[by])
    total = sum(r["bytes"] or 0 for r in rows)
    keys = [alias for alias, _ in _TOP_COLS[by]]
    rows.sort(key=lambda r: (-(r["bytes"] or 0), *(str(r[k]) for k in keys)))
    rows = rows[:limit]
    names = _source_names(db) if "source_id" in keys else {}
    for r in rows:
        r["bytes"] = int(r["bytes"] or 0)
        r["packets"] = int(r["packets"] or 0)
        r["flows"] = int(r["flows"] or 0)
        r["pct"] = (r["bytes"] * 100.0 / total) if total else 0.0
        if "proto" in r:
            r["proto_name"] = proto_name(r["proto"])
        if by == "app":
            r["service"] = service_name(r["proto"], r["port"])
        elif by == "dport":
            r["service"] = service_name(r["proto"], r["dport"])
        if "source_id" in r:
            r["source_name"] = names.get(r["source_id"], str(r["source_id"]))
    return rows


def prune(db: Database, before_ts: float) -> int:
    """Delete flow aggregates older than ``before_ts``; returns the number of rows removed."""
    cur = db.execute("DELETE FROM flows WHERE bucket < ?", (int(before_ts),))
    return int(cur.rowcount or 0)
