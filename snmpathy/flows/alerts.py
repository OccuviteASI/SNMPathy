"""Flow-based alert rules and the Network Analyzer traffic report.

Alert rule kind ``"flow"``
--------------------------
``rule["metric_key"]`` holds a filter expression, ``rule["window_seconds"]`` the averaging window,
``rule["operator"]`` and ``rule["threshold"]`` (bits per second) the condition. Expressions are
space- or comma-separated ``key=value`` terms; bare values are recognised too::

    ""                          all traffic
    "dport=443"                 port 443 (either direction; ``dport``/``sport`` are aliases of ``port``)
    "ip=10.0.0.5"               to or from one host (``host=`` is an alias)
    "cidr=10.1.0.0/16 proto=udp"
    "src=10.0.0.5 port=https"   service names work for ports, names or numbers for protocols
    "source=3"                  one exporter (``source_id=``); a rule's device scopes to its exporters
    "by=src"                    evaluate per top talker (src, dst, app, proto, source): one alert each

The traffic report returns the same dict shape as the builders in :mod:`snmpathy.reporting`.
"""

from __future__ import annotations

import ipaddress
import operator
import time
from typing import Any, Callable

from ..db import Database, loads
from . import query as fq
from .query import FlowFilter

OPERATORS: dict[str, Callable[[float, float], bool]] = {
    ">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le,
    "==": operator.eq, "!=": operator.ne,
}

TRAFFIC_REPORT_TYPE = {
    "title": "Network traffic (flows)",
    "description": "NetFlow / IPFIX / sFlow: top talkers, applications, conversations, protocols and exporters.",
}

_KEY_ALIASES = {
    "ip": "ip", "host": "ip", "addr": "ip", "address": "ip",
    "src": "src", "source_ip": "src", "dst": "dst", "dest": "dst", "destination": "dst",
    "port": "port", "dport": "port", "sport": "port",
    "proto": "proto", "protocol": "proto",
    "cidr": "cidr", "net": "cidr", "network": "cidr", "subnet": "cidr",
    "source": "source_id", "source_id": "source_id", "exporter": "source_id",
    "by": "by", "group": "by", "per": "by",
}
BY_DIMENSIONS = {"src": "src", "dst": "dst", "app": "app", "proto": "proto", "source": "source",
                 "talker": "src", "host": "src", "destination": "dst", "exporter": "source"}


def parse_expression(expr: str) -> dict[str, Any]:
    """Parse a flow filter expression into ``{"ip", "src", ..., "by"}`` (validated, normalised).

    Raises ValueError for unknown keys or bad values.
    """
    from .web import parse_port, parse_proto

    out: dict[str, Any] = {}
    for token in (expr or "").replace(",", " ").split():
        if "=" in token:
            key, _, value = token.partition("=")
            key = _KEY_ALIASES.get(key.strip().lower())
            if key is None:
                raise ValueError(f"unknown flow filter key in {token!r}")
            value = value.strip()
        else:
            key, value = _guess_key(token), token
        if not value:
            raise ValueError(f"empty value in {token!r}")
        if key in ("ip", "src", "dst"):
            if "/" in value and key == "ip":
                key = "cidr"
            else:
                value = str(ipaddress.ip_address(value))
        if key == "cidr":
            value = str(ipaddress.ip_network(value, strict=False))
        elif key == "port":
            value = parse_port(value)
        elif key == "proto":
            value = parse_proto(value)
        elif key == "source_id":
            value = int(value)
        elif key == "by":
            dim = BY_DIMENSIONS.get(value.lower())
            if dim is None:
                raise ValueError(f"cannot group flow alerts by {value!r}")
            value = dim
        out[key] = value
    return out


def _guess_key(token: str) -> str:
    try:
        ipaddress.ip_address(token)
        return "ip"
    except ValueError:
        pass
    if "/" in token:
        return "cidr"
    if token.isdigit():
        return "port"
    from .web import parse_proto

    try:
        parse_proto(token)
        return "proto"
    except ValueError:
        return "port"  # service name, validated by parse_port


def _fmt_bps(value: float) -> str:
    from ..fmt import fmt_bps

    return fmt_bps(value)


def _rule_sources(db: Database, rule: dict[str, Any]) -> list[int] | None:
    """Exporter ids a rule's device / tag scope maps to (``None`` when the rule is not scoped)."""
    device_id = rule.get("device_id")
    tag = (rule.get("device_tag") or "").strip()
    if not device_id and not tag:
        return None
    rows = db.query(
        "SELECT flow_sources.id, devices.id AS device_id, devices.tags FROM flow_sources "
        "JOIN devices ON devices.id = flow_sources.device_id")
    out = []
    for r in rows:
        if device_id and r["device_id"] != device_id:
            continue
        if tag and tag not in loads(r["tags"], []):
            continue
        out.append(r["id"])
    return out


def _filters_for(base: dict[str, Any], start: float, end: float, source_ids: list[int] | None) -> list[FlowFilter]:
    kw = {k: v for k, v in base.items() if k != "by"}
    if source_ids is None or "source_id" in kw:
        if source_ids is not None and kw.get("source_id") not in source_ids:
            return []
        return [FlowFilter(start=start, end=end, **kw)]
    return [FlowFilter(start=start, end=end, source_id=sid, **kw) for sid in source_ids]


def _sum_totals(db: Database, filters: list[FlowFilter]) -> int:
    return sum(fq.totals(db, f)["bytes"] for f in filters)


def _key_fields(by: str) -> list[str]:
    return [alias for alias, _ in fq._TOP_COLS[by]]


def merged_top(db: Database, filters: list[FlowFilter], by: str, limit: int) -> list[dict[str, Any]]:
    """Top-N across several filters (e.g. one per exporter), merged on the dimension's key fields."""
    if len(filters) == 1:
        return fq.top(db, filters[0], by, limit)
    keys = _key_fields(by)
    acc: dict[tuple[Any, ...], dict[str, Any]] = {}
    for f in filters:
        for r in fq.top(db, f, by, 1000):
            k = tuple(r[x] for x in keys)
            slot = acc.get(k)
            if slot is None:
                acc[k] = dict(r)
            else:
                for col in ("bytes", "packets", "flows"):
                    slot[col] += r[col]
    rows = sorted(acc.values(), key=lambda r: (-r["bytes"], *(str(r[x]) for x in keys)))
    total = sum(r["bytes"] for r in rows)
    for r in rows:
        r["pct"] = r["bytes"] * 100.0 / total if total else 0.0
    return rows[:limit]


def _group_label(by: str, row: dict[str, Any]) -> tuple[str, str]:
    """(fingerprint key, human subject) for a per-group flow alert."""
    if by == "src":
        return row["src"], f"{row['src']} sending"
    if by == "dst":
        return row["dst"], f"{row['dst']} receiving"
    if by == "app":
        return f"{row['proto']}/{row['port']}", f"{row['service']} traffic"
    if by == "proto":
        return str(row["proto"]), f"{row['proto_name']} traffic"
    return str(row["source_id"]), f"Exporter {row['source_name']} traffic"


def evaluate_flow_rule(db: Database, rule: dict[str, Any], now: float) -> list[dict[str, Any]]:
    """Evaluate a ``kind == "flow"`` alert rule.

    Returns ``[{"fingerprint", "subject", "message", "value", "device_id"}]`` (``value`` in bits/s,
    averaged over ``window_seconds``) when the condition holds. Invalid expressions raise ValueError.
    """
    op = OPERATORS.get(rule.get("operator") or ">")
    threshold = rule.get("threshold")
    if op is None or threshold is None:
        return []
    threshold = float(threshold)
    window = max(60, int(rule.get("window_seconds") or 300))
    expr = (rule.get("metric_key") or "").strip()
    spec = parse_expression(expr)
    by = spec.get("by")
    start, end = now - window, now
    scoped = _rule_sources(db, rule)
    if scoped == []:
        return []  # scoped to a device without exporters: nothing to evaluate
    filters = _filters_for(spec, start, end, scoped)
    if not filters:
        return []
    what = " ".join(t for t in expr.replace(",", " ").split() if not t.lower().startswith(("by=", "group=", "per=")))
    scope = f" matching {what}" if what else ""
    minutes = f"{window // 60} min" if window % 60 == 0 else f"{window} s"
    cond = f"{rule.get('operator') or '>'} {_fmt_bps(threshold)}"
    device_id = rule.get("device_id") or None

    if not by:
        bps = _sum_totals(db, filters) * 8 / window
        if not op(bps, threshold):
            return []
        return [{
            "fingerprint": f"r{rule['id']}:flow",
            "subject": f"Traffic{scope}" if scope else "Total traffic",
            "message": f"average {_fmt_bps(bps)} over the last {minutes}{scope} ({cond})",
            "value": bps,
            "device_id": device_id,
        }]

    matches = []
    for row in merged_top(db, filters, by, 200):
        bps = row["bytes"] * 8 / window
        if not op(bps, threshold):
            continue
        key, subject = _group_label(by, row)
        matches.append({
            "fingerprint": f"r{rule['id']}:flow:{by}:{key}",
            "subject": subject,
            "message": f"average {_fmt_bps(bps)} over the last {minutes}{scope} ({cond})",
            "value": bps,
            "device_id": device_id,
        })
    return matches


# ------------------------------------------------------------------ report
def _report_filters(db: Database, start: float, end: float, opts: dict[str, Any]) -> tuple[list[FlowFilter], str]:
    from .web import build_filter

    params = {k: opts.get(k) for k in ("source_id", "ip", "src", "dst", "port", "proto", "cidr")}
    base = build_filter({**params, "start": start, "end": end})
    scope = _rule_sources(db, {"device_id": opts.get("device_id"), "device_tag": opts.get("tag") or ""})
    note = ""
    if scope is None:
        return [base], note
    if base.source_id is not None:
        scope = [s for s in scope if s == base.source_id]
    note = f"Limited to {len(scope)} exporter(s) linked to the selected device / tag."
    filters = []
    for sid in scope:
        f = FlowFilter(**{**base.__dict__, "source_id": sid})
        filters.append(f)
    return filters, note


def traffic_report(db: Database, start: float, end: float, label: str, **opts: Any) -> dict[str, Any]:
    """Network traffic report (reporting.py dict shape).

    Options: ``device_id`` / ``tag`` (exporters linked to those devices), ``limit`` (rows per
    section, default 25) and flow filters ``source_id``, ``ip``, ``src``, ``dst``, ``port``,
    ``proto``, ``cidr``.
    """
    limit = max(1, min(int(opts.get("limit") or 25), 1000))
    rep: dict[str, Any] = {
        "id": "traffic", "title": TRAFFIC_REPORT_TYPE["title"], "subtitle": label, "start": start, "end": end,
        "generated_at": time.time(), "summary": [], "sections": [],
    }
    filters, note = _report_filters(db, start, end, opts)
    span = max(1.0, end - start)
    totals = {"bytes": 0, "packets": 0, "flows": 0}
    for f in filters:
        t = fq.totals(db, f)
        for k in totals:
            totals[k] += t[k]
    peak = 0.0
    if len(filters) == 1:
        series = fq.timeseries(db, filters[0])["series"]
        peak = max((p[1] for p in series[0]["points"]), default=0.0) if series else 0.0
    else:
        merged: dict[int, float] = {}
        for f in filters:
            for ts, bps in fq.timeseries(db, f)["series"][0]["points"]:
                merged[ts] = merged.get(ts, 0.0) + bps
        peak = max(merged.values(), default=0.0)

    def top(by: str) -> list[dict[str, Any]]:
        return merged_top(db, filters, by, limit) if filters else []

    def rate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for r in rows:
            r["bps"] = r["bytes"] * 8 / span
        return rows

    talkers = rate(top("src"))
    for r in talkers:
        r["_link"] = f"/traffic/host/{r['src']}"
    dests = rate(top("dst"))
    for r in dests:
        r["_link"] = f"/traffic/host/{r['dst']}"
    apps = rate(top("app"))
    for r in apps:
        r["port_proto"] = f"{r['port']}/{r['proto_name'].lower()}"
    convs = rate(top("conversation"))
    for r in convs:
        r["_link"] = f"/traffic/host/{r['src']}"
    protos = rate(top("proto"))
    sources = rate(top("source"))
    src_info = {s["id"]: s for s in db.query(
        "SELECT flow_sources.*, devices.name AS device_name FROM flow_sources "
        "LEFT JOIN devices ON devices.id = flow_sources.device_id")}
    for r in sources:
        info = src_info.get(r["source_id"]) or {}
        r["address"] = info.get("address", "")
        r["kind"] = info.get("kind", "")
        r["sampling"] = info.get("sampling")
        r["device"] = info.get("device_name") or ""
        r["_link"] = "/traffic/sources"

    rep["summary"] = [
        {"label": "Total traffic", "value": totals["bytes"], "fmt": "bytes"},
        {"label": "Average rate", "value": totals["bytes"] * 8 / span, "fmt": "bps"},
        {"label": "Peak rate", "value": peak, "fmt": "bps"},
        {"label": "Flows", "value": totals["flows"], "fmt": "int"},
        {"label": "Packets", "value": totals["packets"], "fmt": "int"},
        {"label": "Exporters", "value": len(sources), "fmt": "int"},
    ]
    vol = [{"key": "bytes", "label": "Traffic", "fmt": "bytes"}, {"key": "bps", "label": "Avg rate", "fmt": "bps"},
           {"key": "pct", "label": "Share", "fmt": "pct1"}, {"key": "packets", "label": "Packets", "fmt": "int"},
           {"key": "flows", "label": "Flows", "fmt": "int"}]
    rep["sections"] = [
        {"title": "Top talkers (sources)", "note": note,
         "columns": [{"key": "src", "label": "Source IP"}, *vol], "rows": talkers},
        {"title": "Top destinations", "columns": [{"key": "dst", "label": "Destination IP"}, *vol], "rows": dests},
        {"title": "Top applications",
         "columns": [{"key": "service", "label": "Application"}, {"key": "port_proto", "label": "Port"}, *vol],
         "rows": apps},
        {"title": "Top conversations",
         "columns": [{"key": "src", "label": "Source"}, {"key": "dst", "label": "Destination"}, *vol],
         "rows": convs},
        {"title": "Protocols", "columns": [{"key": "proto_name", "label": "Protocol"}, *vol], "rows": protos},
        {"title": "Traffic per exporter",
         "columns": [{"key": "source_name", "label": "Exporter"}, {"key": "address", "label": "Address"},
                     {"key": "kind", "label": "Format"}, {"key": "device", "label": "Device"},
                     {"key": "sampling", "label": "Sampling 1:N", "fmt": "int"}, *vol],
         "rows": sources},
    ]
    if not note:
        rep["sections"][0].pop("note")
    return rep
