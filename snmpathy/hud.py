"""Nagios-style dashlets: status donuts, status bars, state changes, treemap, hypermap and more.

Every function takes ``ids``: the set of device ids the dashboard is scoped to (a device
group / "cluster"), or ``None`` for every device. :func:`scope_device_ids` turns a
dashboard's ``scope`` (tag, site and/or a list of devices) into that set.

States use one vocabulary so the front end can colour them consistently:
``ok`` (green), ``warning`` (amber), ``serious`` (orange), ``critical`` (red), ``unknown`` (grey).
"""

from __future__ import annotations

import re
import time
from typing import Any

from .db import Database, loads

RANK = {"ok": 0, "unknown": 1, "warning": 2, "serious": 3, "critical": 4}
LABEL = {"ok": "OK", "unknown": "UNKNOWN", "warning": "WARNING", "serious": "UNREACHABLE", "critical": "CRITICAL"}


# ------------------------------------------------------------------- scope
def scope_device_ids(db: Database, scope: dict[str, Any] | None) -> set[int] | None:
    """Device ids in a dashboard scope ({"tag", "site", "devices"}); None means no scope (all devices)."""
    scope = scope or {}
    tag, site, wanted = (scope.get("tag") or "").strip(), (scope.get("site") or "").strip(), scope.get("devices") or []
    if not tag and not site and not wanted:
        return None
    from .topology import site_of

    collectors = {c["id"]: c for c in db.query("SELECT id, name, site FROM collectors")}
    names = {str(w).strip().lower() for w in wanted if not str(w).strip().isdigit()}
    numbers = {int(w) for w in wanted if str(w).strip().isdigit()}
    ids = set()
    for d in db.query("SELECT * FROM devices"):
        if tag and tag not in loads(d["tags"], []):
            continue
        if site and site_of(d, collectors) != site:
            continue
        if wanted and d["id"] not in numbers and d["name"].lower() not in names and d["hostname"].lower() not in names:
            continue
        ids.add(d["id"])
    return ids


def describe_scope(scope: dict[str, Any] | None) -> str:
    scope = scope or {}
    parts = []
    if scope.get("tag"):
        parts.append(f"tag {scope['tag']}")
    if scope.get("site"):
        parts.append(f"site {scope['site']}")
    if scope.get("devices"):
        n = len(scope["devices"])
        parts.append(f"{n} device{'s' if n != 1 else ''}")
    return " · ".join(parts)


def _devices(db: Database, ids: set[int] | None, enabled_only: bool = True) -> list[dict[str, Any]]:
    rows = db.query("SELECT * FROM devices" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY name COLLATE NOCASE")
    return [d for d in rows if ids is None or d["id"] in ids]


def _checks(db: Database, ids: set[int] | None) -> list[dict[str, Any]]:
    rows = db.query("SELECT * FROM checks WHERE enabled = 1 ORDER BY name COLLATE NOCASE")
    return [c for c in rows if ids is None or c["device_id"] in ids]


def device_state(d: dict[str, Any]) -> str:
    if d["status"] == "down":
        return "critical"
    if d["status"] == "unreachable":
        return "serious"
    if d["status"] == "up":
        return "warning" if d.get("degraded") else "ok"
    return "unknown"


def check_state(c: dict[str, Any]) -> str:
    if c["state"] == "down":
        return "critical"
    if c["state"] == "up":
        return "warning" if c.get("warning") else "ok"
    return "unknown"


def _worst(states: list[str]) -> str:
    return max(states, key=lambda s: RANK[s]) if states else "unknown"


# ------------------------------------------------------------------ donuts
DEVICE_SEGMENTS = [("ok", "Up"), ("warning", "Degraded"), ("serious", "Unreachable"), ("critical", "Down"),
                   ("unknown", "Unknown")]
CHECK_SEGMENTS = [("ok", "OK"), ("warning", "Warning"), ("critical", "Critical"), ("unknown", "Unknown")]


def status_donut(db: Database, opts: dict[str, Any], ids: set[int] | None) -> dict[str, Any]:
    what = opts.get("of", "devices")
    counts: dict[str, int] = {}
    if what == "checks":
        for c in _checks(db, ids):
            s = check_state(c)
            counts[s] = counts.get(s, 0) + 1
        segments, noun, href = CHECK_SEGMENTS, "checks", "/checks"
    elif what == "interfaces":
        devs = {d["id"] for d in _devices(db, ids)}
        for i in db.query("SELECT device_id, oper_status FROM interfaces WHERE admin_status = 1"):
            if i["device_id"] in devs:
                s = "ok" if i["oper_status"] == 1 else "critical" if i["oper_status"] == 2 else "unknown"
                counts[s] = counts.get(s, 0) + 1
        segments, noun, href = [("ok", "Up"), ("critical", "Down"), ("unknown", "Other")], "ports", "/devices"
    elif what == "alerts":
        for a in db.query("SELECT severity, device_id FROM alerts WHERE state = 'firing'"):
            if ids is not None and a["device_id"] not in ids:
                continue
            s = {"critical": "critical", "warning": "warning"}.get(a["severity"], "unknown")
            counts[s] = counts.get(s, 0) + 1
        segments, noun, href = [("critical", "Critical"), ("warning", "Warning"), ("unknown", "Info")], "firing", "/alerts"
    else:
        for d in _devices(db, ids):
            s = device_state(d)
            counts[s] = counts.get(s, 0) + 1
        segments, noun, href = DEVICE_SEGMENTS, "devices", "/devices"
    out = []
    for key, label in segments:
        if counts.get(key):
            link = href if what in ("alerts", "interfaces") else f"{href}?state={key}"
            out.append({"state": key, "label": label, "count": counts[key], "href": link})
    total = sum(counts.values())
    healthy = counts.get("ok", 0)
    return {"of": what, "segments": out, "total": total, "noun": noun, "href": href,
            "healthy_pct": round(healthy / total * 100, 1) if total and what != "alerts" else None}


# ------------------------------------------------------------------- bars
def status_bars(db: Database, opts: dict[str, Any], ids: set[int] | None) -> dict[str, Any]:
    """Stacked status bars per group (site, collector, device type, tag or device)."""
    from .topology import device_kind, site_of

    by = opts.get("group_by", "site")
    what = opts.get("of", "devices")
    collectors = {c["id"]: c for c in db.query("SELECT id, name, site FROM collectors")}
    devices = {d["id"]: d for d in _devices(db, ids)}

    def groups_of(d: dict[str, Any]) -> list[str]:
        if by == "collector":
            col = collectors.get(d["collector_id"] or 0)
            return [col["name"] if col else "This server"]
        if by == "kind":
            return [device_kind(d).capitalize()]
        if by == "tag":
            return loads(d["tags"], []) or ["(untagged)"]
        if by == "device":
            return [d["name"]]
        return [site_of(d, collectors) or "Unassigned"]

    rows: dict[str, dict[str, Any]] = {}
    items = [(d, device_state(d)) for d in devices.values()] if what != "checks" else \
        [(devices[c["device_id"]], check_state(c)) for c in _checks(db, ids) if c["device_id"] in devices]
    for d, state in items:
        for g in groups_of(d):
            row = rows.setdefault(g, {"name": g, "counts": {}, "total": 0})
            row["counts"][state] = row["counts"].get(state, 0) + 1
            row["total"] += 1
    ordered = sorted(rows.values(), key=lambda r: (-r["total"], r["name"].lower()))
    for r in ordered:
        r["worst"] = _worst(list(r["counts"]))
    return {"rows": ordered[: int(opts.get("limit") or 12)], "of": what, "group_by": by,
            "states": [s for s, _ in (CHECK_SEGMENTS if what == "checks" else DEVICE_SEGMENTS)],
            "labels": dict(CHECK_SEGMENTS if what == "checks" else DEVICE_SEGMENTS)}


# ---------------------------------------------------------- state changes
def _event_state(e: dict[str, Any]) -> str | None:
    t, msg = e["type"], e["message"]
    if t in ("device.down", "check.down", "collector.offline"):
        return "critical"
    if t == "device.unreachable":
        return "serious"
    if t in ("check.warning", "snmp.down"):
        return "warning"
    if t in ("device.up", "check.up", "snmp.up", "collector.online", "alert.resolved"):
        return "ok"
    if t == "alert.firing":
        return "critical" if e["level"] in ("error", "critical") else "warning"
    if t == "device.change" and "changed state" in msg:  # interface up/down
        return "warning" if msg.rstrip().endswith("down") else "ok"
    return None


def state_changes(db: Database, opts: dict[str, Any], ids: set[int] | None) -> dict[str, Any]:
    limit = int(opts.get("limit") or 12)
    names = {d["id"]: d["name"] for d in db.query("SELECT id, name FROM devices")}
    checks = {c["id"]: c["name"] for c in db.query("SELECT id, name FROM checks")}
    rows = []
    for e in db.query("SELECT * FROM events WHERE type IN ('device.down', 'device.up', 'device.unreachable', "
                      "'check.down', 'check.up', 'check.warning', 'snmp.down', 'snmp.up', 'collector.offline', "
                      "'collector.online', 'alert.firing', 'alert.resolved', 'device.change') "
                      "ORDER BY ts DESC, id DESC LIMIT ?", (limit * 6,)):
        if ids is not None and e["device_id"] not in ids:
            continue
        state = _event_state(e)
        if state is None:
            continue
        name = checks.get(e["check_id"]) or names.get(e["device_id"]) or ""
        message = e["message"]
        if e["type"].startswith("alert."):  # "[critical] subject: message" / "RESOLVED subject: message"
            rest = re.sub(r"^(RESOLVED\s+|\[[a-z]+\]\s*)", "", message).strip()
            subject, _, detail = rest.partition(":")
            subject, detail = subject.strip(), detail.strip()
            if e["type"] == "alert.resolved":
                message = f"Resolved: {subject}" if name else "Resolved"
            else:
                message = detail or subject
            name = name or subject or "Alert"
        elif name and message.startswith(name):
            message = message[len(name):].lstrip(" :-")
        href = f"/checks/{e['check_id']}" if e["check_id"] else f"/devices/{e['device_id']}" if e["device_id"] else ""
        rows.append({"ts": e["ts"], "state": state, "label": LABEL[state], "name": name or e["type"].split(".")[0],
                     "output": message, "href": href})
        if len(rows) >= limit:
            break
    return {"rows": rows}


# ---------------------------------------------------------- ranked bars
def ranked_bars(db: Database, panel: dict[str, Any], ids: set[int] | None) -> dict[str, Any]:
    from .dashboards import resolve_metrics

    opts = panel.get("options") or {}
    target = dict((panel.get("targets") or [{}])[0])
    if ids is not None:
        target["scope_ids"] = ids
    metrics = [m for m in resolve_metrics(db, target) if m["last_value"] is not None]
    metrics.sort(key=lambda m: m["last_value"], reverse=opts.get("order", "desc") != "asc")
    per_device: dict[int, int] = {}
    for m in metrics:
        per_device[m["device_id"]] = per_device.get(m["device_id"], 0) + 1
    rows = []
    for m in metrics[: int(opts.get("limit") or 10)]:
        label = m["device_name"]
        if per_device[m["device_id"]] > 1 and m["label"]:
            label += f" · {m['label']}"
        rows.append({"name": label, "value": m["last_value"], "unit": m["unit"], "device_id": m["device_id"]})
    return {"rows": rows}


# ----------------------------------------------------------- group status
def group_status(db: Database, opts: dict[str, Any], ids: set[int] | None, scope: dict[str, Any] | None) -> dict[str, Any]:
    devices, checks = _devices(db, ids), _checks(db, ids)
    states = [device_state(d) for d in devices] + [check_state(c) for c in checks]
    bad = [s for s in states if s != "ok"]
    worst = _worst(bad) if bad else ("ok" if states else "unknown")
    problems = sum(1 for s in states if RANK[s] >= RANK["warning"])
    titles = {"ok": "OK", "warning": "Warning", "serious": "Unreachable", "critical": "Critical", "unknown": "Unknown"}
    return {"state": worst, "label": titles[worst],
            "name": opts.get("label") or describe_scope(scope) or "All devices",
            "devices": len(devices), "checks": len(checks), "problems": problems}


# ---------------------------------------------------------------- treemap
def treemap(db: Database, opts: dict[str, Any], ids: set[int] | None) -> dict[str, Any]:
    """Every device with its services (SNMP and checks), coloured by state."""
    by_device: dict[int, list[dict[str, Any]]] = {}
    for c in _checks(db, ids):
        by_device.setdefault(c["device_id"], []).append({"name": c["name"], "state": check_state(c), "href": f"/checks/{c['id']}"})
    groups = []
    for d in _devices(db, ids)[: int(opts.get("limit") or 60)]:
        items = []
        if d["snmp_enabled"]:
            snmp = d.get("snmp_status") or "unknown"
            items.append({"name": "SNMP", "state": "ok" if snmp == "up" else "critical" if snmp == "down" else "unknown",
                          "href": f"/devices/{d['id']}"})
        items += by_device.get(d["id"], [])
        if not items:
            items = [{"name": d["name"], "state": device_state(d), "href": f"/devices/{d['id']}"}]
        groups.append({"name": d["name"], "href": f"/devices/{d['id']}", "state": device_state(d), "items": items})
    return {"groups": groups}


# --------------------------------------------------------------- hypermap
def hypermap(db: Database, opts: dict[str, Any], ids: set[int] | None) -> dict[str, Any]:
    """A tree for a radial map: SNMPathy at the centre, then collectors, then devices by parent."""
    devices = _devices(db, ids)
    present = {d["id"] for d in devices}
    collectors = {c["id"]: c for c in db.query("SELECT id, name, status FROM collectors")}
    nodes = [{"id": "root", "name": "SNMPathy", "state": "ok", "parent": None, "kind": "root", "href": "/"}]
    used_collectors = set()
    for d in devices:
        if d["parent_id"] in present:
            parent = f"d{d['parent_id']}"
        elif d["collector_id"] in collectors:
            parent = f"c{d['collector_id']}"
            used_collectors.add(d["collector_id"])
        else:
            parent = "root"
        nodes.append({"id": f"d{d['id']}", "name": d["name"], "state": device_state(d), "parent": parent,
                      "kind": "device", "href": f"/devices/{d['id']}", "detail": d["hostname"]})
    for cid in sorted(used_collectors):
        c = collectors[cid]
        nodes.append({"id": f"c{cid}", "name": c["name"], "state": "ok" if c["status"] == "online" else "critical",
                      "parent": "root", "kind": "collector", "href": f"/collectors/{cid}"})
    return {"nodes": nodes}


# ------------------------------------------------------- device services
def device_services(db: Database, opts: dict[str, Any], ids: set[int] | None) -> dict[str, Any]:
    by_device: dict[int, list[dict[str, Any]]] = {}
    for c in _checks(db, ids):
        by_device.setdefault(c["device_id"], []).append({"name": c["name"], "state": check_state(c), "href": f"/checks/{c['id']}"})
    rows = []
    for d in _devices(db, ids)[: int(opts.get("limit") or 30)]:
        chips = []
        if d["snmp_enabled"]:
            snmp = d.get("snmp_status") or "unknown"
            chips.append({"name": "SNMP", "state": "ok" if snmp == "up" else "critical" if snmp == "down" else "unknown",
                          "href": f"/devices/{d['id']}"})
        chips += by_device.get(d["id"], [])
        rows.append({"name": d["name"], "href": f"/devices/{d['id']}", "state": device_state(d),
                     "status": d["status"], "chips": chips})
    return {"rows": rows}


# ------------------------------------------------------------ log dashlets
def log_queries(db: Database, panel: dict[str, Any], start: float, end: float) -> dict[str, Any]:
    """Log events over time, one series per query (Nagios Log Server style)."""
    from .syslog import search

    opts = panel.get("options") or {}
    queries = [t for t in (panel.get("targets") or []) if isinstance(t, dict)] or [{"q": ""}]
    f = search.SyslogFilter(start=start, end=end)
    data = search.histogram_multi(db, f, [t.get("q") or "" for t in queries], int(opts.get("buckets") or 60))
    for s, t in zip(data["series"], queries):
        s["name"] = t.get("label") or t.get("q") or "all messages"
    return data


def log_field(db: Database, panel: dict[str, Any], start: float, end: float) -> dict[str, Any]:
    """Most common values of a log field (status code, client IP, URL, host...)."""
    from .syslog import search

    opts = panel.get("options") or {}
    t = (panel.get("targets") or [{}])[0] or {}
    field = (opts.get("field") or t.get("field") or "host").strip()
    f = search.SyslogFilter(q=t.get("q") or "", start=start, end=end)
    rows = search.field_top(db, f, field, int(opts.get("limit") or 10))
    total = search.count(db, f)
    for r in rows:
        r["label"] = r.get("label") or ("(none)" if r["value"] in (None, "") else str(r["value"]))
    return {"field": field, "rows": rows, "total": total, "q": t.get("q") or ""}


# --------------------------------------------------------- dashboard sets
def _p(type_: str, title: str, w: int, h: int, targets: list | None = None, **options: Any) -> dict[str, Any]:
    return {"type": type_, "title": title, "w": w, "h": h, "targets": targets or [], "options": options}


def hud_config() -> dict[str, Any]:
    """The Main HUD: the whole network at a glance (also the Overview page)."""
    return {"time": "24h", "refresh": 60, "panels": [
        _p("status_donut", "Device status", 3, 2, of="devices"),
        _p("status_donut", "Check status", 3, 2, of="checks"),
        _p("status_bars", "Device status by site", 6, 2, of="devices", group_by="site"),
        _p("state_changes", "Latest state changes", 8, 2, limit=9),
        _p("status_donut", "Firing alerts", 4, 2, of="alerts"),
        _p("timeseries", "Total traffic", 6, 2, [
            {"key": "if.in_bps", "agg": "sum", "alias": "Inbound"},
            {"key": "if.out_bps", "agg": "sum", "alias": "Outbound"}], chart="area"),
        _p("bars", "CPU usage by device", 3, 2, [{"key": "cpu.avg"}], limit=8, thresholds=[70, 90], unit="%"),
        _p("status_donut", "Interfaces", 3, 2, of="interfaces"),
        _p("table", "Busiest interfaces (inbound)", 6, 2, [{"key": "if.in_bps"}], limit=8),
        _p("syslog_histogram", "Syslog volume", 6, 2, [{}]),
    ]}


def cluster_config(scope: dict[str, Any]) -> dict[str, Any]:
    """A cluster dashboard for one group of devices (Nagios-style smart dashboard)."""
    return {"time": "24h", "refresh": 60, "scope": scope, "panels": [
        _p("group_status", "Cluster status", 3, 2),
        _p("treemap", "Device & service treemap", 5, 2),
        _p("hypermap", "Hypermap", 4, 2),
        _p("status_donut", "Services", 3, 2, of="checks"),
        _p("device_services", "Key services", 5, 2),
        _p("bars", "Memory used", 4, 2, [{"key": "mem.used_pct"}], limit=8, thresholds=[80, 95], unit="%"),
        _p("timeseries", "CPU by device", 6, 2, [{"key": "cpu.avg", "limit": 8}], chart="line", y_max=100),
        _p("table", "Disk used", 6, 2, [{"key": "storage.used_pct"}], limit=10),
        _p("timeseries", "Traffic", 6, 2, [
            {"key": "if.in_bps", "agg": "sum", "alias": "Inbound"},
            {"key": "if.out_bps", "agg": "sum", "alias": "Outbound"}], chart="area"),
        _p("state_changes", "Latest state changes", 6, 2, limit=8),
    ]}


def logs_config() -> dict[str, Any]:
    """Log analysis: volume by query, top values of the useful fields, latest errors."""
    return {"time": "6h", "refresh": 60, "panels": [
        _p("log_queries", "Events over time", 8, 2, [
            {"q": "", "label": "All messages"}, {"q": "severity:<=3", "label": "Errors"},
            {"q": "fail* OR denied OR invalid", "label": "Failures"}, {"q": "severity:4", "label": "Warnings"}],
           chart="area"),
        _p("log_field", "By severity", 4, 2, field="severity", style="donut", limit=8),
        _p("log_field", "Top hosts", 4, 2, field="host", style="bars", limit=10),
        _p("log_field", "Top applications", 4, 2, field="app", style="donut", limit=8),
        _p("log_field", "Top source IPs", 4, 2, field="source_ip", style="bars", limit=10),
        _p("log_field", "Failed logins by user", 6, 2, [{"q": "fail* (login OR password OR auth*)"}], field="user",
           style="table", limit=10),
        _p("syslog_stream", "Latest errors", 6, 2, [{"severity": 3}], limit=8),
    ]}


def web_logs_config() -> dict[str, Any]:
    """Web server access & error logs (fields from JSON / GELF / NXLog inputs)."""
    return {"time": "6h", "refresh": 60, "panels": [
        _p("log_queries", "Requests over time", 8, 2, [
            {"q": "", "label": "All requests"}, {"q": "status:4*", "label": "4xx"}, {"q": "status:5*", "label": "5xx"}],
           chart="area"),
        _p("log_field", "HTTP response codes", 4, 2, field="status", style="donut", limit=8),
        _p("log_field", "Top client IPs", 6, 2, field="client_ip", style="bars", limit=10),
        _p("log_field", "Top URLs", 6, 2, field="url", style="table", limit=12),
    ]}


def now() -> float:
    return time.time()
