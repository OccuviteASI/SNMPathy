"""Business logic shared by the REST API, the web UI and the CLI."""

from __future__ import annotations

import json
import time
from typing import Any

from .db import Database, loads

DEVICE_FIELDS = (
    "name", "hostname", "enabled", "snmp_enabled", "snmp_version", "snmp_port", "snmp_community",
    "v3_user", "v3_auth_proto", "v3_auth_key", "v3_priv_proto", "v3_priv_key", "v3_context",
    "poll_interval", "location", "tags", "notes",
)
CHECK_FIELDS = ("device_id", "name", "type", "target", "port", "interval", "timeout", "retries",
                "options", "enabled", "public")
RULE_FIELDS = ("name", "kind", "enabled", "severity", "device_id", "device_tag", "metric_key", "instance",
               "operator", "threshold", "for_seconds", "syslog_query", "syslog_severity", "window_seconds",
               "count_threshold", "channels", "description")
CHANNEL_FIELDS = ("name", "type", "config", "enabled")
SECRET_FIELDS = ("v3_auth_key", "v3_priv_key")


class ValidationError(ValueError):
    pass


def _clean(values: dict[str, Any], allowed: tuple[str, ...]) -> dict[str, Any]:
    out = {}
    for key in allowed:
        if key in values:
            value = values[key]
            if isinstance(value, bool):
                value = int(value)
            if isinstance(value, (list, dict)):
                value = json.dumps(value)
            out[key] = value
    return out


# ------------------------------------------------------------------ devices
def public_device(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["tags"] = loads(d.get("tags"), [])
    for key in SECRET_FIELDS:
        d[f"has_{key}"] = bool(d.get(key))
        d[key] = ""
    return d


def create_device(db: Database, values: dict[str, Any], add_ping_check: bool = True) -> dict[str, Any]:
    now = time.time()
    data = _clean(values, DEVICE_FIELDS)
    if not data.get("name") or not data.get("hostname"):
        raise ValidationError("name and hostname are required")
    if db.one("SELECT 1 FROM devices WHERE name = ?", (data["name"],)):
        raise ValidationError(f"a device named {data['name']!r} already exists")
    data.update(created_at=now, updated_at=now)
    with db.transaction():
        device_id = db.insert("devices", data)
        if add_ping_check:
            db.insert("checks", {
                "device_id": device_id, "name": f"{data['name']} ping", "type": "icmp",
                "target": data["hostname"], "interval": 60, "timeout": 2, "retries": 2,
                "created_at": now, "updated_at": now,
            })
        db.log_event("device.added", f"Device {data['name']} ({data['hostname']}) added", device_id=device_id)
    return db.one("SELECT * FROM devices WHERE id = ?", (device_id,))


def update_device(db: Database, device_id: int, values: dict[str, Any]) -> dict[str, Any]:
    current = db.one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if not current:
        raise KeyError(device_id)
    data = _clean(values, DEVICE_FIELDS)
    for key in SECRET_FIELDS:
        # Secrets are write-only: an empty value means "keep the current one".
        if key in data and not data[key]:
            data.pop(key)
    if "name" in data and data["name"] != current["name"] and db.one(
        "SELECT 1 FROM devices WHERE name = ? AND id != ?", (data["name"], device_id)
    ):
        raise ValidationError(f"a device named {data['name']!r} already exists")
    snmp_keys = {"hostname", "snmp_version", "snmp_port", "snmp_community", "v3_user", "v3_auth_key",
                 "v3_priv_key", "v3_auth_proto", "v3_priv_proto", "v3_context"}
    if any(k in data and data[k] != current[k] for k in snmp_keys):
        data["last_discovered"] = None  # credentials/host changed: rediscover on next poll
    if "hostname" in data and data["hostname"] != current["hostname"]:
        # Keep the auto-created ping check pointing at the device.
        db.execute("UPDATE checks SET target = ? WHERE device_id = ? AND target = ?",
                   (data["hostname"], device_id, current["hostname"]))
    data["updated_at"] = time.time()
    db.update("devices", device_id, data)
    return db.one("SELECT * FROM devices WHERE id = ?", (device_id,))


def delete_device(db: Database, device_id: int) -> None:
    row = db.one("SELECT name FROM devices WHERE id = ?", (device_id,))
    if not row:
        raise KeyError(device_id)
    with db.transaction():
        metric_ids = [r["id"] for r in db.query("SELECT id FROM metrics WHERE device_id = ?", (device_id,))]
        for start in range(0, len(metric_ids), 500):
            chunk = metric_ids[start:start + 500]
            marks = ",".join("?" for _ in chunk)
            db.execute(f"DELETE FROM samples WHERE metric_id IN ({marks})", chunk)
            db.execute(f"DELETE FROM rollups WHERE metric_id IN ({marks})", chunk)
        check_ids = [r["id"] for r in db.query("SELECT id FROM checks WHERE device_id = ?", (device_id,))]
        for cid in check_ids:
            db.execute("DELETE FROM heartbeats WHERE check_id = ?", (cid,))
        db.execute("DELETE FROM alerts WHERE device_id = ?", (device_id,))
        db.execute("UPDATE syslog SET device_id = NULL WHERE device_id = ?", (device_id,))
        db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        db.log_event("device.deleted", f"Device {row['name']} deleted")


def add_custom_metric(db: Database, device_id: int, values: dict[str, Any]) -> dict[str, Any]:
    if not db.one("SELECT 1 FROM devices WHERE id = ?", (device_id,)):
        raise KeyError(device_id)
    key = (values.get("key") or "").strip()
    oid = (values.get("oid") or "").strip().lstrip(".")
    kind = values.get("kind") or "gauge"
    if not key or not oid:
        raise ValidationError("key and oid are required")
    if kind not in {"gauge", "counter", "ratio", "ratio_free"}:
        raise ValidationError("kind must be gauge, counter, ratio or ratio_free")
    if not all(p.isdigit() for p in oid.split(".")):
        raise ValidationError("oid must be numeric, e.g. 1.3.6.1.4.1.2021.10.1.3.1")
    instance = str(values.get("instance") or "")
    if db.one("SELECT 1 FROM metrics WHERE device_id = ? AND key = ? AND instance = ?", (device_id, key, instance)):
        raise ValidationError("a metric with that key/instance already exists on this device")
    metric_id = db.insert("metrics", {
        "device_id": device_id, "key": key, "instance": instance, "label": values.get("label") or key,
        "kind": kind, "oid": oid, "oid2": (values.get("oid2") or "").strip().lstrip("."),
        "unit": values.get("unit") or "", "scale": float(values.get("scale") or 1),
        "counter_bits": int(values.get("counter_bits") or 64), "custom": 1, "enabled": 1,
    })
    return db.one("SELECT * FROM metrics WHERE id = ?", (metric_id,))


# ------------------------------------------------------------------- checks
def public_check(row: dict[str, Any]) -> dict[str, Any]:
    c = dict(row)
    c["options"] = loads(c.get("options"), {})
    return c


def validate_check(data: dict[str, Any]) -> None:
    from .checks.runner import CHECK_TYPES

    if data.get("type") and data["type"] not in CHECK_TYPES:
        raise ValidationError(f"type must be one of {', '.join(CHECK_TYPES)}")
    if data.get("type") == "tcp" and not data.get("port"):
        raise ValidationError("TCP checks need a port")
    if "interval" in data and data["interval"] is not None and int(data["interval"]) < 5:
        raise ValidationError("interval must be at least 5 seconds")


def create_check(db: Database, values: dict[str, Any]) -> dict[str, Any]:
    now = time.time()
    data = _clean(values, CHECK_FIELDS)
    if not data.get("type") or not data.get("target"):
        raise ValidationError("type and target are required")
    data.setdefault("name", f"{data['type'].upper()} {data['target']}")
    validate_check(data)
    data.update(created_at=now, updated_at=now)
    check_id = db.insert("checks", data)
    return db.one("SELECT * FROM checks WHERE id = ?", (check_id,))


def update_check(db: Database, check_id: int, values: dict[str, Any]) -> dict[str, Any]:
    if not db.one("SELECT 1 FROM checks WHERE id = ?", (check_id,)):
        raise KeyError(check_id)
    data = _clean(values, CHECK_FIELDS)
    validate_check(data)
    data["updated_at"] = time.time()
    db.update("checks", check_id, data)
    return db.one("SELECT * FROM checks WHERE id = ?", (check_id,))


def delete_check(db: Database, check_id: int) -> None:
    with db.transaction():
        db.execute("DELETE FROM heartbeats WHERE check_id = ?", (check_id,))
        db.execute("DELETE FROM alerts WHERE check_id = ?", (check_id,))
        db.execute("DELETE FROM checks WHERE id = ?", (check_id,))


# -------------------------------------------------------------------- rules
def public_rule(row: dict[str, Any]) -> dict[str, Any]:
    r = dict(row)
    r["channels"] = loads(r.get("channels"), [])
    return r


def validate_rule(data: dict[str, Any]) -> None:
    from .alerting.engine import OPERATORS, RULE_KINDS, SEVERITIES

    if "kind" in data and data["kind"] not in RULE_KINDS:
        raise ValidationError(f"kind must be one of {', '.join(RULE_KINDS)}")
    if "severity" in data and data["severity"] not in SEVERITIES:
        raise ValidationError(f"severity must be one of {', '.join(SEVERITIES)}")
    if "operator" in data and data["operator"] not in OPERATORS:
        raise ValidationError(f"operator must be one of {' '.join(OPERATORS)}")
    if data.get("kind") == "metric" and (not data.get("metric_key") or data.get("threshold") is None):
        raise ValidationError("metric rules need metric_key and threshold")


def create_rule(db: Database, values: dict[str, Any]) -> dict[str, Any]:
    data = _clean(values, RULE_FIELDS)
    if not data.get("name") or not data.get("kind"):
        raise ValidationError("name and kind are required")
    validate_rule(data)
    data["created_at"] = time.time()
    rule_id = db.insert("alert_rules", data)
    return db.one("SELECT * FROM alert_rules WHERE id = ?", (rule_id,))


def update_rule(db: Database, rule_id: int, values: dict[str, Any]) -> dict[str, Any]:
    current = db.one("SELECT * FROM alert_rules WHERE id = ?", (rule_id,))
    if not current:
        raise KeyError(rule_id)
    data = _clean(values, RULE_FIELDS)
    validate_rule({**current, **data})
    db.update("alert_rules", rule_id, data)
    return db.one("SELECT * FROM alert_rules WHERE id = ?", (rule_id,))


# ----------------------------------------------------------------- channels
def public_channel(row: dict[str, Any]) -> dict[str, Any]:
    c = dict(row)
    config = loads(c.get("config"), {})
    for key in ("smtp_password", "routing_key"):
        if config.get(key):
            config[key] = "********"
    c["config"] = config
    return c


def create_channel(db: Database, values: dict[str, Any]) -> dict[str, Any]:
    from .alerting.notify import CHANNEL_TYPES

    data = _clean(values, CHANNEL_FIELDS)
    if not data.get("name") or data.get("type") not in CHANNEL_TYPES:
        raise ValidationError(f"name and a type ({', '.join(CHANNEL_TYPES)}) are required")
    if db.one("SELECT 1 FROM channels WHERE name = ?", (data["name"],)):
        raise ValidationError("a channel with that name already exists")
    channel_id = db.insert("channels", data)
    return db.one("SELECT * FROM channels WHERE id = ?", (channel_id,))


def update_channel(db: Database, channel_id: int, values: dict[str, Any]) -> dict[str, Any]:
    current = db.one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not current:
        raise KeyError(channel_id)
    if isinstance(values.get("config"), dict):
        old = loads(current["config"], {})
        new = dict(values["config"])
        for key, value in list(new.items()):
            if value == "********":
                new[key] = old.get(key, "")
        values = {**values, "config": new}
    data = _clean(values, CHANNEL_FIELDS)
    db.update("channels", channel_id, data)
    return db.one("SELECT * FROM channels WHERE id = ?", (channel_id,))


# ------------------------------------------------------------------ seeding
DEFAULT_RULES = [
    {"name": "Device unreachable (SNMP)", "kind": "device", "severity": "critical", "for_seconds": 120,
     "description": "A device stopped answering SNMP requests."},
    {"name": "Availability check down", "kind": "check", "severity": "critical", "for_seconds": 0,
     "description": "A ping/TCP/HTTP/DNS/SNMP check has failed its retry budget."},
    {"name": "High CPU", "kind": "metric", "severity": "warning", "metric_key": "cpu.avg", "operator": ">",
     "threshold": 90, "for_seconds": 600, "description": "Average CPU above 90% for 10 minutes."},
    {"name": "High memory usage", "kind": "metric", "severity": "warning", "metric_key": "mem.used_pct",
     "operator": ">", "threshold": 95, "for_seconds": 900},
    {"name": "Disk almost full", "kind": "metric", "severity": "warning", "metric_key": "storage.used_pct",
     "operator": ">", "threshold": 90, "for_seconds": 300},
    {"name": "Interface saturated", "kind": "metric", "severity": "warning", "metric_key": "if.*_util",
     "operator": ">", "threshold": 90, "for_seconds": 600},
    {"name": "Interface errors", "kind": "metric", "severity": "info", "metric_key": "if.in_errors",
     "operator": ">", "threshold": 10, "for_seconds": 600, "description": "More than 10 input errors/s."},
    {"name": "Critical syslog messages", "kind": "syslog", "severity": "critical", "syslog_severity": 2,
     "window_seconds": 300, "count_threshold": 1,
     "description": "Any emergency/alert/critical syslog message."},
]


def seed_defaults(db: Database) -> bool:
    if db.get_meta("seeded"):
        return False
    with db.transaction():
        if not db.scalar("SELECT COUNT(*) FROM alert_rules"):
            for rule in DEFAULT_RULES:
                create_rule(db, rule)
        if not db.scalar("SELECT COUNT(*) FROM channels"):
            create_channel(db, {"name": "Log", "type": "log", "config": {}})
        db.set_meta("seeded", str(time.time()))
    return True


# ------------------------------------------------------------ backup/restore
def export_config(db: Database) -> dict[str, Any]:
    devices = db.query("SELECT * FROM devices ORDER BY id")
    device_names = {d["id"]: d["name"] for d in devices}
    checks = db.query("SELECT * FROM checks ORDER BY id")
    return {
        "version": 1,
        "exported_at": time.time(),
        "devices": [
            {**{k: d[k] for k in DEVICE_FIELDS}, "tags": loads(d["tags"], []),
             "custom_metrics": [
                 {k: m[k] for k in ("key", "instance", "label", "kind", "oid", "oid2", "unit", "scale", "counter_bits")}
                 for m in db.query("SELECT * FROM metrics WHERE device_id = ? AND custom = 1", (d["id"],))
             ]}
            for d in devices
        ],
        "checks": [
            {**{k: c[k] for k in CHECK_FIELDS if k != "device_id"}, "options": loads(c["options"], {}),
             "device": device_names.get(c["device_id"])}
            for c in checks
        ],
        "channels": [{**{k: c[k] for k in CHANNEL_FIELDS}, "config": loads(c["config"], {})}
                     for c in db.query("SELECT * FROM channels ORDER BY id")],
        "rules": [{**{k: r[k] for k in RULE_FIELDS if k != "device_id"}, "channels": loads(r["channels"], []),
                   "device": device_names.get(r["device_id"])}
                  for r in db.query("SELECT * FROM alert_rules ORDER BY id")],
    }


def import_config(db: Database, data: dict[str, Any]) -> dict[str, int]:
    """Merge an exported configuration. Existing objects with the same name are skipped."""
    counts = {"devices": 0, "checks": 0, "channels": 0, "rules": 0}
    with db.transaction():
        for d in data.get("devices", []):
            if db.one("SELECT 1 FROM devices WHERE name = ?", (d["name"],)):
                continue
            device = create_device(db, d, add_ping_check=False)
            for m in d.get("custom_metrics", []):
                add_custom_metric(db, device["id"], m)
            counts["devices"] += 1
        names = {r["name"]: r["id"] for r in db.query("SELECT id, name FROM devices")}
        existing_checks = {(r["name"], r["target"]) for r in db.query("SELECT name, target FROM checks")}
        for c in data.get("checks", []):
            if (c["name"], c["target"]) in existing_checks:
                continue
            create_check(db, {**c, "device_id": names.get(c.get("device"))})
            counts["checks"] += 1
        for ch in data.get("channels", []):
            if db.one("SELECT 1 FROM channels WHERE name = ?", (ch["name"],)):
                continue
            create_channel(db, ch)
            counts["channels"] += 1
        existing_rules = {r["name"] for r in db.query("SELECT name FROM alert_rules")}
        for r in data.get("rules", []):
            if r["name"] in existing_rules:
                continue
            create_rule(db, {**r, "device_id": names.get(r.get("device"))})
            counts["rules"] += 1
    return counts


def overview(db: Database) -> dict[str, Any]:
    q = db.scalar
    return {
        "devices": {
            "total": q("SELECT COUNT(*) FROM devices"),
            "up": q("SELECT COUNT(*) FROM devices WHERE enabled = 1 AND status = 'up'"),
            "down": q("SELECT COUNT(*) FROM devices WHERE enabled = 1 AND status = 'down'"),
            "unknown": q("SELECT COUNT(*) FROM devices WHERE enabled = 1 AND status = 'unknown'"),
            "disabled": q("SELECT COUNT(*) FROM devices WHERE enabled = 0"),
        },
        "checks": {
            "total": q("SELECT COUNT(*) FROM checks"),
            "up": q("SELECT COUNT(*) FROM checks WHERE enabled = 1 AND state = 'up'"),
            "down": q("SELECT COUNT(*) FROM checks WHERE enabled = 1 AND state = 'down'"),
            "unknown": q("SELECT COUNT(*) FROM checks WHERE enabled = 1 AND state = 'unknown'"),
            "paused": q("SELECT COUNT(*) FROM checks WHERE enabled = 0"),
        },
        "interfaces": {
            "total": q("SELECT COUNT(*) FROM interfaces"),
            "down": q("SELECT COUNT(*) FROM interfaces WHERE admin_status = 1 AND oper_status = 2"),
        },
        "alerts": {
            "firing": q("SELECT COUNT(*) FROM alerts WHERE state = 'firing'"),
            "critical": q("SELECT COUNT(*) FROM alerts WHERE state = 'firing' AND severity = 'critical'"),
            "unacknowledged": q("SELECT COUNT(*) FROM alerts WHERE state = 'firing' AND acknowledged = 0"),
        },
        "syslog": {
            "last_hour": q("SELECT COUNT(*) FROM syslog WHERE ts > ?", (time.time() - 3600,)),
            "errors_last_hour": q("SELECT COUNT(*) FROM syslog WHERE ts > ? AND severity <= 3", (time.time() - 3600,)),
        },
    }
