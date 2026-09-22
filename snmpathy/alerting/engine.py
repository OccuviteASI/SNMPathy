"""Alert rule evaluation.

Rule kinds
----------
``metric``  – compare the latest value of a polled metric to a threshold
``check``   – an availability check (ping/TCP/HTTP/...) is down
``device``  – a device stopped answering SNMP
``syslog``  – N or more matching syslog messages from one host within a window

Every rule may be scoped to a single device or to devices carrying a tag.
An alert is ``pending`` until its condition has held for ``for_seconds``,
then ``firing`` (notifications sent) and finally ``resolved``.
"""

from __future__ import annotations

import fnmatch
import logging
import operator
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from ..db import Database, loads
from ..syslog.search import SyslogFilter, top as syslog_top

log = logging.getLogger(__name__)

RULE_KINDS = ("metric", "check", "device", "syslog")
SEVERITIES = ("critical", "warning", "info")
OPERATORS: dict[str, Callable[[float, float], bool]] = {
    ">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le,
    "==": operator.eq, "!=": operator.ne,
}

Notifier = Callable[[str, dict[str, Any], dict[str, Any]], Awaitable[Any]]


@dataclass
class Match:
    fingerprint: str
    subject: str
    message: str
    value: float | None = None
    device_id: int | None = None
    check_id: int | None = None
    since: float | None = None


def _device_in_scope(rule: dict[str, Any], device: dict[str, Any] | None) -> bool:
    if rule.get("device_id") and (not device or device["id"] != rule["device_id"]):
        return False
    tag = (rule.get("device_tag") or "").strip()
    if tag:
        if not device:
            return False
        if tag not in loads(device.get("tags"), []):
            return False
    return True


def _in_maintenance(windows: list[dict[str, Any]], device_id: int | None, check_id: int | None) -> bool:
    for w in windows:
        if w["device_id"] is None and w["check_id"] is None:
            return True
        if device_id is not None and w["device_id"] == device_id:
            return True
        if check_id is not None and w["check_id"] == check_id:
            return True
    return False


def _fmt(value: float | None, unit: str = "") -> str:
    if value is None:
        return "n/a"
    if unit == "bps":
        for div, suffix in ((1e9, "Gbps"), (1e6, "Mbps"), (1e3, "kbps")):
            if abs(value) >= div:
                return f"{value / div:.2f} {suffix}"
        return f"{value:.0f} bps"
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return f"{text}{unit if unit in ('%',) else (' ' + unit if unit else '')}"


def evaluate_rule(db: Database, rule: dict[str, Any], devices: dict[int, dict[str, Any]], now: float) -> list[Match]:
    kind = rule["kind"]
    matches: list[Match] = []
    if kind == "metric":
        op = OPERATORS.get(rule.get("operator") or ">")
        threshold = rule.get("threshold")
        if op is None or threshold is None or not rule.get("metric_key"):
            return []
        key_pattern = rule["metric_key"]
        if any(ch in key_pattern for ch in "*?["):
            rows = db.query("SELECT * FROM metrics WHERE enabled = 1 AND last_value IS NOT NULL")
            rows = [r for r in rows if fnmatch.fnmatchcase(r["key"], key_pattern)]
        else:
            rows = db.query("SELECT * FROM metrics WHERE enabled = 1 AND last_value IS NOT NULL AND key = ?",
                            (key_pattern,))
        inst = (rule.get("instance") or "").strip()
        for m in rows:
            device = devices.get(m["device_id"])
            if not device or not device["enabled"] or not _device_in_scope(rule, device):
                continue
            if inst and not (fnmatch.fnmatch(m["instance"], inst) or fnmatch.fnmatch(m["label"].lower(), inst.lower())):
                continue
            # Ignore stale data (device stopped answering: the device rule covers that).
            max_age = max(3 * int(device.get("poll_interval") or 300), 900)
            if m["last_ts"] and now - m["last_ts"] > max_age:
                continue
            value = float(m["last_value"])
            if op(value, float(threshold)):
                name = m["label"] or m["key"]
                if m["label"] and m["label"] != m["key"]:
                    name = f"{m['key']} {m['label']}"
                matches.append(Match(
                    fingerprint=f"r{rule['id']}:m{m['id']}",
                    subject=f"{device['name']} {name}",
                    message=f"{m['key']} is {_fmt(value, m['unit'])} ({rule['operator']} {_fmt(float(threshold), m['unit'])})",
                    value=value,
                    device_id=device["id"],
                ))
    elif kind == "check":
        for c in db.query("SELECT * FROM checks WHERE enabled = 1 AND state = 'down'"):
            device = devices.get(c["device_id"]) if c["device_id"] else None
            if (rule.get("device_id") or rule.get("device_tag")) and not _device_in_scope(rule, device):
                continue
            down_for = now - (c["state_since"] or now)
            matches.append(Match(
                fingerprint=f"r{rule['id']}:c{c['id']}",
                subject=c["name"],
                message=f"{c['type'].upper()} check to {c['target']} failing: {c['last_message']}",
                value=down_for,
                device_id=c["device_id"],
                check_id=c["id"],
                since=c["state_since"],
            ))
    elif kind == "device":
        for d in devices.values():
            if not d["enabled"] or not d["snmp_enabled"] or d["status"] != "down":
                continue
            if not _device_in_scope(rule, d):
                continue
            matches.append(Match(
                fingerprint=f"r{rule['id']}:d{d['id']}",
                subject=d["name"],
                message=f"device not responding to SNMP: {d['last_error']}",
                value=now - (d["status_since"] or now),
                device_id=d["id"],
                since=d["status_since"],
            ))
    elif kind == "syslog":
        window = int(rule.get("window_seconds") or 300)
        threshold = int(rule.get("count_threshold") or 1)
        f = SyslogFilter(
            q=rule.get("syslog_query") or "",
            severity=rule.get("syslog_severity"),
            device_id=rule.get("device_id"),
            start=now - window,
            end=now,
        )
        # Count per host so one noisy box does not hide the others.
        for row in syslog_top(db, f, "host", limit=200):
            host = row["value"] or ""
            n = int(row["count"])
            if n < threshold:
                continue
            device = next((d for d in devices.values() if host and host.lower() in
                           {d["hostname"].lower(), d["name"].lower(), (d["sys_name"] or "").lower()}), None)
            if rule.get("device_tag") and not _device_in_scope(rule, device):
                continue
            what = f"matching {rule['syslog_query']!r}" if rule.get("syslog_query") else "messages"
            matches.append(Match(
                fingerprint=f"r{rule['id']}:h{host}",
                subject=host or "unknown host",
                message=f"{n} syslog {what} in the last {window // 60 or 1} min",
                value=float(n),
                device_id=device["id"] if device else None,
            ))
    return matches


class AlertEngine:
    def __init__(self, db: Database, notifier: Notifier | None = None):
        self.db = db
        self.notifier = notifier

    async def evaluate(self, now: float | None = None) -> dict[str, int]:
        now = now or time.time()
        db = self.db
        devices = {d["id"]: d for d in db.query("SELECT * FROM devices")}
        windows = db.query("SELECT * FROM maintenance WHERE starts_at <= ? AND ends_at > ?", (now, now))
        active = {a["fingerprint"]: a for a in db.query("SELECT * FROM alerts WHERE state IN ('pending', 'firing')")}
        stats = {"fired": 0, "resolved": 0, "pending": 0, "firing": 0}
        outbox: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

        for rule in db.query("SELECT * FROM alert_rules WHERE enabled = 1"):
            try:
                matches = evaluate_rule(db, rule, devices, now)
            except Exception:
                log.exception("failed to evaluate rule %s", rule["name"])
                # Leave this rule's alerts untouched rather than resolving them.
                for fp in [fp for fp, a in active.items() if a["rule_id"] == rule["id"]]:
                    active.pop(fp)
                continue
            for match in matches:
                existing = active.pop(match.fingerprint, None)
                if _in_maintenance(windows, match.device_id, match.check_id):
                    continue
                if existing is None:
                    started = match.since if match.since and match.since <= now else now
                    alert = {
                        "rule_id": rule["id"], "fingerprint": match.fingerprint, "device_id": match.device_id,
                        "check_id": match.check_id, "subject": match.subject, "severity": rule["severity"],
                        "state": "pending", "value": match.value, "message": match.message,
                        "started_at": started, "last_eval": now,
                    }
                    alert["id"] = db.insert("alerts", alert)
                else:
                    alert = dict(existing)
                    alert.update(value=match.value, message=match.message, subject=match.subject, last_eval=now)
                    db.update("alerts", alert["id"], {
                        "value": match.value, "message": match.message, "subject": match.subject, "last_eval": now,
                    })
                if alert["state"] == "pending" and now - alert["started_at"] >= int(rule.get("for_seconds") or 0):
                    alert.update(state="firing", fired_at=now)
                    db.update("alerts", alert["id"], {"state": "firing", "fired_at": now})
                    db.log_event("alert.firing", f"[{rule['severity']}] {alert['subject']}: {alert['message']}",
                                 "error" if rule["severity"] == "critical" else "warning",
                                 device_id=alert["device_id"], check_id=alert["check_id"], ts=now)
                    outbox.append(("firing", alert, rule))
                    stats["fired"] += 1
                stats[alert["state"]] += 1

        rules = {r["id"]: r for r in db.query("SELECT * FROM alert_rules")}
        for alert in active.values():
            rule = rules.get(alert["rule_id"])
            if rule and rule["enabled"] and _in_maintenance(windows, alert["device_id"], alert["check_id"]):
                continue  # keep state while in maintenance, do not resolve or notify
            if alert["state"] == "pending":
                db.execute("DELETE FROM alerts WHERE id = ?", (alert["id"],))
                continue
            alert = dict(alert)
            alert.update(state="resolved", resolved_at=now)
            db.update("alerts", alert["id"], {"state": "resolved", "resolved_at": now, "last_eval": now})
            db.log_event("alert.resolved", f"RESOLVED {alert['subject']}: {alert['message']}", "info",
                         device_id=alert["device_id"], check_id=alert["check_id"], ts=now)
            stats["resolved"] += 1
            if rule:
                outbox.append(("resolved", alert, rule))

        if self.notifier:
            for event, alert, rule in outbox:
                try:
                    await self.notifier(event, alert, rule)
                except Exception:
                    log.exception("notifier failed")
        return stats
