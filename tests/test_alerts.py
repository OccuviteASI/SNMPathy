import time

from snmpathy.alerting.engine import AlertEngine
from snmpathy.alerting.notify import build_payload, render_text
from snmpathy.services import create_channel, create_rule


def _metric(db, device_id, key="cpu.avg", value=95.0, instance="", ts=None):
    return db.insert("metrics", {"device_id": device_id, "key": key, "instance": instance, "label": key,
                                 "kind": "derived", "unit": "%", "last_value": value, "last_ts": ts or time.time()})


async def test_metric_rule_pending_firing_resolved(db, make_device):
    device = make_device(tags=["core"])
    mid = _metric(db, device["id"])
    create_rule(db, {"name": "High CPU", "kind": "metric", "metric_key": "cpu.avg", "operator": ">",
                     "threshold": 90, "for_seconds": 60, "severity": "critical", "device_tag": "core"})
    sent = []

    async def notifier(event, alert, rule):
        sent.append((event, alert["subject"]))

    engine = AlertEngine(db, notifier)
    t = time.time()
    await engine.evaluate(now=t)
    assert db.one("SELECT state FROM alerts")["state"] == "pending"
    assert not sent
    await engine.evaluate(now=t + 61)
    alert = db.one("SELECT * FROM alerts")
    assert alert["state"] == "firing"
    assert sent == [("firing", "sw1 cpu.avg")]
    db.execute("UPDATE metrics SET last_value = 10, last_ts = ? WHERE id = ?", (t + 62, mid))
    await engine.evaluate(now=t + 90)
    assert db.one("SELECT state FROM alerts")["state"] == "resolved"
    assert sent[-1][0] == "resolved"


async def test_pending_alert_disappears_when_condition_clears(db, make_device):
    device = make_device()
    mid = _metric(db, device["id"])
    create_rule(db, {"name": "High CPU", "kind": "metric", "metric_key": "cpu.*", "threshold": 90, "for_seconds": 300})
    engine = AlertEngine(db)
    t = time.time()
    await engine.evaluate(now=t)
    assert db.scalar("SELECT COUNT(*) FROM alerts") == 1
    db.execute("UPDATE metrics SET last_value = 5 WHERE id = ?", (mid,))
    await engine.evaluate(now=t + 10)
    assert db.scalar("SELECT COUNT(*) FROM alerts") == 0


async def test_device_scope_and_stale_data(db, make_device):
    a = make_device("a", "10.0.0.1")
    b = make_device("b", "10.0.0.2")
    _metric(db, a["id"])
    _metric(db, b["id"], ts=time.time() - 86400)  # stale: device stopped reporting
    create_rule(db, {"name": "cpu", "kind": "metric", "metric_key": "cpu.avg", "threshold": 90})
    await AlertEngine(db).evaluate()
    subjects = [r["subject"] for r in db.query("SELECT subject FROM alerts")]
    assert subjects == ["a cpu.avg"]


async def test_check_down_and_maintenance_suppression(db):
    now = time.time()
    cid = db.insert("checks", {"name": "web", "type": "http", "target": "http://x", "state": "down",
                               "state_since": now - 120, "last_message": "HTTP 503", "created_at": now, "updated_at": now})
    create_rule(db, {"name": "down", "kind": "check", "severity": "critical"})
    db.insert("maintenance", {"name": "deploy", "check_id": cid, "starts_at": now - 10, "ends_at": now + 600,
                              "created_at": now})
    engine = AlertEngine(db)
    await engine.evaluate(now=now)
    assert db.scalar("SELECT COUNT(*) FROM alerts") == 0
    db.execute("DELETE FROM maintenance")
    await engine.evaluate(now=now + 1)
    alert = db.one("SELECT * FROM alerts")
    assert alert["state"] == "firing" and alert["check_id"] == cid
    assert "HTTP 503" in alert["message"]


async def test_syslog_rule_counts_per_host(db):
    now = time.time()
    rows = [(now - 5, now - 5, "fw1", 3, "kernel", "link down"), (now - 4, now - 4, "fw1", 3, "kernel", "link down"),
            (now - 3, now - 3, "sw2", 3, "kernel", "link down"), (now - 3, now - 3, "sw2", 6, "kernel", "link up")]
    db.executemany("INSERT INTO syslog (ts, received_at, host, severity, app, message) VALUES (?, ?, ?, ?, ?, ?)", rows)
    create_rule(db, {"name": "flaps", "kind": "syslog", "syslog_query": '"link down"', "syslog_severity": 3,
                     "count_threshold": 2, "window_seconds": 60})
    await AlertEngine(db).evaluate(now=now)
    alerts = db.query("SELECT subject, value FROM alerts")
    assert [(a["subject"], a["value"]) for a in alerts] == [("fw1", 2.0)]


async def test_notifications_recorded_for_log_channel(db, make_device):
    from snmpathy.alerting.notify import dispatch

    create_channel(db, {"name": "log", "type": "log"})
    alert = {"id": None, "subject": "x", "severity": "warning", "message": "m", "fingerprint": "f"}
    results = await dispatch(db, "firing", alert, {"channels": "[]", "name": "r"})
    assert results == [{"channel": "log", "status": "sent", "error": ""}]
    assert db.one("SELECT status FROM notifications")["status"] == "sent"


def test_payload_and_text():
    alert = {"subject": "sw1", "severity": "critical", "message": "down", "fired_at": 0, "resolved_at": 600}
    assert render_text("firing", alert) == "[CRITICAL] sw1: down"
    assert "after 10 min" in render_text("resolved", alert)
    payload = build_payload("firing", alert, {"name": "r"})
    assert payload["alert"]["subject"] == "sw1" and payload["rule"]["name"] == "r"
