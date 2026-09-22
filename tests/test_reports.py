import time
from datetime import datetime

import pytest

from snmpathy import reporting, reports
from snmpathy.checks.probes import ProbeResult
from snmpathy.checks.runner import record_result
from snmpathy.services import create_check
from snmpathy.storage import rollup, series


def test_interval_math():
    assert reports.merge([(5, 10), (0, 3), (2, 6)]) == [(0, 10)]
    assert reports.subtract([(0, 10)], [(2, 3), (5, 20)]) == [(0, 2), (3, 5)]
    assert reports.clip([(0, 10), (20, 30)], 5, 25) == [(5, 10), (20, 25)]
    assert reports.total([(0, 2), (3, 5)]) == 4


def _history(db, start, pattern):
    """pattern: list of (seconds, ok) steps."""
    check = create_check(db, {"type": "icmp", "target": "10.0.0.1", "retries": 0})
    t = start
    for duration, ok in pattern:
        check = record_result(db, check, ProbeResult(ok, 1.0 if ok else None, "x"), now=t)
        t += duration
    return check, t


def test_availability_with_outage_and_maintenance(db):
    start = 1_000_000.0
    check, end = _history(db, start, [(3600, True), (600, False), (5400, True)])
    a = reports.availability(db, check, start, start + 9600, now=start + 9600)
    assert a["outages"] == 1
    assert a["downtime_seconds"] == pytest.approx(600)
    assert a["uptime_pct"] == pytest.approx(100 * (1 - 600 / 9600))
    assert a["mttr"] == pytest.approx(600)

    db.insert("maintenance", {"name": "planned", "check_id": check["id"], "starts_at": start + 3600,
                              "ends_at": start + 3900, "created_at": start})
    a = reports.availability(db, check, start, start + 9600, now=start + 9600)
    assert a["downtime_seconds"] == pytest.approx(300)
    assert a["maintenance_seconds"] == pytest.approx(300)
    assert a["uptime_pct"] == pytest.approx(100 * (1 - 300 / 9300))


def test_availability_ignores_time_before_first_heartbeat(db):
    start = 2_000_000.0
    check, _ = _history(db, start, [(100, True)])
    a = reports.availability(db, check, start - 86400, start + 100, now=start + 100)
    assert a["uptime_pct"] == 100.0
    assert a["monitored_seconds"] == pytest.approx(100)


def test_resolve_range_calendar_periods():
    now = datetime(2026, 3, 18, 15, 0).timestamp()  # a Wednesday
    s, e, label = reporting.resolve_range("last_week", now)
    assert datetime.fromtimestamp(s) == datetime(2026, 3, 9)
    assert datetime.fromtimestamp(e) == datetime(2026, 3, 16)
    s, e, _ = reporting.resolve_range("last_month", now)
    assert datetime.fromtimestamp(s) == datetime(2026, 2, 1)
    assert datetime.fromtimestamp(e) == datetime(2026, 3, 1)
    s, e, _ = reporting.resolve_range("7d", now)
    assert e - s == 7 * 86400


def _metric(db, device_id, key, instance="1", unit="bps"):
    return db.insert("metrics", {"device_id": device_id, "key": key, "instance": instance, "label": "Gi0/1",
                                 "kind": "counter", "unit": unit})


def test_bandwidth_report_95th_percentile_and_volume(db, make_device):
    device = make_device()
    db.insert("interfaces", {"device_id": device["id"], "if_index": 1, "name": "Gi0/1", "speed": 1e9,
                             "updated_at": 0})
    mid = _metric(db, device["id"], "if.in_bps")
    _metric(db, device["id"], "if.out_bps")
    end = (int(time.time()) // 3600) * 3600
    start = end - 100 * 300
    # 100 five-minute samples: 1..100 Mbps -> 95th percentile = 95 Mbps
    db.executemany("INSERT INTO samples (metric_id, ts, value) VALUES (?, ?, ?)",
                   [(mid, start + i * 300, (i + 1) * 1e6) for i in range(100)])
    rollup(db, end + 1)
    p95, basis = reporting.percentile_95(db, mid, start, end)
    assert basis == "5 min"
    assert p95 == pytest.approx(95e6)
    rep = reporting.bandwidth_report(db, start, end, "test")
    row = rep["sections"][0]["rows"][0]
    assert row["in_p95"] == pytest.approx(95e6)
    # average 50.5 Mbps for 30000 s = 189,375,000 bytes
    assert row["in_bytes"] == pytest.approx(50.5e6 * 30000 / 8, rel=0.02)
    assert row["util_p95"] == pytest.approx(9.5)
    csv_text = reporting.to_csv(rep)
    assert csv_text.splitlines()[0].startswith("Device,Interface")


def test_every_report_builds_on_empty_and_populated_db(db, make_device):
    for key in reporting.REPORT_TYPES:
        rep = reporting.build(db, key, "24h")
        assert rep["title"] and isinstance(rep["sections"], list)
    make_device()
    create_check(db, {"type": "icmp", "target": "10.0.0.1"})
    db.execute("INSERT INTO syslog (ts, received_at, host, severity, facility, app, message) VALUES (?, ?, 'sw1', 3, 1, 'sshd', 'Failed password for root from 10.0.0.9 port 2222')",
               (time.time(), time.time()))
    for key in reporting.REPORT_TYPES:
        rep = reporting.build(db, key, "7d")
        reporting.to_csv(rep)
        reporting.to_text(rep)
    syslog = reporting.build(db, "syslog", "24h")
    pattern = syslog["sections"][3]["rows"][0]["example"]
    assert "Failed password" in pattern
    assert reporting.message_pattern("from 10.0.0.9 port 2222") == "from <ip> port <n>"


def test_series_uses_rollups_for_long_ranges(db, make_device):
    device = make_device()
    mid = _metric(db, device["id"], "cpu.avg", "", "%")
    now = int(time.time())
    db.executemany("INSERT INTO samples (metric_id, ts, value) VALUES (?, ?, ?)",
                   [(mid, now - i * 60, 50.0) for i in range(0, 5 * 86400 // 60, 10)])
    rollup(db, now)
    short = series(db, mid, now - 3600, now)
    assert short["resolution"] == "raw"
    long = series(db, mid, now - 5 * 86400, now)
    assert long["resolution"] == "300"
    assert all(p["avg"] == 50.0 for p in long["points"])
