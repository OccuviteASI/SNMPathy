import pytest

from snmpathy import reports
from snmpathy.alerting.engine import evaluate_rule
from snmpathy.availability import Source, combine, device_report, evaluate_device
from snmpathy.checks.probes import ProbeResult
from snmpathy.checks.runner import record_result
from snmpathy.services import ValidationError, create_check, update_device
from snmpathy.snmp.client import FakeSnmpClient
from snmpathy.snmp.discovery import apply_discovery, discover
from snmpathy.snmp.poller import poll_device

from .conftest import agent_data


def S(state, since=None, kind="icmp", name="ping"):
    return Source(kind=kind, name=name, state=state, since=since)


def test_combine_modes():
    ping_up_snmp_down = [S("up"), S("down", 100, kind="snmp", name="SNMP")]
    v = combine(ping_up_snmp_down, "any")
    assert v.state == "up" and v.degraded and "SNMP" in v.reason
    assert combine(ping_up_snmp_down, "all").state == "down"
    three = [S("up"), S("down", 100), S("down", 200)]
    assert combine(three, "quorum", 2).state == "down"
    assert combine(three, "quorum", 1).state == "up"
    # 'any' goes down when the last source fails: backdate to that failure.
    v = combine([S("down", 100), S("down", 250)], "any")
    assert v.state == "down" and v.since == 250
    # 'all' goes down at the first failure.
    assert combine([S("down", 100), S("down", 250), S("up")], "all").since == 100
    assert combine([], "any").state == "unknown"
    assert combine([S("unknown")], "any").state == "unknown"


async def _snmp_device(db, make_device, **extra):
    device = make_device(**extra)
    client = FakeSnmpClient(agent_data())
    apply_discovery(db, device["id"], await discover(client), now=1000)
    return device


async def test_ping_keeps_device_online_when_snmp_fails(db, make_device):
    device = await _snmp_device(db, make_device)
    ping = create_check(db, {"device_id": device["id"], "type": "icmp", "target": "10.0.0.1", "retries": 0})
    record_result(db, ping, ProbeResult(True, 1.0, "ok"), now=1000)
    await poll_device(db, FakeSnmpClient(agent_data()), db.one("SELECT * FROM devices"), now=1000)
    assert db.one("SELECT status, degraded FROM devices") == {"status": "up", "degraded": 0}

    await poll_device(db, FakeSnmpClient(fail=True), db.one("SELECT * FROM devices"), now=1300)
    row = db.one("SELECT * FROM devices")
    assert row["snmp_status"] == "down"
    assert row["status"] == "up" and row["degraded"] == 1
    assert "SNMP" in row["status_reason"]
    # The SNMP failure alone must not raise the device-offline alert.
    rule = {"id": 1, "kind": "device", "device_id": None, "device_tag": ""}
    devices = {d["id"]: d for d in db.query("SELECT * FROM devices")}
    assert evaluate_rule(db, rule, devices, 1300) == []

    # Now ping fails too: offline, backdated to when the last method failed.
    ping = db.one("SELECT * FROM checks")
    record_result(db, ping, ProbeResult(False, None, "timeout"), now=1400)
    row = db.one("SELECT * FROM devices")
    assert row["status"] == "down" and row["status_since"] == 1400
    outage = db.one("SELECT * FROM device_outages")
    assert outage["started_at"] == 1400 and outage["ended_at"] is None
    assert db.one("SELECT 1 FROM events WHERE type = 'device.down'")

    # Ping recovers: online again, outage closed, availability < 100%.
    record_result(db, db.one("SELECT * FROM checks"), ProbeResult(True, 1.0, "ok"), now=1500)
    assert db.one("SELECT status FROM devices")["status"] == "up"
    assert db.one("SELECT ended_at FROM device_outages")["ended_at"] == 1500
    a = reports.device_availability(db, db.one("SELECT * FROM devices"), 1000, 2000, now=2000)
    assert a["downtime_seconds"] == pytest.approx(100) and a["outages"] == 1


async def test_all_mode_and_snmp_failure_threshold(db, make_device):
    device = await _snmp_device(db, make_device, avail_mode="all", snmp_down_after=2)
    ping = create_check(db, {"device_id": device["id"], "type": "icmp", "target": "10.0.0.1", "retries": 0})
    record_result(db, ping, ProbeResult(True, 1.0, "ok"), now=1000)
    await poll_device(db, FakeSnmpClient(agent_data()), db.one("SELECT * FROM devices"), now=1000)
    await poll_device(db, FakeSnmpClient(fail=True), db.one("SELECT * FROM devices"), now=1300)
    # One failed poll is below the threshold of 2.
    assert db.one("SELECT snmp_status, status FROM devices") == {"snmp_status": "up", "status": "up"}
    await poll_device(db, FakeSnmpClient(fail=True), db.one("SELECT * FROM devices"), now=1600)
    row = db.one("SELECT * FROM devices")
    assert row["snmp_status"] == "down" and row["status"] == "down"
    # Backdated to the first failed poll of the streak.
    assert row["status_since"] == 1300


async def test_checks_excluded_from_device_status(db, make_device):
    device = make_device(snmp_enabled=0)
    http = create_check(db, {"device_id": device["id"], "type": "tcp", "target": "10.0.0.1", "port": 80,
                             "retries": 0, "affects_device": 0})
    ping = create_check(db, {"device_id": device["id"], "type": "icmp", "target": "10.0.0.1", "retries": 0})
    record_result(db, http, ProbeResult(False, None, "refused"), now=10)
    record_result(db, ping, ProbeResult(True, 1.0, "ok"), now=10)
    report = device_report(db, db.one("SELECT * FROM devices"))
    assert [s["name"] for s in report["sources"]] == [ping["name"]]
    assert db.one("SELECT status, degraded FROM devices") == {"status": "up", "degraded": 0}


async def test_parent_down_makes_child_unreachable(db, make_device):
    router = make_device("rtr", "10.0.0.254", snmp_enabled=0)
    switch = make_device("sw", "10.0.1.2", snmp_enabled=0, parent_id=router["id"])
    rping = create_check(db, {"device_id": router["id"], "type": "icmp", "target": "10.0.0.254", "retries": 0})
    sping = create_check(db, {"device_id": switch["id"], "type": "icmp", "target": "10.0.1.2", "retries": 0})
    record_result(db, rping, ProbeResult(True, 1, "ok"), now=10)
    record_result(db, sping, ProbeResult(True, 1, "ok"), now=10)
    record_result(db, rping, ProbeResult(False, None, "timeout"), now=20)
    record_result(db, sping, ProbeResult(False, None, "timeout"), now=21)
    status = {r["name"]: r["status"] for r in db.query("SELECT name, status FROM devices")}
    assert status == {"rtr": "down", "sw": "unreachable"}
    assert db.one("SELECT 1 FROM events WHERE type = 'device.unreachable'")
    # Only the root cause raises the device alert.
    from snmpathy.alerting import engine

    devices = {d["id"]: d for d in db.query("SELECT * FROM devices")}
    matches = engine.evaluate_rule(db, {"id": 1, "kind": "device", "device_id": None, "device_tag": ""}, devices, 30)
    assert [m.subject for m in matches] == ["rtr"]
    # Router back: the child is re-evaluated and becomes plain down (it is still failing).
    record_result(db, db.one("SELECT * FROM checks WHERE id = ?", (rping["id"],)), ProbeResult(True, 1, "ok"), now=40)
    status = {r["name"]: r["status"] for r in db.query("SELECT name, status FROM devices")}
    assert status == {"rtr": "up", "sw": "down"}


def test_parent_loops_rejected(db, make_device):
    a = make_device("a", "10.0.0.1")
    b = make_device("b", "10.0.0.2", parent_id=a["id"])
    with pytest.raises(ValidationError):
        update_device(db, a["id"], {"parent_id": b["id"]})
    with pytest.raises(ValidationError):
        update_device(db, a["id"], {"avail_mode": "sometimes"})


async def test_check_alert_skipped_while_device_online(db, make_device):
    from snmpathy.alerting import engine

    device = await _snmp_device(db, make_device)
    await poll_device(db, FakeSnmpClient(agent_data()), db.one("SELECT * FROM devices"), now=1000)
    ping = create_check(db, {"device_id": device["id"], "type": "icmp", "target": "10.0.0.1", "retries": 0})
    record_result(db, ping, ProbeResult(False, None, "filtered"), now=1010)
    assert db.one("SELECT status FROM devices")["status"] == "up"
    devices = {d["id"]: d for d in db.query("SELECT * FROM devices")}
    rule = {"id": 2, "kind": "check", "device_id": None, "device_tag": "", "skip_online_devices": 1}
    assert engine.evaluate_rule(db, rule, devices, 1020) == []
    rule["skip_online_devices"] = 0
    assert len(engine.evaluate_rule(db, rule, devices, 1020)) == 1


def test_evaluate_device_is_idempotent(db, make_device):
    device = make_device(snmp_enabled=0)
    assert evaluate_device(db, device["id"]) is None
    assert db.one("SELECT status FROM devices")["status"] == "unknown"
