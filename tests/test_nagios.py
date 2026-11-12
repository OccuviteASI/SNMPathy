import sys

import pytest
from fastapi.testclient import TestClient

from snmpathy.app import create_app
from snmpathy.checks import probes
from snmpathy.checks.runner import record_result, run_probe
from snmpathy.config import Settings
from snmpathy.services import ValidationError, create_check


def test_perfdata_and_exit_codes():
    perf = probes.parse_perfdata("'/ used'=81%;80;90;0;100 load1=0.42 rta=1.2ms;100;500;0 pl=0%")
    assert perf[0] == {"label": "/ used", "value": 81.0, "unit": "%", "warn": 80.0, "crit": 90.0, "min": 0.0, "max": 100.0}
    assert [p["label"] for p in perf] == ["/ used", "load1", "rta", "pl"]
    r = probes.parse_plugin_output("DISK WARNING - free space: / 19% | '/'=81%;80;90\nlong text", 1)
    assert r.ok and r.warning and r.message == "DISK WARNING - free space: / 19%" and r.perfdata[0]["value"] == 81
    assert not probes.parse_plugin_output("CRITICAL - down", 2).ok
    unknown = probes.parse_plugin_output("", 3)
    assert not unknown.ok and "UNKNOWN" in unknown.message
    assert probes.parse_plugin_output("OK", 0).ok


def test_plugin_lookup_is_restricted(tmp_path):
    with pytest.raises(ValueError):
        probes.find_plugin("../bin/sh", [str(tmp_path)])
    with pytest.raises(ValueError):
        probes.find_plugin("/bin/sh", [str(tmp_path)])
    with pytest.raises(ValueError):
        probes.find_plugin("check_missing", [str(tmp_path)])


@pytest.mark.skipif(sys.platform.startswith("win"), reason="shell-script plugin")
async def test_run_plugin(tmp_path, monkeypatch, db, make_device):
    plugin = tmp_path / "check_demo"
    plugin.write_text("#!/bin/sh\necho \"DEMO WARNING - host $1 | temp=71C;70;80\"\nexit 1\n")
    plugin.chmod(0o755)
    monkeypatch.setenv("SNMPATHY_PLUGIN_DIRS", str(tmp_path))
    device = make_device("srv", "10.0.0.9", snmp_enabled=0)
    check = create_check(db, {"device_id": device["id"], "type": "nagios", "target": "10.0.0.9", "retries": 0,
                              "options": {"command": "check_demo", "args": "$HOSTADDRESS$"}})
    result = await run_probe(check, device)
    assert result.ok and result.warning and "host 10.0.0.9" in result.message
    record_result(db, check, result, now=100)
    row = db.one("SELECT state, warning FROM checks")
    assert row == {"state": "up", "warning": 1}
    metric = db.one("SELECT * FROM metrics WHERE key = 'perf.temp'")
    assert metric["last_value"] == 71 and metric["unit"] == "C"
    assert db.one("SELECT 1 FROM events WHERE type = 'check.warning'")
    # Timeouts are CRITICAL.
    slow = tmp_path / "check_slow"
    slow.write_text("#!/bin/sh\nsleep 5\n")
    slow.chmod(0o755)
    r = await probes.nagios_plugin("check_slow", "", timeout=0.3, plugin_dirs=[str(tmp_path)])
    assert not r.ok and "timed out" in r.message


def test_nagios_check_needs_a_plugin_name(db):
    with pytest.raises(ValidationError):
        create_check(db, {"type": "nagios", "target": "x", "options": {"command": "/bin/rm"}})


def test_passive_results(tmp_path, db, make_device):
    device = make_device("backup01", "10.0.0.20", snmp_enabled=0)
    check = create_check(db, {"device_id": device["id"], "type": "passive", "name": "Nightly backup",
                              "target": "backup01", "interval": 3600, "retries": 0})
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    with TestClient(app) as c:
        r = c.post("/api/passive", json={"results": [
            {"host": "backup01", "service": "nightly backup", "state": 1, "output": "WARN - slow | size=42GB"},
            {"host": "other", "service": "nope", "state": 0},
        ]})
        assert r.json()["accepted"] == 1 and r.json()["unknown"][0]["service"] == "nope"
        row = db.one("SELECT state, warning, last_message FROM checks")
        assert row == {"state": "up", "warning": 1, "last_message": "WARN - slow"}
        c.post("/api/passive", json={"results": [{"check_id": check["id"], "state": 2, "output": "FAILED"}]})
        assert db.one("SELECT state FROM checks")["state"] == "down"
        assert db.one("SELECT status FROM devices")["status"] == "down"


async def test_stale_passive_check_fails():
    result = await run_probe({"type": "passive", "target": "x", "timeout": 1, "options": {}}, None)
    assert not result.ok and "freshness" in result.message
