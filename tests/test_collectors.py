import asyncio
import io
import tarfile
import time

import pytest
from fastapi.testclient import TestClient

from snmpathy import collectors
from snmpathy.app import create_app
from snmpathy.collectors import CollectorHub, CollectorOffline, encode_values
from snmpathy.config import Settings
from snmpathy.services import create_check
from snmpathy.snmp import mibs
from snmpathy.snmp.client import FakeSnmpClient
from snmpathy.snmp.discovery import apply_discovery, discover

from .conftest import agent_data


def test_tokens(db):
    row, token = collectors.create_collector(db, "Branch A", site="Denver")
    assert token.startswith("col_") and row["token_hash"] != token
    assert collectors.authenticate(db, token)["id"] == row["id"]
    assert collectors.authenticate(db, "col_wrong") is None
    new = collectors.rotate_token(db, row["id"])
    assert collectors.authenticate(db, token) is None and collectors.authenticate(db, new)
    with pytest.raises(ValueError):
        collectors.create_collector(db, "Branch A")
    assert "token_hash" not in collectors.public_collector(row)


def test_value_codec_roundtrip():
    values = {"1.2": b"\x00\x1b\x54\x01\x02\x03", "1.3": "text", "1.4": 5, "1.5": None}
    assert collectors.decode_values(encode_values(values)) == values


async def _collector_device(db, make_device):
    col, _ = collectors.create_collector(db, "Site")
    device = make_device("sw-remote", "10.9.0.1", collector_id=col["id"], poll_interval=60)
    apply_discovery(db, device["id"], await discover(FakeSnmpClient(agent_data())), now=1000)
    return col, db.one("SELECT * FROM devices WHERE id = ?", (device["id"],))


async def test_config_and_ingest(db, make_device):
    col, device = await _collector_device(db, make_device)
    check = create_check(db, {"device_id": device["id"], "type": "icmp", "target": "10.9.0.1", "retries": 0})
    assert check["collector_id"] == col["id"]  # checks follow their device's collector
    hub = CollectorHub(db)
    config = hub.config(col["id"])
    assert [d["name"] for d in config["devices"]] == ["sw-remote"]
    dev = config["devices"][0]
    assert dev["snmp"] and dev["creds"]["snmp_community"] == "public"
    assert mibs.SYS_UPTIME in dev["oids"] and f"{mibs.IF_HC_IN_OCTETS}.1" in dev["oids"]
    assert config["checks"][0]["device"]["name"] == "sw-remote"
    assert config["version"] == hub.config_version(col["id"])

    def snmp_item(ts, in_octets):
        values = {k.lstrip("."): v for k, v in agent_data(in_octets=in_octets, uptime_ticks=int(ts * 100)).items()}
        return {"type": "snmp", "device_id": device["id"], "ts": ts,
                "values": encode_values({o: values.get(o) for o in dev["oids"]}), "duration_ms": 12.5}

    results = [
        snmp_item(2000, 1000), snmp_item(2010, 1000 + 1_250_000),
        {"type": "check", "check_id": check["id"], "ts": 2005, "ok": True, "latency_ms": 3.0, "message": "echo reply"},
        {"type": "check", "check_id": 999, "ts": 2005, "ok": True},  # not this collector's
    ]
    counts = await hub.ingest(col, results)
    assert counts == {"accepted": 3, "ignored": 1}
    bps = db.one("SELECT last_value FROM metrics WHERE key = 'if.in_bps' AND instance = '1'")["last_value"]
    assert bps == pytest.approx(1_000_000)
    assert db.one("SELECT last_poll_ms, status FROM devices") == {"last_poll_ms": 12.5, "status": "up"}
    assert db.one("SELECT state FROM checks")["state"] == "up"
    # Replayed (older) results are ignored.
    assert (await hub.ingest(col, [snmp_item(1990, 5)]))["ignored"] == 1
    # An SNMP error pushed by the collector marks SNMP down; ping keeps the device up.
    await hub.ingest(col, [{"type": "snmp", "device_id": device["id"], "ts": 2100, "error": "timeout"}])
    assert db.one("SELECT snmp_status, status, degraded FROM devices") == {"snmp_status": "down", "status": "up", "degraded": 1}


async def test_offline_collector_makes_devices_unreachable(db, make_device):
    col, device = await _collector_device(db, make_device)
    hub = CollectorHub(db, offline_after=60)
    hub.touch(col, {"hostname": "probe1", "version": "1"}, now=time.time())
    check = create_check(db, {"device_id": device["id"], "type": "icmp", "target": "10.9.0.1", "retries": 0})
    await hub.ingest(db.one("SELECT * FROM collectors"),
                     [{"type": "check", "check_id": check["id"], "ts": time.time() - 1, "ok": True, "message": "ok"}])
    assert db.one("SELECT status FROM devices")["status"] == "up"
    db.execute("UPDATE collectors SET last_seen = ?", (time.time() - 120,))
    assert hub.sweep() == [col["id"]]
    row = db.one("SELECT status, status_reason FROM devices")
    assert row["status"] == "unreachable" and "collector Site is offline" in row["status_reason"]
    assert db.one("SELECT 1 FROM events WHERE type = 'collector.offline'")
    hub.touch(db.one("SELECT * FROM collectors"), {})
    assert db.one("SELECT status FROM collectors")["status"] == "online"
    assert db.one("SELECT status FROM devices")["status"] == "up"


async def test_job_relay(db):
    col, _ = collectors.create_collector(db, "Relay")
    hub = CollectorHub(db)
    with pytest.raises(CollectorOffline):
        await hub.call(col["id"], "ping", {}, timeout=1)
    hub.touch(col, {})
    call = asyncio.create_task(hub.call(col["id"], "snmp_get", {"oids": ["1.3"]}, timeout=5))
    jobs = await hub.next_jobs(col["id"], wait=2)
    assert [j["op"] for j in jobs] == ["snmp_get"]
    assert hub.resolve(col["id"], [{"id": jobs[0]["id"], "ok": True, "result": {"1.3": {"b64": "AAE="}}}]) == 1
    assert await call == {"1.3": {"b64": "AAE="}}
    # SNMP errors come back as SnmpError so callers treat them like local failures.
    from snmpathy.snmp.client import SnmpError

    call = asyncio.create_task(hub.call(col["id"], "snmp_walk", {}, timeout=5))
    jobs = await hub.next_jobs(col["id"], wait=2)
    hub.resolve(col["id"], [{"id": jobs[0]["id"], "ok": False, "error": "timeout", "error_type": "snmp"}])
    with pytest.raises(SnmpError):
        await call
    assert await hub.next_jobs(col["id"], wait=0.05) == []


@pytest.fixture
def app_client(tmp_path, db):
    app = create_app(Settings(database=str(tmp_path / "t.db"), api_token="admintoken"), db=db, start_monitor=False)
    with TestClient(app) as c:
        yield c


def test_collector_http_api(app_client, db):
    admin = {"Authorization": "Bearer admintoken"}
    assert app_client.post("/api/collectors", json={"name": "x"}).status_code == 401
    r = app_client.post("/api/collectors", json={"name": "Branch B", "site": "Austin"}, headers=admin)
    assert r.status_code == 201
    created = r.json()
    token = created["token"]
    assert "install.sh" in created["install"]["linux"] and token in created["install"]["windows"]
    # Collector endpoints use the collector token, not the admin token.
    assert app_client.get("/api/collector/v1/config", headers=admin).status_code == 401
    auth = {"Authorization": f"Bearer {token}", "X-Collector-Hostname": "site-box", "X-Collector-Version": "9.9"}
    r = app_client.get("/api/collector/v1/poll?wait=0", headers=auth)
    assert r.status_code == 200 and r.json()["jobs"] == []
    row = db.one("SELECT * FROM collectors")
    assert row["status"] == "online" and row["hostname"] == "site-box" and row["version"] == "9.9"
    assert app_client.get("/api/collector/v1/config", headers=auth).json()["devices"] == []
    r = app_client.post("/api/collector/v1/results", json={"results": [], "jobs": []}, headers=auth)
    assert r.json()["accepted"] == 0
    listing = app_client.get("/api/collectors", headers=admin).json()
    assert listing[0]["online"] and "token_hash" not in listing[0]
    assert app_client.post(f"/api/collectors/{row['id']}/token", headers=admin).json()["token"] != token
    assert app_client.get("/api/collector/v1/poll?wait=0", headers=auth).status_code == 401


def test_downloads_and_install_scripts(app_client):
    sh = app_client.get("/collector/install.sh")
    assert sh.status_code == 200 and "http://testserver" in sh.text and "systemctl" in sh.text
    ps1 = app_client.get("/collector/install.ps1")
    assert "Register-ScheduledTask" in ps1.text and "http://testserver" in ps1.text
    items = app_client.get("/collector/downloads").json()
    pkg = next(i for i in items if i["platform"] == "python")
    r = app_client.get(f"/collector/download/{pkg['name']}")
    assert r.status_code == 200
    with tarfile.open(fileobj=io.BytesIO(r.content)) as tar:
        names = tar.getnames()
    root = pkg["name"][:-len(".tar.gz")]
    assert f"{root}/pyproject.toml" in names and f"{root}/snmpathy/collector_agent.py" in names
    assert any(n.endswith("web/templates/base.html") for n in names)
    assert app_client.get("/collector/download/auto?os_=Windows").status_code == 404
    assert app_client.get("/collector/download/nope.exe").status_code == 404


async def test_agent_executes_jobs():
    from snmpathy.collector_agent import execute_job

    assert (await execute_job("ping", {}))["pong"] > 0
    with pytest.raises(ValueError):
        await execute_job("rm -rf", {})
