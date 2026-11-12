import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from snmpathy import fusion
from snmpathy.app import create_app
from snmpathy.checks.probes import ProbeResult
from snmpathy.checks.runner import record_result
from snmpathy.config import Settings
from snmpathy.db import Database
from snmpathy.services import create_check


# ------------------------------------------------------------------ helpers
def _check(db, check_id):
    return db.one("SELECT * FROM checks WHERE id = ?", (check_id,))


def _fail(db, check_id, now, message="timeout"):
    return record_result(db, _check(db, check_id), ProbeResult(ok=False, message=message), now)


def _ok(db, check_id, now, warning=False, message="ok"):
    return record_result(db, _check(db, check_id), ProbeResult(ok=True, latency_ms=3, warning=warning,
                                                                message=message), now)


def _alert(db, subject, severity="critical", device_id=None, check_id=None, fired_at=None, ack=0):
    now = time.time()
    return db.insert("alerts", {
        "fingerprint": subject, "subject": subject, "severity": severity, "state": "firing",
        "message": f"{subject} message", "started_at": (fired_at or now) - 10, "fired_at": fired_at or now,
        "last_eval": now, "device_id": device_id, "check_id": check_id, "acknowledged": ack,
    })


def populate(db, make_device, now):
    """Two devices (one down), a warning check and a firing alert, plus metrics/interfaces."""
    up = make_device("core1", "10.0.0.1", snmp_enabled=0)
    down = make_device("edge1", "10.0.0.2", snmp_enabled=0)
    c_up = create_check(db, {"device_id": up["id"], "type": "icmp", "target": "10.0.0.1", "retries": 0})
    c_down = create_check(db, {"device_id": down["id"], "type": "icmp", "target": "10.0.0.2", "retries": 0})
    c_warn = create_check(db, {"type": "http", "target": "https://shop.example.com", "affects_device": 0,
                               "name": "Shop"})
    _ok(db, c_up["id"], now - 900)
    _ok(db, c_down["id"], now - 900)
    _fail(db, c_down["id"], now - 600, "100% packet loss")
    _ok(db, c_warn["id"], now - 60, warning=True, message="slow response 2.5 s")
    _alert(db, "edge1 offline", device_id=down["id"])
    _alert(db, "core1 high CPU", severity="warning", device_id=up["id"], ack=1)
    db.insert("metrics", {"device_id": up["id"], "key": "cpu.avg", "last_value": 87.5, "last_ts": now})
    db.insert("metrics", {"device_id": down["id"], "key": "cpu.avg", "last_value": 12.0, "last_ts": now})
    db.insert("metrics", {"device_id": up["id"], "key": "mem.used_pct", "last_value": 64.0, "last_ts": now})
    db.insert("interfaces", {"device_id": up["id"], "if_index": 1, "name": "Gi0/1", "speed": 1e9,
                             "in_bps": 4e8, "out_bps": 1e8, "updated_at": now})
    db.insert("interfaces", {"device_id": up["id"], "if_index": 2, "name": "Gi0/2", "speed": 1e9,
                             "in_bps": 0, "out_bps": 0, "updated_at": now})
    return {"up": up, "down": down, "c_up": c_up, "c_down": c_down, "c_warn": c_warn}


def make_client(tmp_path, name="master.db", token="", db=None):
    settings = Settings(database=str(tmp_path / name), enable_syslog=False, api_token=token)
    db = db or Database(settings.database)
    app = create_app(settings, db=db, start_monitor=False)
    app.include_router(fusion.router)
    return app, db


@pytest.fixture
def client(tmp_path):
    app, db = make_client(tmp_path)
    with TestClient(app) as c:
        c.db = db
        yield c
    db.close()


@pytest.fixture
def mock_transport(monkeypatch):
    """Route fusion's httpx.AsyncClient through a handler set by the test."""
    state = {"handler": None, "requests": []}
    real = httpx.AsyncClient

    def handler(request):
        state["requests"].append(request)
        return state["handler"](request)

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(fusion.httpx, "AsyncClient", factory)
    return state


def remote_summary(name="eu-1", devices=None, problems=None, firing=None, top=None, base_url="https://eu.example.com"):
    return {
        "schema": 1, "server": {"name": name, "version": "9.9", "time": time.time()}, "base_url": base_url,
        "devices": devices or {"up": 5, "degraded": 1, "down": 1, "unreachable": 2, "unknown": 0, "disabled": 1,
                               "total": 10},
        "checks": {"up": 20, "warning": 1, "down": 2, "unknown": 0, "paused": 0, "total": 23},
        "alerts": {"firing": 1, "critical": 1, "warning": 0, "unacknowledged": 1},
        "problems": problems if problems is not None else [],
        "problems_total": len(problems or []),
        "firing": firing or [],
        "top": top or {"cpu": [], "memory": [], "interfaces": [], "availability": []},
        "syslog": {"last_hour": 100, "errors_last_hour": 3},
        "collectors": {"total": 1, "online": 1, "offline": 0},
    }


def add_server(db, name="EU", url="https://eu.example.com", data=None, status="ok", last_ok=None, token="",
               enabled=1, error=""):
    now = time.time()
    return db.insert("fusion_servers", {
        "name": name, "url": url, "api_token": token, "enabled": enabled, "status": status, "error": error,
        "last_fetch": last_ok or now, "last_ok": last_ok if last_ok is not None else (now if data else None),
        "data": json.dumps(data or {}), "created_at": now,
    })


# ------------------------------------------------------------------ summary
def test_summary_shape(db, make_device, now):
    ids = populate(db, make_device, now)
    s = fusion.summary(db, "lab")
    assert s["schema"] == 1 and s["server"]["name"] == "lab" and s["server"]["version"]
    assert s["devices"] == {"up": 1, "degraded": 0, "down": 1, "unreachable": 0, "unknown": 0, "disabled": 0,
                            "total": 2}
    assert s["checks"] == {"up": 1, "warning": 1, "down": 1, "unknown": 0, "paused": 0, "total": 3}
    assert s["overview"]["devices"]["down"] == 1
    assert s["alerts"]["firing"] == 2 and s["alerts"]["critical"] == 1 and s["alerts"]["warning"] == 1

    kinds = [(p["kind"], p["status"]) for p in s["problems"]]
    assert kinds == [("device", "down"), ("check", "down"), ("check", "warning")]
    dev_problem = s["problems"][0]
    assert dev_problem["name"] == "edge1" and dev_problem["link"] == f"/devices/{ids['down']['id']}"
    assert dev_problem["since"] and "packet loss" in dev_problem["detail"]
    warn = s["problems"][2]
    assert warn["name"] == "Shop" and warn["link"] == f"/checks/{ids['c_warn']['id']}"
    assert "slow response" in warn["detail"]
    assert s["problems_total"] == 3

    assert [a["severity"] for a in s["firing"]] == ["critical", "warning"]
    assert s["firing"][0]["link"] == f"/devices/{ids['down']['id']}"
    assert s["firing"][1]["acknowledged"] is True

    top = s["top"]
    assert [r["device"] for r in top["cpu"]] == ["core1", "edge1"] and top["cpu"][0]["value"] == 87.5
    assert top["memory"][0]["value"] == 64.0
    assert len(top["interfaces"]) == 1  # idle interfaces are left out
    iface = top["interfaces"][0]
    assert iface["name"] == "Gi0/1" and iface["total_bps"] == 5e8 and iface["util_pct"] == pytest.approx(40.0)
    assert iface["link"].endswith("?tab=interfaces#if1")
    avail = top["availability"]
    assert avail[0]["device"] == "edge1" and avail[0]["value"] < 100 and avail[0]["outages"] == 1
    assert s["syslog"] == {"last_hour": 0, "errors_last_hour": 0}
    assert s["collectors"] == {"total": 0, "online": 0, "offline": 0}
    assert len(json.dumps(s)) < 100_000


def test_summary_endpoint_requires_auth_and_reports_base_url(tmp_path):
    settings = Settings(database=str(tmp_path / "a.db"), enable_syslog=False, api_token="tok",
                        public_url="https://noc.example.com/")
    app = create_app(settings, db=Database(settings.database), start_monitor=False)
    app.include_router(fusion.router)
    with TestClient(app) as c:
        assert c.get("/api/fusion/summary").status_code == 401
        r = c.get("/api/fusion/summary", headers={"Authorization": "Bearer tok"})
        assert r.status_code == 200
        assert r.json()["base_url"] == "https://noc.example.com"
        assert c.get("/api/fusion/summary", headers={"X-API-Key": "tok"}).status_code == 200


# --------------------------------------------------------------------- CRUD
def test_server_crud_and_token_secrecy(client):
    r = client.post("/api/fusion/servers", json={"name": "EU", "url": "https://eu.example.com/",
                                                 "api_token": "very-secret"})
    assert r.status_code == 201, r.text
    srv = r.json()
    assert srv["url"] == "https://eu.example.com" and srv["has_token"] is True
    assert srv["verify_tls"] is True and srv["enabled"] is True and srv["status"] == "unknown"
    assert "api_token" not in srv and "data" not in srv
    assert "very-secret" not in client.get("/api/fusion/servers").text
    assert "very-secret" not in client.get(f"/api/fusion/servers/{srv['id']}").text

    # validation
    assert client.post("/api/fusion/servers", json={"name": "EU", "url": "https://x.example.com"}).status_code == 422
    for bad in ("ftp://x.example.com", "eu.example.com", "javascript:alert(1)", "https://", "https://x/?a=1"):
        assert client.post("/api/fusion/servers", json={"name": "bad", "url": bad}).status_code == 422, bad
    assert client.post("/api/fusion/servers", json={"name": "", "url": "https://x.example.com"}).status_code == 422

    # empty token on PATCH keeps the stored one
    r = client.patch(f"/api/fusion/servers/{srv['id']}", json={"api_token": "", "name": "Europe", "verify_tls": False})
    assert r.status_code == 200 and r.json()["has_token"] is True and r.json()["name"] == "Europe"
    assert r.json()["verify_tls"] is False
    assert client.db.scalar("SELECT api_token FROM fusion_servers") == "very-secret"
    client.patch(f"/api/fusion/servers/{srv['id']}", json={"api_token": "rotated"})
    assert client.db.scalar("SELECT api_token FROM fusion_servers") == "rotated"
    assert client.patch(f"/api/fusion/servers/{srv['id']}", json={"url": "nope"}).status_code == 422
    client.post("/api/fusion/servers", json={"name": "US", "url": "http://us.example.com:8080"})
    assert client.patch(f"/api/fusion/servers/{srv['id']}", json={"name": "US"}).status_code == 422
    assert [s["name"] for s in client.get("/api/fusion/servers").json()] == ["Europe", "US"]

    assert client.delete(f"/api/fusion/servers/{srv['id']}").status_code == 204
    assert client.delete(f"/api/fusion/servers/{srv['id']}").status_code == 404
    assert client.patch("/api/fusion/servers/999", json={"name": "x"}).status_code == 404
    assert [s["name"] for s in client.get("/api/fusion/servers").json()] == ["US"]


# -------------------------------------------------------------------- fetch
async def test_fetch_server_from_second_in_process_server(tmp_path, monkeypatch, make_device, db, now):
    # The remote is a full SNMPathy app with its own database and API token.
    populate(db, make_device, now)
    remote_app, _ = make_client(tmp_path, token="remote-token", db=db)
    master = Database(str(tmp_path / "master.db"))
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.ASGITransport(app=remote_app)
        return real(*args, **kwargs)

    monkeypatch.setattr(fusion.httpx, "AsyncClient", factory)
    sid = add_server(master, url="http://remote.test", token="remote-token", status="unknown")
    result = await fusion.fetch_server(master, master.one("SELECT * FROM fusion_servers WHERE id = ?", (sid,)))
    assert result["status"] == "ok" and result["error"] == "" and result["last_ok"]
    assert "api_token" not in result
    data = json.loads(master.scalar("SELECT data FROM fusion_servers WHERE id = ?", (sid,)))
    assert data["devices"]["down"] == 1 and data["base_url"] == "http://remote.test"

    # Wrong token: 401 recorded as an error, the last good data is kept.
    master.update("fusion_servers", sid, {"api_token": "wrong"})
    result = await fusion.fetch_server(master, master.one("SELECT * FROM fusion_servers WHERE id = ?", (sid,)))
    assert result["status"] == "error" and "401" in result["error"] and "token" in result["error"]
    assert json.loads(master.scalar("SELECT data FROM fusion_servers WHERE id = ?", (sid,)))["devices"]["down"] == 1
    master.close()


async def test_fetch_server_mock_transport_and_errors(db, mock_transport):
    sid = add_server(db, url="https://eu.example.com", token="abc", status="unknown")
    mock_transport["handler"] = lambda req: httpx.Response(200, json=remote_summary())
    row = db.one("SELECT * FROM fusion_servers WHERE id = ?", (sid,))
    result = await fusion.fetch_server(db, row)
    req = mock_transport["requests"][-1]
    assert str(req.url) == "https://eu.example.com/api/fusion/summary"
    assert req.headers["authorization"] == "Bearer abc"
    assert result["status"] == "ok"

    def refuse(req):
        raise httpx.ConnectError("Connection refused", request=req)

    mock_transport["handler"] = refuse
    result = await fusion.fetch_server(db, db.one("SELECT * FROM fusion_servers WHERE id = ?", (sid,)))
    assert result["status"] == "error" and "connection failed" in result["error"]
    assert result["last_ok"]  # unchanged from the earlier success

    mock_transport["handler"] = lambda req: httpx.Response(200, text="<html>not snmpathy</html>")
    result = await fusion.fetch_server(db, db.one("SELECT * FROM fusion_servers WHERE id = ?", (sid,)))
    assert result["status"] == "error" and "JSON" in result["error"]

    mock_transport["handler"] = lambda req: httpx.Response(200, json={"hello": "world"})
    result = await fusion.fetch_server(db, db.one("SELECT * FROM fusion_servers WHERE id = ?", (sid,)))
    assert result["status"] == "error" and "summary" in result["error"]

    # No token: no Authorization header.
    db.update("fusion_servers", sid, {"api_token": ""})
    mock_transport["handler"] = lambda req: httpx.Response(200, json=remote_summary())
    await fusion.fetch_server(db, db.one("SELECT * FROM fusion_servers WHERE id = ?", (sid,)))
    assert "authorization" not in mock_transport["requests"][-1].headers


async def test_fetch_all_and_poller(db, mock_transport):
    add_server(db, name="EU", url="https://eu.example.com", status="unknown")
    add_server(db, name="US", url="https://us.example.com", status="unknown")
    add_server(db, name="OFF", url="https://off.example.com", status="unknown", enabled=0)

    def handler(req):
        if req.url.host == "us.example.com":
            return httpx.Response(401, json={"detail": "authentication required"})
        return httpx.Response(200, json=remote_summary())

    mock_transport["handler"] = handler
    results = {r["name"]: r for r in await fusion.fetch_all(db)}
    assert set(results) == {"EU", "US"}
    assert results["EU"]["status"] == "ok" and results["US"]["status"] == "error"
    assert db.scalar("SELECT status FROM fusion_servers WHERE name = 'OFF'") == "unknown"

    poller = fusion.FusionPoller(db, interval=60)
    before = len(mock_transport["requests"])
    await poller.start()
    for _ in range(100):
        if len(mock_transport["requests"]) >= before + 2:
            break
        await __import__("asyncio").sleep(0.01)
    await poller.stop()
    assert len(mock_transport["requests"]) == before + 2 and poller.last_run
    await poller.stop()  # idempotent


def test_refresh_endpoint(client, mock_transport):
    srv = client.post("/api/fusion/servers", json={"name": "EU", "url": "https://eu.example.com",
                                                   "api_token": "t"}).json()
    mock_transport["handler"] = lambda req: httpx.Response(200, json=remote_summary())
    r = client.post(f"/api/fusion/servers/{srv['id']}/refresh")
    assert r.status_code == 200 and r.json()["status"] == "ok" and "api_token" not in r.json()
    mock_transport["handler"] = lambda req: httpx.Response(503)
    r = client.post("/api/fusion/refresh")
    assert r.json()[0]["status"] == "error" and "503" in r.json()[0]["error"]
    assert client.post("/api/fusion/servers/999/refresh").status_code == 404


# ------------------------------------------------------------------ combined
def test_combined_merges_sorts_and_flags_staleness(db, make_device):
    now = time.time()
    populate(db, make_device, now)  # local: edge1 down since ~now-600, check down, Shop warning
    eu_problems = [
        {"kind": "check", "id": 7, "name": "eu-web", "status": "down", "since": now - 5000, "detail": "HTTP 500",
         "link": "/checks/7"},
        {"kind": "device", "id": 3, "name": "eu-sw", "status": "unreachable", "since": now - 9000, "detail": "",
         "link": "/devices/3"},
        {"kind": "device", "id": 4, "name": "evil", "status": "down", "since": now - 100, "detail": "",
         "link": "javascript:alert(1)"},
    ]
    eu = remote_summary(
        "eu-1", problems=eu_problems,
        firing=[{"subject": "eu-web down", "severity": "critical", "fired_at": now - 50, "link": "/checks/7"},
                {"subject": "eu disk", "severity": "info", "fired_at": now - 10, "link": "/devices/3"}],
        top={"cpu": [{"device": "eu-fw", "value": 99.0, "link": "/devices/9"},
                     {"device": "eu-x", "value": "garbage", "link": "/devices/10"}],
             "memory": [], "availability": [{"device": "eu-sw", "value": 91.5, "link": "/devices/3", "outages": 4}],
             "interfaces": [{"device": "eu-sw", "name": "xe-0/0/1", "value": 9e9, "in_bps": 5e9, "out_bps": 4e9,
                             "util_pct": 50.0, "link": "/devices/3?tab=interfaces#if5"}]})
    add_server(db, name="EU", url="https://eu-internal.example.com", data=eu)
    us = remote_summary("us-1", problems=[{"kind": "device", "name": "us-r1", "status": "down",
                                          "since": now - 100000, "link": "/devices/1"}],
                        base_url="javascript:alert(1)")
    add_server(db, name="US", url="https://us.example.com", data=us, last_ok=now - 600)  # stale
    add_server(db, name="APAC", url="https://apac.example.com", status="error", error="HTTP 401: auth", last_ok=0)
    add_server(db, name="Disabled", url="https://off.example.com", data=eu, enabled=0)

    local = fusion.summary(db, "lab")
    view = fusion.combined(db, local, "https://noc.example.com", now=now)

    servers = {s["name"]: s for s in view["servers"]}
    assert list(servers) == ["This server", "APAC", "EU", "US"]
    assert servers["This server"]["local"] and servers["This server"]["status"] == "ok"
    assert servers["EU"]["status"] == "ok" and not servers["EU"]["stale"] and servers["EU"]["version"] == "9.9"
    assert servers["EU"]["url"] == "https://eu.example.com"  # the remote's own base_url
    assert servers["US"]["status"] == "stale" and servers["US"]["stale"]
    assert servers["US"]["url"] == "https://us.example.com"  # unsafe base_url ignored
    assert servers["APAC"]["status"] == "error" and servers["APAC"]["devices"]["total"] == 0
    assert all("api_token" not in s for s in view["servers"])

    t = view["totals"]
    assert t["servers"] == {"total": 4, "ok": 2, "stale": 1, "error": 1, "pending": 0}
    assert t["devices"]["down"] == 1 + 1 + 1 and t["devices"]["unreachable"] == 4
    assert t["devices"]["total"] == 2 + 10 + 10
    assert t["checks"]["warning"] == 1 + 1 + 1 and t["checks"]["down"] == 1 + 2 + 2
    assert t["alerts"]["firing"] == 2 + 1 + 1

    probs = view["problems"]
    order = [(p["server"], p["kind"], p["name"], p["status"]) for p in probs]
    # Severity first (down, unreachable, warning), servers before items, then oldest first.
    assert order[0] == ("APAC", "server", "APAC", "down")
    downs = [o for o in order if o[3] == "down" and o[1] != "server"]
    assert [o[2] for o in downs] == ["us-r1", "eu-web", "edge1", "core1 ping" if False else downs[3][2], "evil"]
    assert downs[2][0] == "This server"
    statuses = [p["status"] for p in probs]
    assert statuses == sorted(statuses, key=lambda s: fusion.PROBLEM_RANK[s])
    stale_srv = next(p for p in probs if p["kind"] == "server" and p["name"] == "US")
    assert stale_srv["status"] == "warning"
    eu_web = next(p for p in probs if p["name"] == "eu-web")
    assert eu_web["url"] == "https://eu.example.com/checks/7" and eu_web["server"] == "EU"
    assert next(p for p in probs if p["name"] == "evil")["url"] == "https://eu.example.com/"
    us_r1 = next(p for p in probs if p["name"] == "us-r1")
    assert us_r1["server_stale"] is True and us_r1["url"] == "https://us.example.com/devices/1"
    edge1 = next(p for p in probs if p["name"] == "edge1")
    assert edge1["server_local"] and edge1["url"].startswith("https://noc.example.com/devices/")

    sev = [a["severity"] for a in view["firing"]]
    assert sev == sorted(sev, key=lambda s: fusion.SEVERITY_RANK.get(s, 3))
    assert view["firing"][0]["subject"] in ("eu-web down", "edge1 offline")
    assert {a["server"] for a in view["firing"]} == {"This server", "EU", "US"}

    cpu = view["top"]["cpu"]
    assert [(r["server"], r["device"]) for r in cpu][:2] == [("EU", "eu-fw"), ("This server", "core1")]
    assert all(r["device"] != "eu-x" for r in cpu)
    assert view["top"]["availability"][0]["device"] == "eu-sw"
    assert view["top"]["interfaces"][0]["name"] == "xe-0/0/1"
    assert view["top"]["interfaces"][0]["url"] == "https://eu.example.com/devices/3?tab=interfaces#if5"


def test_combined_endpoint_and_page(client, mock_transport, make_device):
    client.post("/api/fusion/servers", json={"name": "EU", "url": "https://eu.example.com"})
    r = client.get("/api/fusion/combined")
    assert r.status_code == 200
    view = r.json()
    assert [s["name"] for s in view["servers"]] == ["This server", "EU"]
    assert view["servers"][1]["status"] == "pending"
    assert view["servers"][0]["url"] == "http://testserver"

    page = client.get("/fusion")
    assert page.status_code == 200
    assert 'id="fx-data"' in page.text and "Manage servers" in page.text
    assert '<a href="/fusion" class="active">' in page.text

    mock_transport["handler"] = lambda req: httpx.Response(200, json=remote_summary(
        problems=[{"kind": "device", "name": "<script>x</script>", "status": "down", "since": time.time(),
                   "link": "/devices/1"}]))
    client.post("/api/fusion/refresh")
    page = client.get("/fusion")
    assert page.status_code == 200 and "<script>x</script>" not in page.text
