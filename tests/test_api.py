import time

import pytest
from fastapi.testclient import TestClient

from snmpathy.app import create_app
from snmpathy.config import Settings
from snmpathy.db import Database


@pytest.fixture
def client(tmp_path):
    settings = Settings(database=str(tmp_path / "api.db"), enable_syslog=False)
    app = create_app(settings, db=Database(settings.database), start_monitor=False)
    with TestClient(app) as c:
        yield c


def test_seeded_defaults(client):
    rules = client.get("/api/rules").json()
    assert any(r["kind"] == "device" for r in rules)
    assert client.get("/api/channels").json()[0]["type"] == "log"
    boards = client.get("/api/dashboards").json()
    assert {"network-overview", "syslog"} <= {b["slug"] for b in boards}


def test_device_crud_and_secrets(client):
    r = client.post("/api/devices", json={"name": "fw1", "hostname": "10.0.0.2", "snmp_version": "3",
                                          "v3_user": "mon", "v3_auth_key": "secretpass", "tags": ["edge"]})
    assert r.status_code == 201, r.text
    dev = r.json()
    assert dev["v3_auth_key"] == "" and dev["has_v3_auth_key"] is True
    assert dev["tags"] == ["edge"]
    # A ping check is created with the device.
    checks = client.get(f"/api/checks?device_id={dev['id']}").json()
    assert checks[0]["type"] == "icmp" and checks[0]["target"] == "10.0.0.2"
    assert client.post("/api/devices", json={"name": "fw1", "hostname": "x"}).status_code == 422
    # Empty secret on update keeps the stored one.
    r = client.patch(f"/api/devices/{dev['id']}", json={"v3_auth_key": "", "location": "DC1", "hostname": "10.0.0.3"})
    assert r.json()["has_v3_auth_key"] is True and r.json()["location"] == "DC1"
    assert client.get(f"/api/checks?device_id={dev['id']}").json()[0]["target"] == "10.0.0.3"
    assert client.get("/api/devices?tag=edge").json()[0]["name"] == "fw1"
    assert client.delete(f"/api/devices/{dev['id']}").status_code == 204
    assert client.get(f"/api/devices/{dev['id']}").status_code == 404
    assert client.get("/api/checks").json() == []


def test_checks_rules_channels_maintenance(client):
    r = client.post("/api/checks", json={"type": "http", "target": "https://example.com", "options": {"keyword": "x"}})
    assert r.status_code == 201
    check = r.json()
    assert check["name"] == "HTTP https://example.com" and check["options"] == {"keyword": "x"}
    assert client.post("/api/checks", json={"type": "tcp", "target": "h"}).status_code == 422
    assert client.patch(f"/api/checks/{check['id']}", json={"interval": 30}).json()["interval"] == 30
    assert client.get(f"/api/checks/{check['id']}/uptime?days=7").json()["daily"][-1]["uptime_pct"] is None

    r = client.post("/api/rules", json={"name": "cpu", "kind": "metric", "metric_key": "cpu.avg", "threshold": 80})
    assert r.status_code == 201
    assert client.post("/api/rules", json={"name": "bad", "kind": "metric"}).status_code == 422

    r = client.post("/api/channels", json={"name": "pd", "type": "pagerduty", "config": {"routing_key": "abc"}})
    assert r.json()["config"]["routing_key"] == "********"
    cid = r.json()["id"]
    client.patch(f"/api/channels/{cid}", json={"config": {"routing_key": "********", "url": "http://x"}})
    from snmpathy.db import loads

    raw = client.app.state.db.one("SELECT config FROM channels WHERE id = ?", (cid,))["config"]
    assert loads(raw, {})["routing_key"] == "abc"

    r = client.post("/api/maintenance", json={"name": "upgrade", "duration_minutes": 30})
    assert r.status_code == 201
    assert len(client.get("/api/maintenance?active=true").json()) == 1


def test_syslog_search_endpoints(client):
    db = client.app.state.db
    now = time.time()
    db.executemany(
        "INSERT INTO syslog (ts, received_at, host, severity, facility, app, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(now - 60, now - 60, "sw1", 3, 23, "LINK-3-UPDOWN", "Interface Gi0/1, changed state to down"),
         (now - 30, now - 30, "fw1", 6, 16, "fortigate", "traffic accept dstport=443"),
         (now - 10, now - 10, "sw1", 5, 23, "SYS-5-CONFIG_I", "Configured from console by admin")])
    assert len(client.get("/api/syslog?range=1h").json()) == 3
    hits = client.get('/api/syslog', params={"q": '"changed state"'}).json()
    assert [h["host"] for h in hits] == ["sw1"]
    assert client.get("/api/syslog", params={"q": "configured -admin"}).json() == []
    assert len(client.get("/api/syslog?severity=err").json()) == 1
    assert len(client.get("/api/syslog?host=s*").json()) == 2
    # Odd FTS syntax must not error.
    assert client.get("/api/syslog", params={"q": 'foo-bar "unterminated'}).status_code == 200
    assert client.get("/api/syslog/count?range=1h").json()["count"] == 3
    top = client.get("/api/syslog/top?field=host").json()
    assert top[0] == {"value": "sw1", "count": 2}
    hist = client.get("/api/syslog/histogram?range=1h&buckets=12").json()
    assert sum(b["error"] + b["warning"] + b["info"] for b in hist["buckets"]) == 3


def test_dashboard_crud_and_panel_data(client):
    r = client.post("/api/dashboards", json={"name": "Mine", "config": {"panels": [
        {"type": "timeseries", "title": "t", "targets": [{"key": "if.in_bps"}]},
        {"type": "summary"}, {"type": "text", "options": {"text": "hello"}}]}})
    assert r.status_code == 201, r.text
    dash = r.json()
    assert dash["slug"] == "mine" and dash["config"]["panels"][0]["w"] == 6
    assert client.post("/api/dashboards", json={"name": "bad", "config": {"panels": [{"type": "nope"}]}}).status_code == 422
    for panel in dash["config"]["panels"]:
        assert client.post("/api/panel-data", json={"panel": panel, "range": "6h"}).status_code == 200
    copy = client.post(f"/api/dashboards/{dash['id']}/duplicate").json()
    assert copy["slug"] == "mine-copy"
    assert client.get("/api/dashboards/mine").json()["id"] == dash["id"]
    client.delete(f"/api/dashboards/{dash['id']}")
    assert client.get("/api/dashboards/mine").status_code == 404


def test_reports_api_and_csv(client):
    for report in client.get("/api/report-types").json():
        r = client.get(f"/api/reports/{report}?range=7d")
        assert r.status_code == 200 and r.json()["id"] == report
        csv = client.get(f"/api/reports/{report}?range=last_month&format=csv")
        assert csv.headers["content-type"].startswith("text/csv")
    assert client.get("/api/reports/nope").status_code == 404
    r = client.post("/api/report-schedules", json={"name": "weekly", "report": "uptime", "frequency": "weekly"})
    assert r.status_code == 201 and r.json()["range"] == "last_week"


def test_export_import_roundtrip(client, tmp_path):
    client.post("/api/devices", json={"name": "r1", "hostname": "10.9.9.9"})
    client.post("/api/checks", json={"type": "icmp", "target": "10.9.9.9", "name": "r1 extra"})
    exported = client.get("/api/export").json()
    other = TestClient(create_app(Settings(database=str(tmp_path / "other.db")), start_monitor=False))
    counts = other.post("/api/import", json=exported).json()
    assert counts["devices"] == 1 and counts["checks"] == 2
    assert other.post("/api/import", json=exported).json()["devices"] == 0  # idempotent


def test_grafana_datasource_protocol(client):
    db = client.app.state.db
    dev = client.post("/api/devices", json={"name": "core-sw01", "hostname": "10.0.0.1", "tags": ["core"]}).json()
    now = int(time.time())
    mid = db.insert("metrics", {"device_id": dev["id"], "key": "if.in_bps", "instance": "1", "label": "Gi0/1",
                                "kind": "counter", "unit": "bps", "last_value": 5.0, "last_ts": now})
    db.executemany("INSERT INTO samples VALUES (?, ?, ?)", [(mid, now - i * 60, 1000.0 + i) for i in range(30)])
    assert client.get("/grafana").json()["status"] == "ok"
    metrics = client.post("/grafana/metrics", json={}).json()
    assert {"metric", "check", "syslog", "devices", "count"} <= {m["value"] for m in metrics}
    body = {"range": {"from": "2000-01-01T00:00:00.000Z", "to": "2100-01-01T00:00:00.000Z"},
            "maxDataPoints": 500, "intervalMs": 60000,
            "targets": [{"refId": "A", "target": "metric", "payload": {"key": "if.in_bps", "device": "(core\\-sw01|x)"}},
                        {"refId": "B", "target": "devices", "payload": {}},
                        {"refId": "C", "target": "count", "payload": {"what": "devices_total"}}]}
    body["range"]["from"] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(now - 3600))
    body["range"]["to"] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(now + 60))
    out = client.post("/grafana/query", json=body).json()
    series = out[0]
    assert series["target"] == "core-sw01 Gi0/1" and len(series["datapoints"]) >= 29
    value, ts_ms = series["datapoints"][0]
    assert ts_ms > 1e12 and value > 999
    assert out[1]["type"] == "table" and out[1]["rows"][0][0] == "core-sw01"
    assert out[2]["datapoints"][0][0] == 1
    variables = client.post("/grafana/variable", json={"payload": {"target": "devices"}}).json()
    assert variables == [{"__text": "core-sw01", "__value": "core-sw01"}]
    assert client.post("/grafana/variable", json={"payload": {"target": "tags"}}).json()[0]["__text"] == "core"
    boards = client.get("/grafana/dashboards").json()
    assert len(boards) == 5
    board = client.get("/grafana/dashboards/snmpathy-overview").json()
    assert board["panels"] and all(p["datasource"]["uid"] == "snmpathy" for p in board["panels"])


def test_token_auth(tmp_path):
    settings = Settings(database=str(tmp_path / "auth.db"), api_token="s3cret")
    with TestClient(create_app(settings, start_monitor=False)) as c:
        assert c.get("/api/status").status_code == 401
        assert c.get("/grafana/metrics").status_code in (401, 405)
        assert c.get("/api/status", headers={"Authorization": "Bearer s3cret"}).status_code == 200
        assert c.get("/api/status", headers={"X-API-Key": "s3cret"}).status_code == 200
        assert c.get("/devices", follow_redirects=False).status_code == 303
        assert c.get("/status").status_code == 200  # public status page
        assert c.get("/healthz").status_code == 200
        r = c.post("/login", data={"token": "wrong", "next": "/"}, follow_redirects=False)
        assert "error=1" in r.headers["location"]
        r = c.post("/login", data={"token": "s3cret", "next": "/devices"}, follow_redirects=False)
        assert r.headers["location"] == "/devices"
        assert c.get("/devices").status_code == 200  # cookie set by login


def test_every_page_renders(client):
    dev = client.post("/api/devices", json={"name": "sw", "hostname": "10.0.0.1"}).json()
    check = client.get("/api/checks").json()[0]
    pages = ["/", "/devices", "/devices/new", f"/devices/{dev['id']}", f"/devices/{dev['id']}/edit",
             "/checks", f"/checks/{check['id']}", "/syslog", "/alerts", "/reports", "/dashboards",
             "/dashboards/network-overview", "/maintenance", "/settings", "/status", "/login"]
    pages += [f"/devices/{dev['id']}?tab={t}" for t in ("interfaces", "metrics", "checks", "syslog", "events")]
    pages += [f"/alerts?tab={t}" for t in ("history", "rules", "channels", "notifications")]
    pages += [f"/reports/{r}?range={rng}" for r in ("uptime", "health", "bandwidth", "syslog", "alerts")
              for rng in ("24h", "last_month")]
    for page in pages:
        r = client.get(page)
        assert r.status_code == 200, (page, r.text[:500])
