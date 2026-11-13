"""Nagios-style dashlets (snmpathy/hud.py), dashboard device groups, cluster dashboards and the HUD Overview."""

import json
import time

from fastapi.testclient import TestClient

from snmpathy import dashboards, hud
from snmpathy.app import create_app
from snmpathy.config import Settings
from snmpathy.syslog.server import message_row, store_messages
from snmpathy.syslog.structured import parse_json_event

NOW = time.time()


def _net(db, make_device):
    a = make_device("core", "10.0.0.1", location="HQ / MDF", tags=["hq"])
    b = make_device("access", "10.0.0.2", location="HQ / IDF", tags=["hq"])
    c = make_device("branch", "10.1.0.1", location="Denver", tags=["wan"])
    d = make_device("nas", "10.0.0.9", location="HQ / MDF", tags=["hq", "storage"])
    db.update("devices", a["id"], {"status": "up"})
    db.update("devices", b["id"], {"status": "up", "degraded": 1, "parent_id": a["id"]})
    db.update("devices", c["id"], {"status": "down"})
    db.update("devices", d["id"], {"status": "unreachable", "parent_id": a["id"]})
    for name, dev, state, warn in [("core ping", a, "up", 0), ("web", b, "up", 1), ("vpn", c, "down", 0), ("nas ping", d, "unknown", 0)]:
        db.insert("checks", {"device_id": dev["id"], "name": name, "type": "icmp", "target": dev["hostname"],
                             "state": state, "warning": warn, "created_at": NOW, "updated_at": NOW})
    return a, b, c, d


def test_scope_selects_a_device_group(db, make_device):
    a, b, c, d = _net(db, make_device)
    assert hud.scope_device_ids(db, None) is None and hud.scope_device_ids(db, {}) is None
    assert hud.scope_device_ids(db, {"tag": "hq"}) == {a["id"], b["id"], d["id"]}
    assert hud.scope_device_ids(db, {"site": "Denver"}) == {c["id"]}
    assert hud.scope_device_ids(db, {"devices": ["core", str(c["id"]), "10.0.0.2"]}) == {a["id"], b["id"], c["id"]}
    assert hud.scope_device_ids(db, {"tag": "hq", "site": "HQ", "devices": ["nas"]}) == {d["id"]}
    assert hud.describe_scope({"tag": "hq", "devices": ["a", "b"]}) == "tag hq · 2 devices"


def test_status_donuts_and_bars(db, make_device):
    a, b, c, d = _net(db, make_device)
    donut = hud.status_donut(db, {"of": "devices"}, None)
    assert {s["state"]: s["count"] for s in donut["segments"]} == {"ok": 1, "warning": 1, "serious": 1, "critical": 1}
    assert donut["total"] == 4 and donut["segments"][0]["href"] == "/devices?state=ok"
    checks = hud.status_donut(db, {"of": "checks"}, {a["id"], b["id"]})
    assert {s["label"]: s["count"] for s in checks["segments"]} == {"OK": 1, "Warning": 1}
    assert hud.status_donut(db, {"of": "alerts"}, None)["total"] == 0
    bars = hud.status_bars(db, {"group_by": "site"}, None)
    assert [(r["name"], r["total"], r["worst"]) for r in bars["rows"]] == [("HQ", 3, "serious"), ("Denver", 1, "critical")]
    by_tag = {r["name"]: r["counts"] for r in hud.status_bars(db, {"group_by": "tag", "of": "checks"}, None)["rows"]}
    assert by_tag["hq"] == {"ok": 1, "warning": 1, "unknown": 1} and by_tag["wan"] == {"critical": 1}


def test_group_status_treemap_hypermap_and_services(db, make_device):
    a, b, c, d = _net(db, make_device)
    assert hud.group_status(db, {}, {a["id"]}, {"devices": ["core"]})["state"] == "ok"
    tile = hud.group_status(db, {}, None, None)
    assert (tile["state"], tile["label"], tile["name"], tile["problems"]) == ("critical", "Critical", "All devices", 5)
    groups = {g["name"]: g for g in hud.treemap(db, {}, None)["groups"]}
    assert [i["name"] for i in groups["core"]["items"]] == ["SNMP", "core ping"]
    assert groups["branch"]["items"][-1]["state"] == "critical"
    nodes = {n["id"]: n for n in hud.hypermap(db, {}, None)["nodes"]}
    assert nodes[f"d{b['id']}"]["parent"] == f"d{a['id']}" and nodes[f"d{a['id']}"]["parent"] == "root"
    assert nodes[f"d{d['id']}"]["state"] == "serious"
    # a device whose parent is outside the group hangs off the centre instead
    scoped = {n["id"]: n for n in hud.hypermap(db, {}, {b["id"]})["nodes"]}
    assert scoped[f"d{b['id']}"]["parent"] == "root"
    rows = {r["name"]: r for r in hud.device_services(db, {}, None)["rows"]}
    assert [(ch["name"], ch["state"]) for ch in rows["access"]["chips"]] == [("SNMP", "unknown"), ("web", "warning")]


def test_state_changes_from_events(db, make_device):
    a, b, c, d = _net(db, make_device)
    db.log_event("device.down", "branch is DOWN: no reply", "error", device_id=c["id"], ts=NOW - 30)
    db.log_event("device.change", "core: interface Gi0/1 changed state up -> down", "warning", device_id=a["id"], ts=NOW - 20)
    db.log_event("alert.firing", "[critical] Website slow: response 3 s", "error", ts=NOW - 10)
    db.log_event("alert.resolved", "RESOLVED branch is down: ", "info", device_id=c["id"], ts=NOW - 5)
    db.log_event("device.added", "Device x added", ts=NOW)  # not a state change
    rows = hud.state_changes(db, {"limit": 10}, None)["rows"]
    assert [(r["label"], r["name"], r["output"]) for r in rows] == [
        ("OK", "branch", "Resolved: branch is down"),
        ("CRITICAL", "Website slow", "response 3 s"),
        ("WARNING", "core", "interface Gi0/1 changed state up -> down"),
        ("CRITICAL", "branch", "is DOWN: no reply"),
    ]
    assert [r["name"] for r in hud.state_changes(db, {}, {a["id"]})["rows"]] == ["core"]


def test_log_dashlets(db):
    rows = []
    for i, (code, ip) in enumerate([(200, "10.0.0.5"), (200, "10.0.0.5"), (404, "10.0.0.6"), (500, "10.0.0.5")]):
        event = {"host": "web01", "short_message": f"GET /x {code}", "timestamp": NOW - 60 + i, "_status": code,
                 "_client_ip": ip, "level": 6 if code < 500 else 3}
        rows.append(message_row(parse_json_event(json.dumps(event), "10.9.9.9", NOW)))
    store_messages(db, rows)
    panel = {"type": "log_queries", "targets": [{"q": ""}, {"q": "status:5*", "label": "5xx"}], "options": {"buckets": 10}}
    data = dashboards.panel_data(db, panel, NOW - 3600, NOW)
    assert [(s["name"], s["count"]) for s in data["series"]] == [("all messages", 4), ("5xx", 1)]
    top = dashboards.panel_data(db, {"type": "log_field", "options": {"field": "client_ip"}, "targets": [{}]}, NOW - 3600, NOW)
    assert [(r["label"], r["count"]) for r in top["rows"]] == [("10.0.0.5", 3), ("10.0.0.6", 1)] and top["total"] == 4


def test_panel_data_respects_the_dashboard_group(db, make_device):
    a, b, c, d = _net(db, make_device)
    for dev, v in [(a, 10.0), (c, 90.0)]:
        db.insert("metrics", {"device_id": dev["id"], "key": "cpu.avg", "instance": "", "label": "", "kind": "gauge",
                              "unit": "%", "enabled": 1, "last_value": v, "last_ts": NOW})
    bars = {"type": "bars", "targets": [{"key": "cpu.avg"}], "options": {}}
    assert [r["name"] for r in dashboards.panel_data(db, bars, NOW - 60, NOW)["rows"]] == ["branch", "core"]
    assert [r["name"] for r in dashboards.panel_data(db, bars, NOW - 60, NOW, {"tag": "hq"})["rows"]] == ["core"]
    status = dashboards.panel_data(db, {"type": "status", "options": {"of": "devices"}}, NOW - 60, NOW, {"site": "Denver"})
    assert [i["name"] for i in status["items"]] == ["branch"]
    # scope is validated and stored on the dashboard
    cfg = dashboards.normalize_config({"scope": {"tag": "hq", "site": "", "junk": 1}, "panels": []})
    assert cfg["scope"] == {"tag": "hq"}
    assert "scope" not in dashboards.normalize_config({"scope": {"tag": ""}, "panels": []})


def test_cluster_api_overview_and_filters(tmp_path, db, make_device):
    a, b, c, d = _net(db, make_device)
    app = create_app(Settings(database=str(tmp_path / "t.db"), enable_syslog=False), db=db, start_monitor=False)
    with TestClient(app) as client:
        r = client.post("/api/dashboards/cluster", json={"name": "HQ cluster", "tag": "hq"})
        assert r.status_code == 201
        dash = r.json()
        assert dash["config"]["scope"] == {"tag": "hq"} and "3 devices" in dash["description"]
        assert {p["type"] for p in dash["config"]["panels"]} >= {"group_status", "treemap", "hypermap", "device_services"}
        page = client.get(f"/dashboards/{dash['slug']}").text
        assert "Group: tag hq · 3 devices" in page
        assert client.post("/api/dashboards/cluster", json={"name": "x", "tag": "missing"}).status_code == 422
        assert client.post("/api/dashboards/cluster", json={"name": "x"}).status_code == 422
        r = client.post("/api/panel-data", json={"panel": {"type": "status_donut", "options": {"of": "devices"}},
                                                 "scope": {"site": "Denver"}})
        assert r.json()["total"] == 1
        # the Overview page is the Main HUD dashboard; ?classic=1 keeps the old page
        home = client.get("/").text
        assert "Overview" in home and "main-hud" in home and "status_donut" in home
        assert "Problems" in client.get("/?classic=1").text
        # donut segments link to filtered lists
        down = client.get("/devices?state=critical").text
        assert "Showing only devices that are down" in down and ">branch<" in down and ">core<" not in down
        assert "Showing only checks that are in WARNING" in client.get("/checks?state=warning").text
        # deleting the HUD and restoring the built-ins brings it back
        hud_id = client.get("/api/dashboards/main-hud").json()["id"]
        client.delete(f"/api/dashboards/{hud_id}")
        assert "Problems" in client.get("/").text  # falls back to the classic overview
        assert client.post("/api/dashboards/reset").json()["created"] >= 1
        assert client.get("/api/dashboards/main-hud").status_code == 200
