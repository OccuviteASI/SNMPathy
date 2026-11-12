import time

from fastapi.testclient import TestClient

from snmpathy.app import create_app
from snmpathy.config import Settings
from snmpathy.topology import build_graph, device_kind, site_of, suggest_parents


def _iface(db, device_id, idx, name, speed=1e9, in_bps=0, out_bps=0, oper=1):
    db.insert("interfaces", {"device_id": device_id, "if_index": idx, "name": name, "speed": speed, "in_bps": in_bps,
                             "out_bps": out_bps, "oper_status": oper, "admin_status": 1, "updated_at": time.time()})


def _link(db, a, idx, port, b=None, rport="", rname="", protocol="lldp", chassis=""):
    now = time.time()
    db.insert("links", {"device_id": a, "if_index": idx, "local_port": port, "remote_device_id": b,
                        "remote_name": rname, "remote_port": rport, "protocol": protocol,
                        "remote_chassis": chassis, "first_seen": now, "last_seen": now})


def _net(db, make_device):
    core = make_device("core", "10.0.0.1", location="HQ / MDF")
    acc = make_device("access", "10.0.0.2", location="HQ / IDF 1")
    br = make_device("branch", "10.1.0.1", location="Denver")
    _iface(db, core["id"], 1, "Te1/1/1", speed=1e10, in_bps=6e9)
    _iface(db, acc["id"], 49, "Te1/0/1", speed=1e10)
    _iface(db, core["id"], 2, "Gi1/0/2", oper=2)
    # Both ends report the same link: one edge.
    _link(db, core["id"], 1, "Te1/1/1", acc["id"], "Te1/0/1", "access")
    _link(db, acc["id"], 49, "Te1/0/1", core["id"], "Te1/1/1", "core")
    _link(db, core["id"], 2, "Gi1/0/2", None, "eth0", "printer-3f", chassis="aa:bb:cc:00:00:01")
    _link(db, core["id"], None, "wan", br["id"], "ge-0/0/0", "branch", protocol="manual")
    return core, acc, br


def test_graph(db, make_device):
    core, acc, br = _net(db, make_device)
    g = build_graph(db)
    assert {s["name"] for s in g["sites"]} == {"HQ", "Denver"}
    names = {n["name"]: n for n in g["nodes"]}
    assert names["printer-3f"]["managed"] is False and names["core"]["site"] == "HQ"
    assert len(g["edges"]) == 3
    uplink = next(e for e in g["edges"] if {e["source"], e["target"]} == {f"d{core['id']}", f"d{acc['id']}"})
    assert round(uplink["util"]) == 60 and uplink["speed"] == 1e10 and uplink["protocols"] == ["lldp"]
    assert next(e for e in g["edges"] if e["target"].startswith("u:"))["down"] is True
    assert any(e["manual"] for e in g["edges"])
    hq = build_graph(db, site="HQ", unmanaged=False)
    assert {n["name"] for n in hq["nodes"]} == {"core", "access"}


def test_parents_and_kinds(db, make_device):
    core, acc, br = _net(db, make_device)
    assert suggest_parents(db, core["id"]) == {acc["id"]: core["id"], br["id"]: core["id"]}
    assert device_kind({"sys_descr": "Cisco IOS Software, Catalyst 9300"}) == "switch"
    assert device_kind({"sys_descr": "FortiGate-100F v7.4.3"}) == "firewall"
    assert device_kind({"sys_descr": "Linux web01 6.8.0"}) == "server"
    assert device_kind({"sys_descr": ""}) == "device"
    assert site_of({"location": "Branch, rack 2"}, {}) == "Branch"
    assert site_of({"location": ""}, {}) == "Main site"
    assert site_of({"location": "x", "collector_id": 3}, {3: {"name": "c", "site": "Austin"}}) == "Austin"


def test_map_api(tmp_path, db, make_device):
    core, acc, br = _net(db, make_device)
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    with TestClient(app) as c:
        g = c.get("/api/map").json()
        assert g["view"] == "site=|tag="
        assert c.put("/api/map/positions", json={"view": g["view"], "positions": {"d1": [10, 20]}}).json()["saved"] == 1
        assert c.get("/api/map").json()["positions"] == {"d1": [10.0, 20.0]}
        c.delete(f"/api/map/positions?view={g['view']}")
        assert c.get("/api/map").json()["positions"] == {}
        r = c.post("/api/map/links", json={"device_id": acc["id"], "remote_device_id": br["id"], "local_port": "Te1/0/1"})
        assert r.status_code == 201
        assert c.post("/api/map/links", json={"device_id": acc["id"], "remote_device_id": acc["id"]}).status_code == 422
        lldp = db.one("SELECT id FROM links WHERE protocol = 'lldp'")["id"]
        assert c.delete(f"/api/map/links/{lldp}").status_code == 422
        assert c.delete(f"/api/map/links/{r.json()['id']}").status_code == 204
        r = c.post("/api/map/parents", json={"root_device_id": core["id"], "apply": True}).json()
        assert r["applied"] == 2
        assert db.one("SELECT parent_id FROM devices WHERE id = ?", (acc["id"],))["parent_id"] == core["id"]
        assert c.get("/map").status_code == 200
