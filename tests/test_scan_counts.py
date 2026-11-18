"""A scan's Found / Added describe its latest run; the Scans list follows running scans."""

from fastapi.testclient import TestClient

from snmpathy.app import create_app
from snmpathy.config import Settings
from snmpathy.scanner import ScanManager, found_new_counts

from .test_scanner import Net


async def test_found_and_added_describe_the_latest_run(db):
    net = Net()
    manager = ScanManager(db, local_probe=net.probe, local_clients=net.client)
    scan = manager.create({"name": "lab", "targets": "10.0.0.1-3", "options": {
        "communities": ["secret"], "resolve_dns": False, "auto_add": "snmp", "tags": []}})
    sid = scan["id"]

    first = await manager.run(sid)
    responding = first["found"]
    assert responding >= 2 and first["added_last"] == 1
    assert found_new_counts(db, sid)[sid] == responding  # nothing was a device before

    # Rescan: the device it added is monitored now; hosts not added yet still count as found.
    second = await manager.run(sid)
    assert second["added_last"] == 0
    assert found_new_counts(db, sid)[sid] == responding - 1

    # Add the rest by hand: the next run finds nothing new and adds nothing.
    others = [r["ip"] for r in db.query("SELECT ip FROM scan_results WHERE scan_id = ? AND status = 'new'", (sid,))]
    manager.add(sid, ips=others)
    third = await manager.run(sid)
    assert third["added_last"] == 0 and found_new_counts(db, sid).get(sid, 0) == 0
    event = db.one("SELECT message FROM events WHERE type = 'scan.done' ORDER BY id DESC LIMIT 1")["message"]
    assert "(0 not yet devices)" in event and event.endswith("added 0")


def test_scans_list_and_page_show_the_latest_run(tmp_path, db):
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    manager = app.state.scans
    scan = manager.create({"name": "lab", "targets": "10.0.0.1-3", "options": {"resolve_dns": False}})
    sid = scan["id"]
    rows = [("10.0.0.1", "existing"), ("10.0.0.2", "added"), ("10.0.0.3", "new")]
    for ip, state in rows:
        db.execute("INSERT INTO scan_results (scan_id, ip, status, seen_at) VALUES (?, ?, ?, 0)", (sid, ip, state))
    db.update("scans", sid, {"state": "done", "found": 3, "added": 5, "added_last": 1})
    with TestClient(app) as client:
        api = client.get(f"/api/scans/{sid}").json()
        assert api["found_new"] == 2 and api["added_last"] == 1
        assert next(s for s in client.get("/api/scans").json() if s["id"] == sid)["found_new"] == 2
        page = client.get("/scans").text
        assert "of 3 responding" in page and "5 in all runs" in page
        assert "/api/scans" in page and 'data-state="done"' in page  # the polling hook (idle while done)
        assert "New hosts (latest run)" in client.get(f"/scans/{sid}").text

        # Nothing new: 0 and 0.
        db.execute("UPDATE scan_results SET status = 'existing' WHERE scan_id = ?", (sid,))
        db.update("scans", sid, {"added_last": 0})
        assert client.get(f"/api/scans/{sid}").json()["found_new"] == 0
        assert 'title="Hosts in the latest run that were not devices yet">0<' in client.get("/scans").text

        # Running: progress, not counts.
        db.update("scans", sid, {"state": "running", "scanned": 120, "total": 254, "found": 7})
        page = client.get("/scans").text
        assert 'data-state="running"' in page and "120/254" in page and "7 responding so far" in page
