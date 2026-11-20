"""Live pages: sidebar counts and new alerts for open pages, and which pages refresh themselves."""

import time

import pytest
from fastapi.testclient import TestClient

from snmpathy import adminauth
from snmpathy.app import create_app
from snmpathy.config import Settings

REMOTE = ("203.0.113.9", 50000)


@pytest.fixture
def client(tmp_path, db):
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    with TestClient(app) as c:
        yield c


def _alert(db, device_id=None, fired_at=None, state="firing", acked=0, subject="Device down"):
    now = time.time()
    return db.insert("alerts", {"fingerprint": f"fp{now}{subject}", "device_id": device_id, "subject": subject,
                                "severity": "critical", "state": state, "message": "no answer",
                                "started_at": now, "fired_at": fired_at, "last_eval": now, "acknowledged": acked})


def test_status_counts_and_new_alerts(client, db, make_device):
    first = client.get("/api/ui/status").json()
    assert first["alerts"] == 0 and first["new_alerts"] == []  # the first poll only records the time
    since = first["now"]
    dev = make_device("sw1", "10.0.0.1")
    _alert(db, fired_at=since - 600, subject="Old")  # fired before the page opened
    fresh = _alert(db, device_id=dev["id"], fired_at=since + 1)
    _alert(db, fired_at=since + 2, acked=1, subject="Acked")
    _alert(db, fired_at=since + 3, state="pending", subject="Pending")
    db.update("collectors", db.insert("collectors", {"name": "c", "token_hash": "x", "created_at": 0}),
              {"status": "offline"})
    data = client.get(f"/api/ui/status?since={since}").json()
    assert data["alerts"] == 2 and data["collectors_offline"] == 1  # same as the sidebar
    assert [a["id"] for a in data["new_alerts"]] == [fresh]
    assert data["new_alerts"][0]["device_name"] == "sw1" and data["new_alerts"][0]["subject"] == "Device down"
    page = client.get("/devices").text
    assert 'id="nav-alerts"' in page and '<span class="count">2</span>' in page


def test_view_only_browsers_get_live_updates(client, db):
    adminauth.set_passcode(db, "edit-1234", kind="edit")
    with TestClient(client.app, client=REMOTE) as remote:
        assert remote.get("/api/ui/status").status_code == 200


def test_status_pages_refresh_themselves(client, db, make_device):
    dev = make_device("sw1", "10.0.0.1")
    for page in ("/devices", f"/devices/{dev['id']}", "/alerts", "/checks", "/collectors", "/scans", "/maintenance"):
        assert 'data-refresh="30"' in client.get(page).text, page
    for page in ("/settings", "/fusion", "/syslog", "/traffic", "/map", "/devices/new", "/alerts?tab=rules"):
        r = client.get(page)
        assert r.status_code == 200 and "data-refresh" not in r.text.split("<body", 1)[1][:80], page
    # Every page with the sidebar has the Live menu.
    page = client.get("/devices").text
    assert 'id="live-menu"' in page and 'id="live-sound-name"' in page and 'id="live-sound-play"' in page
