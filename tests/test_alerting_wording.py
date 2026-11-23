"""Alerts read "alerting" (not "firing") on the pages; stored values and the API keep "firing"."""

import json
import time

from fastapi.testclient import TestClient

from snmpathy import dashboards
from snmpathy.app import create_app
from snmpathy.config import Settings


def _alert(db, **extra):
    now = time.time()
    return db.insert("alerts", {"fingerprint": f"fp{now}", "subject": "Core switch down", "severity": "critical",
                                "state": "firing", "message": "no answer", "started_at": now, "fired_at": now,
                                "last_eval": now, **extra})


def test_pages_say_alerting(tmp_path, db, make_device):
    dev = make_device("sw1", "10.0.0.1")
    _alert(db, device_id=dev["id"])
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    with TestClient(app) as client:
        alerts = client.get("/alerts").text
        assert '<span class="status firing">alerting</span>' in alerts
        assert ">firing<" not in alerts
        assert "Alerting from" in client.get("/alerts?tab=history").text
        device = client.get(f"/devices/{dev['id']}").text
        assert "Alerting now" in device and "Firing alerts" not in device
        classic = client.get("/?classic=1").text
        assert "Alerting" in classic and "Alerts firing" not in classic and "began alerting" in classic
        # The API and stored data keep their names.
        assert client.get("/api/alerts").json()[0]["state"] == "firing"


def test_tray_status_says_alerting(db):
    from snmpathy.tray import status_summary

    _alert(db)
    assert status_summary(db) == ("warning", "1 alerting")


def test_saved_dashboard_panels_are_renamed_once(db):
    now = time.time()
    config = {"panels": [{"type": "alerts", "title": "Firing alerts"}, {"type": "text", "title": "Firing alerts?!"}]}
    did = db.insert("dashboards", {"name": "Mine", "slug": "mine", "config": json.dumps(config),
                                   "created_at": now, "updated_at": now})
    db.set_meta("panels_renamed_alerting", "")
    assert dashboards.rename_alerting_panels(db) == 1
    titles = [p["title"] for p in json.loads(db.one("SELECT config FROM dashboards WHERE id = ?", (did,))["config"])["panels"]]
    assert titles == ["Alerting now", "Firing alerts?!"]  # only the old default title
    # Only once: a title someone sets later is left alone.
    db.update("dashboards", did, {"config": json.dumps(config)})
    assert dashboards.rename_alerting_panels(db) == 0
