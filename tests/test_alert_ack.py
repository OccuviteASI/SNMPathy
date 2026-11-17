import re
import time

from fastapi.testclient import TestClient

from snmpathy.app import create_app
from snmpathy.config import Settings
from snmpathy.db import Database
from tests.test_fusion import _alert


def _badge(html: str) -> str:
    match = re.search(r'href="/alerts"[^>]*>.*?Alerts(?:<span class="count">(\d+)</span>)?</a>', html, re.S)
    return match.group(1) or "" if match else "missing"


def test_acknowledge_all_and_unacknowledged_badge(tmp_path):
    settings = Settings(database=str(tmp_path / "a.db"), enable_syslog=False)
    db = Database(settings.database)
    first = _alert(db, "core1 down")
    _alert(db, "edge1 down", severity="warning")
    _alert(db, "already seen", ack=1)
    resolved = _alert(db, "old one")
    db.update("alerts", resolved, {"state": "resolved", "resolved_at": time.time()})
    with TestClient(create_app(settings, db=db, start_monitor=False)) as client:
        page = client.get("/alerts").text
        assert _badge(page) == "2"  # 3 firing, one already acknowledged
        assert "Acknowledge all (2)" in page
        client.post(f"/api/alerts/{first}/ack", json={"by": "web"})
        assert _badge(client.get("/devices").text) == "1"  # every page's sidebar
        assert client.post("/api/alerts/ack-all", json={"by": "web"}).json() == {"acknowledged": 1}
        page = client.get("/alerts").text
        assert _badge(page) == "" and "Acknowledge all" not in page
        rows = {r["subject"]: r for r in db.query("SELECT subject, acknowledged, ack_by, state FROM alerts")}
        assert all(r["acknowledged"] for s, r in rows.items() if s != "old one")
        assert rows["old one"]["acknowledged"] == 0  # resolved alerts are left as they were
        assert rows["edge1 down"]["ack_by"] == "web" and rows["already seen"]["ack_by"] in (None, "")
        assert client.post("/api/alerts/ack-all", json={}).json() == {"acknowledged": 0}
        # A new alert firing makes the badge come back.
        _alert(db, "new trouble")
        assert _badge(client.get("/alerts").text) == "1"
