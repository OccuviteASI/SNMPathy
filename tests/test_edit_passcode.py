"""Edit passcode: other computers are view only until they unlock editing."""

import pytest
from fastapi.testclient import TestClient

from snmpathy import adminauth
from snmpathy.app import create_app
from snmpathy.cli import main as cli_main
from snmpathy.config import Settings
from snmpathy.db import Database

REMOTE = ("203.0.113.9", 50000)
NEW_DEVICE = {"name": "sw9", "hostname": "10.9.9.9"}


@pytest.fixture
def app(tmp_path):
    adminauth._failures.clear()
    settings = Settings(database=str(tmp_path / "e.db"), enable_syslog=False, api_token="")
    db = Database(settings.database)
    return create_app(settings, db=db, start_monitor=False), db


def test_without_an_edit_passcode_everyone_can_edit(app):
    app, db = app
    with TestClient(app, client=REMOTE) as remote:
        assert remote.post("/api/devices", json=NEW_DEVICE).status_code == 201
        assert "Unlock editing" not in remote.get("/devices").text
        assert remote.get("/api/system/edit-passcode").json()["set"] is False


def test_remote_browser_is_view_only_until_unlocked(app):
    app, db = app
    local, remote = TestClient(app), TestClient(app, client=REMOTE)
    with local, remote:
        # Only Server admin sets it, and it must differ from the Server admin passcode.
        assert remote.put("/api/system/edit-passcode", json={"passcode": "edit-1234"}).status_code == 403
        local.put("/api/system/admin-passcode", json={"passcode": "admin-pass"})
        assert local.put("/api/system/edit-passcode", json={"passcode": "admin-pass"}).status_code == 422
        assert not adminauth.passcode_set(db, "edit")
        assert local.put("/api/system/edit-passcode", json={"passcode": "edit-1234"}).json() == {"set": True}
        assert "An edit passcode is set" in local.get("/admin").text

        # Viewing works; changing does not.
        page = remote.get("/devices").text
        assert "View only" in page and 'id="edit-modal"' in page
        assert remote.get("/api/devices").status_code == 200
        r = remote.post("/api/devices", json=NEW_DEVICE)
        assert r.status_code == 403 and r.json()["code"] == "edit_locked"
        assert remote.post("/api/panel-data", json={}).status_code != 403  # read-only POSTs stay open
        # The server itself is never view only.
        assert local.post("/api/devices", json=NEW_DEVICE).status_code == 201
        assert "Unlock editing" not in local.get("/devices").text

        # Wrong passcode, then the right one.
        assert remote.post("/edit/unlock", json={"passcode": "nope"}).status_code == 403
        assert remote.post("/edit/unlock", json={"passcode": "admin-pass"}).status_code == 403  # not this one
        r = remote.post("/edit/unlock", json={"passcode": "edit-1234"})
        assert r.status_code == 200 and adminauth.EDIT_COOKIE in r.cookies
        remote.cookies.set(adminauth.EDIT_COOKIE, r.cookies[adminauth.EDIT_COOKIE])
        assert remote.patch("/api/devices/1", json={"name": "sw10"}).status_code == 200
        assert "Lock editing" in remote.get("/devices").text
        # Editing does not open Server admin.
        assert remote.get("/api/system/firewall").status_code == 403

        # Changing the passcode signs everyone out.
        local.put("/api/system/edit-passcode", json={"passcode": "edit-5678"})
        assert remote.patch("/api/devices/1", json={"name": "sw11"}).status_code == 403
        events = [e["message"] for e in db.query("SELECT message FROM events WHERE type = 'edit.unlock'")]
        assert any("Wrong edit passcode" in m for m in events) and any("unlocked" in m for m in events)


def test_server_admin_access_includes_editing(app):
    app, db = app
    adminauth.set_passcode(db, "admin-pass")
    adminauth.set_passcode(db, "edit-1234", kind="edit")
    with TestClient(app, client=REMOTE) as remote:
        assert remote.post("/api/devices", json=NEW_DEVICE).status_code == 403
        remote.post("/admin/unlock", data={"passcode": "admin-pass"}, follow_redirects=False)
        assert remote.post("/api/devices", json=NEW_DEVICE).status_code == 201
        # ... and Server admin can remove it from another computer.
        assert remote.delete("/api/system/edit-passcode").json() == {"set": False}


def test_api_token_header_can_edit(tmp_path):
    settings = Settings(database=str(tmp_path / "t.db"), enable_syslog=False, api_token="tok")
    db = Database(settings.database)
    adminauth.set_passcode(db, "edit-1234", kind="edit")
    app = create_app(settings, db=db, start_monitor=False)
    with TestClient(app, client=REMOTE) as remote:
        assert remote.post("/api/devices", json=NEW_DEVICE, headers={"Authorization": "Bearer tok"}).status_code == 201
        # The login cookie alone (a browser) is view only.
        remote.cookies.set("snmpathy_token", "tok")
        assert remote.post("/api/devices", json={**NEW_DEVICE, "name": "x"}).status_code == 403


def test_wrong_guesses_lock_the_address_out(app):
    app, db = app
    adminauth.set_passcode(db, "edit-1234", kind="edit")
    with TestClient(app, client=REMOTE) as remote:
        for _ in range(adminauth.MAX_FAILURES):
            remote.post("/edit/unlock", json={"passcode": "nope"})
        r = remote.post("/edit/unlock", json={"passcode": "edit-1234"})
        assert r.status_code == 429 and "try again" in r.json()["detail"]


def test_cli_edit_passcode(tmp_path, capsys):
    conf = tmp_path / "c.yaml"
    conf.write_text(f"database: {tmp_path / 'c.db'}\n")
    assert cli_main(["admin-passcode", "set", "--passcode", "admin-pass", "--config", str(conf)]) == 0
    assert cli_main(["edit-passcode", "set", "--passcode", "admin-pass", "--config", str(conf)]) == 2
    assert cli_main(["edit-passcode", "set", "--passcode", "edit-1234", "--config", str(conf)]) == 0
    cli_main(["edit-passcode", "status", "--config", str(conf)])
    assert "view only" in capsys.readouterr().out
    assert adminauth.check_passcode(Database(str(tmp_path / "c.db")), "edit-1234", kind="edit")
    assert cli_main(["edit-passcode", "clear", "--config", str(conf)]) == 0
    assert not adminauth.passcode_set(Database(str(tmp_path / "c.db")), "edit")
