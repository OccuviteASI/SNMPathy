import pytest
from fastapi.testclient import TestClient

from snmpathy import adminauth
from snmpathy.app import create_app
from snmpathy.cli import main as cli_main
from snmpathy.config import Settings
from snmpathy.db import Database

REMOTE = ("203.0.113.9", 50000)
ADMIN_APIS = [("get", "/api/system/firewall"), ("get", "/api/system/autostart"), ("get", "/api/export"),
              ("post", "/api/system/update")]


@pytest.fixture
def app(tmp_path):
    adminauth._failures.clear()
    settings = Settings(database=str(tmp_path / "a.db"), enable_syslog=False, api_token="")
    db = Database(settings.database)
    return create_app(settings, db=db, start_monitor=False), db


def _denied(client):
    return [path for method, path in ADMIN_APIS if getattr(client, method)(path).status_code == 403]


def test_remote_browser_needs_the_passcode(app):
    app, db = app
    local, remote = TestClient(app), TestClient(app, client=REMOTE)
    with local, remote:
        # No passcode: only the server itself.
        page = remote.get("/admin").text
        assert "Server admin is locked" in page and 'id="no-passcode"' in page and "Add firewall rules" not in page
        assert _denied(remote) == [p for _, p in ADMIN_APIS]
        assert remote.put("/api/system/admin-passcode", json={"passcode": "1234"}).status_code == 403
        assert "Add firewall rules" in local.get("/admin").text and "Set passcode" in local.get("/admin").text
        # Set on the server.
        assert local.put("/api/system/admin-passcode", json={"passcode": "12"}).status_code == 422  # too short
        assert local.put("/api/system/admin-passcode", json={"passcode": "s3cret-code"}).json() == {"set": True}
        assert 'action="/admin/unlock"' in remote.get("/admin").text
        r = remote.post("/admin/unlock", data={"passcode": "wrong"}, follow_redirects=False)
        assert r.headers["location"] == "/admin?error=wrong" and adminauth.SESSION_COOKIE not in r.cookies
        assert "not right" in remote.get("/admin?error=wrong").text
        r = remote.post("/admin/unlock", data={"passcode": "s3cret-code"}, follow_redirects=False)
        assert r.headers["location"] == "/admin"
        page = remote.get("/admin").text
        assert "Add firewall rules" in page and "Lock now" in page and "Set passcode" not in page
        assert _denied(remote) == []  # all allowed now (updating says 409 here: not an executable)
        # Only the server changes the passcode.
        assert remote.put("/api/system/admin-passcode", json={"passcode": "other-code"}).status_code == 403
        assert remote.delete("/api/system/admin-passcode").status_code == 403
        # Lock again.
        remote.post("/admin/lock")
        assert "Server admin is locked" in remote.get("/admin").text
        # Changing the passcode signs out every unlocked browser.
        remote.post("/admin/unlock", data={"passcode": "s3cret-code"})
        assert remote.get("/api/system/firewall").status_code == 200
        local.put("/api/system/admin-passcode", json={"passcode": "new-code-9"})
        assert remote.get("/api/system/firewall").status_code == 403
        assert local.delete("/api/system/admin-passcode").json() == {"set": False}
        assert 'id="no-passcode"' in remote.get("/admin").text


def test_wrong_guesses_lock_the_address_out(app):
    app, db = app
    adminauth.set_passcode(db, "right-code")
    with TestClient(app, client=REMOTE) as remote:
        for _ in range(adminauth.MAX_FAILURES):
            remote.post("/admin/unlock", data={"passcode": "nope"})
        r = remote.post("/admin/unlock", data={"passcode": "right-code"}, follow_redirects=False)
        assert r.headers["location"].startswith("/admin?error=locked")  # even the right one, for a while
        assert "Too many wrong passcodes" in remote.get(r.headers["location"]).text
    assert db.scalar("SELECT COUNT(*) FROM events WHERE type = 'admin.unlock' AND level = 'warning'") == 5


def test_proxied_requests_are_not_local(app):
    app, db = app
    with TestClient(app) as client:
        assert client.get("/api/system/firewall").status_code == 200
        assert client.get("/api/system/firewall", headers={"X-Forwarded-For": "198.51.100.7"}).status_code == 403


def test_tray_link_unlocks_once(app):
    app, db = app
    ticket = adminauth.new_ticket()
    with TestClient(app, client=REMOTE) as browser:  # e.g. a server whose web UI listens on its LAN address
        browser.get(f"/admin/open?ticket={ticket}")
        assert browser.get("/api/system/firewall").status_code == 200
    with TestClient(app, client=REMOTE) as other:
        other.get(f"/admin/open?ticket={ticket}")  # used already
        assert other.get("/api/system/firewall").status_code == 403


def test_api_token_header_but_not_the_login_cookie(tmp_path):
    settings = Settings(database=str(tmp_path / "t.db"), enable_syslog=False, api_token="tok-123")
    app = create_app(settings, db=Database(settings.database), start_monitor=False)
    with TestClient(app, client=REMOTE) as remote:
        assert remote.get("/api/system/firewall", headers={"X-API-Key": "tok-123"}).status_code == 200
        remote.post("/login", data={"token": "tok-123", "next": "/"})  # a browser signed in to the web UI
        assert remote.get("/api/system/firewall").status_code == 403  # still needs the passcode
        ticket = adminauth.new_ticket()
        with TestClient(app, client=REMOTE) as tray_browser:  # the tray's link also signs in to the web UI
            tray_browser.get(f"/admin/open?ticket={ticket}")
            assert "Add firewall rules" in tray_browser.get("/admin").text


def test_passcode_command_line(tmp_path, capsys):
    cfg = tmp_path / "snmpathy.yaml"
    cfg.write_text(f"database: {tmp_path / 'cli.db'}\n")
    assert cli_main(["admin-passcode", "status", "--config", str(cfg)]) == 0
    assert "no passcode" in capsys.readouterr().out
    assert cli_main(["admin-passcode", "set", "--passcode", "abc", "--config", str(cfg)]) == 2
    assert cli_main(["admin-passcode", "set", "--passcode", "long-enough", "--config", str(cfg)]) == 0
    db = Database(str(tmp_path / "cli.db"))
    assert adminauth.check_passcode(db, "long-enough") and not adminauth.check_passcode(db, "nope")
    assert cli_main(["admin-passcode", "clear", "--config", str(cfg)]) == 0
    assert not adminauth.passcode_set(Database(str(tmp_path / "cli.db")))


def test_sessions_expire():
    import time

    class _DB:
        meta = {}

        def get_meta(self, k, d=None):
            return self.meta.get(k, d)

        def set_meta(self, k, v):
            self.meta[k] = v
    db = _DB()
    cookie = adminauth.make_session(db, now=time.time() - adminauth.SESSION_HOURS * 3600 - 5)
    assert adminauth.session_expires(db, cookie) is None
    assert adminauth.session_expires(db, adminauth.make_session(db)) and not adminauth.session_expires(db, "x.y")


def test_server_admin_is_hidden_from_browsers_that_cannot_use_it(app):
    app, db = app
    local, remote = TestClient(app), TestClient(app, client=REMOTE)
    with local, remote:
        assert 'id="nav-admin"' in local.get("/devices").text
        assert "Open Server admin" in local.get("/settings").text
        for page in ("/devices", "/settings"):
            text = remote.get(page).text
            assert 'id="nav-admin"' not in text and "Open Server admin" not in text
            assert 'href="/admin"' in text  # the version link still leads to the unlock page
        adminauth.set_passcode(db, "s3cret-code")
        assert 'id="nav-admin"' not in remote.get("/devices").text
        remote.post("/admin/unlock", data={"passcode": "s3cret-code"}, follow_redirects=False)
        assert 'id="nav-admin"' in remote.get("/devices").text
