import plistlib
import subprocess
import sys
import types

import pytest
from fastapi.testclient import TestClient

from snmpathy import autostart
from snmpathy.app import create_app
from snmpathy.config import Settings


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(autostart.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    monkeypatch.setattr(autostart, "_in_container", lambda: False)
    calls = []
    monkeypatch.setattr(autostart.subprocess, "run",
                        lambda argv, **kw: calls.append(argv) or subprocess.CompletedProcess(argv, 0, "", ""))
    monkeypatch.setattr(autostart.shutil, "which", lambda name: f"/usr/bin/{name}")
    return tmp_path, calls


def _settings(tmp_path):
    s = Settings(database=str(tmp_path / "data" / "snmpathy.db"))
    s.config_path = str(tmp_path / "snmpathy.yaml")
    return s


def test_launch_command_pins_config_and_database(tmp_path):
    argv = autostart.launch_command(_settings(tmp_path))
    assert argv[-5:] == ["serve", "--config", str(tmp_path / "snmpathy.yaml"), "--db",
                         str(tmp_path / "data" / "snmpathy.db")]
    assert "--open" not in argv


def test_linux_systemd_user(home, monkeypatch):
    tmp, calls = home
    monkeypatch.setattr(autostart, "platform_name", lambda: "linux")
    monkeypatch.setattr(autostart, "_systemd_user_available", lambda: True)
    s = _settings(tmp)
    assert not autostart.status(s)["enabled"]
    info = autostart.enable(s)
    unit = tmp / ".config" / "systemd" / "user" / "snmpathy.service"
    assert info["enabled"] and unit.exists()
    text = unit.read_text()
    assert "ExecStart=" in text and "serve --config" in text and "WantedBy=default.target" in text
    assert ["systemctl", "--user", "enable", "snmpathy.service"] in calls
    info = autostart.disable(s)
    assert not info["enabled"] and not unit.exists()
    assert ["systemctl", "--user", "disable", "snmpathy.service"] in calls


def test_linux_desktop_entry_without_systemd(home, monkeypatch):
    tmp, _ = home
    monkeypatch.setattr(autostart, "platform_name", lambda: "linux")
    monkeypatch.setattr(autostart, "_systemd_user_available", lambda: False)
    autostart.enable(_settings(tmp))
    desktop = tmp / ".config" / "autostart" / "snmpathy.desktop"
    assert "Exec=" in desktop.read_text() and autostart.status()["enabled"]
    autostart.disable()
    assert not desktop.exists()


def test_macos_launch_agent(home, monkeypatch):
    tmp, calls = home
    monkeypatch.setattr(autostart, "platform_name", lambda: "macos")
    autostart.enable(_settings(tmp))
    plist = tmp / "Library" / "LaunchAgents" / "com.snmpathy.autostart.plist"
    data = plistlib.loads(plist.read_bytes())
    assert data["RunAtLoad"] is True and data["ProgramArguments"][-4:-2] == ["--config", str(tmp / "snmpathy.yaml")]
    assert autostart.status()["enabled"]
    autostart.disable()
    assert not plist.exists() and calls[-1][:2] == ["launchctl", "unload"]


def test_windows_run_key(home, monkeypatch):
    tmp, _ = home
    store: dict[str, str] = {}

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    fake = types.SimpleNamespace(
        HKEY_CURRENT_USER=1, KEY_SET_VALUE=2, KEY_READ=3, REG_SZ=1,
        OpenKey=lambda *a: Key(),
        SetValueEx=lambda key, name, _r, _t, value: store.__setitem__(name, value),
        DeleteValue=lambda key, name: store.pop(name) if name in store else (_ for _ in ()).throw(FileNotFoundError()),
        QueryValueEx=lambda key, name: (store[name], 1) if name in store else (_ for _ in ()).throw(FileNotFoundError()),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(autostart, "platform_name", lambda: "windows")
    s = _settings(tmp)
    s.database = str(tmp / "My Data" / "snmpathy.db")
    info = autostart.enable(s)
    assert info["enabled"] and store["SNMPathy"].startswith("wscript.exe //B")
    vbs = (tmp / "AppData" / "Local" / "SNMPathy" / "autostart.vbs").read_text()
    # Paths with spaces are double-quoted inside the VBScript string; 0 = hidden window.
    assert '""' + str(tmp / "My Data" / "snmpathy.db") + '""' in vbs and ", 0, False" in vbs
    assert not autostart.disable(s)["enabled"]
    assert "SNMPathy" not in store and not (tmp / "AppData" / "Local" / "SNMPathy" / "autostart.vbs").exists()


def test_containers_are_not_supported(monkeypatch):
    monkeypatch.setattr(autostart, "_in_container", lambda: True)
    assert autostart.status()["supported"] is False
    with pytest.raises(autostart.AutostartError):
        autostart.enable()


def test_api_and_settings_page(home, monkeypatch, db):
    tmp, _ = home
    monkeypatch.setattr(autostart, "platform_name", lambda: "linux")
    monkeypatch.setattr(autostart, "_systemd_user_available", lambda: False)
    app = create_app(Settings(database=str(tmp / "t.db")), db=db, start_monitor=False)
    with TestClient(app) as c:
        assert c.get("/api/system/autostart").json()["enabled"] is False
        assert "Start SNMPathy automatically" in c.get("/settings").text
        r = c.put("/api/system/autostart", json={"enabled": True})
        assert r.status_code == 200 and r.json()["enabled"] is True
        assert c.put("/api/system/autostart", json={"enabled": False}).json()["enabled"] is False
