import subprocess

import pytest
from fastapi.testclient import TestClient

from snmpathy import firewall
from snmpathy.app import create_app
from snmpathy.config import Settings


def settings(**kw):
    return Settings(database=":memory:", **kw)


def test_wanted_rules():
    s = settings(syslog_udp_port=514, syslog_tcp_port=6514, netflow_port=2055, ipfix_port=2055, sflow_port=0)
    names = [r.name for r in firewall.wanted_rules(s)]
    assert names == ["SNMPathy Syslog UDP 514", "SNMPathy Syslog TCP 6514"]
    flows = firewall.wanted_rules(s, ["flows"])
    assert [(r.proto, r.port) for r in flows] == [("udp", 2055)]  # one rule for a shared port
    assert firewall.wanted_rules(settings(enable_syslog=False)) == []


def test_commands_per_backend():
    rules = firewall.wanted_rules(settings())
    win = firewall.commands("windows", rules)
    assert win[0][:5] == ["netsh", "advfirewall", "firewall", "add", "rule"]
    assert "name=SNMPathy Syslog UDP 5514" in win[0] and "localport=5514" in win[0] and "protocol=UDP" in win[0]
    assert firewall.commands("windows", rules, remove=True)[1][4] == "rule"
    fwd = firewall.commands("firewalld", rules)
    assert fwd == [["firewall-cmd", "--permanent", "--add-port=5514/udp"],
                   ["firewall-cmd", "--permanent", "--add-port=5514/tcp"], ["firewall-cmd", "--reload"]]
    assert firewall.commands("ufw", rules)[0][:3] == ["ufw", "allow", "5514/udp"]
    assert firewall.commands("ufw", rules, remove=True)[0][:4] == ["ufw", "--force", "delete", "allow"]
    mac = firewall.commands("macos", rules)
    assert mac[0][1] == "--add" and mac[1][1] == "--unblockapp"
    text = firewall.shell_text("windows", win)
    assert '"name=SNMPathy Syslog UDP 5514"' in text


@pytest.fixture
def fake(monkeypatch):
    calls = []

    def run(argv, timeout=30):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "ok", "")
    monkeypatch.setattr(firewall, "_run", run)
    monkeypatch.setattr(firewall, "_in_container", lambda: False)
    return calls


def test_apply_firewalld_as_root(fake, monkeypatch):
    monkeypatch.setattr(firewall, "detect_backend", lambda: "firewalld")
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    result = firewall.apply(settings())
    assert result["ok"] and result["applied"]
    assert fake == [["firewall-cmd", "--permanent", "--add-port=5514/udp"],
                    ["firewall-cmd", "--permanent", "--add-port=5514/tcp"], ["firewall-cmd", "--reload"]]


def test_apply_without_root_returns_commands(fake, monkeypatch):
    monkeypatch.setattr(firewall, "detect_backend", lambda: "ufw")
    monkeypatch.setattr(firewall, "is_admin", lambda: False)
    monkeypatch.setattr(firewall, "_quiet", lambda argv: 1)  # sudo -n needs a password
    monkeypatch.setattr(firewall.shutil, "which", lambda name: "/usr/bin/" + name)
    result = firewall.apply(settings())
    assert not result["ok"] and "sudo ufw allow 5514/udp" in result["manual"]
    assert fake == []


def test_apply_with_passwordless_sudo(fake, monkeypatch):
    monkeypatch.setattr(firewall, "detect_backend", lambda: "ufw")
    monkeypatch.setattr(firewall, "is_admin", lambda: False)
    monkeypatch.setattr(firewall, "_quiet", lambda argv: 0)
    monkeypatch.setattr(firewall.shutil, "which", lambda name: "/usr/bin/" + name)
    assert firewall.apply(settings())["ok"]
    assert fake[0][:4] == ["sudo", "-n", "ufw", "allow"]


def test_windows_elevation(fake, monkeypatch):
    monkeypatch.setattr(firewall, "detect_backend", lambda: "windows")
    monkeypatch.setattr(firewall, "is_admin", lambda: False)
    result = firewall.apply(settings())
    assert result["ok"] and "UAC" in result["output"]
    assert fake[0][0] == "powershell" and "-Verb RunAs" in fake[0][-1]


def test_unknown_group_and_no_firewall(fake, monkeypatch):
    with pytest.raises(ValueError):
        firewall.apply(settings(), ["everything"])
    monkeypatch.setattr(firewall, "detect_backend", lambda: "none")
    result = firewall.apply(settings())
    assert not result["applied"] and "iptables -I INPUT -p udp --dport 5514" in result["manual"]


def test_status_and_api(fake, monkeypatch, tmp_path, db):
    monkeypatch.setattr(firewall, "detect_backend", lambda: "firewalld")
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "_quiet", lambda argv: 0 if "--query-port=5514/udp" in argv else 1)
    info = firewall.status(settings())
    present = {r["name"]: r["present"] for r in info["rules"]}
    assert present["SNMPathy Syslog UDP 5514"] is True and present["SNMPathy Syslog TCP 5514"] is False
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    with TestClient(app) as c:
        assert c.get("/api/system/firewall").json()["backend"] == "firewalld"
        assert c.post("/api/system/firewall", json={"groups": ["syslog"]}).json()["ok"] is True
        assert c.post("/api/system/firewall", json={"groups": ["nope"]}).status_code == 422
        page = c.get("/settings").text
        assert "Add firewall rules" in page and "Syslog (UDP and TCP)" in page
