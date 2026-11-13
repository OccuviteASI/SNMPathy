import hashlib
import importlib.util
import io
import sys
from pathlib import Path

import pytest

from snmpathy import selfupdate, tray
from snmpathy.cli import build_parser
from snmpathy.selfupdate import Release, UpdateError

ROOT = Path(__file__).resolve().parent.parent
POSIX = not sys.platform.startswith("win")


def api_release(tag="v0.9.0", commit="abcdef1234567890", name=None, url=None, size=10, digest=""):
    name = name or selfupdate.asset_name()
    return {"tag_name": tag, "target_commitish": commit, "body": "notes",
            "assets": [{"name": "other.zip", "browser_download_url": "https://github.com/x/y/other.zip", "size": 1},
                       {"name": name, "size": size, "digest": digest,
                        "browser_download_url": url or f"https://github.com/OccuviteASI/SNMPathy/releases/download/{tag}/{name}"}]}


def test_release_from_api():
    rel = Release.from_api(api_release())
    assert rel.version == "0.9.0" and rel.commit == "abcdef1234567890" and rel.size == 10
    assert Release.from_api(api_release(name="SNMPathy-windows.exe"), "win32").url.endswith("SNMPathy-windows.exe")
    assert selfupdate.asset_name("darwin") == "SNMPathy-macos" and selfupdate.asset_name("linux") == "SNMPathy-linux"
    data = api_release(commit="main")
    data["body"] = "changes\n---\nbuild 0123456789abcdef\n"
    assert Release.from_api(data).commit == "0123456789abcdef"  # from the notes when the target is a branch
    with pytest.raises(UpdateError):
        Release.from_api(api_release(url="https://evil.example/SNMPathy"))
    with pytest.raises(UpdateError):
        Release.from_api({"tag_name": "v1", "assets": []})


def test_is_newer():
    rel = Release("0.7.3", "v0.7.3", "abcdef1234", "u", 1)
    assert rel.is_newer("0.7.2", "")
    assert not rel.is_newer("0.8.0", "")  # never downgrade
    assert rel.is_newer("0.7.3", "1234567, 2026-11-13")  # same version, another commit
    assert not rel.is_newer("0.7.3", "abcdef1, 2026-11-13")
    assert not rel.is_newer("0.7.3", "abcdef1+local changes, 2026-11-13")
    assert not rel.is_newer("0.7.3", "")  # unknown build of the same version: leave it
    assert selfupdate.parse_version("0.10.1") > selfupdate.parse_version("0.9.9")


class FakeResponse(io.BytesIO):
    def __init__(self, data, length=None):
        super().__init__(data)
        self.headers = {"Content-Length": str(len(data) if length is None else length)}


def test_download_checks_size_and_digest(monkeypatch, tmp_path):
    payload = b"new snmpathy binary"
    monkeypatch.setattr(selfupdate, "_open", lambda url, accept, timeout: FakeResponse(payload))
    good = Release("0.9.0", "v0.9.0", "abc1234", "https://github.com/x", len(payload),
                   "sha256:" + hashlib.sha256(payload).hexdigest())
    seen = []
    out = selfupdate.download(good, tmp_path / "SNMPathy.new", lambda done, total: seen.append((done, total)))
    assert out.read_bytes() == payload and seen[-1] == (len(payload), len(payload))
    assert not (tmp_path / "SNMPathy.new.part").exists()
    if POSIX:
        assert out.stat().st_mode & 0o111
    for bad in (Release("0.9.0", "v", "c", "u", len(payload) + 5),
                Release("0.9.0", "v", "c", "u", len(payload), "sha256:" + "0" * 64)):
        with pytest.raises(UpdateError):
            selfupdate.download(bad, tmp_path / "bad.new")
        assert not (tmp_path / "bad.new").exists() and not (tmp_path / "bad.new.part").exists()


def test_latest_release_none_and_errors(monkeypatch):
    import urllib.error

    def raise_(code):
        def _open(url, accept, timeout):
            raise urllib.error.HTTPError(url, code, "x", {}, None)
        return _open
    monkeypatch.setattr(selfupdate, "_open", raise_(404))
    assert selfupdate.latest_release() is None
    monkeypatch.setattr(selfupdate, "_open", raise_(403))
    with pytest.raises(UpdateError, match="limiting"):
        selfupdate.latest_release()


def test_install_swaps_and_rolls_back(tmp_path, monkeypatch):
    exe, new = tmp_path / "SNMPathy.exe", tmp_path / "SNMPathy.exe.new"
    exe.write_text("old")
    new.write_text("new")
    selfupdate.install(new, exe)
    assert exe.read_text() == "new" and selfupdate.old_path(exe).read_text() == "old" and not new.exists()
    selfupdate.cleanup_old(exe)
    assert not selfupdate.old_path(exe).exists()
    # The new file cannot be moved in: the working one is put back.
    real = selfupdate.os.replace

    def failing(a, b):
        if Path(a).name.endswith(".new"):
            raise OSError("locked")
        return real(a, b)
    new.write_text("newer")
    monkeypatch.setattr(selfupdate.os, "replace", failing)
    with pytest.raises(OSError):
        selfupdate.install(new, exe)
    assert exe.read_text() == "new"


@pytest.mark.skipif(not POSIX, reason="uses a shell script as the downloaded executable")
def test_run_update_end_to_end(monkeypatch, tmp_path):
    exe = tmp_path / "SNMPathy"
    exe.write_text("#!/bin/sh\necho 'snmpathy 0.7.0'\n")
    exe.chmod(0o755)
    rel = Release("0.9.0", "v0.9.0", "abcdef1234", "https://github.com/x", 0)
    monkeypatch.setattr(selfupdate, "latest_release", lambda: rel)

    def fake_download(release, dest, progress=None):
        dest.write_text("#!/bin/sh\necho 'snmpathy 0.9.0 (build abcdef1, 2026-11-14)'\n")
        dest.chmod(0o755)
        progress(5, 10)
        progress(10, 10)
        return dest
    events = []
    monkeypatch.setattr(selfupdate, "download", fake_download)
    monkeypatch.setattr(selfupdate, "stop", lambda e: events.append(("stop", e)) or True)
    monkeypatch.setattr(selfupdate, "start", lambda e: events.append(("start", e)))
    said = []
    assert selfupdate.run_update(exe, lambda pct, msg: said.append((pct, msg))) == "ok"
    assert "0.9.0" in selfupdate.reported_version(exe) and selfupdate.old_path(exe).exists()
    assert events == [("stop", exe), ("start", exe)]
    pcts = [p for p, _ in said]
    assert pcts == sorted(pcts) and pcts[-1] == 100 and "Updated to SNMPathy 0.9.0" in said[-1][1]

    # Already the latest: nothing downloaded or restarted.
    events.clear()
    monkeypatch.setattr(selfupdate, "__version__", "0.9.0")
    monkeypatch.setattr(Release, "is_newer", lambda self, version="0.9.0", build="": False)
    assert selfupdate.run_update(exe, lambda *a: None) == "current" and events == []

    # A download that does not start is rejected and the installed one is left alone.
    monkeypatch.setattr(Release, "is_newer", lambda self, version="", build="": True)

    def broken(release, dest, progress=None):
        dest.write_text("#!/bin/sh\nexit 1\n")
        dest.chmod(0o755)
        return dest
    monkeypatch.setattr(selfupdate, "download", broken)
    with pytest.raises(UpdateError, match="did not start"):
        selfupdate.run_update(exe, lambda *a: None)
    assert "0.9.0" in selfupdate.reported_version(exe) and events == []


def test_no_release_yet(monkeypatch, tmp_path):
    monkeypatch.setattr(selfupdate, "latest_release", lambda: None)
    with pytest.raises(UpdateError, match="no SNMPathy release"):
        selfupdate.run_update(tmp_path / "SNMPathy", lambda *a: None)


def test_frozen_tray_updates_itself(monkeypatch, tmp_path):
    monkeypatch.setattr(tray, "is_frozen", lambda: True)
    launched = []
    monkeypatch.setattr(tray.subprocess, "Popen", lambda argv, **kw: launched.append((argv, kw)))
    app = tray.TrayApp.__new__(tray.TrayApp)
    app.run_update()
    argv, kw = launched[0]
    assert argv == [sys.executable, "self-update", "--gui"] and kw["stdout"] is tray.subprocess.DEVNULL
    assert tray.update_available()
    app.available = ""
    assert app.update_label() == "Update SNMPathy"
    app.available = "0.9.0"
    assert app.update_label() == "Update SNMPathy (0.9.0 available)"


def test_self_update_command():
    args = build_parser().parse_args(["self-update", "--gui", "--force"])
    assert args.gui and args.force and not args.check and not args.no_restart
    assert selfupdate.main() == 2  # running from Python, not an executable


def test_release_notes():
    spec = importlib.util.spec_from_file_location("release_notes", ROOT / "scripts" / "release_notes.py")
    notes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(notes)
    from snmpathy import __version__

    assert notes.version() == __version__
    text = notes.notes("0123456789abcdef")
    assert "build 0123456789abcdef" in text and notes.changelog_section(__version__) in text
    assert Release.from_api({**api_release(commit="main"), "body": text}).commit == "0123456789abcdef"
