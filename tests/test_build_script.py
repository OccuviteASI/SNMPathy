"""Destination logic of scripts/build_executable.py (no executable is built here)."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_executable.py"


@pytest.fixture
def build(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("build_executable", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("SNMPATHY_EXE_DIR", raising=False)
    for var in ("OneDrive", "OneDriveCommercial", "OneDriveConsumer"):
        monkeypatch.delenv(var, raising=False)
    # Pretend the repository is somewhere unrelated unless a test says otherwise.
    monkeypatch.setattr(module, "ROOT", tmp_path / "elsewhere" / "SNMPathy")
    module.home = home
    return module


def test_finds_claude_folder_with_sibling_projects(build):
    claude = build.home / "Documents" / "Claude"
    for name in ("KASTR", "DiskWorks", "LinkTest"):
        (claude / name).mkdir(parents=True)
    (build.home / "Claude").mkdir()  # an empty "Claude" folder must not win over the real one
    assert build.find_claude_folder() == claude
    assert build.resolve_destination(None) == claude / "SNMPathy"


def test_repository_inside_claude_folder(build, tmp_path, monkeypatch):
    claude = tmp_path / "work" / "Claude"
    (claude / "LinkTest").mkdir(parents=True)
    monkeypatch.setattr(build, "ROOT", claude / "SNMPathy")
    assert build.resolve_destination(None) == claude / "SNMPathy"


def test_explicit_destination_and_env_override(build, monkeypatch, tmp_path):
    assert build.resolve_destination(str(tmp_path / "x")) == (tmp_path / "x").resolve()
    monkeypatch.setenv("SNMPATHY_EXE_DIR", str(tmp_path / "y"))
    assert build.resolve_destination(None) == (tmp_path / "y").resolve()


def test_no_claude_folder(build):
    assert build.find_claude_folder() is None
    assert build.resolve_destination(None) is None


def test_build_stamp_is_written(build, tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "snmpathy").mkdir(parents=True)
    monkeypatch.setattr(build, "ROOT", root)
    stamp = build.write_build_stamp()
    text = (root / "snmpathy" / "_build.py").read_text()
    assert f"BUILD = {stamp!r}" in text and stamp  # date only outside a git checkout


def test_version_string_includes_build(monkeypatch):
    import snmpathy

    monkeypatch.setattr(snmpathy, "BUILD", "abc1234, 2026-11-12")
    assert snmpathy.version_string() == f"{snmpathy.__version__} (build abc1234, 2026-11-12)"
