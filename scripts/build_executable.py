#!/usr/bin/env python3
"""Build a standalone SNMPathy executable and store it in your Claude folder.

    python scripts/build_executable.py                # Windows: py -3 scripts\\build_executable.py
    python scripts/build_executable.py --dest D:\\Tools\\SNMPathy
    python scripts/build_executable.py --no-copy      # just build into ./dist

The executable is a single file (SNMPathy.exe on Windows, SNMPathy on macOS /
Linux) that needs no Python installation. By default it is copied to

    <Claude folder>/SNMPathy/

where <Claude folder> is the folder that holds your other projects (KASTR,
DiskWorks, LinkTest). The folder is found automatically; pass --dest, or set
SNMPATHY_EXE_DIR, to choose another location. An existing database and
configuration in the destination are never overwritten.

PyInstaller builds for the platform it runs on, so run this script on each
OS you need an executable for (CI also publishes all three as artifacts).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIBLINGS = ("KASTR", "DiskWorks", "LinkTest")
APP_FOLDER = "SNMPathy"
IS_WINDOWS = sys.platform.startswith("win")
EXE_NAME = "SNMPathy.exe" if IS_WINDOWS else "SNMPathy"
BUILD_DIR = ROOT / "build"
VENV_DIR = BUILD_DIR / "venv"


def log(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


# --------------------------------------------------------------- destination
def _has_sibling(folder: Path) -> bool:
    try:
        names = {p.name.lower() for p in folder.iterdir() if p.is_dir()}
    except OSError:
        return False
    return any(s.lower() in names for s in SIBLINGS)


def _candidate_folders() -> list[Path]:
    home = Path.home()
    out = list(ROOT.parents)  # the repository usually lives inside the Claude folder
    bases = [home, home / "Documents", home / "Desktop", home / "Projects", home / "source" / "repos"]
    for env in ("OneDrive", "OneDriveCommercial", "OneDriveConsumer"):
        if os.environ.get(env):
            bases += [Path(os.environ[env]), Path(os.environ[env]) / "Documents"]
    bases.append(home / "OneDrive" / "Documents")
    for base in bases:
        out += [base / "Claude", base / "claude"]
    seen, unique = set(), []
    for p in out:
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def find_claude_folder() -> Path | None:
    """The folder containing KASTR / DiskWorks / LinkTest, else one named 'Claude'."""
    candidates = [p for p in _candidate_folders() if p.is_dir()]
    for folder in candidates:
        if _has_sibling(folder):
            return folder
    for folder in candidates:
        if folder.name.lower() == "claude":
            return folder
    return None


def resolve_destination(dest: str | None) -> Path | None:
    if dest:
        return Path(dest).expanduser().resolve()
    if os.environ.get("SNMPATHY_EXE_DIR"):
        return Path(os.environ["SNMPATHY_EXE_DIR"]).expanduser().resolve()
    claude = find_claude_folder()
    return (claude / APP_FOLDER) if claude else None


# --------------------------------------------------------------------- build
def venv_python() -> Path:
    return VENV_DIR / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def ensure_build_env(fresh: bool) -> Path:
    """An isolated virtualenv with SNMPathy and PyInstaller, so your own Python stays untouched."""
    if fresh and VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
    if not venv_python().exists():
        log(f"creating build environment in {VENV_DIR}")
        venv.EnvBuilder(with_pip=True, clear=True).create(VENV_DIR)
    py = str(venv_python())
    log("installing SNMPathy and PyInstaller into the build environment")
    subprocess.run([py, "-m", "pip", "install", "--quiet", "--upgrade", "pip"], check=True)
    subprocess.run([py, "-m", "pip", "install", "--quiet", str(ROOT), "pyinstaller>=6.0"], check=True)
    return venv_python()


def build(py: Path) -> Path:
    log("running PyInstaller (this takes a minute)")
    subprocess.run(
        [str(py), "-m", "PyInstaller", "--noconfirm", "--clean",
         "--distpath", str(ROOT / "dist"), "--workpath", str(BUILD_DIR / "pyinstaller"),
         str(ROOT / "packaging" / "snmpathy.spec")],
        check=True, cwd=ROOT,
    )
    exe = ROOT / "dist" / EXE_NAME
    if not exe.exists():
        raise SystemExit(f"build finished but {exe} was not produced")
    return exe


def smoke_test(exe: Path) -> None:
    out = subprocess.run([str(exe), "version"], capture_output=True, text=True, timeout=120)
    if out.returncode != 0 or "snmpathy" not in out.stdout:
        raise SystemExit(f"smoke test failed:\n{out.stdout}\n{out.stderr}")
    log(f"smoke test ok: {out.stdout.strip()}")


RUN_NOTES = """SNMPathy
========

Start:    double-click {exe} (or run it from a terminal). The web UI opens at
          http://localhost:8080/ and the console window shows the log.
Stop:     press Ctrl+C in the console window (or close it).
Demo:     {exe} demo --open        (simulated devices, separate database)
Help:     {exe} --help             (serve, demo, walk, get, discover, ping, ...)

Data:     snmpathy.db in this folder (created on first start).
Config:   edit snmpathy.yaml in this folder, then restart.
Syslog:   point devices at this machine on UDP/TCP port 5514.
{extra}"""


def install(exe: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / EXE_NAME
    tmp = dest / (EXE_NAME + ".new")
    shutil.copy2(exe, tmp)
    try:
        os.replace(tmp, target)
    except PermissionError:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"{target} is in use: stop the running SNMPathy and build again")
    if not IS_WINDOWS:
        target.chmod(0o755)
    config = dest / "snmpathy.yaml"
    if not config.exists():
        subprocess.run([str(target), "init-config", str(config)], check=True, capture_output=True)
        log(f"wrote default configuration {config}")
    extra = ("Windows:  allow SNMPathy through the firewall when prompted, or run\n"
             "          deploy\\windows\\install-service.ps1 from the repository to install a service.\n"
             if IS_WINDOWS else
             "Service:  see deploy/ in the repository (systemd unit, launchd plist).\n")
    (dest / "README.txt").write_text(RUN_NOTES.format(exe=EXE_NAME, extra=extra), encoding="utf-8")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", help="folder to store the executable in (default: <Claude folder>/SNMPathy)")
    parser.add_argument("--no-copy", action="store_true", help="only build into ./dist")
    parser.add_argument("--fresh", action="store_true", help="recreate the build environment")
    args = parser.parse_args()

    dest = None if args.no_copy else resolve_destination(args.dest)
    if not args.no_copy and dest is None:
        log("could not find your Claude folder (the one containing " + ", ".join(SIBLINGS) + ").")
        log("re-run with --dest <folder>, e.g. --dest \"%USERPROFILE%\\Claude\\SNMPathy\"" if IS_WINDOWS
            else "re-run with --dest <folder>, e.g. --dest ~/Claude/SNMPathy")
        return 2
    if dest:
        log(f"executable will be stored in {dest}")

    py = ensure_build_env(args.fresh)
    exe = build(py)
    smoke_test(exe)
    if args.no_copy:
        log(f"built {exe}")
        return 0
    target = install(exe, dest)
    size = target.stat().st_size / 1_048_576
    log(f"done: {target} ({size:.0f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
