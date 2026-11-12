#!/usr/bin/env python3
"""Update SNMPathy: pull the latest code, rebuild the executable and restart it.

    scripts\\update.cmd                 (Windows: double-click, or "Update SNMPathy.cmd" next to SNMPathy.exe)
    scripts/update.sh                  (macOS / Linux)
    tray menu > Update SNMPathy        (runs this through scripts/update_gui.py: a progress window)

Steps:
  1. git fetch, switch to main and fast-forward to origin/main (local edits are never discarded)
  2. stop if nothing changed and the installed executable is already this build
  3. close the running SNMPathy (the one in your Claude folder) so it can be replaced
  4. build and install the executable (scripts/build_executable.py)
  5. start SNMPathy again if it was running

Options:
  --force         rebuild even if nothing changed
  --no-restart    do not start SNMPathy again afterwards
  --quiet         no prompts; log to build/update.log (used by the scheduled update)
  --schedule      also check for updates every day (Windows scheduled task / cron); --unschedule removes it
  --dest DIR      where the executable lives (default: <Claude folder>/SNMPathy)
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IS_WINDOWS = sys.platform.startswith("win")
EXE_NAME = "SNMPathy.exe" if IS_WINDOWS else "SNMPathy"
TASK_NAME = "SNMPathy Update"
BRANCH = "main"
LOG_FILE = ROOT / "build" / "update.log"
LOCK_FILE = ROOT / "build" / "update.lock"
LOCK_STALE = 2 * 3600  # an update never takes this long: the lock was left by a crash
_quiet = False


def log(msg: str) -> None:
    line = f"[update] {msg}"
    print(line, flush=True)
    if _quiet:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")


class UpdateError(RuntimeError):
    pass


# ---------------------------------------------------------------------- git
def git(*args: str, check: bool = True) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=300)
    except FileNotFoundError as exc:
        raise UpdateError("git is not installed or not on PATH (install Git for Windows from git-scm.com)") from exc
    if check and out.returncode != 0:
        raise UpdateError(f"git {' '.join(args)} failed: {(out.stderr or out.stdout).strip()}")
    return out.stdout.strip()


def pull_latest() -> tuple[str, str]:
    """Fast-forward the checkout to origin/main. Returns (old commit, new commit)."""
    if not (ROOT / ".git").exists():
        raise UpdateError(f"{ROOT} is not a git checkout; clone it with: git clone https://github.com/OccuviteASI/SNMPathy.git")
    old = git("rev-parse", "--short", "HEAD")
    log(f"checking {git('remote', 'get-url', 'origin', check=False) or 'origin'} for updates")
    git("fetch", "--quiet", "origin", BRANCH)
    if git("status", "--porcelain", "--untracked-files=no"):
        raise UpdateError("the source folder has local changes; commit or undo them (git stash) and run the update again")
    if git("rev-parse", "--abbrev-ref", "HEAD") != BRANCH:
        log(f"switching to {BRANCH}")
        git("checkout", "--quiet", BRANCH)
    git("merge", "--ff-only", "--quiet", f"origin/{BRANCH}")
    new = git("rev-parse", "--short", "HEAD")
    if new != old:
        count = git("rev-list", "--count", f"{old}..{new}", check=False) or "?"
        log(f"updated {old} -> {new} ({count} new commit(s))")
    else:
        log(f"source is already up to date ({new})")
    return old, new


# --------------------------------------------------------------- executable
def installed_build(exe: Path) -> str:
    """The commit the installed executable was built from ('' if unknown)."""
    if not exe.exists():
        return ""
    try:
        out = subprocess.run([str(exe), "version"], capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    match = re.search(r"\(build ([0-9a-f]{6,40})", out)
    return match.group(1) if match else ""


def needs_build(installed: str, head: str, force: bool = False) -> bool:
    return force or not installed or not head.startswith(installed[:7]) and not installed.startswith(head[:7])


def running_pids(exe: Path) -> list[int]:
    """Processes running this exact executable."""
    target = str(exe.resolve()).lower()
    if IS_WINDOWS:
        ps = ("Get-Process -Name SNMPathy -ErrorAction SilentlyContinue | "
              "ForEach-Object { \"$($_.Id)`t$($_.Path)\" }")
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                             timeout=60).stdout
        pids = []
        for line in out.splitlines():
            pid, _, path = line.partition("\t")
            if pid.strip().isdigit() and path.strip().lower() == target:
                pids.append(int(pid))
        return pids
    out = subprocess.run(["pgrep", "-f", str(exe)], capture_output=True, text=True).stdout
    return [int(p) for p in out.split() if p.isdigit() and int(p) != os.getpid()]


def stop(exe: Path) -> bool:
    pids = running_pids(exe)
    if not pids:
        return False
    log(f"closing the running SNMPathy (pid {', '.join(map(str, pids))}) so it can be replaced")
    for pid in pids:
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
        else:
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
    for _ in range(30):
        if not running_pids(exe):
            break
        time.sleep(0.5)
    time.sleep(1)  # let Windows release the file
    return True


def start(exe: Path) -> None:
    log(f"starting {exe}")
    # Never hand SNMPathy our stdout: the update progress window waits for it to close.
    quiet = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if IS_WINDOWS:
        vbs = Path(os.environ.get("LOCALAPPDATA", "")) / "SNMPathy" / "autostart.vbs"
        if vbs.exists():  # started at login without a window: do the same
            subprocess.Popen(["wscript.exe", "//B", "//nologo", str(vbs)], cwd=exe.parent, **quiet)
        else:  # in the system tray, without a console window
            subprocess.Popen([str(exe), "tray"], cwd=exe.parent, creationflags=subprocess.CREATE_NO_WINDOW,
                             **quiet)
    else:
        subprocess.Popen([str(exe), "tray"], cwd=exe.parent, start_new_session=True, **quiet)


def load_build_module():
    # Loaded after the pull so the newest build logic is used.
    spec = importlib.util.spec_from_file_location("build_executable", ROOT / "scripts" / "build_executable.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------- lock
def acquire_lock() -> bool:
    """Only one update at a time (tray click, double-click and the nightly schedule)."""
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(2):
        try:
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                if time.time() - LOCK_FILE.stat().st_mtime < LOCK_STALE:
                    return False
                LOCK_FILE.unlink()
            except FileNotFoundError:
                pass
            continue
        with os.fdopen(fd, "w") as fh:
            fh.write(str(os.getpid()))
        return True
    return False


def release_lock() -> None:
    try:
        LOCK_FILE.unlink()
    except FileNotFoundError:
        pass


# ----------------------------------------------------------------- schedule
def schedule(enable: bool) -> None:
    if IS_WINDOWS:
        if enable:
            # Run hidden so no console window pops up at night.
            command = (f"powershell -NoProfile -WindowStyle Hidden -Command "
                       f"\"& '{ROOT / 'scripts' / 'update.cmd'}' --quiet\"")
            subprocess.run(["schtasks", "/Create", "/F", "/SC", "DAILY", "/ST", "03:17", "/TN", TASK_NAME,
                            "/TR", command], check=True, capture_output=True)
            log(f"scheduled task '{TASK_NAME}' checks for updates every day at 03:17 (log: {LOG_FILE})")
        else:
            subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME], capture_output=True)
            log(f"scheduled task '{TASK_NAME}' removed")
        return
    line = f"17 3 * * * {shlex.quote(str(ROOT / 'scripts' / 'update.sh'))} --quiet  # SNMPathy update"
    current = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    kept = [ln for ln in current.splitlines() if "# SNMPathy update" not in ln]
    if enable:
        kept.append(line)
    subprocess.run(["crontab", "-"], input="\n".join(kept) + "\n", text=True, check=True)
    log("daily update check " + ("added to" if enable else "removed from") + " your crontab (03:17)")


# --------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    global _quiet
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--no-restart", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--schedule", action="store_true")
    parser.add_argument("--unschedule", action="store_true")
    parser.add_argument("--dest")
    parser.add_argument("--from-tray", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    _quiet = args.quiet

    if args.schedule or args.unschedule:
        try:
            schedule(enable=args.schedule)
        except (OSError, subprocess.CalledProcessError) as exc:
            log(f"could not change the schedule: {exc}")
            return 1
        if args.unschedule:
            return 0

    if not acquire_lock():
        log(f"UPDATE FAILED: another update is already running (if it is not, delete {LOCK_FILE})")
        return 3
    try:
        return run_update(args)
    finally:
        release_lock()


def run_update(args: argparse.Namespace) -> int:
    try:
        _, head = pull_latest()
    except UpdateError as exc:
        log(f"UPDATE FAILED: {exc}")
        return 1

    build = load_build_module()
    dest = build.resolve_destination(args.dest)
    if dest is None:
        log("UPDATE FAILED: could not find your Claude folder; run again with --dest <folder that holds SNMPathy.exe>")
        return 2
    exe = dest / EXE_NAME
    have = installed_build(exe)
    if not needs_build(have, head, args.force):
        log(f"SNMPathy in {dest} is already build {have}: nothing to do")
        return 0
    log(f"installed build: {have or 'unknown'}; building {head}")

    was_running = stop(exe)
    rc = build.main(["--dest", str(dest)])
    if rc != 0:
        log("UPDATE FAILED: the build did not succeed (see the messages above)")
        if was_running and exe.exists() and not args.no_restart:
            start(exe)  # bring the previous version back
        return rc
    if was_running and not args.no_restart:
        start(exe)
    log(f"UPDATE OK: SNMPathy is now build {installed_build(exe) or head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
