"""Update the SNMPathy executable by downloading the latest release from GitHub.

CI builds SNMPathy for Windows, macOS and Linux on every change to ``main`` and publishes
the executables as a GitHub release (``.github/workflows/ci.yml``). Updating therefore
needs nothing installed on the computer - no Python, no Git, no build:

1. ask GitHub for the latest release and compare it with this executable's version and
   build commit (``snmpathy version``),
2. download this platform's executable next to the running one, check its size and
   SHA-256 and that it starts (``<new> version``),
3. close the running SNMPathy, swap the files (the old one is kept as ``SNMPathy.old.exe``
   until the next start, and put back if anything goes wrong) and start the new one.

``snmpathy self-update`` runs it (``--gui`` shows a progress window: what the tray's
**Update SNMPathy** opens; ``--check`` only reports). Running from a source checkout,
``scripts/update`` (git pull + local build) is still the way to update.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import BUILD, __version__

log = logging.getLogger(__name__)

REPO = "OccuviteASI/SNMPathy"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"
IS_WINDOWS = sys.platform.startswith("win")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
AUTO_CLOSE_SECONDS = 5

Say = Callable[[int, str], None]  # (percent, message)


class UpdateError(RuntimeError):
    pass


def asset_name(platform: str | None = None) -> str:
    platform = platform or sys.platform
    if platform.startswith("win"):
        return "SNMPathy-windows.exe"
    if platform == "darwin":
        return "SNMPathy-macos"
    return "SNMPathy-linux"


def parse_version(text: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", text.split("+")[0])[:4])


def own_commit(build: str = BUILD) -> str:
    match = re.match(r"([0-9a-f]{7,40})\b", build or "")
    return match.group(1) if match else ""


@dataclass
class Release:
    version: str
    tag: str
    commit: str
    url: str
    size: int
    digest: str = ""
    notes: str = ""

    @classmethod
    def from_api(cls, data: dict, platform: str | None = None) -> "Release":
        name = asset_name(platform)
        asset = next((a for a in data.get("assets") or [] if a.get("name") == name), None)
        if asset is None:
            raise UpdateError(f"the latest release ({data.get('tag_name')}) has no {name}")
        url = asset.get("browser_download_url") or ""
        if not url.startswith("https://github.com/"):
            raise UpdateError(f"unexpected download address {url!r}")
        commit = data.get("target_commitish") or ""
        if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
            found = re.search(r"\bbuild ([0-9a-f]{7,40})\b", data.get("body") or "")
            commit = found.group(1) if found else ""
        return cls(version=(data.get("tag_name") or "").lstrip("v"), tag=data.get("tag_name") or "", commit=commit,
                   url=url, size=int(asset.get("size") or 0), digest=asset.get("digest") or "",
                   notes=data.get("body") or "")

    def is_newer(self, version: str = __version__, build: str = BUILD) -> bool:
        """True when this release is a later version, or the same version from another commit."""
        mine, theirs = parse_version(version), parse_version(self.version)
        if theirs != mine:
            return theirs > mine
        commit = own_commit(build)
        return bool(commit and self.commit) and not (self.commit.startswith(commit) or commit.startswith(self.commit))


# --------------------------------------------------------------------------- network
def _contexts() -> list[ssl.SSLContext]:
    """The system's certificates first (company proxies add theirs there), then certifi's."""
    out = [ssl.create_default_context()]
    try:
        import certifi

        out.append(ssl.create_default_context(cafile=certifi.where()))
    except Exception:
        pass
    return out


def _open(url: str, accept: str, timeout: float):
    headers = {"Accept": accept, "User-Agent": f"SNMPathy-updater/{__version__}"}
    token = os.environ.get("SNMPATHY_GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    last: Exception | None = None
    for context in _contexts():
        try:
            return urllib.request.urlopen(request, timeout=timeout, context=context)
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                last = exc
                continue
            raise
    raise UpdateError(f"could not verify GitHub's certificate: {last}")


def latest_release(timeout: float = 20, platform: str | None = None) -> Release | None:
    """The latest published release, or None when there is none yet."""
    try:
        with _open(LATEST_URL, "application/vnd.github+json", timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code in (403, 429):
            raise UpdateError("GitHub is limiting requests from this network right now; try again in an hour")
        raise UpdateError(f"GitHub answered {exc.code} {exc.reason}")
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError(f"could not reach GitHub: {getattr(exc, 'reason', exc)}")
    return Release.from_api(data, platform)


def download(release: Release, dest: Path, progress: Callable[[int, int], None] | None = None,
             timeout: float = 60) -> Path:
    """Download the release's executable to ``dest`` (checked against its size and SHA-256)."""
    part = dest.with_name(dest.name + ".part")
    sha = hashlib.sha256()
    done = 0
    try:
        with _open(release.url, "application/octet-stream", timeout) as resp, part.open("wb") as fh:
            total = int(resp.headers.get("Content-Length") or release.size or 0)
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                sha.update(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
    except (urllib.error.URLError, OSError) as exc:
        part.unlink(missing_ok=True)
        raise UpdateError(f"download failed: {getattr(exc, 'reason', exc)}")
    if release.size and done != release.size:
        part.unlink(missing_ok=True)
        raise UpdateError(f"download incomplete ({done} of {release.size} bytes)")
    if release.digest.startswith("sha256:") and sha.hexdigest() != release.digest.split(":", 1)[1].lower():
        part.unlink(missing_ok=True)
        raise UpdateError("the download is damaged (SHA-256 does not match the release)")
    if not IS_WINDOWS:
        part.chmod(0o755)
    os.replace(part, dest)
    return dest


def reported_version(exe: Path) -> str:
    """What ``<exe> version`` prints ('' if it does not start)."""
    try:
        out = subprocess.run([str(exe), "version"], capture_output=True, text=True, timeout=180,
                             stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return ""
    return (out.stdout or "").strip()


# --------------------------------------------------------------------------- swap
def old_path(exe: Path) -> Path:
    return exe.with_name(f"{exe.stem}.old{exe.suffix}")


def cleanup_old(exe: Path) -> None:
    """Remove what an earlier update left behind (still locked right after it: next start then)."""
    for path in (old_path(exe), exe.with_name(exe.name + ".new"), exe.with_name(exe.name + ".new.part")):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def install(new: Path, exe: Path) -> None:
    """Put ``new`` in place of ``exe``. Windows lets a running executable be renamed, not replaced."""
    old = old_path(exe)
    try:
        old.unlink(missing_ok=True)
    except OSError:
        old = exe.with_name(f"{exe.stem}.old-{int(time.time())}{exe.suffix}")
    moved = False
    if exe.exists():
        os.replace(exe, old)
        moved = True
    try:
        os.replace(new, exe)
    except OSError:
        if moved:
            os.replace(old, exe)  # put the working one back
        raise


def running_pids(exe: Path, exclude: set[int] | None = None) -> list[int]:
    """Processes running this executable (a one-file build runs as two: a launcher and SNMPathy)."""
    exclude = exclude if exclude is not None else {os.getpid(), os.getppid()}
    target = str(exe.resolve()).lower()
    pids: list[int] = []
    try:
        if IS_WINDOWS:
            ps = (f"Get-Process -Name '{exe.stem}' -ErrorAction SilentlyContinue | "
                  "ForEach-Object { \"$($_.Id)`t$($_.Path)\" }")
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                                 timeout=60, creationflags=NO_WINDOW).stdout
            for line in out.splitlines():
                pid, _, path = line.partition("\t")
                if pid.strip().isdigit() and path.strip().lower() == target:
                    pids.append(int(pid))
        else:
            out = subprocess.run(["pgrep", "-f", str(exe)], capture_output=True, text=True, timeout=30).stdout
            pids = [int(p) for p in out.split() if p.isdigit()]
    except (OSError, subprocess.SubprocessError):
        return []
    return [p for p in pids if p not in exclude]


def stop(exe: Path) -> bool:
    """Close the running SNMPathy (not this updater). Returns whether one was running."""
    pids = running_pids(exe)
    if not pids:
        return False
    for pid in pids:
        if IS_WINDOWS:
            # Not /T: this updater was started by the tray, so it is part of the tray's process tree.
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, creationflags=NO_WINDOW)
        else:
            try:
                os.kill(pid, 15)
            except (ProcessLookupError, PermissionError):
                pass
    for _ in range(40):
        if not running_pids(exe):
            break
        time.sleep(0.5)
    time.sleep(1)  # let Windows release the file
    return True


def start(exe: Path) -> None:
    """Start SNMPathy in the tray again, the way it was started at login if it was."""
    quiet = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if IS_WINDOWS:
        vbs = Path(os.environ.get("LOCALAPPDATA", "")) / "SNMPathy" / "autostart.vbs"
        if vbs.exists():
            subprocess.Popen(["wscript.exe", "//B", "//nologo", str(vbs)], cwd=exe.parent, **quiet)
        else:
            subprocess.Popen([str(exe), "tray"], cwd=exe.parent, creationflags=NO_WINDOW, **quiet)
    else:
        subprocess.Popen([str(exe), "tray"], cwd=exe.parent, start_new_session=True, **quiet)


# --------------------------------------------------------------------------- the update
def run_update(exe: Path, say: Say, force: bool = False, restart: bool = True) -> str:
    """Update ``exe`` to the latest release. Returns 'ok' or 'current'; raises UpdateError."""
    say(3, "Checking for updates…")
    release = latest_release()
    if release is None:
        raise UpdateError(f"no SNMPathy release has been published yet ({RELEASES_PAGE})")
    say(6, f"Latest release: {release.version} (build {release.commit[:7] or '?'}); "
           f"this is {__version__}{f' (build {own_commit()})' if own_commit() else ''}")
    if not force and not release.is_newer():
        say(100, f"SNMPathy is up to date ({__version__}).")
        return "current"

    new = exe.with_name(exe.name + ".new")
    mb = release.size / 1048576 if release.size else 0
    say(8, f"Downloading SNMPathy {release.version}{f' ({mb:.0f} MB)' if mb else ''}…")
    last = [0]

    def progress(done: int, total: int) -> None:
        pct = 8 + int(72 * done / total) if total else 40
        if pct != last[0]:
            last[0] = pct
            say(pct, f"Downloading SNMPathy {release.version}… {done / 1048576:.0f} of {total / 1048576:.0f} MB"
                if total else f"Downloading SNMPathy {release.version}… {done / 1048576:.0f} MB")
    download(release, new, progress)

    say(82, "Checking the new version starts…")
    reported = reported_version(new)
    if release.version not in reported:
        new.unlink(missing_ok=True)
        raise UpdateError(f"the downloaded SNMPathy did not start properly ({reported or 'no output'})")

    say(88, "Closing SNMPathy…")
    was_running = stop(exe)
    say(93, "Installing the new version…")
    try:
        install(new, exe)
    except OSError as exc:
        if was_running and restart:
            start(exe)
        raise UpdateError(f"could not replace {exe} ({exc}); is the folder read-only?")
    if restart:
        say(97, "Starting SNMPathy…")
        start(exe)
    say(100, f"Updated to SNMPathy {release.version}.")
    return "ok"


def current_exe() -> Path:
    return Path(sys.executable).resolve()


# --------------------------------------------------------------------------- window
class UpdateWindow:
    """Progress window: status line, progress bar, details; closes itself after a success."""

    def __init__(self, work: Callable[[Say], str]):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText

        self.work = work
        self.events: queue.Queue[tuple] = queue.Queue()
        self.outcome: str | None = None
        self.running = True
        self.close_timer = None
        _dpi_aware()
        root = self.root = tk.Tk()
        root.title("Updating SNMPathy")
        root.resizable(True, False)
        root.minsize(480, 0)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        _set_icon(root)
        frame = ttk.Frame(root, padding=(18, 16, 18, 14))
        frame.pack(fill="both", expand=True)
        bold = ("Segoe UI", 12, "bold") if IS_WINDOWS else ("TkDefaultFont", 12, "bold")
        self.title = ttk.Label(frame, text="Updating SNMPathy", font=bold)
        self.title.pack(anchor="w")
        self.status = ttk.Label(frame, text="Starting…", wraplength=520, justify="left")
        self.status.pack(anchor="w", pady=(6, 10), fill="x")
        self.bar = ttk.Progressbar(frame, mode="determinate", maximum=100, length=520)
        self.bar.pack(fill="x")
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(14, 0))
        self.details_btn = ttk.Button(buttons, text="Show details", command=self.toggle_details)
        self.details_btn.pack(side="left")
        self.close_btn = ttk.Button(buttons, text="Run in background", command=self.on_close)
        self.close_btn.pack(side="right")
        self.log = ScrolledText(frame, height=12, width=80, wrap="word",
                                font=("Consolas", 9) if IS_WINDOWS else ("TkFixedFont", 9), state="disabled")
        self.details_shown = False
        root.update_idletasks()
        x = (root.winfo_screenwidth() - root.winfo_width()) // 2
        y = (root.winfo_screenheight() - root.winfo_height()) // 3
        root.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        root.lift()
        root.attributes("-topmost", True)
        root.after(800, lambda: root.attributes("-topmost", False))

    def _worker(self) -> None:
        try:
            outcome = self.work(lambda pct, msg: self.events.put(("say", pct, msg)))
            self.events.put(("done", outcome, ""))
        except UpdateError as exc:
            self.events.put(("done", "failed", str(exc)))
        except Exception as exc:  # anything unexpected: show it rather than vanish
            log.exception("update failed")
            self.events.put(("done", "failed", f"{type(exc).__name__}: {exc}"))

    def poll(self) -> None:
        try:
            while True:
                kind, a, b = self.events.get_nowait()
                if kind == "say":
                    self.bar["value"] = a
                    self.status["text"] = b
                    self.add_log(b)
                else:
                    self.finish(a, b)
                    return
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def finish(self, outcome: str, error: str) -> None:
        self.running, self.outcome = False, outcome
        if outcome == "failed":
            self.title["text"] = "SNMPathy update failed"
            self.status["text"] = f"Update failed: {error}"
            self.add_log(f"UPDATE FAILED: {error}\nSNMPathy keeps running the version it had.")
            if not self.details_shown:
                self.toggle_details()
        else:
            self.bar["value"] = 100
            self.title["text"] = "SNMPathy is up to date" if outcome == "current" else "SNMPathy updated"
        self.root.title(self.title["text"])
        self.close_btn["text"] = "Close"
        if self.root.state() == "withdrawn":
            self.root.destroy()
            return
        if outcome != "failed" and not self.details_shown:
            self.countdown(AUTO_CLOSE_SECONDS)

    def countdown(self, seconds: int) -> None:
        if seconds <= 0:
            self.root.destroy()
            return
        self.close_btn["text"] = f"Close ({seconds})"
        self.close_timer = self.root.after(1000, lambda: self.countdown(seconds - 1))

    def cancel_countdown(self) -> None:
        if self.close_timer is not None:
            self.root.after_cancel(self.close_timer)
            self.close_timer = None
            self.close_btn["text"] = "Close"

    def add_log(self, line: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", f"{time.strftime('%H:%M:%S')}  {line}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def toggle_details(self) -> None:
        self.cancel_countdown()
        if self.details_shown:
            self.log.pack_forget()
            self.root.resizable(True, False)
        else:
            self.log.pack(fill="both", expand=True, pady=(12, 0))
            self.root.resizable(True, True)
        self.details_shown = not self.details_shown
        self.details_btn["text"] = "Hide details" if self.details_shown else "Show details"

    def on_close(self) -> None:
        if not self.running:
            self.root.destroy()
            return
        self.root.withdraw()  # keep going in the background

    def run(self) -> int:
        threading.Thread(target=self._worker, name="snmpathy-update", daemon=True).start()
        self.root.after(100, self.poll)
        self.root.mainloop()
        return 0 if self.outcome in ("ok", "current") else 1


def has_window() -> bool:
    try:
        import tkinter  # noqa: F401
    except Exception:
        return False
    return True


def _dpi_aware() -> None:
    if IS_WINDOWS:
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
        except Exception:
            pass


def _set_icon(root) -> None:
    """The tray icon's blue pulse tile, drawn with Tk."""
    try:
        import tkinter as tk

        size = 32
        img = tk.PhotoImage(width=size, height=size)
        img.put("#2a78d6", to=(0, 0, size, size))
        for x, y in [(6, 18), (7, 18), (8, 18), (9, 18), (10, 18), (11, 17), (12, 15), (13, 12), (14, 10),
                     (15, 13), (16, 17), (17, 21), (18, 23), (19, 20), (20, 17), (21, 16), (22, 16), (23, 16),
                     (24, 16), (25, 16)]:
            img.put("#ffffff", to=(x, y - 1, x + 1, y + 2))
        root.iconphoto(True, img)
        root._icon = img
    except Exception:
        pass


def main(gui: bool = False, check: bool = False, force: bool = False, restart: bool = True,
         exe: Path | None = None) -> int:
    """``snmpathy self-update``."""
    if check:
        try:
            release = latest_release()
        except UpdateError as exc:
            print(f"update check failed: {exc}")
            return 1
        if release is None:
            print("no release published yet")
        elif release.is_newer():
            print(f"SNMPathy {release.version} (build {release.commit[:7]}) is available; this is {__version__}")
        else:
            print(f"up to date: {__version__} (latest release {release.version})")
        print(f"progress window: {'yes' if has_window() else 'no (updates run without a window)'}")
        return 0
    from .config import is_frozen

    target = exe or current_exe()
    if exe is None and not is_frozen():
        print("self-update replaces the SNMPathy executable; this is running from Python "
              "(update a source checkout with scripts/update)")
        return 2
    cleanup_old(target)

    def work(say: Say) -> str:
        return run_update(target, say, force=force, restart=restart)

    if gui:
        try:
            window = UpdateWindow(work)
        except Exception as exc:  # no Tk or no display: carry on without a window
            log.warning("no update window (%s); updating in the background", exc)
        else:
            return window.run()
    try:
        outcome = work(lambda pct, msg: print(f"[{pct:3d}%] {msg}", flush=True))
    except UpdateError as exc:
        print(f"UPDATE FAILED: {exc}", flush=True)
        return 1
    return 0 if outcome in ("ok", "current") else 1
