#!/usr/bin/env python3
"""A progress window for updating SNMPathy (what the tray's "Update SNMPathy" opens).

Runs scripts/update.py in the background with no console window, turns its output
into a progress bar and a one-line status, and keeps the full log under "Details".
Any options are passed on to update.py (e.g. --dest, --force).

Without Tk (some minimal Linux installs) the update still runs, silently, logging
to build/update.log.
"""

from __future__ import annotations

import os
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPDATE_SCRIPT = ROOT / "scripts" / "update.py"
IS_WINDOWS = sys.platform.startswith("win")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# (pattern in the update / build output, progress %, status shown to the user)
STAGES: list[tuple[str, int, str]] = [
    (r"checking .* for updates", 4, "Checking for updates…"),
    (r"switching to", 6, "Switching to the main branch…"),
    (r"updated \w+ -> \w+", 10, "Downloaded the latest version"),
    (r"source is already up to date", 10, "Source is up to date"),
    (r"installed build:", 12, "Preparing the update…"),
    (r"closing the running SNMPathy", 14, "Closing SNMPathy…"),
    (r"executable will be stored", 16, "Preparing the build…"),
    (r"step 1/4", 18, "Preparing the build environment…"),
    (r"step 2/4", 24, "Installing packages (the first update downloads about 60 MB)…"),
    (r"step 3/4", 50, "Building SNMPathy (a minute or two)…"),
    (r"step 4/4", 88, "Checking the new version starts…"),
    (r"BUILD OK", 93, "Installing the new version…"),
    (r"\[update\] starting ", 97, "Starting SNMPathy…"),
]
AUTO_CLOSE_SECONDS = 5  # after a successful update the window closes itself (failures stay open)
# While pip / PyInstaller print lines, creep forward inside the current stage.
CREEP_LIMIT = {24: 46, 50: 86}


def parse_line(line: str, percent: int) -> tuple[int, str | None, str | None]:
    """Progress after this output line: (percent, new status or None, outcome or None).

    outcome is "ok", "current" (nothing to update) or "failed".
    """
    text = line.strip()
    if "UPDATE FAILED" in text or "BUILD FAILED" in text:
        reason = text.split("FAILED", 1)[1].lstrip(": ").strip().replace("messages above", "details below")
        reason = reason or "see the details below"
        return percent, f"Update failed: {reason}", "failed"
    if "UPDATE OK" in text:
        build = re.search(r"build (\S+)", text)
        return 100, f"SNMPathy is up to date{f' (build {build.group(1)})' if build else ''}.", "ok"
    if "nothing to do" in text:
        build = re.search(r"already build (\S+?):", text)
        return 100, f"SNMPathy is already the latest version{f' (build {build.group(1)})' if build else ''}.", "current"
    for pattern, pct, status in STAGES:
        if re.search(pattern, text):
            return max(percent, pct), status, None
    for start, limit in CREEP_LIMIT.items():
        if start <= percent < limit and text:
            return percent + (1 if percent < limit - 1 else 0), None, None
    return percent, None, None


def error_line(line: str) -> bool:
    """A line that names the cause of a failure (pip, git and Python errors)."""
    text = line.strip()
    return bool(re.match(r"(ERROR|error|fatal|\w+Error)\b[:\s]", text)) and "FAILED" not in text


def console_python() -> str:
    """python.exe rather than pythonw.exe, so the update's child processes share one hidden console."""
    exe = Path(sys.executable)
    if exe.name.lower() == "pythonw.exe" and exe.with_name("python.exe").exists():
        return str(exe.with_name("python.exe"))
    return str(exe)


def update_command(args: list[str]) -> list[str]:
    return [console_python(), "-u", str(UPDATE_SCRIPT), "--from-tray", *args]


def start_update(args: list[str]) -> subprocess.Popen:
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    return subprocess.Popen(update_command(args), cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=NO_WINDOW)


# ----------------------------------------------------------------- window
class UpdateWindow:
    def __init__(self, args: list[str]):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText

        self.tk, self.args = tk, args
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.percent, self.outcome, self.proc = 0, None, None
        self.last_error = ""
        self.close_timer = None
        self.running = True

        _dpi_aware()
        root = self.root = tk.Tk()
        root.title("Updating SNMPathy")
        root.resizable(True, False)
        root.minsize(480, 0)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        _set_icon(root)

        frame = ttk.Frame(root, padding=(18, 16, 18, 14))
        frame.pack(fill="both", expand=True)
        self.title = ttk.Label(frame, text="Updating SNMPathy", font=("Segoe UI", 12, "bold") if IS_WINDOWS
                               else ("TkDefaultFont", 12, "bold"))
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

        self.log = ScrolledText(frame, height=14, width=80, wrap="word", font=("Consolas", 9) if IS_WINDOWS
                                else ("TkFixedFont", 9), state="disabled")
        self.details_shown = False

        root.update_idletasks()
        x = (root.winfo_screenwidth() - root.winfo_width()) // 2
        y = (root.winfo_screenheight() - root.winfo_height()) // 3
        root.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        root.lift()
        root.attributes("-topmost", True)
        root.after(800, lambda: root.attributes("-topmost", False))

    # -------------------------------------------------------------- update
    def start(self) -> None:
        try:
            self.proc = start_update(self.args)
        except OSError as exc:
            self.lines.put(f"[update] UPDATE FAILED: could not start the updater: {exc}")
            self.lines.put(None)
            return
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for raw in self.proc.stdout:
            self.lines.put(raw.decode("utf-8", errors="replace").rstrip())
        self.proc.wait()
        self.lines.put(None)

    def poll(self) -> None:
        try:
            while True:
                line = self.lines.get_nowait()
                if line is None:
                    self.finish(self.proc.returncode if self.proc else 1)
                    return
                self.add_log(line)
                if error_line(line):
                    self.last_error = re.sub(r"^(ERROR|error):\s*", "", line.strip())
                self.percent, status, outcome = parse_line(line, self.percent)
                self.bar["value"] = self.percent
                if outcome == "failed":
                    if self.outcome != "failed":  # the first failure is the cause; later ones are follow-ups
                        self.status["text"] = f"Update failed: {self.last_error}" if self.last_error else status
                    self.outcome = outcome
                elif status and self.outcome != "failed":
                    self.status["text"] = status
                    self.outcome = outcome or self.outcome
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def finish(self, rc: int) -> None:
        self.running = False
        if rc != 0 and self.outcome != "failed":
            self.outcome = "failed"
            self.status["text"] = (f"Update failed: {self.last_error}" if self.last_error
                                   else f"Update failed (exit code {rc}); see the details below.")
        if self.outcome == "failed":
            self.title["text"] = "SNMPathy update failed"
            self.root.title("SNMPathy update failed")
            if not self.details_shown:
                self.toggle_details()
            self.add_log("\nNothing was changed if the build did not finish; SNMPathy keeps running the "
                         "previous version. Send the lines above if you need help.")
        else:
            self.bar["value"] = 100
            self.title["text"] = "SNMPathy is up to date" if self.outcome == "current" else "SNMPathy updated"
            self.root.title(self.title["text"])
        self.close_btn["text"] = "Close"
        if self.root.state() == "withdrawn":  # closed while running: nothing left to show
            self.root.destroy()
            return
        if self.outcome != "failed" and not self.details_shown:
            self.countdown(AUTO_CLOSE_SECONDS)

    def countdown(self, seconds: int) -> None:
        """Close by itself after a successful update; the button shows the seconds left."""
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

    # -------------------------------------------------------------- ui
    def add_log(self, line: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def toggle_details(self) -> None:
        self.cancel_countdown()  # reading the log: stay open
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
        # Keep reading its output so the update can finish; just stop showing it.
        self.root.withdraw()

    def run(self) -> int:
        self.start()
        self.root.after(100, self.poll)
        self.root.mainloop()
        return 0 if self.outcome in ("ok", "current") else 1


def _dpi_aware() -> None:
    if IS_WINDOWS:  # crisp text on high-DPI screens
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
        except Exception:
            pass


def _set_icon(root) -> None:
    """The same blue pulse tile as the tray icon, drawn without Pillow."""
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
        root._icon = img  # keep a reference
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        import tkinter  # noqa: F401

        window = UpdateWindow(args)
    except Exception:  # no Tk, or no display: update without a window
        proc = subprocess.run([console_python(), str(UPDATE_SCRIPT), "--quiet", *args], cwd=ROOT,
                              creationflags=NO_WINDOW)
        return proc.returncode
    return window.run()


if __name__ == "__main__":
    raise SystemExit(main())
