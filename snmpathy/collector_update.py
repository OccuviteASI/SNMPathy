"""Collectors update themselves to their server's version.

Every poll answer carries the server's version. When it is newer than this collector's, the
collector downloads the matching build **from its server** (``/collector/download/...``, which
the server fetches from the release once), checks that it starts and reports a newer version,
swaps it in and restarts:

* Linux: ``exec`` of the new executable in place (same process, so systemd and launchd keep
  tracking it);
* Windows: starts the new executable with the same arguments and exits (tray app, scheduled
  task or a console).

Results not yet sent are saved to the collector's buffer first, so the new copy sends them.
Only the standalone executables update themselves (a pip install is updated with pip). Turn it
off with ``auto_update: false`` in ``collector.yaml``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from . import __version__

log = logging.getLogger("snmpathy.collector.update")

FIRST_CHECK = 20  # seconds after start
CHECK_EVERY = 60
RETRY_AFTER = 6 * 3600  # a failed update of one version is tried again after this long
IS_WINDOWS = sys.platform.startswith("win")


def _version_tuple(text: str) -> tuple[int, ...]:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in match.groups()) if match else ()


def enabled(conf: dict[str, Any] | None) -> bool:
    from .config import is_frozen

    value = (conf or {}).get("auto_update", True)
    return is_frozen() and str(value).lower() not in ("false", "0", "no", "off")


def newer_server_version(agent: Any, current: str = __version__) -> str:
    """The server's version when it is newer than this collector's ('' otherwise)."""
    server = getattr(agent, "server_version", "") or ""
    mine, theirs = _version_tuple(current), _version_tuple(server)
    return server if mine and theirs and theirs > mine else ""


def download_path() -> tuple[str, dict[str, str]]:
    """Where this program's own build is on the server: the Collector app or the full SNMPathy."""
    from . import selfupdate

    if selfupdate.PRODUCT == "SNMPathy-Collector":
        return f"/collector/download/{selfupdate.asset_name()}", {}
    return "/collector/download/server", {"os_": "Windows" if IS_WINDOWS else "Linux"}


def fetch(agent: Any, exe: Path, version: str) -> Path:
    """Download the server's build next to ``exe`` and check it (raises RuntimeError)."""
    import httpx

    from .selfupdate import reported_version

    path, params = download_path()
    new = exe.with_name(exe.name + ".new")
    part = new.with_name(new.name + ".part")
    try:
        with httpx.Client(base_url=agent.server, verify=agent.verify, follow_redirects=True,
                          timeout=httpx.Timeout(300.0, connect=15.0),
                          headers={"User-Agent": f"snmpathy-collector/{__version__}"}) as http:
            with http.stream("GET", path, params=params) as r:
                if r.status_code != 200:
                    raise RuntimeError(f"the server has no build to update to ({path}: HTTP {r.status_code})")
                with part.open("wb") as fh:
                    for chunk in r.iter_bytes(256 * 1024):
                        fh.write(chunk)
    except httpx.HTTPError as exc:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"download failed: {exc}")
    if not IS_WINDOWS:
        part.chmod(0o755)
    os.replace(part, new)
    reported = reported_version(new)
    if _version_tuple(reported) <= _version_tuple(__version__):
        new.unlink(missing_ok=True)
        raise RuntimeError(f"the server's build is not newer ({reported or 'it did not start'}; this is {__version__})")
    return new


def update(agent: Any, version: str, exe: Path | None = None) -> Path:
    """Download, check and swap in the new build (the caller then restarts)."""
    from . import procutil, selfupdate, tray  # noqa: F401 - everything used after the swap, loaded now

    exe = exe or Path(sys.executable).resolve()
    selfupdate.cleanup_old(exe)
    new = fetch(agent, exe, version)
    # From here on this process runs from a renamed file: import nothing new (see selfupdate.run_update).
    selfupdate._preload()
    selfupdate.install(new, exe)
    return exe


def relaunch(exe: Path) -> bool:
    """Start the new build with this process's arguments. Linux: never returns. Windows: True."""
    from .procutil import self_env
    from .tray import DETACHED_ENV

    argv = [str(exe), *sys.argv[1:]]
    env = self_env({DETACHED_ENV: "1"})
    if not IS_WINDOWS:
        os.execve(str(exe), argv, env)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    quiet = dict(cwd=str(exe.parent), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                 stderr=subprocess.DEVNULL)
    try:  # out of a scheduled task's job, so it keeps running when this copy exits
        subprocess.Popen(argv, creationflags=flags | getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0), **quiet)
    except OSError:
        subprocess.Popen(argv, creationflags=flags, **quiet)
    return True


async def auto_update_loop(agent: Any, conf: dict[str, Any] | None = None,
                           on_restart: Callable[[], None] = lambda: os._exit(0),
                           first: float = FIRST_CHECK, every: float = CHECK_EVERY,
                           do_update: Callable[..., Path] = update, do_relaunch: Callable[[Path], bool] = relaunch,
                           ) -> None:
    """Watch the server's version and update this collector when it is newer."""
    if not enabled(conf) and do_update is update:
        return
    tried: dict[str, float] = {}
    await asyncio.sleep(first)
    while True:
        version = newer_server_version(agent)
        if version and time.time() - tried.get(version, 0) >= RETRY_AFTER:
            tried[version] = time.time()
            log.info("the server runs SNMPathy %s and this collector %s: updating", version, __version__)
            try:
                exe = await asyncio.to_thread(do_update, agent, version)
            except Exception as exc:
                log.warning("collector update to %s failed: %s (trying again in %d hours)", version, exc,
                            RETRY_AFTER // 3600)
            else:
                log.info("updated to %s: restarting", version)
                agent.hand_over()  # results not sent yet go to the buffer the new copy reads
                if do_relaunch(exe):
                    on_restart()
                    return
        await asyncio.sleep(every)
