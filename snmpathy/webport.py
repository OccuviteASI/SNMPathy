"""The web UI's port: find a free one when the configured port is taken, and remember it.

Another program (a second web server, a proxy, an old SNMPathy) may already use 8080. The
tray app then moves to the next free port, saves it as ``http_port`` in ``snmpathy.yaml`` (next
to the executable), and says so in a notification. Server admin > Web port changes it by hand.
"""

from __future__ import annotations

import re
import socket
from pathlib import Path

from .config import Settings, app_dir, is_frozen

TRIES = 20  # ports after the configured one to look at


def port_free(host: str, port: int) -> bool:
    """True when this process could listen on host:port right now."""
    family = socket.AF_INET6 if ":" in (host or "") else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows: do not share a port someone else holds
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            sock.bind((host or "0.0.0.0", port))
        except OSError:
            return False
    return True


def pick_port(host: str, preferred: int, tries: int = TRIES) -> int | None:
    """The preferred port if free, else the next free one (None if none of them is)."""
    for port in range(preferred, min(preferred + tries, 65535) + 1):
        if port_free(host, port):
            return port
    return None


def config_file(settings: Settings) -> Path | None:
    """Where the port is saved: the configuration in use, or snmpathy.yaml next to the executable."""
    if getattr(settings, "config_path", ""):
        return Path(settings.config_path)
    if is_frozen():
        return app_dir() / "snmpathy.yaml"
    return None  # running from source without a config file: nothing to save into


def save_port(settings: Settings, port: int) -> Path | None:
    """Write http_port into the configuration file (keeping everything else in it)."""
    if not 1 <= int(port) <= 65535:
        raise ValueError("the port must be between 1 and 65535")
    path = config_file(settings)
    if path is None:
        return None
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    line = f"http_port: {int(port)}"
    if re.search(r"^http_port\s*:.*$", text, flags=re.M):
        text = re.sub(r"^http_port\s*:.*$", line, text, count=1, flags=re.M)
    else:
        text = (text.rstrip("\n") + "\n" if text.strip() else "") + line + "\n"
    path.write_text(text, encoding="utf-8")
    settings.config_path = str(path.resolve())
    return path


def ensure_free_port(settings: Settings) -> str:
    """Before starting: move off a taken port. Returns a message for the user ('' if nothing moved)."""
    wanted = settings.http_port
    if port_free(settings.http_host, wanted):
        return ""
    found = pick_port(settings.http_host, wanted + 1)
    if found is None:
        return f"Port {wanted} is in use and so are the next {TRIES}: the web UI cannot start. " \
               f"Set another port (http_port) in snmpathy.yaml."
    settings.http_port = found
    try:
        saved = save_port(settings, found)
    except OSError:
        saved = None
    return (f"Port {wanted} is in use by another program, so SNMPathy's web UI is on port {found}"
            + (" (saved for next time)." if saved else "."))
