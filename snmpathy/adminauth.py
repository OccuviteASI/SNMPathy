"""Who may use Server admin (startup, firewall, updates, configuration export / import).

Those settings change the computer SNMPathy runs on, so a browser elsewhere needs a
**passcode** that can only be set on that computer: in the tray (*Server admin > Server admin
config*), from a browser on the server itself, or with ``snmpathy admin-passcode set``.

A request may use Server admin when it is

* **from the server itself**: a loopback address with no reverse-proxy headers, or a browser
  the tray opened with a one-time ticket (``/admin/open?ticket=...``),
* **unlocked with the passcode**: a signed cookie, valid for ``SESSION_HOURS``,
* **an API client with the API token** in a header (``Authorization: Bearer`` / ``X-API-Key``;
  the token cookie of a logged-in browser does not count).

The passcode is stored as a salted PBKDF2 hash in the database; repeated wrong guesses lock
that address out for a while.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import threading
import time
from typing import Any

from fastapi import Request

from .db import Database

SESSION_COOKIE = "snmpathy_admin"
SESSION_HOURS = 12
TICKET_SECONDS = 120
MIN_LENGTH = 4
PBKDF2_ROUNDS = 200_000
MAX_FAILURES = 5  # wrong passcodes from one address ...
FAILURE_WINDOW = 600  # ... within this many seconds lock it out for as long
META_HASH = "admin_passcode"
META_SECRET = "admin_secret"
PROXY_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip", "x-forwarded-host")

_tickets: dict[str, float] = {}
_failures: dict[str, list[float]] = {}
_lock = threading.Lock()


class AdminDenied(Exception):
    pass


# ------------------------------------------------------------------ passcode
def passcode_set(db: Database) -> bool:
    return bool(db.get_meta(META_HASH, ""))


def set_passcode(db: Database, passcode: str) -> None:
    passcode = (passcode or "").strip()
    if len(passcode) < MIN_LENGTH:
        raise ValueError(f"the passcode needs at least {MIN_LENGTH} characters")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", passcode.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS).hex()
    db.set_meta(META_HASH, f"pbkdf2-sha256${PBKDF2_ROUNDS}${salt}${digest}")
    db.set_meta(META_SECRET, secrets.token_hex(32))  # a new passcode signs out every unlocked browser


def clear_passcode(db: Database) -> None:
    db.set_meta(META_HASH, "")
    db.set_meta(META_SECRET, secrets.token_hex(32))


def check_passcode(db: Database, passcode: str) -> bool:
    stored = db.get_meta(META_HASH, "") or ""
    try:
        _, rounds, salt, digest = stored.split("$")
        got = hashlib.pbkdf2_hmac("sha256", (passcode or "").strip().encode(), bytes.fromhex(salt), int(rounds)).hex()
    except ValueError:
        return False
    return hmac.compare_digest(got, digest)


# ------------------------------------------------------------------ sessions
def _secret(db: Database) -> bytes:
    secret = db.get_meta(META_SECRET, "")
    if not secret:
        secret = secrets.token_hex(32)
        db.set_meta(META_SECRET, secret)
    return bytes.fromhex(secret)


def make_session(db: Database, now: float | None = None) -> str:
    expires = int((now or time.time()) + SESSION_HOURS * 3600)
    sig = hmac.new(_secret(db), str(expires).encode(), hashlib.sha256).hexdigest()
    return f"{expires}.{sig}"


def session_expires(db: Database, value: str, now: float | None = None) -> float | None:
    """When a session cookie runs out, or None if it is not valid (any more)."""
    try:
        expires_text, sig = (value or "").split(".", 1)
        expires = int(expires_text)
    except ValueError:
        return None
    good = hmac.new(_secret(db), expires_text.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, good) or expires < (now or time.time()):
        return None
    return float(expires)


# ------------------------------------------------------------------ tickets (the tray)
def new_ticket() -> str:
    """A one-time link for the tray's browser: unlocks Server admin on the server itself."""
    token = secrets.token_urlsafe(24)
    now = time.time()
    with _lock:
        for t, exp in list(_tickets.items()):
            if exp < now:
                del _tickets[t]
        _tickets[token] = now + TICKET_SECONDS
    return token


def use_ticket(token: str) -> bool:
    with _lock:
        expires = _tickets.pop(token or "", 0)
    return expires >= time.time()


# ------------------------------------------------------------------ wrong guesses
def locked_out(address: str, now: float | None = None) -> float:
    """Seconds this address must wait after too many wrong passcodes (0 = may try)."""
    now = now or time.time()
    with _lock:
        recent = [t for t in _failures.get(address, []) if now - t < FAILURE_WINDOW]
        _failures[address] = recent
        if len(recent) >= MAX_FAILURES:
            return max(1.0, FAILURE_WINDOW - (now - recent[-MAX_FAILURES]))
    return 0.0


def record_failure(address: str, now: float | None = None) -> None:
    with _lock:
        _failures.setdefault(address, []).append(now or time.time())


def clear_failures(address: str) -> None:
    with _lock:
        _failures.pop(address, None)


# ------------------------------------------------------------------ requests
def client_address(request: Any) -> str:
    return request.client.host if request.client else ""


def is_local(request: Any) -> bool:
    """From a browser on the server itself (not through a reverse proxy)."""
    if any(h in request.headers for h in PROXY_HEADERS):
        return False
    try:
        return ipaddress.ip_address(client_address(request).split("%")[0]).is_loopback
    except ValueError:
        return client_address(request) in ("testclient", "localhost")


def _api_token_header(request: Any) -> bool:
    token = request.app.state.settings.api_token
    if not token:
        return False
    auth = request.headers.get("authorization", "")
    given = [request.headers.get("x-api-key", "")] + ([auth[7:].strip()] if auth.lower().startswith("bearer ") else [])
    return any(g and hmac.compare_digest(g, token) for g in given)


def access(request: Any) -> dict[str, Any]:
    """How (and whether) this request may use Server admin."""
    db = request.app.state.db
    if is_local(request):
        return {"allowed": True, "how": "local", "expires": None}
    expires = session_expires(db, request.cookies.get(SESSION_COOKIE, ""))
    if expires:
        return {"allowed": True, "how": "passcode", "expires": expires}
    if _api_token_header(request):
        return {"allowed": True, "how": "api-token", "expires": None}
    return {"allowed": False, "how": "", "expires": None}


def require_admin(request: Request) -> None:
    """FastAPI dependency for Server admin endpoints."""
    if not access(request)["allowed"]:
        from fastapi import HTTPException

        raise HTTPException(403, "Server admin passcode required: unlock Server admin first"
                            if passcode_set(request.app.state.db) else
                            "Server admin is only available on the server itself until a passcode is set "
                            "(tray: Server admin > Server admin config)")


def require_local(request: Request) -> None:
    """FastAPI dependency: only on the server itself (setting the passcode)."""
    if not is_local(request):
        from fastapi import HTTPException

        raise HTTPException(403, "the passcode can only be changed on the server itself "
                            "(tray: Server admin > Server admin config)")
