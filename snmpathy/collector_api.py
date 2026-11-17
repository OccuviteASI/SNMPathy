"""HTTP endpoints for remote collectors.

* ``/api/collector/v1/*`` - used by collectors themselves, authenticated with
  the collector's own token (``Authorization: Bearer col_...``).
* ``/api/collectors/*``   - management API for administrators (normal auth).
* ``/collector/*``        - public downloads and one-line install scripts, so
  a site machine can fetch the collector straight from this server.
"""

from __future__ import annotations

import io
import logging
import os
import sys
import tarfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from . import __version__, collectors
from .config import app_dir, is_frozen
from .db import Database

log = logging.getLogger("snmpathy.collector_api")
router = APIRouter()


def _db(request: Request) -> Database:
    return request.app.state.db


def _hub(request: Request) -> collectors.CollectorHub:
    return request.app.state.hub


# ======================================================= collector-facing API
def _collector(request: Request) -> dict[str, Any]:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-collector-token", "")
    row = collectors.authenticate(_db(request), token)
    if not row:
        raise HTTPException(401, "invalid collector token")
    info = {
        "last_ip": request.client.host if request.client else "",
        "hostname": request.headers.get("x-collector-hostname", ""),
        "platform": request.headers.get("x-collector-platform", ""),
        "version": request.headers.get("x-collector-version", ""),
    }
    if request.headers.get("x-collector-backlog") is not None:
        info["backlog"] = request.headers.get("x-collector-backlog")
    _hub(request).touch(row, info)
    return row


@router.get("/api/collector/v1/poll", include_in_schema=False)
async def collector_poll(request: Request, wait: float = 25.0):
    collector = _collector(request)
    hub = _hub(request)
    version = hub.config_version(collector["id"])
    if version == request.headers.get("x-collector-config"):
        # Nothing new yet: wait for jobs (or a config change) before answering.
        jobs = await hub.next_jobs(collector["id"], wait=max(0.0, min(wait, 30.0)),
                                   until=lambda: hub.config_version(collector["id"]) != version)
        version = hub.config_version(collector["id"])
    else:
        jobs = await hub.next_jobs(collector["id"], wait=0)
    if jobs:
        # Answering takes a while for long polls: refresh last_seen.
        hub.touch({**collector, "status": "online"}, {})
    return {"config_version": version, "jobs": jobs, "server_time": time.time(), "server_version": __version__}


@router.get("/api/collector/v1/config", include_in_schema=False)
async def collector_config(request: Request):
    collector = _collector(request)
    return _hub(request).config(collector["id"])


class ResultsIn(BaseModel):
    results: list[dict[str, Any]] = []
    jobs: list[dict[str, Any]] = []


@router.post("/api/collector/v1/results", include_in_schema=False)
async def collector_results(body: ResultsIn, request: Request):
    collector = _collector(request)
    hub = _hub(request)
    answered = hub.resolve(collector["id"], body.jobs)
    counts = await hub.ingest(collector, body.results[:5000])
    return {**counts, "jobs": answered}


class EnrollIn(BaseModel):
    name: str = Field("", max_length=100)
    port: int = Field(8080, ge=1, le=65535)
    url: str = ""  # when this server cannot reach it at the address it connects from


@router.post("/api/collector/v1/enroll", include_in_schema=False)
def collector_enroll(body: EnrollIn, request: Request):
    """The Collector setup chose "Full SNMPathy server": add it to Fusion in place of this collector."""
    from .fusion import normalize_url

    collector = _collector(request)
    db = _db(request)
    host = request.client.host if request.client else ""
    url = body.url or (f"http://[{host}]:{body.port}" if ":" in host else f"http://{host}:{body.port}")
    try:
        url = normalize_url(url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    existing = db.one("SELECT * FROM fusion_servers WHERE url = ?", (url,))
    if existing:
        server_id, name = existing["id"], existing["name"]
        db.update("fusion_servers", server_id, {"enabled": 1, "status": "unknown", "error": ""})
    else:
        base = (body.name or collector["name"]).strip()[:100] or "SNMPathy"
        name, n = base, 2
        while db.one("SELECT 1 FROM fusion_servers WHERE name = ?", (name,)):
            name, n = f"{base} ({n})", n + 1
        server_id = db.insert("fusion_servers", {"name": name, "url": url, "api_token": "", "verify_tls": 1,
                                                 "enabled": 1, "created_at": time.time()})
    collectors.delete_collector(db, collector["id"])
    _hub(request).invalidate(collector["id"])
    db.log_event("fusion.added", f"Fusion server {name} ({url}) added by the setup of collector "
                 f"{collector['name']}, which it replaces")
    return {"id": server_id, "name": name, "url": url}


# ========================================================== management API
class CollectorIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    site: str = ""
    description: str = ""


class CollectorPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    site: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    failover: Optional[bool] = None  # this server takes over while the collector is offline


def _base_url(request: Request) -> str:
    public = request.app.state.settings.public_url
    return (public or str(request.base_url)).rstrip("/")


def install_commands(request: Request, token: str) -> dict[str, str]:
    from .collector_app import encode_setup_code

    base = _base_url(request)
    return {
        "app": encode_setup_code(base, token),
        "linux": f"curl -fsSL {base}/collector/install.sh | sudo bash -s -- --token {token}",
        "macos": f"curl -fsSL {base}/collector/install.sh | sudo bash -s -- --token {token}",
        "windows": (f"powershell -ExecutionPolicy Bypass -Command \"& ([scriptblock]::Create((iwr -UseBasicParsing "
                    f"'{base}/collector/install.ps1').Content)) -Token '{token}'\""),
        "docker": (f"docker run -d --name snmpathy-collector --restart unless-stopped --network host "
                   f"-v snmpathy-collector:/data -e SNMPATHY_COLLECTOR_SERVER={base} "
                   f"-e SNMPATHY_COLLECTOR_TOKEN={token} snmpathy collector --state-dir /data"),
        "manual": f"snmpathy collector --server {base} --token {token}",
    }


@router.get("/api/collectors", tags=["collectors"])
def list_collectors(db: Database = Depends(_db)):
    rows = db.query("SELECT * FROM collectors ORDER BY name COLLATE NOCASE")
    counts = {r["collector_id"]: r["n"] for r in db.query(
        "SELECT collector_id, COUNT(*) AS n FROM devices WHERE collector_id IS NOT NULL GROUP BY collector_id")}
    return [{**collectors.public_collector(r), "devices": counts.get(r["id"], 0)} for r in rows]


@router.post("/api/collectors", status_code=201, tags=["collectors"])
def create_collector(body: CollectorIn, request: Request, db: Database = Depends(_db)):
    try:
        row, token = collectors.create_collector(db, body.name, body.site, body.description)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {**collectors.public_collector(row), "token": token, "install": install_commands(request, token)}


@router.get("/api/collectors/{collector_id}", tags=["collectors"])
def get_collector(collector_id: int, db: Database = Depends(_db)):
    row = db.one("SELECT * FROM collectors WHERE id = ?", (collector_id,))
    if not row:
        raise HTTPException(404, "collector not found")
    return collectors.public_collector(row)


@router.patch("/api/collectors/{collector_id}", tags=["collectors"])
def patch_collector(collector_id: int, body: CollectorPatch, db: Database = Depends(_db)):
    if not db.one("SELECT 1 FROM collectors WHERE id = ?", (collector_id,)):
        raise HTTPException(404, "collector not found")
    values = body.model_dump(exclude_unset=True)
    for key in ("enabled", "failover"):
        if key in values:
            values[key] = int(values[key])
    if values.get("name") and db.one("SELECT 1 FROM collectors WHERE name = ? AND id != ?", (values["name"], collector_id)):
        raise HTTPException(422, "a collector with that name already exists")
    db.update("collectors", collector_id, values)
    return collectors.public_collector(db.one("SELECT * FROM collectors WHERE id = ?", (collector_id,)))


@router.post("/api/collectors/{collector_id}/token", tags=["collectors"])
def rotate_collector_token(collector_id: int, request: Request, db: Database = Depends(_db)):
    """Issue a new token (the old one stops working immediately)."""
    try:
        token = collectors.rotate_token(db, collector_id)
    except KeyError as exc:
        raise HTTPException(404, "collector not found") from exc
    return {"token": token, "install": install_commands(request, token)}


@router.delete("/api/collectors/{collector_id}", status_code=204, tags=["collectors"])
def delete_collector(collector_id: int, request: Request, db: Database = Depends(_db)):
    collectors.delete_collector(db, collector_id)
    _hub(request).invalidate(collector_id)


@router.post("/api/collectors/{collector_id}/ping", tags=["collectors"])
async def ping_collector(collector_id: int, request: Request):
    """Round-trip a no-op job through the collector."""
    started = time.perf_counter()
    try:
        result = await _hub(request).call(collector_id, "ping", {}, timeout=40)
    except collectors.CollectorOffline as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "rtt_ms": round((time.perf_counter() - started) * 1000, 1), **(result or {})}


# ================================================================ downloads
PLATFORM_HINTS = {
    "windows": ("windows", "win", ".exe"),
    "linux": ("linux",),
    "macos": ("macos", "darwin", "mac"),
}


def downloads_dir(request: Request) -> Path:
    configured = request.app.state.settings.downloads_dir
    if configured:
        return Path(configured)
    db_path = Path(request.app.state.settings.database)
    return (app_dir() if is_frozen() else db_path.resolve().parent) / "downloads"


def _platform_of(name: str) -> str:
    low = name.lower()
    if low.endswith(".exe") or "windows" in low or "-win" in low:
        return "windows"
    if "mac" in low or "darwin" in low:
        return "macos"
    if "linux" in low:
        return "linux"
    return ""


def _self_platform() -> str:
    return {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")


RELEASE_REPO = "OccuviteASI/SNMPathy"
RELEASE_PLATFORMS = {"windows": ".exe", "linux": ""}  # what CI publishes with each release
COLLECTOR_APP = "SNMPathy-Collector"
_fetch_lock = threading.Lock()


def _kind(name: str) -> str:
    """'collector' for the SNMPathy Collector app, 'server' for the full SNMPathy."""
    return "collector" if "collector" in name.lower() else "server"


def release_asset(product: str, platform: str) -> str:
    return f"{product}-{platform}{RELEASE_PLATFORMS.get(platform, '')}"


def _fetch_release_asset(name: str, folder: Path) -> Path:
    """Download a release file from GitHub into the downloads folder (kept for next time).

    The release matching this server's version first, then the latest release. Kept per version
    (``downloads/releases/v<version>/``), so after the server is updated collectors get the
    matching build, and the files of older versions are removed.
    """
    import shutil

    import httpx

    cache = folder / "releases"
    target = cache / f"v{__version__}"
    target.mkdir(parents=True, exist_ok=True)
    dest = target / name
    with _fetch_lock:
        for old in cache.iterdir():
            if old.is_dir() and old != target:
                shutil.rmtree(old, ignore_errors=True)
        if dest.is_file() and dest.stat().st_size:
            return dest
        part = dest.with_name(dest.name + ".part")
        errors = []
        for tag in (f"download/v{__version__}", "latest/download"):
            url = f"https://github.com/{RELEASE_REPO}/releases/{tag}/{name}"
            try:
                with httpx.stream("GET", url, follow_redirects=True, timeout=httpx.Timeout(120.0, connect=15.0)) as r:
                    if r.status_code != 200:
                        errors.append(f"{url}: HTTP {r.status_code}")
                        continue
                    with part.open("wb") as fh:
                        for chunk in r.iter_bytes(256 * 1024):
                            fh.write(chunk)
            except httpx.HTTPError as exc:
                part.unlink(missing_ok=True)
                errors.append(f"{url}: {exc}")
                continue
            if not name.endswith(".exe"):
                part.chmod(0o755)
            os.replace(part, dest)
            log.info("fetched %s from %s", name, url)
            return dest
    raise OSError("; ".join(errors) or f"{name} is not published")


fetch_release_asset = _fetch_release_asset  # tests replace this (no network)


def available_downloads(request: Request) -> list[dict[str, Any]]:
    """What this server hands to site machines: the Collector app first, then the full SNMPathy."""
    items: list[dict[str, Any]] = []
    folder = downloads_dir(request)
    if folder.is_dir():
        for f in sorted(folder.iterdir()):
            if f.is_file() and not f.name.startswith(".") and not f.name.endswith(".part"):
                items.append({"name": f.name, "platform": _platform_of(f.name), "size": f.stat().st_size,
                              "kind": _kind(f.name), "source": "downloads folder"})
    for platform in RELEASE_PLATFORMS:
        if not any(i["kind"] == "collector" and i["platform"] == platform for i in items):
            items.append({"name": release_asset(COLLECTOR_APP, platform), "platform": platform, "size": None,
                          "kind": "collector", "release": True,
                          "source": "SNMPathy release on GitHub (fetched once, then kept in the downloads folder)"})
    if is_frozen() and not any(i["kind"] == "server" and i["platform"] == _self_platform() for i in items):
        exe = Path(sys.executable)
        items.append({"name": f"SNMPathy-{_self_platform()}{exe.suffix}", "platform": _self_platform(),
                      "size": exe.stat().st_size, "kind": "server", "source": "this server's executable",
                      "self": True})
    if not is_frozen():
        items.append({"name": f"snmpathy-{__version__}.tar.gz", "platform": "python", "size": None,
                      "kind": "server", "source": "Python package (pip install, any OS with Python 3.10+)",
                      "sdist": True})
    order = {"collector": 0, "server": 1}
    items.sort(key=lambda i: (order.get(i["kind"], 2), i["platform"] == "python", i["platform"]))
    return items


def _find_download(request: Request, name: str) -> dict[str, Any] | None:
    return next((i for i in available_downloads(request) if i["name"] == name), None)


def build_sdist() -> bytes:
    """A pip-installable source archive of the running SNMPathy package."""
    from importlib import metadata

    pkg = Path(__file__).resolve().parent
    try:
        requires = [r for r in (metadata.requires("snmpathy") or []) if "extra ==" not in r]
    except metadata.PackageNotFoundError:
        requires = ["fastapi>=0.110", "uvicorn[standard]>=0.27", "jinja2>=3.1", "pysnmp>=7.1", "httpx>=0.27",
                    "pyyaml>=6.0", "python-multipart>=0.0.9", "cryptography>=42"]
    deps = ",\n    ".join(f'"{r}"' for r in requires)
    pyproject = f"""[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "snmpathy"
version = "{__version__}"
requires-python = ">=3.10"
dependencies = [
    {deps}
]

[project.scripts]
snmpathy = "snmpathy.cli:main"

[tool.setuptools.packages.find]
include = ["snmpathy*"]

[tool.setuptools.package-data]
snmpathy = ["web/templates/*.html", "web/static/*"]
"""
    root = f"snmpathy-{__version__}"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = pyproject.encode()
        info = tarfile.TarInfo(f"{root}/pyproject.toml")
        info.size, info.mtime = len(data), int(time.time())
        tar.addfile(info, io.BytesIO(data))
        for path in pkg.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo"):
                tar.add(path, arcname=f"{root}/snmpathy/{path.relative_to(pkg).as_posix()}")
    return buf.getvalue()


@router.get("/collector/downloads", include_in_schema=False)
def list_downloads(request: Request):
    return available_downloads(request)


OS_NAMES = {"windows_nt": "windows", "windows": "windows", "win32": "windows", "darwin": "macos",
            "macos": "macos", "linux": "linux"}


def _serve(request: Request, item: dict[str, Any]) -> Response:
    """The file for one download entry (fetching a release file first; OSError if that fails)."""
    if item.get("sdist"):
        return Response(build_sdist(), media_type="application/gzip",
                        headers={"Content-Disposition": f'attachment; filename="{item["name"]}"'})
    if item.get("self"):
        path = Path(sys.executable)
    elif item.get("release"):
        path = fetch_release_asset(item["name"], downloads_dir(request))
    else:
        path = downloads_dir(request) / item["name"]
    return FileResponse(path, filename=item["name"], media_type="application/octet-stream")


def _serve_first(request: Request, candidates: list[dict[str, Any]], what: str) -> Response:
    errors = []
    for item in candidates:
        try:
            return _serve(request, item)
        except OSError as exc:
            log.warning("download %s unavailable: %s", item["name"], exc)
            errors.append(f"{item['name']}: {exc}")
    raise HTTPException(404, f"no {what} on this server" + (f" ({'; '.join(errors)})" if errors else ""))


def _arch_first(candidates: list[dict[str, Any]], arch: str) -> list[dict[str, Any]]:
    if not arch:
        return candidates
    low = arch.lower()

    def matches(i: dict[str, Any]) -> bool:
        name = i["name"].lower()
        return low in name or (low in ("x86_64", "amd64") and ("x64" in name or "amd64" in name))

    return [i for i in candidates if matches(i)] + [i for i in candidates if not matches(i)]


@router.get("/collector/download/server", include_in_schema=False)
def download_server(request: Request, os_: str = ""):
    """The full SNMPathy for the Collector setup's "Full SNMPathy server" choice."""
    wanted = OS_NAMES.get(os_.lower(), "")
    candidates = [i for i in available_downloads(request) if i["kind"] == "server" and i["platform"] == wanted]
    if wanted in RELEASE_PLATFORMS:
        candidates.append({"name": release_asset("SNMPathy", wanted), "platform": wanted, "kind": "server",
                           "release": True})
    return _serve_first(request, candidates, f"SNMPathy executable for {os_ or 'this OS'}")


@router.get("/collector/download/{name}", include_in_schema=False)
def download(name: str, request: Request, os_: str = "", arch: str = ""):
    if name == "auto":
        # The install scripts: the Collector app for the OS, else the full SNMPathy (both run 'collector').
        wanted = OS_NAMES.get(os_.lower(), "")
        candidates = _arch_first([i for i in available_downloads(request) if i["platform"] == wanted], arch)
        return _serve_first(request, candidates, f"collector executable for {os_ or 'this OS'}")
    item = _find_download(request, name)
    if not item:
        raise HTTPException(404, "no such download")
    try:
        return _serve(request, item)
    except OSError as exc:
        raise HTTPException(502, f"{name} could not be fetched from GitHub: {exc}") from exc


@router.get("/collector/install.sh", include_in_schema=False, response_class=PlainTextResponse)
def install_sh(request: Request):
    return PlainTextResponse(INSTALL_SH.replace("@@SERVER@@", _base_url(request)).replace("@@VERSION@@", __version__),
                             media_type="text/x-shellscript")


@router.get("/collector/install.ps1", include_in_schema=False, response_class=PlainTextResponse)
def install_ps1(request: Request):
    return PlainTextResponse(INSTALL_PS1.replace("@@SERVER@@", _base_url(request)).replace("@@VERSION@@", __version__),
                             media_type="text/plain")


INSTALL_SH = r"""#!/usr/bin/env bash
# SNMPathy collector installer for Linux and macOS (generated by @@SERVER@@).
#   curl -fsSL @@SERVER@@/collector/install.sh | sudo bash -s -- --token col_xxx
# Options: --token TOKEN (required)  --server URL  --insecure  --uninstall
set -euo pipefail
SERVER="@@SERVER@@"; TOKEN=""; INSECURE=0; UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2;;
    --server) SERVER="$2"; shift 2;;
    --insecure) INSECURE=1; shift;;
    --uninstall) UNINSTALL=1; shift;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
done
[ "$(id -u)" = "0" ] || { echo "please run as root (sudo)" >&2; exit 1; }
OS="$(uname -s)"; ARCH="$(uname -m)"
DIR=/opt/snmpathy-collector; CONF=/etc/snmpathy/collector.yaml; STATE=/var/lib/snmpathy-collector
CURL="curl -fsSL"; [ "$INSECURE" = 1 ] && CURL="$CURL -k"

if [ "$UNINSTALL" = 1 ]; then
  if [ "$OS" = "Darwin" ]; then launchctl unload /Library/LaunchDaemons/com.snmpathy.collector.plist 2>/dev/null || true; rm -f /Library/LaunchDaemons/com.snmpathy.collector.plist
  else systemctl disable --now snmpathy-collector 2>/dev/null || true; rm -f /etc/systemd/system/snmpathy-collector.service; systemctl daemon-reload || true; fi
  rm -rf "$DIR"; echo "SNMPathy collector removed (config $CONF and buffer $STATE kept)."; exit 0
fi
[ -n "$TOKEN" ] || { echo "--token is required (create a collector in SNMPathy > Collectors)" >&2; exit 2; }

mkdir -p "$DIR" "$(dirname "$CONF")" "$STATE"
BIN="$DIR/snmpathy"
echo "Downloading the collector for $OS/$ARCH from $SERVER ..."
if $CURL "$SERVER/collector/download/auto?os_=$OS&arch=$ARCH" -o "$BIN.new" 2>/dev/null; then
  mv "$BIN.new" "$BIN"; chmod 755 "$BIN"
else
  rm -f "$BIN.new"
  echo "No prebuilt executable on the server; installing the Python package instead."
  PY="$(command -v python3 || true)"
  [ -n "$PY" ] || { echo "python3 (3.10+) is required" >&2; exit 1; }
  "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { echo "python 3.10+ is required" >&2; exit 1; }
  "$PY" -m venv "$DIR/venv"
  PKG="$($CURL "$SERVER/collector/downloads" | "$PY" -c 'import json,sys; print(next(i["name"] for i in json.load(sys.stdin) if i["platform"]=="python"))')"
  $CURL "$SERVER/collector/download/$PKG" -o "$DIR/$PKG"
  "$DIR/venv/bin/pip" install --quiet --upgrade pip
  "$DIR/venv/bin/pip" install --quiet "$DIR/$PKG"
  ln -sf "$DIR/venv/bin/snmpathy" "$BIN"
fi

umask 077
cat > "$CONF" <<EOF
server: $SERVER
token: $TOKEN
verify_tls: $([ "$INSECURE" = 1 ] && echo false || echo true)
state_dir: $STATE
EOF
echo "Wrote $CONF"

if [ "$OS" = "Darwin" ]; then
  cat > /Library/LaunchDaemons/com.snmpathy.collector.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.snmpathy.collector</string>
  <key>ProgramArguments</key><array><string>$BIN</string><string>collector</string><string>--config</string><string>$CONF</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/snmpathy-collector.log</string>
  <key>StandardErrorPath</key><string>/var/log/snmpathy-collector.log</string>
</dict></plist>
EOF
  launchctl unload /Library/LaunchDaemons/com.snmpathy.collector.plist 2>/dev/null || true
  launchctl load -w /Library/LaunchDaemons/com.snmpathy.collector.plist
else
  cat > /etc/systemd/system/snmpathy-collector.service <<EOF
[Unit]
Description=SNMPathy remote collector
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN collector --config $CONF
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_RAW
StateDirectory=snmpathy-collector

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now snmpathy-collector
  systemctl restart snmpathy-collector
fi
echo "SNMPathy collector installed and running. It should show as online in SNMPathy within a few seconds."
"""


INSTALL_PS1 = r"""# SNMPathy collector installer for Windows (generated by @@SERVER@@).
# Run in an elevated PowerShell:
#   & ([scriptblock]::Create((iwr -UseBasicParsing '@@SERVER@@/collector/install.ps1').Content)) -Token 'col_xxx'
param(
    [string]$Token = "",
    [string]$Server = "@@SERVER@@",
    [string]$InstallDir = (Join-Path $env:ProgramFiles "SNMPathy Collector"),
    [string]$TaskName = "SNMPathy Collector",
    [switch]$Insecure,
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run this from an elevated (Administrator) PowerShell."
}
$stateDir = Join-Path $env:ProgramData "SNMPathy Collector"
if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Write-Host "SNMPathy collector removed (buffer and config in $stateDir kept)."
    return
}
if (-not $Token) { throw "-Token is required (create a collector in SNMPathy > Collectors)." }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($Insecure) {
    add-type "using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAll : ICertificatePolicy { public bool CheckValidationResult(ServicePoint a, X509Certificate b, WebRequest c, int d) { return true; } }"
    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
}
New-Item -ItemType Directory -Force -Path $InstallDir, $stateDir | Out-Null
$exe = Join-Path $InstallDir "snmpathy-collector.exe"
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
Write-Host "Downloading the collector from $Server ..."
$command = $null
try {
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/collector/download/auto?os_=Windows&arch=$env:PROCESSOR_ARCHITECTURE" -OutFile $exe
    $command = $exe; $prefix = @()
} catch {
    Write-Host "No prebuilt Windows executable on the server; installing the Python package instead."
    $py = (Get-Command py -ErrorAction SilentlyContinue)
    if (-not $py) { $py = (Get-Command python -ErrorAction SilentlyContinue) }
    if (-not $py) { throw "Python 3.10+ is required (or copy SNMPathy.exe into the server's downloads folder)." }
    $venv = Join-Path $InstallDir "venv"
    & $py.Source -m venv $venv
    $list = Invoke-RestMethod -UseBasicParsing "$Server/collector/downloads"
    $pkg = ($list | Where-Object { $_.platform -eq "python" } | Select-Object -First 1).name
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/collector/download/$pkg" -OutFile (Join-Path $InstallDir $pkg)
    & (Join-Path $venv "Scripts\pip.exe") install --quiet (Join-Path $InstallDir $pkg)
    $command = Join-Path $venv "Scripts\snmpathy.exe"
}
$conf = Join-Path $stateDir "collector.yaml"
@"
server: $Server
token: $Token
verify_tls: $(if ($Insecure) { 'false' } else { 'true' })
state_dir: $($stateDir -replace '\\','/')
"@ | Set-Content -Encoding UTF8 $conf
icacls $conf /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
$action = New-ScheduledTaskAction -Execute $command -Argument "collector --config `"$conf`"" -WorkingDirectory $stateDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "SNMPathy collector installed and running (scheduled task '$TaskName'). It should show as online in SNMPathy within a few seconds."
"""
