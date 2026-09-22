"""FastAPI application factory."""

from __future__ import annotations

import hmac
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import router as api_router
from .grafana import router as grafana_router
from .checks.runner import ProbeFunc
from .config import Settings
from .dashboards import seed_dashboards
from .db import Database
from .monitor import Monitor, SnmpFactory
from .services import seed_defaults
from .web import router as web_router

log = logging.getLogger(__name__)

PUBLIC_PATHS = ("/static/", "/status", "/api/status-page", "/login", "/healthz")
COOKIE = "snmpathy_token"


def _token_ok(request: Request, expected: str) -> bool:
    candidates = [
        request.headers.get("x-api-key", ""),
        request.cookies.get(COOKIE, ""),
        request.query_params.get("token", ""),
    ]
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        candidates.append(auth[7:].strip())
    return any(c and hmac.compare_digest(c, expected) for c in candidates)


def create_app(settings: Settings | None = None, db: Database | None = None, start_monitor: bool = True,
               snmp_factory: SnmpFactory | None = None, probe: ProbeFunc | None = None) -> FastAPI:
    settings = settings or Settings.load()
    db = db or Database(settings.database)
    seed_defaults(db)
    seed_dashboards(db)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if start_monitor:
            monitor = Monitor(db, settings, snmp_factory=snmp_factory, probe=probe)
            app.state.monitor = monitor
            await monitor.start()
        try:
            yield
        finally:
            if app.state.monitor:
                await app.state.monitor.stop()

    app = FastAPI(
        title="SNMPathy",
        version=__version__,
        description="Network monitoring: SNMP polling, syslog ingest and uptime reporting.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.db = db
    app.state.monitor = None

    @app.middleware("http")
    async def auth(request: Request, call_next):
        token = settings.api_token
        path = request.url.path
        if token and not path.startswith(PUBLIC_PATHS) and not _token_ok(request, token):
            if path.startswith(("/api/", "/grafana")) or path in ("/docs", "/openapi.json", "/redoc"):
                return JSONResponse({"detail": "authentication required"}, status_code=401)
            return RedirectResponse(f"/login?next={quote(str(request.url.path))}", status_code=303)
        return await call_next(request)

    @app.post("/login", include_in_schema=False)
    async def do_login(token: str = Form(...), next: str = Form("/")):
        if not settings.api_token or hmac.compare_digest(token, settings.api_token):
            target = next if next.startswith("/") and not next.startswith("//") else "/"
            resp = RedirectResponse(target, status_code=303)
            resp.set_cookie(COOKIE, token, httponly=True, samesite="lax", max_age=30 * 86400)
            return resp
        return RedirectResponse(f"/login?error=1&next={quote(next)}", status_code=303)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        monitor = app.state.monitor
        return {"ok": True, "version": __version__, "monitor": bool(monitor)}

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "web" / "static")), name="static")
    app.include_router(api_router)
    app.include_router(grafana_router)
    app.include_router(web_router)
    return app
