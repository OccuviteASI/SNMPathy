"""Scheduled report delivery (daily / weekly / monthly) via notification channels."""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import ssl
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Any

import httpx

from . import reporting
from .db import Database, loads

log = logging.getLogger(__name__)

FREQUENCIES = ("daily", "weekly", "monthly")


def previous_occurrence(schedule: dict[str, Any], now: float) -> float:
    """The most recent scheduled run time at or before ``now``."""
    dt = datetime.fromtimestamp(now)
    hour = int(schedule.get("hour") or 0)
    candidate = dt.replace(hour=hour, minute=0, second=0, microsecond=0)
    freq = schedule.get("frequency") or "weekly"
    if freq == "daily":
        if candidate > dt:
            candidate -= timedelta(days=1)
    elif freq == "weekly":
        weekday = int(schedule.get("weekday") or 0)
        candidate -= timedelta(days=(candidate.weekday() - weekday) % 7)
        if candidate > dt:
            candidate -= timedelta(days=7)
    else:
        day = max(1, min(28, int(schedule.get("monthday") or 1)))
        candidate = candidate.replace(day=day)
        if candidate > dt:
            prev_month = (candidate.replace(day=1) - timedelta(days=1)).replace(day=day)
            candidate = prev_month
    return candidate.timestamp()


def default_range(frequency: str) -> str:
    return {"daily": "yesterday", "weekly": "last_week", "monthly": "last_month"}.get(frequency, "7d")


def is_due(schedule: dict[str, Any], now: float) -> bool:
    if not schedule.get("enabled"):
        return False
    occurrence = previous_occurrence(schedule, now)
    if occurrence < (schedule.get("created_at") or 0):
        return False
    return (schedule.get("last_run") or 0) < occurrence


def render_html(report: dict[str, Any], base_url: str = "") -> str:
    from .web import templates

    template = templates.env.get_template("report_email.html")
    return template.render(report=report, fmt=reporting.format_cell, base_url=base_url.rstrip("/"))


async def deliver(db: Database, schedule: dict[str, Any], settings: Any) -> list[dict[str, Any]]:
    options = loads(schedule.get("options"), {})
    report = await asyncio.to_thread(
        reporting.build, db, schedule["report"], schedule.get("range") or default_range(schedule["frequency"]),
        **options,
    )
    base_url = getattr(settings, "public_url", "") or ""
    html = render_html(report, base_url)
    csv_text = reporting.to_csv(report)
    text = reporting.to_text(report)
    link = f"{base_url.rstrip('/')}/reports/{report['id']}?range={schedule.get('range') or ''}" if base_url else ""
    channel_ids = loads(schedule.get("channels"), [])
    if channel_ids:
        marks = ",".join("?" for _ in channel_ids)
        channels = db.query(f"SELECT * FROM channels WHERE enabled = 1 AND id IN ({marks})", channel_ids)
    else:
        channels = db.query("SELECT * FROM channels WHERE enabled = 1 AND type = 'email'")
    results = []
    async with httpx.AsyncClient(timeout=20) as client:
        for ch in channels:
            config = loads(ch["config"], {})
            try:
                if ch["type"] == "email":
                    await asyncio.to_thread(_send_email, config, settings, schedule, report, html, csv_text, text)
                elif ch["type"] in ("slack", "teams"):
                    body = f"*{schedule['name']}*\n{text}" + (f"\n{link}" if link else "")
                    (await client.post(config["url"], json={"text": body})).raise_for_status()
                elif ch["type"] == "discord":
                    body = f"**{schedule['name']}**\n{text}" + (f"\n{link}" if link else "")
                    (await client.post(config["url"], json={"content": body[:1990]})).raise_for_status()
                elif ch["type"] == "webhook":
                    payload = {"event": "report", "schedule": schedule["name"], "report": report, "link": link}
                    resp = await client.post(config["url"], content=json.dumps(payload, default=str),
                                             headers={"Content-Type": "application/json", **(config.get("headers") or {})})
                    resp.raise_for_status()
                elif ch["type"] == "log":
                    log.info("scheduled report %s:\n%s", schedule["name"], text)
                else:
                    raise ValueError(f"channel type {ch['type']} cannot deliver reports")
                results.append({"channel": ch["name"], "status": "sent"})
            except Exception as exc:
                log.warning("report %s via %s failed: %s", schedule["name"], ch["name"], exc)
                results.append({"channel": ch["name"], "status": "failed", "error": str(exc)[:300]})
    if not channels:
        results.append({"channel": "-", "status": "failed", "error": "no channels configured"})
    status = "; ".join(f"{r['channel']}: {r['status']}" + (f" ({r['error']})" if r.get("error") else "") for r in results)
    db.update("report_schedules", schedule["id"], {"last_run": time.time(), "last_status": status[:500]})
    return results


def _send_email(config: dict[str, Any], settings: Any, schedule: dict[str, Any], report: dict[str, Any],
                html: str, csv_text: str, text: str) -> None:
    host = config.get("smtp_host") or getattr(settings, "smtp_host", "")
    if not host:
        raise ValueError("no SMTP server configured")
    to = config.get("to")
    if isinstance(to, str):
        to = [a.strip() for a in to.split(",") if a.strip()]
    if not to:
        raise ValueError("email channel has no recipients")
    msg = EmailMessage()
    msg["Subject"] = f"{schedule['name']}: {report['title']} ({report['subtitle']})"
    msg["From"] = config.get("from") or getattr(settings, "smtp_from", "snmpathy@localhost")
    msg["To"] = ", ".join(to)
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    msg.add_attachment(csv_text.encode("utf-8"), maintype="text", subtype="csv",
                       filename=f"{report['id']}-{time.strftime('%Y%m%d')}.csv")
    port = int(config.get("smtp_port") or getattr(settings, "smtp_port", 25))
    user = config.get("smtp_user") or getattr(settings, "smtp_user", "")
    password = config.get("smtp_password") or getattr(settings, "smtp_password", "")
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=30, context=ssl.create_default_context()) as smtp:
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            if config.get("starttls", getattr(settings, "smtp_starttls", False)):
                smtp.starttls(context=ssl.create_default_context())
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)


async def run_due(db: Database, settings: Any, now: float | None = None) -> int:
    now = now or time.time()
    sent = 0
    for schedule in db.query("SELECT * FROM report_schedules WHERE enabled = 1"):
        if is_due(schedule, now):
            try:
                await deliver(db, schedule, settings)
                sent += 1
            except Exception:
                log.exception("scheduled report %s failed", schedule["name"])
                db.update("report_schedules", schedule["id"], {"last_run": now, "last_status": "error building report"})
    return sent
