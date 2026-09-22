"""Notification channels: webhook, Slack, Microsoft Teams, Discord, PagerDuty, email, log."""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import ssl
import time
from email.message import EmailMessage
from typing import Any

import httpx

from ..db import Database, loads

log = logging.getLogger(__name__)

CHANNEL_TYPES = {
    "webhook": "Generic webhook (JSON POST)",
    "slack": "Slack / Mattermost / Rocket.Chat incoming webhook",
    "teams": "Microsoft Teams incoming webhook",
    "discord": "Discord webhook",
    "pagerduty": "PagerDuty Events API v2",
    "email": "Email (SMTP)",
    "log": "Write to the SNMPathy log only",
}

SEVERITY_EMOJI = {"critical": ":red_circle:", "warning": ":large_orange_circle:", "info": ":large_blue_circle:"}


def render_text(event: str, alert: dict[str, Any]) -> str:
    state = "RESOLVED" if event == "resolved" else alert.get("severity", "alert").upper()
    text = f"[{state}] {alert.get('subject', '')}: {alert.get('message', '')}"
    if event == "resolved" and alert.get("fired_at") is not None and alert.get("resolved_at") is not None:
        mins = (alert["resolved_at"] - alert["fired_at"]) / 60
        text += f" (after {mins:.0f} min)"
    return text


def build_payload(event: str, alert: dict[str, Any], rule: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "event": event,
        "source": "snmpathy",
        "timestamp": time.time(),
        "text": render_text(event, alert),
        "alert": {k: alert.get(k) for k in (
            "id", "fingerprint", "subject", "severity", "state", "value", "message",
            "started_at", "fired_at", "resolved_at", "device_id", "check_id")},
        "rule": {k: (rule or {}).get(k) for k in ("id", "name", "kind", "severity", "description")},
    }


async def send(channel: dict[str, Any], event: str, alert: dict[str, Any], rule: dict[str, Any] | None,
               settings: Any = None, client: httpx.AsyncClient | None = None) -> None:
    """Deliver one notification. Raises on failure."""
    ctype = channel["type"]
    config = loads(channel.get("config"), {}) if isinstance(channel.get("config"), str) else (channel.get("config") or {})
    payload = build_payload(event, alert, rule)
    text = payload["text"]
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=10)
    try:
        if ctype == "webhook":
            headers = config.get("headers") or {}
            resp = await client.request(config.get("method", "POST"), config["url"], json=payload, headers=headers)
            resp.raise_for_status()
        elif ctype == "slack":
            emoji = ":white_check_mark:" if event == "resolved" else SEVERITY_EMOJI.get(alert.get("severity"), "")
            body: dict[str, Any] = {"text": f"{emoji} {text}".strip()}
            if config.get("channel"):
                body["channel"] = config["channel"]
            resp = await client.post(config["url"], json=body)
            resp.raise_for_status()
        elif ctype == "teams":
            resp = await client.post(config["url"], json={"text": text})
            resp.raise_for_status()
        elif ctype == "discord":
            resp = await client.post(config["url"], json={"content": text[:1990]})
            resp.raise_for_status()
        elif ctype == "pagerduty":
            body = {
                "routing_key": config["routing_key"],
                "event_action": "resolve" if event == "resolved" else "trigger",
                "dedup_key": alert.get("fingerprint"),
                "payload": {
                    "summary": text[:1024],
                    "source": alert.get("subject") or "snmpathy",
                    "severity": {"critical": "critical", "warning": "warning"}.get(alert.get("severity"), "info"),
                    "custom_details": payload["alert"],
                },
            }
            resp = await client.post(config.get("url", "https://events.pagerduty.com/v2/enqueue"), json=body)
            resp.raise_for_status()
        elif ctype == "email":
            await asyncio.to_thread(_send_email, config, settings, text, payload)
        elif ctype == "log":
            log.warning("ALERT %s", text)
        else:
            raise ValueError(f"unknown channel type {ctype!r}")
    finally:
        if own_client:
            await client.aclose()


def _send_email(config: dict[str, Any], settings: Any, text: str, payload: dict[str, Any]) -> None:
    host = config.get("smtp_host") or getattr(settings, "smtp_host", "")
    if not host:
        raise ValueError("no SMTP server configured")
    port = int(config.get("smtp_port") or getattr(settings, "smtp_port", 25))
    user = config.get("smtp_user") or getattr(settings, "smtp_user", "")
    password = config.get("smtp_password") or getattr(settings, "smtp_password", "")
    sender = config.get("from") or getattr(settings, "smtp_from", "snmpathy@localhost")
    starttls = config.get("starttls", getattr(settings, "smtp_starttls", False))
    to = config.get("to")
    if isinstance(to, str):
        to = [a.strip() for a in to.split(",") if a.strip()]
    if not to:
        raise ValueError("email channel has no recipients")
    msg = EmailMessage()
    msg["Subject"] = text[:200]
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg.set_content(text + "\n\n" + json.dumps(payload, indent=2, default=str))
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context()) as smtp:
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if starttls:
                smtp.starttls(context=ssl.create_default_context())
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)


async def dispatch(db: Database, event: str, alert: dict[str, Any], rule: dict[str, Any] | None,
                   settings: Any = None) -> list[dict[str, Any]]:
    """Send ``event`` for ``alert`` to the rule's channels (all enabled channels if none are set)."""
    channel_ids = loads(rule.get("channels"), []) if rule else []
    if channel_ids:
        marks = ",".join("?" for _ in channel_ids)
        channels = db.query(f"SELECT * FROM channels WHERE enabled = 1 AND id IN ({marks})", channel_ids)
    else:
        channels = db.query("SELECT * FROM channels WHERE enabled = 1")
    results = []
    async with httpx.AsyncClient(timeout=10) as client:
        for channel in channels:
            status, error = "sent", ""
            try:
                await send(channel, event, alert, rule, settings, client)
            except Exception as exc:  # report every failure, never crash the engine
                status, error = "failed", f"{type(exc).__name__}: {exc}"[:500]
                log.warning("notification via %s failed: %s", channel["name"], error)
            db.insert("notifications", {
                "alert_id": alert.get("id"), "channel_id": channel["id"], "event": event,
                "status": status, "error": error, "ts": time.time(),
            })
            results.append({"channel": channel["name"], "status": status, "error": error})
    return results
