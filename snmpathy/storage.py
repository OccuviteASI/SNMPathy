"""Time-series queries, rollups and data retention."""

from __future__ import annotations

import math
import time
from typing import Any

from .db import Database

ROLLUP_PERIODS = (300, 3600)
RAW_MAX_SPAN = 2 * 86400
FIVE_MIN_MAX_SPAN = 21 * 86400
MAX_POINTS = 1500


def rollup(db: Database, now: float | None = None) -> dict[int, int]:
    """Aggregate completed buckets of raw samples into 5-minute and 1-hour rollups."""
    now = int(now or time.time())
    written: dict[int, int] = {}
    for period in ROLLUP_PERIODS:
        key = f"rollup_watermark_{period}"
        end = (now // period) * period
        watermark = db.get_meta(key)
        if watermark is None:
            first = db.scalar("SELECT MIN(ts) FROM samples")
            if first is None:
                continue
            start = (int(first) // period) * period
        else:
            start = int(watermark)
        if end <= start:
            continue
        with db.transaction() as conn:
            cur = conn.execute(
                """
                INSERT OR REPLACE INTO rollups (metric_id, period, bucket, vmin, vmax, vavg, vcount)
                SELECT metric_id, ?, (ts / ?) * ?, MIN(value), MAX(value), AVG(value), COUNT(*)
                FROM samples WHERE ts >= ? AND ts < ?
                GROUP BY metric_id, ts / ?
                """,
                (period, period, period, start, end, period),
            )
            written[period] = cur.rowcount
            db.set_meta(key, str(end))
    return written


def apply_retention(db: Database, settings: Any, now: float | None = None) -> dict[str, int]:
    now = now or time.time()
    day = 86400
    removed = {}
    with db.transaction() as conn:
        removed["samples"] = conn.execute(
            "DELETE FROM samples WHERE ts < ?", (int(now - settings.retention_raw_days * day),)
        ).rowcount
        removed["rollups_5m"] = conn.execute(
            "DELETE FROM rollups WHERE period = 300 AND bucket < ?",
            (int(now - min(settings.retention_rollup_days, 35) * day),),
        ).rowcount
        removed["rollups_1h"] = conn.execute(
            "DELETE FROM rollups WHERE period = 3600 AND bucket < ?",
            (int(now - settings.retention_rollup_days * day),),
        ).rowcount
        removed["heartbeats"] = conn.execute(
            "DELETE FROM heartbeats WHERE ts < ?", (now - settings.retention_heartbeat_days * day,)
        ).rowcount
        removed["events"] = conn.execute(
            "DELETE FROM events WHERE ts < ?", (now - settings.retention_rollup_days * day,)
        ).rowcount
        removed["alerts"] = conn.execute(
            "DELETE FROM alerts WHERE state = 'resolved' AND resolved_at < ?",
            (now - settings.retention_rollup_days * day,),
        ).rowcount
    # Syslog can be large; delete in chunks so writers are not blocked for long.
    cutoff = now - settings.retention_syslog_days * day
    total = 0
    while True:
        with db.transaction() as conn:
            n = conn.execute(
                "DELETE FROM syslog WHERE id IN (SELECT id FROM syslog WHERE ts < ? ORDER BY id LIMIT 5000)",
                (cutoff,),
            ).rowcount
        total += n
        if n < 5000:
            break
    removed["syslog"] = total
    return removed


def series(db: Database, metric_id: int, start: float, end: float, resolution: str = "auto") -> dict[str, Any]:
    """Return points for a metric between ``start`` and ``end``.

    Picks raw samples for short ranges and rollups for longer ones so a
    chart never has more than a few thousand points.
    """
    start, end = int(start), int(end)
    span = max(1, end - start)
    if resolution == "auto":
        if span <= RAW_MAX_SPAN:
            resolution = "raw"
        elif span <= FIVE_MIN_MAX_SPAN:
            resolution = "300"
        else:
            resolution = "3600"
    if resolution == "raw":
        step = max(1, math.ceil(span / MAX_POINTS))
        count = db.scalar(
            "SELECT COUNT(*) FROM samples WHERE metric_id = ? AND ts >= ? AND ts <= ?", (metric_id, start, end)
        ) or 0
        if count <= MAX_POINTS:
            rows = db.query(
                "SELECT ts, value AS avg, value AS min, value AS max FROM samples "
                "WHERE metric_id = ? AND ts >= ? AND ts <= ? ORDER BY ts",
                (metric_id, start, end),
            )
        else:
            rows = db.query(
                "SELECT (ts / ?) * ? AS ts, AVG(value) AS avg, MIN(value) AS min, MAX(value) AS max FROM samples "
                "WHERE metric_id = ? AND ts >= ? AND ts <= ? GROUP BY ts / ? ORDER BY 1",
                (step, step, metric_id, start, end, step),
            )
        return {"resolution": "raw", "points": rows}

    period = int(resolution)
    rows = db.query(
        "SELECT bucket AS ts, vavg AS avg, vmin AS min, vmax AS max FROM rollups "
        "WHERE metric_id = ? AND period = ? AND bucket >= ? AND bucket <= ? ORDER BY bucket",
        (metric_id, period, start, end),
    )
    # Append not-yet-rolled-up recent data (and cover fresh installs) from raw samples.
    last = rows[-1]["ts"] + period if rows else start
    tail = db.query(
        "SELECT (ts / ?) * ? AS ts, AVG(value) AS avg, MIN(value) AS min, MAX(value) AS max FROM samples "
        "WHERE metric_id = ? AND ts >= ? AND ts <= ? GROUP BY ts / ? ORDER BY 1",
        (period, period, metric_id, last, end, period),
    )
    return {"resolution": str(period), "points": rows + tail}


def metric_summary(db: Database, metric_id: int, start: float, end: float) -> dict[str, Any]:
    row = db.one(
        "SELECT MIN(value) AS min, MAX(value) AS max, AVG(value) AS avg, COUNT(*) AS count FROM samples "
        "WHERE metric_id = ? AND ts >= ? AND ts <= ?",
        (metric_id, int(start), int(end)),
    ) or {}
    if not row.get("count"):
        row = db.one(
            "SELECT MIN(vmin) AS min, MAX(vmax) AS max, SUM(vavg * vcount) / SUM(vcount) AS avg, SUM(vcount) AS count "
            "FROM rollups WHERE metric_id = ? AND period = 3600 AND bucket >= ? AND bucket <= ?",
            (metric_id, int(start), int(end)),
        ) or {}
    values = [v for v in (
        db.scalar(
            "SELECT value FROM samples WHERE metric_id = ? AND ts >= ? AND ts <= ? ORDER BY value "
            "LIMIT 1 OFFSET (SELECT CAST(COUNT(*) * 0.95 AS INTEGER) FROM samples WHERE metric_id = ? AND ts >= ? AND ts <= ?)",
            (metric_id, int(start), int(end), metric_id, int(start), int(end)),
        ),
    ) if v is not None]
    row["p95"] = values[0] if values else None
    return row


def database_stats(db: Database) -> dict[str, Any]:
    stats = {}
    for table in ("devices", "interfaces", "metrics", "samples", "rollups", "checks", "heartbeats",
                  "outages", "syslog", "alerts", "events"):
        stats[table] = db.scalar(f"SELECT COUNT(*) FROM {table}")
    page_count = db.scalar("PRAGMA page_count") or 0
    page_size = db.scalar("PRAGMA page_size") or 0
    stats["size_bytes"] = page_count * page_size
    return stats
