"""SQLite storage.

SNMPathy keeps everything in a single SQLite database running in WAL mode.
All access goes through :class:`Database`, which serialises writers with a
lock so the async poller, the syslog writer and the API thread pool can
share one connection safely.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, Sequence

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id               INTEGER PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    hostname         TEXT NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    snmp_enabled     INTEGER NOT NULL DEFAULT 1,
    snmp_version     TEXT NOT NULL DEFAULT '2c',
    snmp_port        INTEGER NOT NULL DEFAULT 161,
    snmp_community   TEXT NOT NULL DEFAULT 'public',
    v3_user          TEXT NOT NULL DEFAULT '',
    v3_auth_proto    TEXT NOT NULL DEFAULT 'sha',
    v3_auth_key      TEXT NOT NULL DEFAULT '',
    v3_priv_proto    TEXT NOT NULL DEFAULT 'aes',
    v3_priv_key      TEXT NOT NULL DEFAULT '',
    v3_context       TEXT NOT NULL DEFAULT '',
    poll_interval    INTEGER NOT NULL DEFAULT 300,
    location         TEXT NOT NULL DEFAULT '',
    tags             TEXT NOT NULL DEFAULT '[]',
    notes            TEXT NOT NULL DEFAULT '',
    sys_name         TEXT NOT NULL DEFAULT '',
    sys_descr        TEXT NOT NULL DEFAULT '',
    sys_object_id    TEXT NOT NULL DEFAULT '',
    sys_location     TEXT NOT NULL DEFAULT '',
    sys_contact      TEXT NOT NULL DEFAULT '',
    sys_uptime       REAL,
    vendor           TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'unknown',
    status_since     REAL,
    last_polled      REAL,
    last_poll_ms     REAL,
    last_discovered  REAL,
    last_error       TEXT NOT NULL DEFAULT '',
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS interfaces (
    id            INTEGER PRIMARY KEY,
    device_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index      INTEGER NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    descr         TEXT NOT NULL DEFAULT '',
    alias         TEXT NOT NULL DEFAULT '',
    if_type       INTEGER,
    speed         REAL,
    mtu           INTEGER,
    mac           TEXT NOT NULL DEFAULT '',
    admin_status  INTEGER,
    oper_status   INTEGER,
    last_change   REAL,
    in_bps        REAL,
    out_bps       REAL,
    updated_at    REAL NOT NULL,
    UNIQUE (device_id, if_index)
);

-- One row per time series (a metric on a device, optionally per instance).
CREATE TABLE IF NOT EXISTS metrics (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    instance    TEXT NOT NULL DEFAULT '',
    label       TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT 'gauge',
    oid         TEXT NOT NULL DEFAULT '',
    oid2        TEXT NOT NULL DEFAULT '',
    unit        TEXT NOT NULL DEFAULT '',
    scale       REAL NOT NULL DEFAULT 1,
    counter_bits INTEGER NOT NULL DEFAULT 32,
    custom      INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_raw    REAL,
    last_raw_ts REAL,
    last_value  REAL,
    last_text   TEXT,
    last_ts     REAL,
    UNIQUE (device_id, key, instance)
);
CREATE INDEX IF NOT EXISTS idx_metrics_key ON metrics(key);

CREATE TABLE IF NOT EXISTS samples (
    metric_id INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    value     REAL NOT NULL,
    PRIMARY KEY (metric_id, ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS rollups (
    metric_id INTEGER NOT NULL,
    period    INTEGER NOT NULL,
    bucket    INTEGER NOT NULL,
    vmin      REAL NOT NULL,
    vmax      REAL NOT NULL,
    vavg      REAL NOT NULL,
    vcount    INTEGER NOT NULL,
    PRIMARY KEY (metric_id, period, bucket)
) WITHOUT ROWID;

-- Availability checks (ICMP / TCP / HTTP / SNMP), with or without a device.
CREATE TABLE IF NOT EXISTS checks (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    target          TEXT NOT NULL,
    port            INTEGER,
    interval        INTEGER NOT NULL DEFAULT 60,
    timeout         REAL NOT NULL DEFAULT 5,
    retries         INTEGER NOT NULL DEFAULT 2,
    options         TEXT NOT NULL DEFAULT '{}',
    enabled         INTEGER NOT NULL DEFAULT 1,
    public          INTEGER NOT NULL DEFAULT 0,
    state           TEXT NOT NULL DEFAULT 'unknown',
    state_since     REAL,
    fail_count      INTEGER NOT NULL DEFAULT 0,
    last_checked    REAL,
    last_latency_ms REAL,
    last_message    TEXT NOT NULL DEFAULT '',
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS heartbeats (
    check_id   INTEGER NOT NULL,
    ts         REAL NOT NULL,
    ok         INTEGER NOT NULL,
    latency_ms REAL,
    message    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (check_id, ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS outages (
    id          INTEGER PRIMARY KEY,
    check_id    INTEGER NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    started_at  REAL NOT NULL,
    ended_at    REAL,
    reason      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_outages_check ON outages(check_id, started_at);

CREATE TABLE IF NOT EXISTS maintenance (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    device_id   INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    check_id    INTEGER REFERENCES checks(id) ON DELETE CASCADE,
    starts_at   REAL NOT NULL,
    ends_at     REAL NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS syslog (
    id           INTEGER PRIMARY KEY,
    ts           REAL NOT NULL,
    received_at  REAL NOT NULL,
    source_ip    TEXT NOT NULL DEFAULT '',
    host         TEXT NOT NULL DEFAULT '',
    device_id    INTEGER,
    facility     INTEGER,
    severity     INTEGER,
    app          TEXT NOT NULL DEFAULT '',
    procid       TEXT NOT NULL DEFAULT '',
    msgid        TEXT NOT NULL DEFAULT '',
    message      TEXT NOT NULL DEFAULT '',
    structured   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_syslog_ts ON syslog(ts);
CREATE INDEX IF NOT EXISTS idx_syslog_host_ts ON syslog(host, ts);
CREATE INDEX IF NOT EXISTS idx_syslog_sev_ts ON syslog(severity, ts);

CREATE TABLE IF NOT EXISTS channels (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL UNIQUE,
    type     TEXT NOT NULL,
    config   TEXT NOT NULL DEFAULT '{}',
    enabled  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    severity        TEXT NOT NULL DEFAULT 'warning',
    device_id       INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    device_tag      TEXT NOT NULL DEFAULT '',
    metric_key      TEXT NOT NULL DEFAULT '',
    instance        TEXT NOT NULL DEFAULT '',
    operator        TEXT NOT NULL DEFAULT '>',
    threshold       REAL,
    for_seconds     INTEGER NOT NULL DEFAULT 0,
    syslog_query    TEXT NOT NULL DEFAULT '',
    syslog_severity INTEGER,
    window_seconds  INTEGER NOT NULL DEFAULT 300,
    count_threshold INTEGER NOT NULL DEFAULT 1,
    channels        TEXT NOT NULL DEFAULT '[]',
    description     TEXT NOT NULL DEFAULT '',
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY,
    rule_id      INTEGER REFERENCES alert_rules(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL,
    device_id    INTEGER,
    check_id     INTEGER,
    subject      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    state        TEXT NOT NULL,
    value        REAL,
    message      TEXT NOT NULL DEFAULT '',
    started_at   REAL NOT NULL,
    fired_at     REAL,
    resolved_at  REAL,
    last_eval    REAL NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    ack_by       TEXT NOT NULL DEFAULT '',
    ack_at       REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state);
CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts(fingerprint, state);

CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY,
    alert_id    INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    channel_id  INTEGER REFERENCES channels(id) ON DELETE SET NULL,
    event       TEXT NOT NULL,
    status      TEXT NOT NULL,
    error       TEXT NOT NULL DEFAULT '',
    ts          REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY,
    ts         REAL NOT NULL,
    level      TEXT NOT NULL DEFAULT 'info',
    device_id  INTEGER,
    check_id   INTEGER,
    type       TEXT NOT NULL,
    message    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

-- Grafana-style dashboards: config holds time range, refresh and panels as JSON.
CREATE TABLE IF NOT EXISTS dashboards (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    config      TEXT NOT NULL DEFAULT '{}',
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS report_schedules (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    report      TEXT NOT NULL,
    range       TEXT NOT NULL DEFAULT '7d',
    frequency   TEXT NOT NULL DEFAULT 'weekly',
    hour        INTEGER NOT NULL DEFAULT 7,
    weekday     INTEGER NOT NULL DEFAULT 0,
    monthday    INTEGER NOT NULL DEFAULT 1,
    options     TEXT NOT NULL DEFAULT '{}',
    channels    TEXT NOT NULL DEFAULT '[]',
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run    REAL,
    last_status TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL
);
"""


# Full-text index for syslog search. FTS5 ships with the SQLite bundled in
# CPython on Windows, macOS and most Linux distros; if it is missing we fall
# back to LIKE-based search.
FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS syslog_fts USING fts5(
    message, host, app, content='syslog', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS syslog_ai AFTER INSERT ON syslog BEGIN
    INSERT INTO syslog_fts(rowid, message, host, app) VALUES (new.id, new.message, new.host, new.app);
END;
CREATE TRIGGER IF NOT EXISTS syslog_ad AFTER DELETE ON syslog BEGIN
    INSERT INTO syslog_fts(syslog_fts, rowid, message, host, app) VALUES ('delete', old.id, old.message, old.host, old.app);
END;
"""


def _dict_factory(cursor: sqlite3.Cursor, row: Sequence[Any]) -> dict[str, Any]:
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


class Database:
    """Thread-safe wrapper around a single SQLite connection."""

    def __init__(self, path: str = "snmpathy.db"):
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self.conn.row_factory = _dict_factory
        self.conn.execute("PRAGMA foreign_keys = ON")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("PRAGMA synchronous = NORMAL")
        self.conn.execute("PRAGMA busy_timeout = 30000")
        self.has_fts = False
        self.migrate()

    # -- lifecycle -----------------------------------------------------
    def migrate(self) -> None:
        with self._lock:
            self.conn.executescript(SCHEMA)
            try:
                self.conn.executescript(FTS_SCHEMA)
                self.has_fts = True
            except sqlite3.OperationalError:
                self.has_fts = False
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # -- primitives ----------------------------------------------------
    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self.conn.execute(sql, params)

    def executemany(self, sql: str, seq: Iterable[Sequence[Any]]) -> None:
        with self._lock:
            with self.transaction():
                self.conn.executemany(sql, seq)

    def query(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> dict[str, Any] | None:
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> Any:
        row = self.one(sql, params)
        if not row:
            return None
        return next(iter(row.values()))

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self.conn.in_transaction:
                # Nested use: piggy-back on the outer transaction.
                yield self.conn
                return
            self.conn.execute("BEGIN")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def insert(self, table: str, values: dict[str, Any]) -> int:
        cols = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        cur = self.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", list(values.values()))
        return int(cur.lastrowid)

    def update(self, table: str, row_id: int, values: dict[str, Any]) -> None:
        if not values:
            return
        sets = ", ".join(f"{col} = ?" for col in values)
        self.execute(f"UPDATE {table} SET {sets} WHERE id = ?", [*values.values(), row_id])

    # -- key/value ---------------------------------------------------------
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        value = self.scalar("SELECT value FROM meta WHERE key = ?", (key,))
        return default if value is None else value

    def set_meta(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def log_event(
        self,
        type_: str,
        message: str,
        level: str = "info",
        device_id: int | None = None,
        check_id: int | None = None,
        ts: float | None = None,
    ) -> None:
        self.execute(
            "INSERT INTO events(ts, level, device_id, check_id, type, message) VALUES (?, ?, ?, ?, ?, ?)",
            (ts or time.time(), level, device_id, check_id, type_, message),
        )


def loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default
