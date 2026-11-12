"""UDP flow collector: NetFlow v5/v9, IPFIX and sFlow v5 with minute aggregation into SQLite.

Every listener sniffs the export format, so any configured port accepts any format. Decoded records
are summed in memory per (minute bucket, exporter, src, dst, sport, dport, proto, in_if, out_if) and
written to the ``flows`` table every ``flush_interval`` seconds as plain INSERTs; readers sum over
rows (see :mod:`snmpathy.flows.query`). Exporters are tracked in ``flow_sources``.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Any

from ..db import Database
from .parser import FlowDecodeError, TemplateCache, decode

log = logging.getLogger(__name__)

DEFAULT_PORTS: dict[str, int | None] = {"netflow": 2055, "ipfix": 4739, "sflow": 6343}
MAX_KEYS = 200_000          # in-memory aggregation cap between flushes
RECENT_WINDOW = 600.0       # record end times older than this fall back to the receive time
CLOCK_SKEW = 60.0           # tolerate exporters whose clock runs slightly ahead

AggKey = tuple[int, int, str, str, int, int, int, int, int]


class FlowStats:
    """Counters exposed by :class:`FlowCollector` (also readable as ``stats["datagrams"]``)."""

    def __init__(self) -> None:
        self.datagrams = 0      # UDP payloads received / ingested
        self.records = 0        # flow records accepted into the aggregation
        self.errors = 0         # undecodable datagrams and failed flushes
        self.dropped = 0        # records dropped because the aggregation was full
        self.skipped = 0        # records/sets the decoder could not use (unknown template, non-IP)
        self.ignored = 0        # datagrams from disabled sources
        self.stored = 0         # rows written to ``flows``
        self.started_at = time.time()

    def __getitem__(self, name: str) -> Any:
        return self.as_dict()[name]

    def as_dict(self) -> dict[str, Any]:
        return {
            "datagrams": self.datagrams,
            "records": self.records,
            "errors": self.errors,
            "dropped": self.dropped,
            "skipped": self.skipped,
            "ignored": self.ignored,
            "stored": self.stored,
            "uptime": time.time() - self.started_at,
        }


class _SourceDelta:
    """Pending ``flow_sources`` counter updates for one exporter since the last flush."""

    __slots__ = ("kind", "sampling", "last_seen", "packets", "records")

    def __init__(self) -> None:
        self.kind = ""
        self.sampling = 1
        self.last_seen = 0.0
        self.packets = 0
        self.records = 0


class _FlowProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: "FlowCollector"):
        self.collector = collector

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        self.collector.ingest(data, addr[0])

    def error_received(self, exc: Exception) -> None:  # pragma: no cover - OS specific
        log.debug("flow UDP error: %s", exc)


class FlowCollector:
    """Receive flow exports on one or more UDP ports and store minute aggregates.

    ``ports`` maps a listener name to a UDP port; a port of 0/None disables that listener. After
    :meth:`start`, ``listening`` maps each bound listener to ``"host:port"``.
    """

    def __init__(
        self,
        db: Database,
        host: str = "0.0.0.0",
        ports: dict[str, int | None] | None = None,
        flush_interval: float = 10.0,
        max_keys: int = MAX_KEYS,
    ):
        self.db = db
        self.host = host
        self.ports: dict[str, int | None] = dict(DEFAULT_PORTS if ports is None else ports)
        self.flush_interval = flush_interval
        self.max_keys = max_keys
        self.cache = TemplateCache()
        self.stats = FlowStats()
        self.listening: dict[str, str] = {}
        self._transports: list[asyncio.DatagramTransport] = []
        self._flush_task: asyncio.Task | None = None
        self._agg: dict[AggKey, list[int]] = {}
        self._pending: dict[int, _SourceDelta] = {}
        # exporter address -> (flow_sources.id, enabled)
        self._sources: dict[str, tuple[int, bool]] = {}

    # ---------------------------------------------------------------- intake
    def ingest(self, data: bytes, addr: str, now: float | None = None) -> int:
        """Decode one datagram from ``addr`` and add its records to the aggregation.

        Synchronous and exception-safe (used by the UDP protocol and by tests). Returns the number of
        records aggregated.
        """
        self.stats.datagrams += 1
        now = time.time() if now is None else now
        if addr.startswith("::ffff:"):
            addr = addr[7:]
        try:
            result = decode(data, addr, self.cache)
        except FlowDecodeError as exc:
            self.stats.errors += 1
            log.debug("undecodable flow datagram from %s: %s", addr, exc)
            return 0
        except Exception:  # never let a decoder bug kill the listener
            self.stats.errors += 1
            log.exception("flow decoder failed on datagram from %s", addr)
            return 0
        self.stats.skipped += result.skipped
        exporter = result.agent if result.kind == "sflow" and result.agent else addr
        try:
            source_id, enabled = self._source(exporter, now)
        except Exception:
            self.stats.errors += 1
            log.exception("cannot register flow source %s", exporter)
            return 0
        if not enabled:
            self.stats.ignored += 1
            return 0

        delta = self._pending.get(source_id)
        if delta is None:
            delta = self._pending[source_id] = _SourceDelta()
        delta.kind = result.kind
        delta.sampling = max(1, result.sampling)
        delta.last_seen = max(delta.last_seen, now)
        delta.packets += 1

        agg = self._agg
        added = 0
        for rec in result.records:
            end = rec.get("end")
            ts = now
            if end is not None and now - RECENT_WINDOW <= end <= now + CLOCK_SKEW:
                ts = min(end, now)
            key: AggKey = (
                int(ts) // 60 * 60, source_id, rec["src"], rec["dst"], int(rec["sport"]), int(rec["dport"]),
                int(rec["proto"]), int(rec["in_if"]), int(rec["out_if"]),
            )
            slot = agg.get(key)
            if slot is None:
                if len(agg) >= self.max_keys:
                    self.stats.dropped += 1
                    continue
                slot = agg[key] = [0, 0, 0]
            slot[0] += int(rec["bytes"])
            slot[1] += int(rec["packets"])
            slot[2] += 1
            added += 1
        delta.records += added
        self.stats.records += added
        return added

    def _source(self, address: str, now: float) -> tuple[int, bool]:
        """Return (flow_sources.id, enabled) for an exporter, creating the row on first sight."""
        known = self._sources.get(address)
        if known is not None:
            return known
        row = self.db.one("SELECT id, enabled FROM flow_sources WHERE address = ?", (address,))
        if row is None:
            device_id = self.db.scalar("SELECT id FROM devices WHERE hostname = ? ORDER BY id LIMIT 1", (address,))
            self.db.execute(
                "INSERT OR IGNORE INTO flow_sources (address, device_id, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                (address, device_id, now, now),
            )
            row = self.db.one("SELECT id, enabled FROM flow_sources WHERE address = ?", (address,))
            if row is None:  # pragma: no cover - only if the insert was rolled back underneath us
                raise RuntimeError(f"flow source {address} vanished")
            log.info("new flow exporter %s (source %s)", address, row["id"])
        entry = (int(row["id"]), bool(row["enabled"]))
        self._sources[address] = entry
        return entry

    def invalidate_sources(self) -> None:
        """Forget cached source rows (call after editing/deleting ``flow_sources``)."""
        self._sources = {}

    # ---------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        for name, port in self.ports.items():
            if not port:
                continue
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _FlowProtocol(self), local_addr=(self.host, int(port)), family=family
                )
            except OSError as exc:
                log.error("cannot bind flow listener %s on udp/%s:%s: %s", name, self.host, port, exc)
                continue
            sock = transport.get_extra_info("socket")
            if sock is not None:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                except OSError:
                    pass
                port = sock.getsockname()[1]
                self.ports[name] = port
            self._transports.append(transport)
            self.listening[name] = f"{self.host}:{port}"
            log.info("flow collector %s listening on udp/%s:%s", name, self.host, port)
        self._flush_task = asyncio.create_task(self._flusher(), name="flow-flusher")

    async def stop(self) -> None:
        for transport in self._transports:
            transport.close()
        self._transports.clear()
        self.listening.clear()
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None
        await self.flush()

    async def _flusher(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval)
            try:
                await self.flush()
            except Exception:  # keep collecting even if one flush fails
                self.stats.errors += 1
                log.exception("failed to store flow aggregates")

    # ---------------------------------------------------------------- storage
    def _take(self) -> tuple[dict[AggKey, list[int]], dict[int, _SourceDelta]]:
        """Detach the current aggregation (called on the event-loop thread)."""
        agg, self._agg = self._agg, {}
        pending, self._pending = self._pending, {}
        return agg, pending

    async def flush(self) -> int:
        """Write the current aggregation to the database; returns the number of rows stored."""
        agg, pending = self._take()
        if not agg and not pending:
            return 0
        return await asyncio.to_thread(self._write, agg, pending)

    def flush_now(self) -> int:
        """Synchronous :meth:`flush` (for tests and shutdown paths without a loop)."""
        return self._write(*self._take())

    def _write(self, agg: dict[AggKey, list[int]], pending: dict[int, _SourceDelta]) -> int:
        rows = [(*key, b, p, n) for key, (b, p, n) in agg.items()]
        with self.db.transaction():
            if rows:
                self.db.executemany(
                    "INSERT INTO flows (bucket, source_id, src, dst, sport, dport, proto, in_if, out_if, "
                    "bytes, packets, flows) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
            for source_id, delta in pending.items():
                self.db.execute(
                    "UPDATE flow_sources SET kind = ?, sampling = ?, last_seen = MAX(last_seen, ?), "
                    "packets = packets + ?, records = records + ? WHERE id = ?",
                    (delta.kind, delta.sampling, delta.last_seen, delta.packets, delta.records, source_id),
                )
        self.stats.stored += len(rows)
        # Pick up enable/disable changes made through the UI since the last flush.
        self._sources = {
            r["address"]: (int(r["id"]), bool(r["enabled"]))
            for r in self.db.query("SELECT id, address, enabled FROM flow_sources")
        }
        return len(rows)
