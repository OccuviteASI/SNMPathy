"""UDP + TCP syslog listeners with batched writes to SQLite."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from typing import Any

from ..db import Database
from .parser import SyslogMessage, parse, split_octet_counted

log = logging.getLogger(__name__)

MAX_TCP_FRAME = 64 * 1024


class SyslogStats:
    def __init__(self) -> None:
        self.received = 0
        self.stored = 0
        self.dropped = 0
        self.errors = 0
        self.started_at = time.time()

    def as_dict(self) -> dict[str, Any]:
        return {
            "received": self.received,
            "stored": self.stored,
            "dropped": self.dropped,
            "errors": self.errors,
            "uptime": time.time() - self.started_at,
        }


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: "SyslogServer"):
        self.server = server

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        self.server.enqueue(data, addr[0])

    def error_received(self, exc: Exception) -> None:  # pragma: no cover - OS specific
        log.debug("syslog UDP error: %s", exc)


class SyslogServer:
    def __init__(
        self,
        db: Database,
        host: str = "0.0.0.0",
        udp_port: int = 5514,
        tcp_port: int = 5514,
        batch_size: int = 500,
        flush_interval: float = 1.0,
        queue_size: int = 100_000,
    ):
        self.db = db
        self.host = host
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.queue: asyncio.Queue[tuple[bytes, str, float]] = asyncio.Queue(maxsize=queue_size)
        self.stats = SyslogStats()
        self._transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.base_events.Server | None = None
        self._writer_task: asyncio.Task | None = None
        self._device_map: dict[str, int] = {}
        self._device_map_at = 0.0
        self.listening: dict[str, str] = {}

    # ---------------------------------------------------------------- intake
    def enqueue(self, data: bytes, source_ip: str) -> None:
        self.stats.received += 1
        if source_ip.startswith("::ffff:"):
            source_ip = source_ip[7:]
        try:
            self.queue.put_nowait((data, source_ip, time.time()))
        except asyncio.QueueFull:
            self.stats.dropped += 1

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        source_ip = peer[0]
        buffer = bytearray()
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                buffer.extend(chunk)
                for frame in split_octet_counted(buffer):
                    self.enqueue(frame, source_ip)
                if len(buffer) > MAX_TCP_FRAME:
                    # No delimiter in a very long line: flush it as one message.
                    self.enqueue(bytes(buffer), source_ip)
                    buffer.clear()
            if buffer.strip():
                self.enqueue(bytes(buffer), source_ip)
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    # ---------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        if self.udp_port:
            family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
            try:
                self._transport, _ = await loop.create_datagram_endpoint(
                    lambda: _UdpProtocol(self), local_addr=(self.host, self.udp_port), family=family
                )
                sock = self._transport.get_extra_info("socket")
                if sock is not None:
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                    except OSError:
                        pass
                    self.udp_port = sock.getsockname()[1]
                self.listening["udp"] = f"{self.host}:{self.udp_port}"
                log.info("syslog listening on udp/%s:%s", self.host, self.udp_port)
            except OSError as exc:
                log.error("cannot bind syslog UDP %s:%s: %s", self.host, self.udp_port, exc)
        if self.tcp_port:
            try:
                self._tcp_server = await asyncio.start_server(self._handle_tcp, self.host, self.tcp_port)
                sockets = self._tcp_server.sockets or []
                if sockets:
                    self.tcp_port = sockets[0].getsockname()[1]
                self.listening["tcp"] = f"{self.host}:{self.tcp_port}"
                log.info("syslog listening on tcp/%s:%s", self.host, self.tcp_port)
            except OSError as exc:
                log.error("cannot bind syslog TCP %s:%s: %s", self.host, self.tcp_port, exc)
        self._writer_task = asyncio.create_task(self._writer(), name="syslog-writer")

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            try:
                await asyncio.wait_for(self._tcp_server.wait_closed(), 2)
            except asyncio.TimeoutError:
                pass
        if self._writer_task:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass
        await self.flush()

    # ---------------------------------------------------------------- storage
    async def _writer(self) -> None:
        while True:
            try:
                first = await self.queue.get()
            except asyncio.CancelledError:
                raise
            batch = [first]
            deadline = time.monotonic() + self.flush_interval
            while len(batch) < self.batch_size:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self.queue.get(), timeout))
                except asyncio.TimeoutError:
                    break
            try:
                await asyncio.to_thread(self.store, batch)
            except Exception:  # keep ingesting even if one batch fails
                self.stats.errors += len(batch)
                log.exception("failed to store syslog batch")

    async def flush(self) -> None:
        batch = []
        while not self.queue.empty():
            batch.append(self.queue.get_nowait())
        if batch:
            await asyncio.to_thread(self.store, batch)

    def _devices(self) -> dict[str, int]:
        if time.time() - self._device_map_at > 60:
            mapping: dict[str, int] = {}
            for row in self.db.query("SELECT id, name, hostname, sys_name FROM devices"):
                for key in (row["hostname"], row["name"], row["sys_name"]):
                    if key:
                        mapping.setdefault(key.lower(), row["id"])
                host = row["hostname"]
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    try:
                        mapping.setdefault(socket.gethostbyname(host), row["id"])
                    except OSError:
                        pass
            self._device_map = mapping
            self._device_map_at = time.time()
        return self._device_map

    def invalidate_devices(self) -> None:
        self._device_map_at = 0

    def store(self, batch: list[tuple[bytes, str, float]]) -> int:
        devices = self._devices()
        rows = []
        for data, source_ip, received in batch:
            try:
                msg = parse(data, source_ip, received)
            except Exception:
                self.stats.errors += 1
                continue
            rows.append(message_row(msg, devices))
        store_messages(self.db, rows)
        self.stats.stored += len(rows)
        return len(rows)


def message_row(msg: SyslogMessage, devices: dict[str, int] | None = None) -> tuple[Any, ...]:
    devices = devices or {}
    device_id = devices.get(msg.source_ip)
    if device_id is None and msg.host:
        device_id = devices.get(msg.host.lower())
    return (
        msg.ts, msg.received_at, msg.source_ip, msg.host[:255], device_id, msg.facility, msg.severity,
        msg.app[:128], msg.procid[:64], msg.msgid[:64], msg.message[:8192], msg.structured[:4096],
    )


def store_messages(db: Database, rows: list[tuple[Any, ...]]) -> None:
    if rows:
        db.executemany(
            "INSERT INTO syslog (ts, received_at, source_ip, host, device_id, facility, severity, app, procid, "
            "msgid, message, structured) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
