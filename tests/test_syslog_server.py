import asyncio
import socket

from snmpathy.syslog.server import SyslogServer


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def test_udp_and_tcp_ingest(db, make_device):
    make_device("core-sw01", "127.0.0.1")
    port = _free_port()
    server = SyslogServer(db, "127.0.0.1", udp_port=port, tcp_port=port, flush_interval=0.05)
    await server.start()
    try:
        assert server.listening == {"udp": f"127.0.0.1:{port}", "tcp": f"127.0.0.1:{port}"}
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.sendto(b"<11>Oct 11 22:14:15 core-sw01 sshd[1]: udp message", ("127.0.0.1", server.udp_port))
        udp.close()
        _, writer = await asyncio.open_connection("127.0.0.1", server.tcp_port)
        first = b"<13>1 - host1 app - - - framed message"
        writer.write(str(len(first)).encode() + b" " + first + b"<14>newline message\n")
        await writer.drain()
        writer.close()
        for _ in range(100):
            await asyncio.sleep(0.05)
            if db.scalar("SELECT COUNT(*) FROM syslog") >= 3:
                break
    finally:
        await server.stop()
    rows = {r["message"]: r for r in db.query("SELECT * FROM syslog")}
    assert set(rows) == {"udp message", "framed message", "newline message"}
    assert rows["udp message"]["severity"] == 3
    assert rows["udp message"]["device_id"] is not None  # mapped by source IP
    assert server.stats.received == 3 and server.stats.stored == 3
