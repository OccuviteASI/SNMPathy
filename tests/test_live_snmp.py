"""Integration test against a real SNMP agent.

Skipped unless SNMPATHY_TEST_AGENT is set, e.g. ``SNMPATHY_TEST_AGENT=127.0.0.1:16161``
(net-snmp's snmpd with ``rocommunity public``). Set SNMPATHY_TEST_V3 to
``user:authpass:privpass`` to also exercise SNMPv3 authPriv (SHA/AES).
"""

import os

import pytest

from snmpathy.snmp import mibs
from snmpathy.snmp.client import PySnmpClient, SnmpCredentials, SnmpError
from snmpathy.snmp.discovery import apply_discovery, discover
from snmpathy.snmp.poller import poll_device

AGENT = os.environ.get("SNMPATHY_TEST_AGENT")
pytestmark = pytest.mark.skipif(not AGENT, reason="SNMPATHY_TEST_AGENT not set")


def _target():
    host, _, port = AGENT.partition(":")
    return host, int(port or 161)


async def test_v2c_get_walk_discover_poll(db, make_device):
    host, port = _target()
    client = PySnmpClient(host, SnmpCredentials(community="public", port=port), timeout=2)
    try:
        values = await client.get([mibs.SYS_NAME, mibs.SYS_UPTIME, "1.3.6.1.2.1.1.99.0"])
        assert values[mibs.SYS_NAME]
        assert isinstance(values[mibs.SYS_UPTIME], int)
        assert values["1.3.6.1.2.1.1.99.0"] is None
        names = await client.walk(mibs.IF_DESCR)
        assert names
        result = await discover(client)
        assert result.interfaces and result.system["vendor"]
        device = make_device("agent", host, snmp_port=port)
        apply_discovery(db, device["id"], result)
        first = await poll_device(db, client, db.one("SELECT * FROM devices"))
        second = await poll_device(db, client, db.one("SELECT * FROM devices"))
        assert first.ok and second.ok
        assert db.scalar("SELECT COUNT(*) FROM samples") > 0
    finally:
        client.close()


async def test_v3_auth_priv():
    creds = os.environ.get("SNMPATHY_TEST_V3")
    if not creds:
        pytest.skip("SNMPATHY_TEST_V3 not set")
    user, auth, priv = creds.split(":")
    host, port = _target()
    good = PySnmpClient(host, SnmpCredentials(version="3", port=port, v3_user=user, v3_auth_key=auth,
                                              v3_priv_key=priv), timeout=2)
    bad = PySnmpClient(host, SnmpCredentials(version="3", port=port, v3_user=user, v3_auth_key="wrongpass1",
                                             v3_priv_key=priv), timeout=1, retries=0)
    try:
        assert (await good.get([mibs.SYS_NAME]))[mibs.SYS_NAME]
        with pytest.raises(SnmpError):
            await bad.get([mibs.SYS_NAME])
    finally:
        good.close()
        bad.close()


async def test_timeout_raises():
    client = PySnmpClient("127.0.0.1", SnmpCredentials(port=1), timeout=0.5, retries=0)
    try:
        with pytest.raises(SnmpError):
            await client.get([mibs.SYS_NAME])
    finally:
        client.close()
