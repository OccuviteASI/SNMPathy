import time

import pytest

from snmpathy.db import Database
from snmpathy.snmp import mibs


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "test.db"))
    yield database
    database.close()


def agent_data(in_octets=1000, out_octets=2000, uptime_ticks=100_000, oper=1, cpu=(10, 30)):
    """OID -> value map describing a small switch with two interfaces."""
    data = {
        mibs.SYS_DESCR: "Cisco IOS Software, C2960 Software",
        mibs.SYS_OBJECT_ID: "1.3.6.1.4.1.9.1.1208",
        mibs.SYS_UPTIME: uptime_ticks,
        mibs.SYS_NAME: "sw1",
        mibs.SYS_LOCATION: "lab",
        mibs.SYS_CONTACT: "noc",
    }
    for idx, name in ((1, "Gi0/1"), (2, "Gi0/2")):
        data[f"{mibs.IF_DESCR}.{idx}"] = name
        data[f"{mibs.IF_NAME}.{idx}"] = name
        data[f"{mibs.IF_ALIAS}.{idx}"] = "uplink" if idx == 1 else ""
        data[f"{mibs.IF_TYPE}.{idx}"] = 6
        data[f"{mibs.IF_MTU}.{idx}"] = 1500
        data[f"{mibs.IF_SPEED}.{idx}"] = 1_000_000_000
        data[f"{mibs.IF_HIGH_SPEED}.{idx}"] = 1000
        data[f"{mibs.IF_PHYS_ADDRESS}.{idx}"] = bytes([0, 1, 2, 3, 4, idx])
        data[f"{mibs.IF_ADMIN_STATUS}.{idx}"] = 1
        data[f"{mibs.IF_OPER_STATUS}.{idx}"] = oper if idx == 1 else 2
        data[f"{mibs.IF_LAST_CHANGE}.{idx}"] = 0
        data[f"{mibs.IF_HC_IN_OCTETS}.{idx}"] = in_octets * idx
        data[f"{mibs.IF_HC_OUT_OCTETS}.{idx}"] = out_octets * idx
        data[f"{mibs.IF_IN_ERRORS}.{idx}"] = 0
        data[f"{mibs.IF_OUT_ERRORS}.{idx}"] = 0
        data[f"{mibs.IF_IN_DISCARDS}.{idx}"] = 0
        data[f"{mibs.IF_OUT_DISCARDS}.{idx}"] = 0
    for n, load in enumerate(cpu, start=1):
        data[f"{mibs.HR_PROCESSOR_LOAD}.{n}"] = load
    data[f"{mibs.HR_STORAGE_TYPE}.1"] = mibs.HR_STORAGE_RAM
    data[f"{mibs.HR_STORAGE_DESCR}.1"] = "Physical memory"
    data[f"{mibs.HR_STORAGE_ALLOC}.1"] = 1024
    data[f"{mibs.HR_STORAGE_SIZE}.1"] = 1000
    data[f"{mibs.HR_STORAGE_USED}.1"] = 250
    data[f"{mibs.HR_STORAGE_TYPE}.31"] = mibs.HR_STORAGE_FIXED_DISK
    data[f"{mibs.HR_STORAGE_DESCR}.31"] = "/"
    data[f"{mibs.HR_STORAGE_ALLOC}.31"] = 4096
    data[f"{mibs.HR_STORAGE_SIZE}.31"] = 1000
    data[f"{mibs.HR_STORAGE_USED}.31"] = 950
    return data


@pytest.fixture
def make_device(db):
    from snmpathy.services import create_device

    def _make(name="sw1", hostname="10.0.0.1", **extra):
        return create_device(db, {"name": name, "hostname": hostname, **extra}, add_ping_check=extra.pop("ping", False))

    return _make


@pytest.fixture
def now():
    return time.time()
