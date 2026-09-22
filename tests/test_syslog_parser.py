import time

from snmpathy.syslog.parser import parse, split_octet_counted


def test_rfc5424_with_structured_data():
    msg = parse(
        '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 '
        '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][p@1 class="hi \\"x\\""] An application event',
        received_at=1065910455,
    )
    assert (msg.facility, msg.severity) == (20, 5)
    assert msg.host == "mymachine.example.com"
    assert msg.app == "evntslog"
    assert msg.msgid == "ID47"
    assert msg.procid == ""
    assert msg.sd["exampleSDID@32473"]["eventID"] == "1011"
    assert msg.sd["p@1"]["class"] == 'hi "x"'
    assert msg.message == "An application event"
    assert abs(msg.ts - 1065910455.003) < 0.01


def test_rfc5424_nil_values_and_bom():
    msg = parse("<34>1 - host app 123 - - ﻿hello", received_at=1000.0)
    assert msg.ts == 1000.0
    assert msg.procid == "123"
    assert msg.message == "hello"


def test_rfc3164_classic():
    now = time.time()
    lt = time.localtime(now)
    month = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()[lt.tm_mon - 1]
    stamp = f"{month} {lt.tm_mday:>2} {lt.tm_hour:02d}:{lt.tm_min:02d}:{lt.tm_sec:02d}"
    msg = parse(f"<34>{stamp} mymachine su[42]: 'su root' failed", "10.0.0.5", now)
    assert (msg.facility, msg.severity) == (4, 2)
    assert msg.host == "mymachine"
    assert msg.app == "su"
    assert msg.procid == "42"
    assert msg.message == "'su root' failed"
    assert abs(msg.ts - int(now)) < 2


def test_bsd_without_hostname_uses_source_ip():
    msg = parse("<14>Sep 22 18:00:00 kernel: something happened", "192.0.2.9")
    assert msg.host == "192.0.2.9"
    assert msg.app == "kernel"
    assert msg.message == "something happened"


def test_iso_timestamp_in_bsd_message():
    msg = parse("<30>2026-09-22T10:00:00.5+02:00 web01 nginx[99]: GET / 200", received_at=1790064000)
    assert msg.host == "web01"
    assert msg.app == "nginx"
    assert msg.message == "GET / 200"


def test_cisco_ios_with_sequence_and_unsynced_clock():
    msg = parse("<187>52: *Mar  1 00:01:02.345: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
                "10.1.1.1", 5000.0)
    assert msg.app == "LINK-3-UPDOWN"
    assert msg.severity == 3
    assert msg.host == "10.1.1.1"
    assert msg.ts == 5000.0  # '*' = unsynchronised clock -> receipt time
    assert msg.message.startswith("Interface Gi0/1")


def test_cisco_with_hostname():
    msg = parse("<189>1234: core-sw1: Mar 22 10:11:12.123 UTC: %SYS-5-CONFIG_I: Configured from console")
    assert msg.host == "core-sw1"
    assert msg.app == "SYS-5-CONFIG_I"
    assert msg.message == "Configured from console"


def test_missing_pri_defaults_to_user_notice():
    msg = parse("just some text", "10.0.0.1")
    assert (msg.facility, msg.severity) == (1, 5)
    assert msg.message == "just some text"


def test_skewed_device_clock_uses_receipt_time():
    msg = parse("<34>1 1999-01-01T00:00:00Z h a - - - old", received_at=1_700_000_000)
    assert msg.ts == 1_700_000_000


def test_octet_counting_and_newline_framing():
    first = b"<13>1 - h a - - - one"
    buf = bytearray(str(len(first)).encode() + b" " + first + b"<14>two\n<15>thr")
    frames = split_octet_counted(buf)
    assert frames == [first, b"<14>two"]
    assert bytes(buf) == b"<15>thr"
    buf.extend(b"ee\x00")
    assert split_octet_counted(buf) == [b"<15>three"]
    assert not buf
