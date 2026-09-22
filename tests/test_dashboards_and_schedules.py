import time
from datetime import datetime

import pytest

from snmpathy import dashboards, scheduled
from snmpathy.grafana import grafana_dashboards, grafana_value, write_provisioning


def test_nice_step():
    assert dashboards.nice_step(3600) == 30
    assert dashboards.nice_step(86400) == 300
    assert dashboards.nice_step(86400, min_step=600) == 600
    assert dashboards.nice_step(365 * 86400) == 86400 * 2


def test_query_target_each_and_sum(db, make_device):
    now = int(time.time()) // 300 * 300
    series_ids = []
    for name in ("a", "b"):
        dev = make_device(name, f"10.0.0.{len(series_ids) + 1}", poll_interval=60)
        mid = db.insert("metrics", {"device_id": dev["id"], "key": "if.in_bps", "instance": "1", "label": "Gi0/1",
                                    "kind": "counter", "unit": "bps", "last_value": 10.0 * (len(series_ids) + 1)})
        series_ids.append(mid)
        db.executemany("INSERT INTO samples VALUES (?, ?, ?)", [(mid, now - i * 60, 100.0) for i in range(60)])
    each = dashboards.query_target(db, {"key": "if.in_bps"}, now - 3600, now)
    assert [s["name"] for s in each] == ["b Gi0/1", "a Gi0/1"]  # ordered by current value
    total = dashboards.query_target(db, {"key": "if.in_bps", "agg": "sum", "alias": "Total"}, now - 3600, now)
    assert total[0]["name"] == "Total"
    assert {v for _, v in total[0]["points"]} == {200.0}
    only_a = dashboards.query_target(db, {"key": "if.*_bps", "device": "a", "instance": "Gi0/*"}, now - 3600, now)
    assert len(only_a) == 1 and only_a[0]["unit"] == "bps"


def test_all_panel_types_render(db, make_device):
    make_device()
    now = time.time()
    for ptype in dashboards.PANEL_TYPES:
        data = dashboards.panel_data(db, {"type": ptype, "targets": [{"key": "cpu.avg"}], "options": {}}, now - 3600, now)
        assert "error" not in data, ptype


def test_default_dashboards_are_valid(db):
    assert dashboards.seed_dashboards(db) == len(dashboards.DEFAULT_DASHBOARDS)
    assert dashboards.seed_dashboards(db) == 0
    for row in db.query("SELECT config FROM dashboards"):
        import json

        cfg = json.loads(row["config"])
        assert cfg["panels"] and all(p["type"] in dashboards.PANEL_TYPES for p in cfg["panels"])


def test_grafana_value_unescaping():
    assert grafana_value("core\\-sw01") == "core-sw01"
    assert grafana_value("(a|b\\.c)") == ["a", "b.c"]
    assert grafana_value("$__all") == "*"
    assert grafana_value("{x,y}") == ["x", "y"]


def test_grafana_dashboards_and_provisioning(tmp_path):
    boards = grafana_dashboards()
    assert len(boards) == 5
    for board in boards.values():
        ids = [p["id"] for p in board["panels"]]
        assert len(ids) == len(set(ids))
        for p in board["panels"]:
            g = p["gridPos"]
            assert g["x"] + g["w"] <= 24
    files = write_provisioning(str(tmp_path), token="")
    assert any(f.endswith("snmpathy.yaml") for f in files)
    assert (tmp_path / "dashboards" / "json" / "snmpathy-overview.json").exists()


@pytest.mark.parametrize("schedule,now,expected", [
    ({"frequency": "daily", "hour": 7}, datetime(2026, 3, 18, 8, 0), datetime(2026, 3, 18, 7, 0)),
    ({"frequency": "daily", "hour": 7}, datetime(2026, 3, 18, 6, 0), datetime(2026, 3, 17, 7, 0)),
    ({"frequency": "weekly", "hour": 7, "weekday": 0}, datetime(2026, 3, 18, 8, 0), datetime(2026, 3, 16, 7, 0)),
    ({"frequency": "weekly", "hour": 9, "weekday": 2}, datetime(2026, 3, 18, 8, 0), datetime(2026, 3, 11, 9, 0)),
    ({"frequency": "monthly", "hour": 7, "monthday": 1}, datetime(2026, 3, 18, 8, 0), datetime(2026, 3, 1, 7, 0)),
    ({"frequency": "monthly", "hour": 7, "monthday": 20}, datetime(2026, 3, 18, 8, 0), datetime(2026, 2, 20, 7, 0)),
])
def test_schedule_previous_occurrence(schedule, now, expected):
    assert scheduled.previous_occurrence(schedule, now.timestamp()) == expected.timestamp()


async def test_scheduled_report_delivery(db):
    from snmpathy.config import Settings
    from snmpathy.services import create_channel

    create_channel(db, {"name": "log", "type": "log"})
    created = datetime(2026, 3, 1).timestamp()
    sid = db.insert("report_schedules", {"name": "daily uptime", "report": "uptime", "range": "yesterday",
                                         "frequency": "daily", "hour": 7, "channels": "[1]", "created_at": created})
    schedule = db.one("SELECT * FROM report_schedules WHERE id = ?", (sid,))
    now = datetime(2026, 3, 18, 8, 0).timestamp()
    assert scheduled.is_due(schedule, now)
    assert await scheduled.run_due(db, Settings(), now=now) == 1
    schedule = db.one("SELECT * FROM report_schedules WHERE id = ?", (sid,))
    assert "log: sent" in schedule["last_status"]
    assert not scheduled.is_due(schedule, now + 60)
    html = scheduled.render_html({"id": "uptime", "title": "T", "subtitle": "S", "summary": [], "sections": []})
    assert "<h1" in html
