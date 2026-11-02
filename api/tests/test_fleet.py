"""Fleet views (wall, groups, capacity, anomalies) and the extra reports."""

import time
from datetime import UTC, datetime

from sqlalchemy import text

from app.db import ServiceSession
from app.routes.fleet import availability, busy_matrix, fmt, judge
from app.services.heartbeats import redis

from .conftest import User, insert_host
from .test_monitoring_depth import _push, needs_vm


def test_judge():
    # 80% against a usual 20% ± 5: confirmed, 4x.
    assert judge(80, 20, 5, 10) == ("confirmed", 4.0)
    # Within the usual spread: nothing.
    assert judge(30, 20, 5, 10) is None
    # A tiny metric tripling (0.1 → 0.3) is below the floor: nothing.
    assert judge(0.3, 0.1, 0.01, 10) is None
    # Big rise, but only 1.3x the usual level: not unusual enough.
    assert judge(65, 50, 1, 10) is None
    got = judge(45, 20, 6, 10)
    assert got is not None
    sev, factor = got
    assert sev == "likely" and round(factor, 2) == 2.25


def test_busy_matrix_and_helpers():
    monday_9 = int(datetime(2026, 10, 26, 9, tzinfo=UTC).timestamp())  # a Monday
    pts = [[monday_9, 40.0], [monday_9 + 7 * 86400, 60.0], [monday_9 + 3600, 10.0]]
    m = busy_matrix(pts, 0)
    assert m[0][9] == 50.0 and m[0][10] == 10.0 and m[1][9] is None
    # In UTC+05:30 the 09:00 UTC slot is 14:30 local, so hour 14.
    assert busy_matrix(pts, 330 * 60)[0][14] == 50.0
    assert availability(None, 10) is None
    assert availability(100, 3000) == 100.0 and availability(50, 3000) == 50.0
    assert fmt(2_500_000, "bytes_per_second") == "2.5 MB/s" and fmt(42.4, "percent") == "42%"


@needs_vm
async def test_fleet_views_and_reports(alice: User, bob: User):
    tid = await alice.tenant_id()
    web = await insert_host(tid, "web-1")
    await insert_host(tid, "gone-1")
    async with ServiceSession() as db, db.begin():
        await db.execute(text("UPDATE hosts SET tags = '{web}' WHERE id = :h"), {"h": web})
        await db.execute(
            text(
                "INSERT INTO incidents (tenant_id, host_id, summary, rule_name, hostname, "
                "severity) VALUES (:t, :h, 'Disk almost full', 'disk', 'web-1', 'warning')"
            ),
            {"t": tid, "h": web},
        )
    await redis.set(f"pg:last_seen:{web}", int(time.time()))
    _push(tid, web, ["sentinel_cpu_usage_percent{} 30", "sentinel_uptime_seconds{} 100"])

    w = (await alice.request("GET", "/v1/fleet/wall")).json()
    by_name = {x["name"]: x for x in w["tiles"]}
    assert by_name["gone-1"]["status"] == "down" and by_name["gone-1"]["reason"].startswith("Not")
    assert (
        by_name["web-1"]["status"] == "warning" and by_name["web-1"]["reason"] == "Disk almost full"
    )
    assert w["tiles"][0]["name"] == "gone-1"  # worst first
    assert (await bob.request("GET", "/v1/fleet/wall")).json()["tiles"] == []

    g = {x["name"]: x for x in (await alice.request("GET", "/v1/fleet/groups")).json()}
    assert g["web"]["servers"] == 1 and g["web"]["counts"]["warning"] == 1
    assert g["Untagged"]["counts"]["down"] == 1

    cap = (await alice.request("GET", "/v1/fleet/capacity?days=1")).json()
    assert cap[0]["name"] == "All servers" and cap[0]["servers"] == 2
    assert {c["name"] for c in cap} == {"All servers", "web", "Untagged"}

    r = await alice.request("GET", "/v1/fleet/anomalies")
    assert r.status_code == 200 and r.json() == []  # no week of history

    for path in (
        "/v1/reports/busy-hours?metric=cpu&days=7",
        "/v1/reports/top?metric=cpu&days=1",
        "/v1/reports/outages?days=7",
        "/v1/reports/restarts?days=7",
    ):
        r = await alice.request("GET", path)
        assert r.status_code == 200, (path, r.text)
    assert len((await alice.request("GET", "/v1/reports/busy-hours")).json()["matrix"]) == 7
    inv = {x["hostname"]: x for x in (await alice.request("GET", "/v1/reports/inventory")).json()}
    assert set(inv) == {"web-1", "gone-1"} and inv["web-1"]["tags"] == ["web"]
    assert (await bob.request("GET", "/v1/reports/inventory")).json() == []
