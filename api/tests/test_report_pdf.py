"""Server report PDFs: one or many servers, any period, own servers only."""

import uuid

from .conftest import User, insert_host


async def test_pdf_for_one_and_many_servers(alice: User):
    tid = await alice.tenant_id()
    web, db = await insert_host(tid, "web-1"), await insert_host(tid, "db-1")
    one = await alice.request("GET", "/v1/reports/servers.pdf", params={"host_id": str(web)})
    assert one.status_code == 200, one.text
    assert one.headers["content-type"] == "application/pdf"
    assert one.content.startswith(b"%PDF") and "web-1" in one.headers["content-disposition"]

    params = {"host_id": [str(web), str(db)], "lifetime": "true", "tz": "UTC"}
    many = await alice.request("GET", "/v1/reports/servers.pdf", params=params)
    assert many.status_code == 200 and many.content.startswith(b"%PDF")


async def test_pdf_periods_and_ownership(alice: User, bob: User):
    web = await insert_host(await alice.tenant_id(), "web-1")
    theirs = await insert_host(await bob.tenant_id(), "bob-1")
    path = "/v1/reports/servers.pdf"
    r = await alice.request("GET", path, params={"host_id": str(theirs)})
    assert r.status_code == 404
    r = await alice.request("GET", path, params={"host_id": str(uuid.uuid4())})
    assert r.status_code == 404
    bad = {"host_id": str(web), "start": "2026-02-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"}
    assert (await alice.request("GET", path, params=bad)).status_code == 422
    huge = {"host_id": str(web), "start": "2010-01-01T00:00:00Z"}
    assert (await alice.request("GET", path, params=huge)).status_code == 422
    assert (
        await alice.request("GET", path, params={"host_id": str(web), "tz": "Mars/Base"})
    ).status_code == 422


def test_charts_break_at_gaps_and_sort_naturally():
    from app.services.hostpdf import natural, segments

    pts: list[list[float]] = [[0, 1], [60, 1], [120, 1], [3600, 2], [3660, 2]]
    assert [len(r) for r in segments(pts)] == [3, 2]
    assert sorted(["15m", "1m", "5m"], key=natural) == ["1m", "5m", "15m"]


def test_downtimes_daily_availability_and_disk_forecast():
    from zoneinfo import ZoneInfo

    from app.services.hostpdf import daily_availability, disk_forecasts, downtimes

    day = 86400
    pts: list[list[float]] = [[t, 1] for t in range(0, day, 60) if not 3600 <= t < 7200]
    gaps = downtimes(pts, day)
    assert gaps and gaps[0][1] - gaps[0][0] >= 3600
    daily = daily_availability(0, day, 0, gaps, ZoneInfo("UTC"))
    assert len(daily) == 1 and 95 < daily[0][1] < 96  # one hour of 24 missing

    growing = [[t, 50 + t / day * 5] for t in range(0, 4 * day, 3600)]
    (f,) = disk_forecasts([{"labels": {"mountpoint": "/var"}, "points": growing}])
    assert f.mount == "/var" and f.per_day is not None and abs(f.per_day - 5) < 0.1
    # ~70% now, +5 points a day: about six days left.
    assert f.full_in_days is not None and 5.5 < f.full_in_days < 6.5


def test_findings_flag_what_matters():
    from types import SimpleNamespace
    from typing import Any, cast

    from app.services.hostpdf import DiskForecast, HostData, findings

    host = cast(Any, SimpleNamespace(cpu_cores=4))
    d = HostData(host=host, availability=98.5, incidents=[])
    d.downtimes = [(0, 3600)]
    d.restarts = 2
    d.disks = [DiskForecast("/", 92, 90, 95, 1.5, 5.3)]
    d.series = {"cpu": [{"labels": {}, "points": [[t, 95] for t in range(30)]}]}
    text = " ".join(t for _, t in findings(d))
    assert "Availability 98.50%" in text and "Rebooted 2 times" in text
    assert "full in about 5 days" in text and "CPU was busy" in text
    healthy = HostData(host=host, availability=100, incidents=[])
    assert findings(healthy) == [("good", "Nothing needs attention in this period.")]
