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
