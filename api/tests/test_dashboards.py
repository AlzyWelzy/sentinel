"""Custom dashboards and comparing servers on one chart."""

import time

from .conftest import User, insert_host
from .test_monitoring_depth import _push, needs_vm


async def test_dashboards_crud_and_isolation(alice: User, bob: User):
    tid = await alice.tenant_id()
    web = await insert_host(tid, "web-1")
    body = {
        "name": "Web tier",
        "panels": [
            {"title": "CPU", "metric": "cpu", "host_ids": [str(web)]},
            {"title": "Disk by tag", "metric": "disk", "tag": "web", "width": 2},
        ],
    }
    r = await alice.request("POST", "/v1/dashboards", json=body)
    assert r.status_code == 201, r.text
    d = r.json()
    assert [p["title"] for p in d["panels"]] == ["CPU", "Disk by tag"]
    assert (await alice.request("POST", "/v1/dashboards", json=body)).status_code == 409
    empty = {"name": "x", "panels": [{"title": "t", "metric": "cpu"}]}
    assert (await alice.request("POST", "/v1/dashboards", json=empty)).status_code == 422
    # Bob can't see it, nor point a panel at Alice's server.
    assert (await bob.request("GET", "/v1/dashboards")).json() == []
    assert (await bob.request("GET", f"/v1/dashboards/{d['id']}")).status_code == 404
    stolen = {"name": "Mine", "panels": [{"title": "CPU", "metric": "cpu", "host_ids": [str(web)]}]}
    assert (await bob.request("POST", "/v1/dashboards", json=stolen)).status_code == 422
    renamed = await alice.request("PUT", f"/v1/dashboards/{d['id']}", json={**body, "name": "Web"})
    assert renamed.json()["name"] == "Web"
    assert (await alice.request("DELETE", f"/v1/dashboards/{d['id']}")).status_code == 204


@needs_vm
async def test_compare_servers(alice: User, bob: User):
    tid = await alice.tenant_id()
    a, b = await insert_host(tid, "app-a"), await insert_host(tid, "app-b")
    _push(tid, a, ["pulsegrid_cpu_usage_percent{} 21"])
    _push(tid, b, ["pulsegrid_cpu_usage_percent{} 64"])
    now = int(time.time())
    r = await alice.request(
        "GET",
        "/v1/metrics/compare",
        params=[
            ("metric", "cpu"),
            ("host_id", str(a)),
            ("host_id", str(b)),
            ("start", now - 600),
            ("end", now),
        ],
    )
    assert r.status_code == 200, r.text
    got = {s["hostname"]: s["points"][-1][1] for s in r.json()["series"]}
    assert got == {"app-a": 21, "app-b": 64}
    # Bob asking for Alice's servers gets nothing.
    theirs = await bob.request(
        "GET", "/v1/metrics/compare", params=[("metric", "cpu"), ("host_id", str(a))]
    )
    assert theirs.json()["series"] == []
