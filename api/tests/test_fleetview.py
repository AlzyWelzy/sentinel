"""Fleet overview (status counts, latest CPU/memory/disk) and disk forecasts."""

import time
import uuid

from sqlalchemy import text

from app.db import ServiceSession
from app.services.heartbeats import redis

from .conftest import User, access_token, insert_host
from .test_monitoring_depth import _push, needs_vm


@needs_vm
async def test_overview_and_disks(alice: User, bob: User, client):
    tid = await alice.tenant_id()
    busy = await insert_host(tid, "busy-1")
    quiet = await insert_host(tid, "quiet-1")
    await insert_host(tid, "gone-1")
    now = int(time.time())
    for h in (busy, quiet):
        await redis.set(f"pg:last_seen:{h}", now)
    _push(
        tid,
        busy,
        [
            "sentinel_cpu_usage_percent{} 91.2",
            "sentinel_memory_used_percent{} 70",
            'sentinel_disk_used_percent{mountpoint="/",device="/dev/sda1"} 82',
            'sentinel_disk_used_percent{mountpoint="/data",device="/dev/sdb1"} 40',
            'sentinel_disk_free_bytes{mountpoint="/",device="/dev/sda1"} 18000000000',
            'sentinel_disk_total_bytes{mountpoint="/",device="/dev/sda1",fstype="ext4"} 1e11',
            'sentinel_disk_used_bytes{mountpoint="/",device="/dev/sda1"} 82000000000',
            'sentinel_load{period="1m"} 3.5',
        ],
    )
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "INSERT INTO incidents (tenant_id, host_id, summary, rule_name, hostname, "
                "severity) VALUES (:t, :h, 'CPU high', 'cpu', 'busy-1', 'critical')"
            ),
            {"t": tid, "h": busy},
        )
    r = await alice.request("GET", "/v1/servers/overview")
    assert r.status_code == 200, r.text
    body = r.json()
    by_name = {s["hostname"]: s for s in body["servers"]}
    assert by_name["busy-1"]["status"] == "critical" and by_name["busy-1"]["cpu"] == 91.2
    assert by_name["busy-1"]["disk"] == 82 and by_name["busy-1"]["load1"] == 3.5
    assert by_name["quiet-1"]["status"] == "up" and by_name["gone-1"]["status"] == "down"
    assert body["counts"] == {
        "paused": 0,
        "down": 1,
        "critical": 1,
        "warning": 0,
        "maintenance": 0,
        "up": 1,
    }
    assert (await bob.request("GET", "/v1/servers/overview")).json()["servers"] == []

    disks = (await alice.request("GET", f"/v1/hosts/{busy}/disks")).json()
    root = next(d for d in disks if d["mountpoint"] == "/")
    assert root["fstype"] == "ext4" and root["total_bytes"] == 1e11 and root["used_percent"] == 82
    data = next(d for d in disks if d["mountpoint"] == "/data")
    assert data["total_bytes"] is None  # no free/total reported for it
    assert (await bob.request("GET", f"/v1/hosts/{busy}/disks")).status_code == 404
    # Staff see the same disks from the all-accounts view.
    token = access_token(str(uuid.uuid4()), "demo-support@example.com", superadmin=True)
    staff = await client.get(
        f"/admin/v1/hosts/{busy}/disks", headers={"Authorization": f"Bearer {token}"}
    )
    assert staff.status_code == 200 and staff.json() == disks


def test_timeline_merges_worst_state():
    from app.routes.fleetview import timeline

    segs = timeline(
        [(100, 400, "warning"), (200, 300, "critical"), (350, 500, "down"), (50, 80, "warning")],
        60,
        450,
    )
    assert [(s.start, s.end, s.state) for s in segs] == [
        (60, 80, "warning"),
        (100, 200, "warning"),
        (200, 300, "critical"),
        (300, 350, "warning"),
        (350, 450, "down"),
    ]
    assert timeline([], 0, 100) == []


@needs_vm
async def test_server_summary(alice: User, bob: User, client):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "sum-1")
    await redis.set(f"pg:last_seen:{host}", int(time.time()))
    _push(
        tid,
        host,
        [
            "sentinel_uptime_seconds{} 7200",
            "sentinel_processes_total{} 140",
            "sentinel_open_files{} 2944",
        ],
    )
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "INSERT INTO incidents (tenant_id, host_id, summary, rule_name, hostname, "
                "severity, opened_at, resolved_at, status) VALUES "
                "(:t, :h, 'Memory high', 'mem', 'sum-1', 'warning', now() - interval '2 hours', "
                "now() - interval '1 hour', 'resolved'), "
                "(:t, :h, 'CPU high', 'cpu', 'sum-1', 'critical', "
                "now() - interval '10 minutes', null, 'open')"
            ),
            {"t": tid, "h": host},
        )
    r = await alice.request("GET", f"/v1/hosts/{host}/summary?range=86400")
    assert r.status_code == 200, r.text
    s = r.json()
    assert [seg["state"] for seg in s["timeline"]] == ["warning", "critical"]
    assert [h["summary"] for h in s["history"]] == ["CPU high", "Memory high"]
    assert s["root_causes"] == ["CPU high"] and s["downtimes"] == 0
    assert s["uptime_seconds"] == 7200 and s["processes"] == 140 and s["open_files"] == 2944
    assert (await bob.request("GET", f"/v1/hosts/{host}/summary")).status_code == 404
    token = access_token(str(uuid.uuid4()), "demo-support@example.com", superadmin=True)
    staff = await client.get(
        f"/admin/v1/hosts/{host}/summary", headers={"Authorization": f"Bearer {token}"}
    )
    assert staff.status_code == 200 and staff.json()["root_causes"] == ["CPU high"]


@needs_vm
async def test_notes_deliveries_and_forecast(alice: User, bob: User, client):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "note-1")
    r = await alice.request(
        "PATCH", f"/v1/hosts/{host}", json={"notes": "  Billing DB. Owner: Asha  "}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["notes"] == "Billing DB. Owner: Asha" and body["notes_updated_by"]
    assert (await alice.request("PATCH", f"/v1/hosts/{host}", json={"notes": ""})).json()[
        "notes"
    ] is None
    assert (await bob.request("PATCH", f"/v1/hosts/{host}", json={"notes": "x"})).status_code == 404

    r = await alice.request("GET", f"/v1/deliveries?host_id={host}")
    assert r.status_code == 200 and r.json() == []

    _push(tid, host, ["sentinel_cpu_usage_percent{} 12"])
    r = await alice.request("GET", f"/v1/hosts/{host}/forecast")
    assert r.status_code == 200, r.text
    f = r.json()
    assert f["series"] == []  # under a day of history: nothing is projected
    assert (await bob.request("GET", f"/v1/hosts/{host}/forecast")).status_code == 404
    token = access_token(str(uuid.uuid4()), "demo-support@example.com", superadmin=True)
    staff = await client.get(
        f"/admin/v1/hosts/{host}/forecast", headers={"Authorization": f"Bearer {token}"}
    )
    assert staff.status_code == 200 and staff.json()["series"] == []
