"""Fleet overview (status counts, latest CPU/memory/disk) and disk forecasts."""

import time

from sqlalchemy import text

from app.db import ServiceSession
from app.services.heartbeats import redis

from .conftest import User, insert_host
from .test_monitoring_depth import _push, needs_vm


@needs_vm
async def test_overview_and_disks(alice: User, bob: User):
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
            "pulsegrid_cpu_usage_percent{} 91.2",
            "pulsegrid_memory_used_percent{} 70",
            'pulsegrid_disk_used_percent{mountpoint="/",device="/dev/sda1"} 82',
            'pulsegrid_disk_used_percent{mountpoint="/data",device="/dev/sdb1"} 40',
            'pulsegrid_disk_free_bytes{mountpoint="/",device="/dev/sda1"} 18000000000',
            'pulsegrid_disk_total_bytes{mountpoint="/",device="/dev/sda1",fstype="ext4"} 1e11',
            'pulsegrid_disk_used_bytes{mountpoint="/",device="/dev/sda1"} 82000000000',
            'pulsegrid_load{period="1m"} 3.5',
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
    assert body["counts"] == {"down": 1, "critical": 1, "warning": 0, "maintenance": 0, "up": 1}
    assert (await bob.request("GET", "/v1/servers/overview")).json()["servers"] == []

    disks = (await alice.request("GET", f"/v1/hosts/{busy}/disks")).json()
    root = next(d for d in disks if d["mountpoint"] == "/")
    assert root["fstype"] == "ext4" and root["total_bytes"] == 1e11 and root["used_percent"] == 82
    data = next(d for d in disks if d["mountpoint"] == "/data")
    assert data["total_bytes"] is None  # no free/total reported for it
    assert (await bob.request("GET", f"/v1/hosts/{busy}/disks")).status_code == 404
