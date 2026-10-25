import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.db import ServiceSession
from app.services.insights import host_verdict, rule_advice, slo_numbers

from .conftest import User, insert_host


def test_rule_advice():
    assert rule_advice(0, 0, 0, 30) is None
    assert "recovery threshold" in rule_advice(6, 3, 0, 30)
    assert "raise the duration" in rule_advice(6, 0, 4, 30)
    assert "several times a day" in rule_advice(120, 0, 0, 30)
    assert rule_advice(2, 0, 0, 30) is None


def test_host_verdict():
    assert host_verdict(None, 50, 4, 8 * 1024**3)[0] == "unknown"
    verdict, advice = host_verdict(9, 30, 8, 16 * 1024**3)
    assert verdict == "oversized" and "4 vCPU" in advice and "8 GB" in advice
    assert host_verdict(95, 40, 2, 4 * 1024**3)[0] == "undersized"
    assert "memory" in host_verdict(50, 97, 2, 4 * 1024**3)[1]
    assert host_verdict(50, 60, 2, 4 * 1024**3) == ("ok", None)
    assert host_verdict(5, 10, 1, 1024**3)[0] == "ok"  # nothing smaller to move to


def test_slo_numbers():
    budget, used, left, burn, status = slo_numbers(99.9, 99.95, 30, 100)
    assert round(budget, 1) == 43.2 and round(used, 1) == 21.6 and round(left) == 50
    assert burn == 0 and status == "healthy"
    assert slo_numbers(99.9, 99.8, 30, None)[4] == "breached"
    assert slo_numbers(99.9, 99.99, 30, 99.0)[4] == "at_risk"  # burning 10x right now
    assert slo_numbers(99.9, None, 30, None)[4] == "unknown"


async def _incident(tid, host, rule_name, opened, resolved=None, flapping=False, acked=None):
    async with ServiceSession() as db, db.begin():
        return (
            await db.execute(
                text(
                    "INSERT INTO incidents (id, tenant_id, host_id, status, summary, rule_name, "
                    "hostname, opened_at, resolved_at, acknowledged_at, flapping, severity) "
                    "VALUES (:id, :t, :h, :s, :sum, :r, 'web-1', :o, :res, :a, :f, 'critical') "
                    "RETURNING id"
                ),
                {
                    "id": uuid.uuid4(),
                    "t": tid,
                    "h": host,
                    "s": "resolved" if resolved else "open",
                    "sum": f"{rule_name} on web-1",
                    "r": rule_name,
                    "o": opened,
                    "res": resolved,
                    "a": acked,
                    "f": flapping,
                },
            )
        ).scalar_one()


async def test_insights_endpoint(alice: User, bob: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "web-1")
    now = datetime.now(UTC)
    for i in range(4):  # short spikes that cleared themselves
        o = now - timedelta(hours=i + 1)
        await _incident(tid, host, "CPU high", o, resolved=o + timedelta(minutes=2))
    o = now - timedelta(hours=10)
    await _incident(
        tid, host, "Disk full", o, resolved=o + timedelta(hours=1), acked=o + timedelta(minutes=4)
    )
    r = await alice.request("GET", "/v1/insights", params={"days": 7})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["incidents"] == 5 and data["self_resolved_quickly"] == 4
    cpu = next(x for x in data["rules"] if x["rule_name"] == "CPU high")
    assert cpu["incidents"] == 4 and "raise the duration" in cpu["advice"]
    assert round(data["mtta_seconds"]) == 240
    assert [h["hostname"] for h in data["hosts"]] == ["web-1"]
    # Another tenant sees none of it.
    assert (await bob.request("GET", "/v1/insights")).json()["incidents"] == 0


async def test_snooze_and_postmortem(alice: User, bob: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "web-1")
    inc = await _incident(tid, host, "Nginx down", datetime.now(UTC) - timedelta(minutes=30))
    r = await alice.request(
        "POST", f"/v1/incidents/{inc}/snooze", json={"minutes": 60, "reason": "deploying a fix"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["snoozed_until"] and body["status"] == "open"
    assert body["events"][-1]["message"] == "Snoozed for 1 hour: deploying a fix"
    assert (
        await bob.request("POST", f"/v1/incidents/{inc}/snooze", json={"minutes": 60})
    ).status_code == 404
    await alice.request("POST", f"/v1/incidents/{inc}/notes", json={"message": "nginx OOM-killed"})
    r = await alice.request("DELETE", f"/v1/incidents/{inc}/snooze")
    assert r.json()["snoozed_until"] is None
    await alice.request("POST", f"/v1/incidents/{inc}/resolve", json={"message": "raised memory"})
    r = await alice.request("POST", f"/v1/incidents/{inc}/snooze", json={"minutes": 60})
    assert r.status_code == 409
    md = (await alice.request("GET", f"/v1/incidents/{inc}/postmortem")).text
    assert md.startswith("# Postmortem: Nginx down on web-1")
    for part in ("| Server | web-1 |", "Snoozed for 1 hour", "nginx OOM-killed", "## Action items"):
        assert part in md, part


async def test_check_slo_target(alice: User):
    body = {"name": "site", "type": "http", "target": "https://example.com", "on_probes": True}
    r = await alice.request("POST", "/v1/checks", json={**body, "slo_target": 99.5})
    assert r.status_code == 201, r.text
    assert r.json()["slo_target"] == 99.5
    r = await alice.request("POST", "/v1/checks", json={**body, "name": "x", "slo_target": 100})
    assert r.status_code == 422
    log = {"name": "errors", "type": "log", "target": "/var/log/app.log", "tag": "web"}
    r = await alice.request("POST", "/v1/checks", json={**log, "params": {"pattern": "ERROR"}})
    assert r.status_code == 201, r.text
    slos = (await alice.request("GET", "/v1/insights")).json()["slos"]
    assert [x["name"] for x in slos] == ["site"]  # log checks aren't availability
    slo = slos[0]
    assert slo["target"] == 99.5 and round(slo["budget_minutes"]) == 216
