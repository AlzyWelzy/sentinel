"""Merging related incidents, finding them, and test alerts for a rule."""

import uuid

from sqlalchemy import text

from app.db import ServiceSession

from .conftest import User, insert_host


async def _incident(tenant_id, host_id, summary, severity="warning") -> str:
    async with ServiceSession() as db, db.begin():
        return str(
            (
                await db.execute(
                    text(
                        "INSERT INTO incidents (tenant_id, host_id, summary, rule_name, "
                        "hostname, severity) VALUES (:t, :h, :s, 'r', 'web-1', :sev) RETURNING id"
                    ),
                    {"t": tenant_id, "h": host_id, "s": summary, "sev": severity},
                )
            ).scalar_one()
        )


async def test_merge_and_related(alice: User, bob: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "web-1")
    main = await _incident(tid, host, "web-1 is not reporting")
    disk = await _incident(tid, host, "Disk above 90% on web-1", severity="critical")
    cpu = await _incident(tid, host, "CPU above 90% on web-1")

    related = (await alice.request("GET", f"/v1/incidents/{main}/related")).json()
    assert {i["id"] for i in related} == {disk, cpu}

    r = await alice.request(
        "POST", "/v1/incidents/merge", json={"into": main, "incident_ids": [disk, cpu]}
    )
    assert r.status_code == 200, r.text
    merged = r.json()
    assert merged["severity"] == "critical"  # takes the worst of the merged
    assert merged["events"][-1]["kind"] == "merged"
    child = (await alice.request("GET", f"/v1/incidents/{disk}")).json()
    assert child["status"] == "resolved" and child["merged_into"] == main
    assert (await alice.request("GET", f"/v1/incidents/{main}/related")).json() == []
    # Can't merge into one that was merged away, nor someone else's.
    again = await alice.request(
        "POST", "/v1/incidents/merge", json={"into": disk, "incident_ids": [cpu]}
    )
    assert again.status_code == 409
    theirs = await bob.request(
        "POST", "/v1/incidents/merge", json={"into": main, "incident_ids": [cpu]}
    )
    assert theirs.status_code == 404


async def test_rule_test_alert(alice: User):
    rule = {"name": "Server down", "kind": "host_down", "duration_seconds": 120}
    created = (await alice.request("POST", "/v1/alert-rules", json=rule)).json()
    r = await alice.request("POST", f"/v1/alert-rules/{created['id']}/test")
    # The account's own console email is its verified default contact.
    assert r.status_code == 202, r.text
    assert r.json()["sent_to"][0]["why"] == "default contact"
    log = (await alice.request("GET", "/v1/deliveries")).json()
    assert log[0]["kind"] == "test" and log[0]["subject"] == "[Sentinel] TEST: Server down"
    missing = await alice.request("POST", f"/v1/alert-rules/{uuid.uuid4()}/test")
    assert missing.status_code == 404


async def test_digest(alice: User, monkeypatch):
    from datetime import UTC, datetime, timedelta

    from app import jobs
    from app.models import OutboundMessage, Tenant
    from app.services import digest, heartbeats

    async def nobody_seen(ids):
        return {}

    monkeypatch.setattr(heartbeats, "last_seen", nobody_seen)
    tid = await alice.tenant_id()
    host = await insert_host(tid, "web-1")
    await _incident(tid, host, "web-1 is not reporting", severity="critical")
    settings = await alice.request(
        "PUT",
        "/v1/reports/settings",
        json={
            "monthly_report": True,
            "digest": "daily",
            "digest_hour": 0,
            "digest_timezone": "UTC",
        },
    )
    assert settings.status_code == 200, settings.text
    assert (await alice.request("GET", "/v1/reports/settings")).json()["digest"] == "daily"

    now = datetime.now(UTC)
    async with ServiceSession() as db:
        d = await digest.build(db, tid, now - timedelta(days=1), now)
    assert (d.opened, d.critical, d.open_count) == (1, 1, 1)
    assert d.silent == ["web-1"] and not d.quiet
    assert "web-1 is not reporting" in digest.render_html(d, "Alice", "https://x")

    async with ServiceSession() as db:
        t = await db.get(Tenant, tid)
        assert t is not None
        # Brand new: nothing until it has a full day behind it.
        assert not jobs.digest_due(t, now)
    async with ServiceSession() as db, db.begin():
        t = await db.get(Tenant, tid)
        assert t is not None
        t.created_at = now - timedelta(days=2)
    async with ServiceSession() as db:
        t = await db.get(Tenant, tid)
        assert t is not None
        assert jobs.digest_due(t, now)
    await jobs.send_digests(now)
    async with ServiceSession() as db:
        rows = list(
            await db.scalars(
                __import__("sqlalchemy")
                .select(OutboundMessage)
                .where(OutboundMessage.tenant_id == tid, OutboundMessage.kind == "digest")
            )
        )
        t = await db.get(Tenant, tid)
    assert t is not None
    assert len(rows) == 1 and rows[0].payload["subject"].startswith(
        "[Sentinel] Your monitoring day"
    )
    assert not jobs.digest_due(t, now)  # once per slot


async def test_diagnosis_survives_later_failing_runs():
    import json as _json

    from app.services import checkresults
    from app.services.heartbeats import redis

    cid = uuid.uuid4()
    key = checkresults.CHECK_RESULT_KEY.format(check_id=cid)
    diag = {"summary": "DNS ok · TCP to 1.1.1.1:81 i/o timeout", "connect": []}
    await redis.hset(
        key,
        mapping={
            # The current run failed without a diagnosis (the agent made one
            # five minutes ago, kept under diag:).
            "probe:in-dc1": _json.dumps(
                {"ok": False, "detail": "timeout", "ts": 600_000, "region": "in-dc1"}
            ),
            "fail:probe:in-dc1": _json.dumps(
                {"ok": False, "detail": "timeout", "ts": 600_000, "region": "in-dc1"}
            ),
            "diag:probe:in-dc1": _json.dumps({"ts": 300_000, "diagnosis": diag}),
            "probe:in-dc2": _json.dumps({"ok": True, "ts": 600_000, "region": "in-dc2"}),
        },
    )
    try:
        latest = (await checkresults.latest([cid]))[cid]
        assert [r["region"] for r in latest] == ["in-dc1", "in-dc2"]  # diag: isn't a place
        assert latest[0]["diagnosis"] == diag and "diagnosis" not in latest[1]
        assert (await checkresults.last_failures([cid]))[cid]["diagnosis"] == diag
    finally:
        await redis.delete(key)


async def test_pausing_a_server_closes_its_incidents_and_resume_clears_it(alice: User):
    tenant = await alice.tenant_id()
    host = await insert_host(tenant, "paused-web")
    async with ServiceSession() as db, db.begin():
        incident = (
            await db.execute(
                text(
                    "INSERT INTO incidents (tenant_id, host_id, summary, rule_name, hostname) "
                    "VALUES (:t, :h, 'CPU high', 'CPU', 'paused-web') RETURNING id"
                ),
                {"t": tenant, "h": host},
            )
        ).scalar_one()

    paused = (await alice.request("POST", f"/v1/hosts/{host}/pause")).json()
    assert paused["paused"] is True and paused["paused_by"]
    detail = (await alice.request("GET", f"/v1/incidents/{incident}")).json()
    assert detail["status"] == "resolved"
    assert any("paused" in e["message"] for e in detail["events"])
    fleet = (await alice.request("GET", "/v1/servers/overview")).json()
    assert [s["status"] for s in fleet["servers"] if s["id"] == str(host)] == ["paused"]

    resumed = (await alice.request("POST", f"/v1/hosts/{host}/resume")).json()
    assert resumed["paused"] is False and resumed["paused_at"] is None

    body = {"host_ids": [str(host)], "action": "pause"}
    bulk = await alice.request("POST", "/v1/hosts/bulk", json=body)
    assert bulk.status_code == 200 and bulk.json()["changed"] == 1
    assert (await alice.request("GET", f"/v1/hosts/{host}")).json()["paused"] is True


async def test_an_incident_names_the_silent_hosts_behind_it(alice: User, bob: User):
    import time

    from app.services.heartbeats import redis

    tid = await alice.tenant_id()
    switch = await insert_host(tid, "tor-1")
    behind_a = await insert_host(tid, "web-a")
    behind_b = await insert_host(tid, "web-b")
    two_hops = await insert_host(tid, "vm-under-web-a")
    still_up = await insert_host(tid, "web-up")
    never_seen = await insert_host(tid, "web-new")
    async with ServiceSession() as db, db.begin():
        for h, up in (
            (behind_a, switch),
            (behind_b, switch),
            (still_up, switch),
            (never_seen, switch),
            (two_hops, behind_a),
        ):
            await db.execute(
                text("UPDATE hosts SET depends_on_host_id = :u WHERE id = :h"), {"u": up, "h": h}
            )
    old = int(time.time()) - 3600
    for h in (switch, behind_a, behind_b, two_hops):
        await redis.set(f"pg:last_seen:{h}", old)
    await redis.set(f"pg:last_seen:{still_up}", int(time.time()))
    incident = await _incident(tid, switch, "tor-1 is not reporting", severity="critical")

    detail = (await alice.request("GET", f"/v1/incidents/{incident}")).json()
    assert [a["hostname"] for a in detail["affected"]] == ["vm-under-web-a", "web-a", "web-b"]
    assert (await bob.request("GET", f"/v1/incidents/{incident}")).status_code == 404

    resolved = await alice.request("POST", f"/v1/incidents/{incident}/resolve")
    assert resolved.status_code == 200 and resolved.json()["affected"] == []


async def test_reminders_are_an_organisation_setting(alice: User):
    assert (await alice.request("GET", "/v1/organisation/alerting")).json() == {
        "reminder_minutes": 240
    }
    for bad in (5, 20000, -1):
        r = await alice.request("PUT", "/v1/organisation/alerting", json={"reminder_minutes": bad})
        assert r.status_code == 422, bad
    for good in (0, 30, 1440):
        r = await alice.request("PUT", "/v1/organisation/alerting", json={"reminder_minutes": good})
        assert r.status_code == 200 and r.json()["reminder_minutes"] == good
        # Saved, not just echoed.
        saved = await alice.request("GET", "/v1/organisation/alerting")
        assert saved.json()["reminder_minutes"] == good
