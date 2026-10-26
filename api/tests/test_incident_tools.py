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
                        "INSERT INTO incidents (tenant_id, host_id, summary, rule_name, hostname, severity) "
                        "VALUES (:t, :h, :s, 'r', 'web-1', :sev) RETURNING id"
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
    assert log[0]["kind"] == "test" and log[0]["subject"] == "[Pulsegrid] TEST: Server down"
    missing = await alice.request("POST", f"/v1/alert-rules/{uuid.uuid4()}/test")
    assert missing.status_code == 404
