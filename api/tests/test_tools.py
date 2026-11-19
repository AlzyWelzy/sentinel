"""Search, bulk server changes, the agent doctor and install commands."""

from sqlalchemy import text

from app.db import ServiceSession

from .conftest import User, insert_host


async def test_search(alice: User, bob: User):
    tid = await alice.tenant_id()
    await insert_host(tid, "payments-db-1")
    await alice.request(
        "POST",
        "/v1/alert-rules",
        json={"name": "Payments down", "kind": "host_down", "duration_seconds": 120},
    )
    hits = (await alice.request("GET", "/v1/search", params={"q": "payments"})).json()
    assert {(h["kind"], h["title"]) for h in hits} >= {
        ("server", "payments-db-1"),
        ("rule", "Payments down"),
    }
    assert (await bob.request("GET", "/v1/search", params={"q": "payments"})).json() == []
    assert (await alice.request("GET", "/v1/search", params={"q": "p"})).status_code == 422


async def test_bulk(alice: User, bob: User):
    tid = await alice.tenant_id()
    a, b = await insert_host(tid, "a"), await insert_host(tid, "b")
    r = await alice.request(
        "POST",
        "/v1/hosts/bulk",
        json={"host_ids": [str(a), str(b)], "action": "add_tag", "tag": "Web"},
    )
    assert r.json() == {"action": "add_tag", "changed": 2}
    tags = {h["hostname"]: h["tags"] for h in (await alice.request("GET", "/v1/hosts")).json()}
    assert tags["a"] == ["web"] and tags["b"] == ["web"]
    muted = await alice.request(
        "POST", "/v1/hosts/bulk", json={"host_ids": [str(a)], "action": "mute", "minutes": 60}
    )
    assert muted.status_code == 200
    assert any(
        w["name"] == "Muted a" for w in (await alice.request("GET", "/v1/maintenance")).json()
    )
    # Bob can't touch Alice's servers.
    theirs = await bob.request(
        "POST", "/v1/hosts/bulk", json={"host_ids": [str(a)], "action": "delete"}
    )
    assert theirs.status_code == 404
    gone = await alice.request(
        "POST", "/v1/hosts/bulk", json={"host_ids": [str(b)], "action": "delete"}
    )
    assert gone.json()["changed"] == 1
    assert [h["hostname"] for h in (await alice.request("GET", "/v1/hosts")).json()] == ["a"]


async def test_doctor(alice: User):
    tid = await alice.tenant_id()
    host = await insert_host(tid, "quiet-1")
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text("UPDATE hosts SET agent_version = '0.0.9' WHERE id = :h"), {"h": host}
        )
        # Other tests move the rollout; this one needs 0.0.9 to be behind.
        await db.execute(
            text(
                "UPDATE agent_rollout SET stable_version = '1.0.0', candidate_version = NULL, "
                "candidate_percent = 0"
            )
        )
    r = await alice.request("GET", f"/v1/hosts/{host}/doctor")
    assert r.status_code == 200, r.text
    d = r.json()
    assert not d["healthy"]
    assert d["findings"][0]["title"] == "Never reported" and d["findings"][0]["fix"]
    assert any("offered" in f["title"] for f in d["findings"])


async def test_install_commands_include_docker(alice: User):
    key = (
        await alice.request("POST", "/v1/agent-keys", json={"name": "k", "tags": ["web"]})
    ).json()
    assert (
        "SENTINEL_TAGS=web" in key["docker_command"] and "sentinel-agent" in key["docker_command"]
    )
    assert "--tags web" in key["install_command"]
