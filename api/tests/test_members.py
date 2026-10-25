"""Team members: sharing an account with viewer, operator and admin roles."""

from datetime import UTC, datetime, timedelta

from .conftest import User, _new_user, insert_host

CPU_RULE = {
    "name": "High CPU",
    "kind": "metric",
    "metric": "cpu",
    "operator": ">",
    "threshold": 90,
    "duration_seconds": 300,
}


def window(host: str) -> dict:
    now = datetime.now(UTC)
    return {
        "name": "upgrade",
        "host_id": host,
        "schedule": "once",
        "starts_at": now.isoformat(),
        "ends_at": (now + timedelta(hours=1)).isoformat(),
    }


def acting_for(user: User, tenant_id) -> dict:
    return {**user.headers, "X-Pulsegrid-Account": str(tenant_id)}


async def invite(owner: User, email: str, role: str) -> dict:
    r = await owner.request("POST", "/v1/members", json={"email": email.upper(), "role": role})
    assert r.status_code == 201, r.text
    return r.json()


async def test_roles(client, alice: User, bob: User):
    tid = await alice.tenant_id()
    host = str(await insert_host(tid, "shared-web"))
    member = await invite(alice, bob.email, "viewer")
    assert member["email"] == bob.email and not member["joined"]

    as_bob = acting_for(bob, tid)
    # Viewer: reads the shared account, changes nothing.
    hosts = await client.get("/v1/hosts", headers=as_bob)
    assert [h["hostname"] for h in hosts.json()] == ["shared-web"]
    assert (await client.get("/v1/me", headers=as_bob)).json()["role"] == "viewer"
    r = await client.post("/v1/maintenance", json=window(host), headers=as_bob)
    assert r.status_code == 403 and "viewer" in r.json()["detail"]
    # Bob's own account is untouched.
    assert (await bob.request("GET", "/v1/hosts")).json() == []
    assert (await bob.request("GET", "/v1/me")).json()["role"] == "owner"

    # Operator: maintenance yes, rules no.
    await alice.request("PATCH", f"/v1/members/{member['id']}", json={"role": "operator"})
    r = await client.post("/v1/maintenance", json=window(host), headers=as_bob)
    assert r.status_code == 201, r.text
    r = await client.post("/v1/alert-rules", json=CPU_RULE, headers=as_bob)
    assert r.status_code == 403

    # Admin: rules yes; members and API tokens stay with the owner.
    await alice.request("PATCH", f"/v1/members/{member['id']}", json={"role": "admin"})
    r = await client.post("/v1/alert-rules", json=CPU_RULE, headers=as_bob)
    assert r.status_code == 201, r.text
    for method, path, body in [
        ("GET", "/v1/members", None),
        ("POST", "/v1/members", {"email": "x@example.com"}),
        ("GET", "/v1/api-tokens", None),
        ("POST", "/v1/api-tokens", {"name": "t"}),
    ]:
        r = await client.request(method, path, json=body, headers=as_bob)
        assert r.status_code == 403, (method, path)

    listed = (await alice.request("GET", "/v1/members")).json()
    assert listed[0]["joined"] and listed[0]["role"] == "admin"
    accounts = (await bob.request("GET", "/v1/me/accounts")).json()
    assert [(a["tenant_id"], a["role"]) for a in accounts] == [(str(tid), "admin")]

    # Removed: the shared account is gone.
    assert (await alice.request("DELETE", f"/v1/members/{member['id']}")).status_code == 204
    assert (await client.get("/v1/hosts", headers=as_bob)).status_code == 403
    assert (await bob.request("GET", "/v1/me/accounts")).json() == []


async def test_strangers_and_claimed_invites(client, alice: User, bob: User):
    tid = await alice.tenant_id()
    carol = _new_user(client, "carol")
    assert (await client.get("/v1/hosts", headers=acting_for(carol, tid))).status_code == 403
    assert (await client.get("/v1/hosts", headers=acting_for(bob, "nope"))).status_code == 400

    await invite(alice, bob.email, "viewer")
    assert (await client.get("/v1/hosts", headers=acting_for(bob, tid))).status_code == 200
    # Claimed by bob's console account: another account later given the same
    # email doesn't inherit it.
    impostor = User(client, "another-uid", bob.email)
    assert (await client.get("/v1/hosts", headers=acting_for(impostor, tid))).status_code == 403


async def test_invites_are_validated(alice: User, bob: User):
    assert (
        await alice.request("POST", "/v1/members", json={"email": alice.email})
    ).status_code == 400
    assert (
        await alice.request("POST", "/v1/members", json={"email": "not-an-email"})
    ).status_code == 422
    await invite(alice, bob.email, "viewer")
    again = await alice.request("POST", "/v1/members", json={"email": bob.email})
    assert again.status_code == 409
    # Bob can't see or touch Alice's member list from his own account.
    assert (await bob.request("GET", "/v1/members")).json() == []
