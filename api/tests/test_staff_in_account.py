"""Console staff working inside a customer's account (X-Pulsegrid-Account)."""

import uuid

from .conftest import User, console_token, insert_host


def _headers(tenant_id, role="admin", **extra) -> dict:
    token = console_token(str(uuid.uuid4()), "support@example.com", role=role, **extra)
    return {"Authorization": f"Bearer {token}", "X-Pulsegrid-Account": str(tenant_id)}


async def test_staff_can_read_and_change_any_account(client, alice: User):
    tid = await alice.tenant_id()
    await insert_host(tid, "alice-web")
    h = _headers(tid)
    me = (await client.get("/v1/me", headers=h)).json()
    assert me["tenant_id"] == str(tid) and me["role"] == "staff"
    assert [x["hostname"] for x in (await client.get("/v1/hosts", headers=h)).json()] == [
        "alice-web"
    ]
    # Owner-only areas too: team and API tokens.
    assert (await client.get("/v1/members", headers=h)).status_code == 200
    r = await client.post("/v1/agent-keys", json={"name": "for alice"}, headers=h)
    assert r.status_code == 201
    # It's in Alice's account, and her audit log says staff did it.
    keys = (await alice.request("GET", "/v1/agent-keys")).json()
    assert [k["name"] for k in keys] == ["for alice"]
    entry = (await alice.request("GET", "/v1/audit-log")).json()[0]
    assert entry["actor"] == "support@example.com" and entry["actor_kind"] == "staff"


async def test_customers_and_view_as_sessions_cannot(client, alice: User, bob: User):
    tid = await alice.tenant_id()
    await bob.tenant_id()
    # A customer naming someone else's account is refused.
    bob_headers = {**bob.headers, "X-Pulsegrid-Account": str(tid)}
    assert (await client.get("/v1/hosts", headers=bob_headers)).status_code == 403
    # Unknown staff-like roles are not staff.
    assert (await client.get("/v1/hosts", headers=_headers(tid, role="sales"))).status_code == 403
    # A read-only view-as-customer session can't use it to write.
    r = await client.post(
        "/v1/agent-keys", json={"name": "x"}, headers=_headers(tid, imp="staff-uid")
    )
    assert r.status_code == 403


async def test_unknown_account_is_404(client):
    r = await client.get("/v1/hosts", headers=_headers(uuid.uuid4()))
    assert r.status_code == 404
