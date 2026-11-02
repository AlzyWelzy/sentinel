"""A superadmin working inside a customer's organisation: only through an
impersonation, which is audited, time-limited and read-only by default."""

import uuid

from .conftest import User, impersonate, insert_host, superadmin_headers


async def test_impersonation_reads_and_with_writes_changes(client, alice: User):
    tid = await alice.tenant_id()
    await insert_host(tid, "alice-web")
    h = await impersonate(client, tid, writes=True)
    me = (await client.get("/v1/me", headers=h)).json()
    assert me["tenant_id"] == str(tid) and me["role"] == "staff" and me["impersonating"]
    assert [x["hostname"] for x in (await client.get("/v1/hosts", headers=h)).json()] == [
        "alice-web"
    ]
    assert (await client.get("/v1/members", headers=h)).status_code == 200
    r = await client.post("/v1/agent-keys", json={"name": "for alice"}, headers=h)
    assert r.status_code == 201
    keys = (await alice.request("GET", "/v1/agent-keys")).json()
    assert [k["name"] for k in keys] == ["for alice"]
    entry = (await alice.request("GET", "/v1/audit-log")).json()[0]
    assert entry["actor_kind"] == "staff"


async def test_ending_an_impersonation_takes_effect_at_once(client, alice: User):
    tid = await alice.tenant_id()
    admin = await superadmin_headers()
    r = await client.post(
        f"/admin/v1/tenants/{tid}/impersonate", headers=admin, json={"reason": "debugging alerts"}
    )
    imp = r.json()
    h = {"Authorization": f"Bearer {imp['access_token']}"}
    assert (await client.get("/v1/hosts", headers=h)).status_code == 200
    listed = (await client.get("/admin/v1/impersonations", headers=admin)).json()
    assert any(i["id"] == imp["id"] and i["reason"] == "debugging alerts" for i in listed)
    # The impersonation token itself can't reach the admin panel.
    end = f"/admin/v1/impersonations/{imp['id']}/end"
    assert (await client.post(end, headers=h)).status_code == 403
    assert (await client.post(end, headers=admin)).status_code == 204
    assert (await client.get("/v1/hosts", headers=h)).status_code == 401


async def test_customers_cannot_reach_other_organisations(client, alice: User, bob: User):
    tid = await alice.tenant_id()
    await bob.tenant_id()
    r = await bob.request("GET", "/v1/hosts", headers={"X-Sentinel-Account": str(tid)})
    assert r.status_code == 403
    r = await bob.request(
        "POST", f"/admin/v1/tenants/{tid}/impersonate", json={"reason": "let me in please"}
    )
    assert r.status_code == 403


async def test_impersonating_an_unknown_organisation_is_404(client):
    r = await client.post(
        f"/admin/v1/tenants/{uuid.uuid4()}/impersonate",
        headers=await superadmin_headers(),
        json={"reason": "no such organisation"},
    )
    assert r.status_code == 404
