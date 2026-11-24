from tests.conftest import User


async def test_access_review_lists_people_and_tokens(alice: User):
    r = await alice.request("GET", "/v1/access-review")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["due"] is True and body["reviewed_at"] is None
    me = [m for m in body["members"] if m["email"] == alice.email]
    assert me and me[0]["role"] == "owner" and me[0]["two_factor"] is False

    assert (
        await alice.request("POST", "/v1/api-tokens", json={"name": "ci", "read_only": True})
    ).status_code == 201
    assert [
        t["name"] for t in (await alice.request("GET", "/v1/access-review")).json()["tokens"]
    ] == ["ci"]

    assert (await alice.request("POST", "/v1/access-review")).status_code == 204
    after = (await alice.request("GET", "/v1/access-review")).json()
    assert after["due"] is False and after["reviewed_by"]
    log = (await alice.request("GET", "/v1/audit-log")).json()
    entries = log if isinstance(log, list) else log.get("items", [])
    assert any(e.get("action") == "access.review" for e in entries)


async def test_only_owners_and_admins(alice: User, bob: User):
    tenant = await alice.tenant_id()
    invite = await alice.request("POST", "/v1/members", json={"email": bob.email, "role": "viewer"})
    assert invite.status_code == 201, invite.text
    accept = await bob.request("POST", f"/auth/invitations/pending/{invite.json()['id']}/accept")
    assert accept.status_code in (200, 204), accept.text
    r = await bob.request("GET", "/v1/access-review", headers={"X-Sentinel-Account": str(tenant)})
    assert r.status_code == 403
