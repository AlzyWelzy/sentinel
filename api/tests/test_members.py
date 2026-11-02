"""Organisation members: invitations, and the viewer, operator and admin roles."""

import re
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.db import ServiceSession

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


async def emailed_token(email: str, kind: str = "invitation") -> str:
    """The token in the newest email of that kind, as the recipient would click it."""
    async with ServiceSession() as db:
        body = await db.scalar(
            text(
                "SELECT payload->>'text' FROM account_emails WHERE to_address = :e AND kind = :k "
                "ORDER BY created_at DESC LIMIT 1"
            ),
            {"e": email.lower(), "k": kind},
        )
    match = re.search(r"token=([A-Za-z0-9_%-]+)", body or "")
    assert match, body
    return match.group(1)


async def join(owner: User, member: User, role: str) -> dict:
    m = await invite(owner, member.email, role)
    r = await member.request(
        "POST", f"/auth/invitations/{await emailed_token(member.email)}/accept"
    )
    assert r.status_code == 200, r.text
    return m


async def test_roles(client, alice: User, bob: User):
    tid = await alice.tenant_id()
    await bob.tenant_id()  # bob signed up on his own first
    host = str(await insert_host(tid, "shared-web"))
    member = await invite(alice, bob.email, "viewer")
    assert member["email"] == bob.email and not member["joined"]
    as_bob = acting_for(bob, tid)
    # Invited isn't joined: nothing until the invitation is accepted.
    assert (await bob.request("GET", "/v1/hosts", headers=as_bob)).status_code == 403
    token = await emailed_token(bob.email)
    preview = (await bob.request("GET", f"/auth/invitations/{token}")).json()
    assert preview["role"] == "read-only" and preview["email"] == bob.email
    accepted = await bob.request("POST", f"/auth/invitations/{token}/accept")
    assert accepted.json() == {"tenant_id": str(tid), "role": "viewer"}
    # Single use.
    assert (await bob.request("POST", f"/auth/invitations/{token}/accept")).status_code == 404

    # Viewer: reads the shared account, changes nothing.
    hosts = await client.get("/v1/hosts", headers=as_bob)
    assert [h["hostname"] for h in hosts.json()] == ["shared-web"]
    assert (await client.get("/v1/me", headers=as_bob)).json()["role"] == "viewer"
    r = await client.post("/v1/maintenance", json=window(host), headers=as_bob)
    assert r.status_code == 403 and "read-only" in r.json()["detail"]
    # Bob's own account is untouched.
    assert (await bob.request("GET", "/v1/hosts")).json() == []
    assert (await bob.request("GET", "/v1/me")).json()["role"] == "owner"

    # Operator: maintenance yes, rules no.
    await alice.request("PATCH", f"/v1/members/{member['id']}", json={"role": "operator"})
    r = await client.post("/v1/maintenance", json=window(host), headers=as_bob)
    assert r.status_code == 201, r.text
    r = await client.post("/v1/alert-rules", json=CPU_RULE, headers=as_bob)
    assert r.status_code == 403

    # Admin: rules and members yes; API tokens and deleting the
    # organisation stay with the owner.
    await alice.request("PATCH", f"/v1/members/{member['id']}", json={"role": "admin"})
    r = await client.post("/v1/alert-rules", json=CPU_RULE, headers=as_bob)
    assert r.status_code == 201, r.text
    assert (await client.get("/v1/members", headers=as_bob)).status_code == 200
    for method, path, body in [
        ("GET", "/v1/api-tokens", None),
        ("POST", "/v1/api-tokens", {"name": "t"}),
        ("POST", "/v1/organisation/delete", {"confirm_name": "x"}),
    ]:
        r = await client.request(method, path, json=body, headers=as_bob)
        assert r.status_code == 403, (method, path)
    # Nobody but the owner touches the owner's row.
    owner_row = next(
        m for m in (await alice.request("GET", "/v1/members")).json() if m["role"] == "owner"
    )
    r = await client.patch(
        f"/v1/members/{owner_row['id']}", json={"role": "viewer"}, headers=as_bob
    )
    assert r.status_code == 400

    listed = (await alice.request("GET", "/v1/members")).json()
    assert [(m["role"], m["joined"]) for m in listed] == [("owner", True), ("admin", True)]
    # Bob's email became one of the organisation's contacts.
    contacts = (await alice.request("GET", "/v1/channels")).json()
    assert any(c["target"] == bob.email and c["source"] == "team" for c in contacts)
    accounts = (await bob.request("GET", "/v1/me/accounts")).json()
    assert [(a["tenant_id"], a["role"]) for a in accounts] == [
        (str(await bob.tenant_id()), "owner"),
        (str(tid), "admin"),
    ]

    # Removed: the shared organisation is gone, and so is the contact.
    assert (await alice.request("DELETE", f"/v1/members/{member['id']}")).status_code == 204
    assert (await client.get("/v1/hosts", headers=as_bob)).status_code == 403
    assert [a["role"] for a in (await bob.request("GET", "/v1/me/accounts")).json()] == ["owner"]
    contacts = (await alice.request("GET", "/v1/channels")).json()
    assert not any(c["target"] == bob.email for c in contacts)


async def test_strangers_and_invitations_for_someone_else(client, alice: User, bob: User):
    tid = await alice.tenant_id()
    carol = _new_user(client, "carol")
    assert (
        await carol.request("GET", "/v1/hosts", headers=acting_for(carol, tid))
    ).status_code == 403
    assert (
        await bob.request("GET", "/v1/hosts", headers=acting_for(bob, "nope"))
    ).status_code == 400

    await invite(alice, bob.email, "viewer")
    token = await emailed_token(bob.email)
    # Carol has the link but isn't bob: refused, and the invitation still works.
    assert (await carol.request("POST", f"/auth/invitations/{token}/accept")).status_code == 403
    assert (await bob.request("POST", f"/auth/invitations/{token}/accept")).status_code == 200
    assert (await bob.request("GET", "/v1/hosts", headers=acting_for(bob, tid))).status_code == 200
    # A later user with the same email (impossible through sign-up, emails
    # are unique) wouldn't inherit it: membership is by user id.
    impostor = User(client, str(uuid.uuid4()), f"x-{bob.email}")
    assert (
        await impostor.request("GET", "/v1/hosts", headers=acting_for(impostor, tid))
    ).status_code == 403


async def test_members_can_leave_and_create_their_own(client, alice: User, bob: User):
    tid = await alice.tenant_id()
    member = await join(alice, bob, "viewer")
    as_bob = acting_for(bob, tid)
    # A viewer can't remove others, but can leave.
    owner_row = next(
        m for m in (await alice.request("GET", "/v1/members")).json() if m["role"] == "owner"
    )
    assert (
        await bob.request("DELETE", f"/v1/members/{owner_row['id']}", headers=as_bob)
    ).status_code == 400
    assert (
        await bob.request("DELETE", f"/v1/members/{member['id']}", headers=as_bob)
    ).status_code == 204
    # Another organisation of bob's own.
    r = await bob.request("POST", "/v1/organisations", json={"name": "Bob Labs"})
    assert r.status_code == 201 and r.json()["role"] == "owner"
    new = r.json()["tenant_id"]
    me = (await bob.request("GET", "/v1/me", headers=acting_for(bob, new))).json()
    assert me["tenant_id"] == new and me["display_name"] == "Bob Labs"
    renamed = await bob.request(
        "PATCH", "/v1/organisation", json={"name": "Bob Labs Inc"}, headers=acting_for(bob, new)
    )
    assert renamed.json()["name"] == "Bob Labs Inc"
    # Deleting needs the name typed.
    bad = await bob.request(
        "POST", "/v1/organisation/delete", json={"confirm_name": "x"}, headers=acting_for(bob, new)
    )
    assert bad.status_code == 400


async def test_invites_are_validated(alice: User, bob: User):
    assert (
        await alice.request("POST", "/v1/members", json={"email": alice.email})
    ).status_code == 409
    assert (
        await alice.request("POST", "/v1/members", json={"email": "not-an-email"})
    ).status_code == 422
    await invite(alice, bob.email, "viewer")
    again = await alice.request("POST", "/v1/members", json={"email": bob.email})
    assert again.status_code == 409
    # Bob can't see or touch Alice's member list from his own account.
    assert [m["role"] for m in (await bob.request("GET", "/v1/members")).json()] == ["owner"]


async def test_an_invited_user_without_an_organisation_lands_in_the_shared_one(alice: User, bob):
    """Signing up from an invitation: no empty organisation of their own."""
    tid = await alice.tenant_id()
    await join(alice, bob, "operator")
    me = (await bob.request("GET", "/v1/me")).json()
    assert me["tenant_id"] == str(tid) and me["role"] == "operator"
