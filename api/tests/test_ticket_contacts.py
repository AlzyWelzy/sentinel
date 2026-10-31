"""Monitoring ticket recipients: the default email contact, others copied."""

from app.config import settings

from .conftest import User


def internal() -> dict:
    return {"X-Internal-Api-Key": settings.INTERNAL_API_KEY}


async def test_default_contact_first_others_copied(client, alice: User):
    await alice.tenant_id()
    path = f"/internal/v1/tenants/{alice.uid}/ticket-contacts"
    body = (await client.get(path, headers=internal())).json()
    assert body == {"to": alice.email.lower(), "cc": []}

    team = {"email": alice.email, "members": [{"email": "Ops@Example.com", "name": "Ops"}]}
    r = await client.put(
        f"/internal/v1/tenants/{alice.uid}/team-contacts", json=team, headers=internal()
    )
    assert r.status_code == 200, r.text
    # An address someone typed in but never confirmed gets no mail.
    unverified = {"type": "email", "target": "maybe@example.com", "label": "Maybe"}
    await alice.request("POST", "/v1/channels", json=unverified)

    body = (await client.get(path, headers=internal())).json()
    assert body["to"] == alice.email.lower()
    assert "ops@example.com" in body["cc"] and "maybe@example.com" not in body["cc"]


async def test_unknown_account_and_auth(client):
    path = "/internal/v1/tenants/nobody-here/ticket-contacts"
    assert (await client.get(path, headers=internal())).json() == {"to": None, "cc": []}
    assert (await client.get(path)).status_code in (401, 403)
