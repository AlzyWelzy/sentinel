import base64
import hashlib
import hmac
import json
import time

import pytest

from app.config import settings
from app.routes.webhooks import undeliverable_reason, verify_svix
from tests.conftest import User

SECRET = "whsec_" + base64.b64encode(b"sentinel-test-secret-32-bytes!!!").decode()


def signed(body: bytes, ts: int | None = None, msg_id: str = "msg_1") -> dict[str, str]:
    ts = ts or int(time.time())
    key = base64.b64decode(SECRET.removeprefix("whsec_"))
    sig = base64.b64encode(
        hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()
    ).decode()
    return {
        "svix-id": msg_id,
        "svix-timestamp": str(ts),
        "svix-signature": f"v1,AAAA v1,{sig}",
        "content-type": "application/json",
    }


def test_signature_checks():
    body = b'{"type":"email.bounced"}'
    assert verify_svix(SECRET, signed(body), body)
    assert not verify_svix(SECRET, signed(body), body + b" ")
    assert not verify_svix(SECRET, signed(body, ts=int(time.time()) - 3600), body)
    assert not verify_svix("", signed(body), body)


def test_which_reports_count():
    assert undeliverable_reason({"type": "email.complained"})
    assert undeliverable_reason(
        {"type": "email.bounced", "data": {"bounce": {"type": "Permanent"}}}
    )
    assert (
        undeliverable_reason({"type": "email.bounced", "data": {"bounce": {"type": "Transient"}}})
        is None
    )
    assert undeliverable_reason({"type": "email.delivered"}) is None


@pytest.fixture
def webhook_secret(monkeypatch):
    monkeypatch.setattr(settings, "RESEND_WEBHOOK_SECRET", SECRET)


async def test_bounce_marks_contact_undeliverable(alice: User, client, webhook_secret):
    default = (await alice.request("GET", "/v1/channels")).json()[0]
    assert default["type"] == "email" and not default["undeliverable"]
    event = {
        "type": "email.bounced",
        "data": {
            "to": [default["target"].upper()],
            "bounce": {"type": "Permanent", "message": "mailbox does not exist"},
        },
    }
    body = json.dumps(event).encode()

    bad = signed(body)
    bad["svix-signature"] = "v1,bm9wZQ=="
    assert (await client.post("/webhooks/resend", content=body, headers=bad)).status_code == 401

    assert (
        await client.post("/webhooks/resend", content=body, headers=signed(body))
    ).status_code == 204
    after = next(
        c for c in (await alice.request("GET", "/v1/channels")).json() if c["id"] == default["id"]
    )
    assert after["undeliverable"]
    assert "mailbox does not exist" in after["undeliverable_reason"]


async def test_off_without_secret(client):
    assert (await client.post("/webhooks/resend", content=b"{}")).status_code == 404
