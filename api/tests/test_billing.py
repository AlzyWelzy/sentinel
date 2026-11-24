import hashlib
import hmac
import json
import time
from pathlib import Path

import pytest

from app.config import settings
from app.services import billing
from tests.conftest import User

HOOK_SECRET = "razorpay-test-webhook-secret"


def test_catalog_matches_ingest_copy():
    root = Path(__file__).resolve().parents[2]
    assert (root / "proto" / "plans.json").read_bytes() == billing.PATH.read_bytes()


def test_plan_lookup():
    assert billing.plan("pro")["limits"]["hosts"] == 50
    assert billing.plan("nope")["id"] == "free"
    assert billing.plan("grandfathered")["limits"]["hosts"] is None


@pytest.fixture
def billing_on(monkeypatch):
    monkeypatch.setattr(settings, "RAZORPAY_KEY_ID", "rzp_test_x")
    monkeypatch.setattr(settings, "RAZORPAY_KEY_SECRET", "secret")
    monkeypatch.setattr(settings, "RAZORPAY_WEBHOOK_SECRET", HOOK_SECRET)


async def page(user: User, slug: str):
    return await user.request("POST", "/v1/status-pages", json={"slug": slug, "title": slug})


async def test_no_limits_while_billing_is_off(alice: User):
    for i in range(3):
        assert (await page(alice, f"off-{alice.uid[:8]}-{i}")).status_code == 201
    assert (await alice.request("GET", "/v1/billing")).json()["enabled"] is False


async def test_free_plan_limit_and_webhook_upgrade(alice: User, client, billing_on):
    b = (await alice.request("GET", "/v1/billing")).json()
    assert b["enabled"] and b["plan"]["id"] == "free"
    assert (await page(alice, f"one-{alice.uid[:8]}")).status_code == 201
    over = await page(alice, f"two-{alice.uid[:8]}")
    assert over.status_code == 402 and "Free plan includes 1 status pages" in over.json()["detail"]

    tenant_id = (await alice.request("GET", "/v1/me/accounts")).json()[0]["tenant_id"]

    def hook(event: str, sub_id: str = "sub_1", created: int | None = None):
        body = json.dumps(
            {
                "event": event,
                "created_at": created or int(time.time()),
                "payload": {
                    "subscription": {
                        "entity": {
                            "id": sub_id,
                            "current_end": int(time.time()) + 30 * 86400,
                            "notes": {"tenant_id": tenant_id, "plan": "pro"},
                        }
                    }
                },
            }
        ).encode()
        sig = hmac.new(HOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        return body, {"x-razorpay-signature": sig, "content-type": "application/json"}

    body, headers = hook("subscription.activated")
    assert (
        await client.post(
            "/webhooks/razorpay", content=body, headers={**headers, "x-razorpay-signature": "bad"}
        )
    ).status_code == 401
    assert (
        await client.post("/webhooks/razorpay", content=body, headers=headers)
    ).status_code == 204
    b = (await alice.request("GET", "/v1/billing")).json()
    assert b["plan"]["id"] == "pro" and b["subscribed"] and b["renews_at"]
    assert (await page(alice, f"two-{alice.uid[:8]}")).status_code == 201

    body, headers = hook("subscription.cancelled", created=int(time.time()) + 1)
    assert (
        await client.post("/webhooks/razorpay", content=body, headers=headers)
    ).status_code == 204
    # A replay of the same event changes nothing a second time.
    assert (
        await client.post("/webhooks/razorpay", content=body, headers=headers)
    ).status_code == 204
    b = (await alice.request("GET", "/v1/billing")).json()
    assert b["plan"]["id"] == "free" and b["plan_status"] == "cancelled" and not b["subscribed"]


async def test_only_owner_subscribes(alice: User, billing_on):
    r = await alice.request("POST", "/v1/billing/subscribe", json={"plan": "pro"})
    # The owner gets past the role check; without RAZORPAY_PLAN_PRO it can't be bought.
    assert r.status_code == 409
