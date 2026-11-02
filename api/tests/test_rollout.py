"""Agent rollouts: stable, a canary share, pins, promotion, rollback and the
health gate."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.config import settings
from app.db import ServiceSession
from app.services import heartbeats, rollout

from .conftest import User, access_token, insert_host


def test_bucket_matches_ingest():
    # The same fixtures as ingest/rollout_test.go.
    assert rollout.bucket("00000000-0000-0000-0000-000000000000") == 57
    assert rollout.bucket("6806cca1-0006-4afb-9288-c5cfc2a1c30b") == 47
    assert rollout.bucket("ABC") == rollout.bucket("abc")


def test_version_for():
    r = rollout.Rollout(stable_version="1.0.0", candidate_version="1.1.0", candidate_percent=48)
    assert rollout.version_for(r, "6806cca1-0006-4afb-9288-c5cfc2a1c30b", None) == "1.1.0"
    assert rollout.version_for(r, "00000000-0000-0000-0000-000000000000", None) == "1.0.0"
    assert rollout.version_for(r, "00000000-0000-0000-0000-000000000000", "0.9.0") == "0.9.0"


async def _reset() -> None:
    # The service role may read and update the rollout, not delete it: reset
    # it to "no candidate" (a test may create the row on first use).
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "UPDATE agent_rollout SET stable_version = '0.0.1', candidate_version = NULL, "
                "candidate_percent = 0, candidate_since = NULL, rolled_back_version = NULL"
            )
        )
        await db.execute(text("UPDATE tenants SET agent_version_pin = NULL"))


@pytest.fixture
async def clean_rollout():
    await _reset()
    yield
    await _reset()


async def test_adopt_release(clean_rollout, monkeypatch):
    monkeypatch.setattr(settings, "AGENT_VERSION", "1.0.0")
    async with ServiceSession() as db, db.begin():
        first = await rollout.adopt_release(db)
        # A fresh database adopts it as stable; after the reset (0.0.1 stable)
        # it's the canary.
        assert first in ("stable 1.0.0", "candidate 1.0.0 at 10%")
        r = await rollout.current(db)
        r.stable_version, r.candidate_version, r.candidate_percent = "1.0.0", None, 0
        await rollout.save(db, r, "test")
        assert await rollout.adopt_release(db) is None
    monkeypatch.setattr(settings, "AGENT_VERSION", "1.1.0")
    monkeypatch.setattr(settings, "AGENT_CANARY_PERCENT", 10)
    async with ServiceSession() as db, db.begin():
        assert await rollout.adopt_release(db) == "candidate 1.1.0 at 10%"
        r = await rollout.current(db)
    assert (r.stable_version, r.candidate_version, r.candidate_percent) == ("1.0.0", "1.1.0", 10)
    # A rolled-back candidate isn't offered again by the same deploy.
    async with ServiceSession() as db, db.begin():
        r.rolled_back_version, r.candidate_version, r.candidate_percent = "1.1.0", None, 0
        await rollout.save(db, r, "test")
        assert await rollout.adopt_release(db) is None


def staff_headers() -> dict:
    token = access_token(str(uuid.uuid4()), "ops@example.com", superadmin=True)
    return {"Authorization": f"Bearer {token}"}


async def test_staff_rollout_api(clean_rollout, client, alice: User):
    h = staff_headers()
    r = await client.put(
        "/admin/v1/agent-rollout",
        headers=h,
        json={"stable_version": "1.0.0", "candidate_version": "1.1.0", "candidate_percent": 25},
    )
    assert r.status_code == 200, r.text
    assert r.json()["updated_by"] == "ops@example.com"
    bad = await client.put(
        "/admin/v1/agent-rollout",
        headers=h,
        json={"stable_version": "1.0.0", "candidate_percent": 5},
    )
    assert bad.status_code == 422
    promoted = (await client.post("/admin/v1/agent-rollout/promote", headers=h)).json()
    assert (promoted["stable_version"], promoted["candidate_version"]) == ("1.1.0", None)
    assert (await client.post("/admin/v1/agent-rollout/rollback", headers=h)).status_code == 409

    tid = await alice.tenant_id()
    pin = await client.put(
        f"/admin/v1/tenants/{tid}/agent-pin", headers=h, json={"version": "1.0.0"}
    )
    assert pin.json()["version"] == "1.0.0"
    pins = (await client.get("/admin/v1/agent-rollout", headers=h)).json()["pins"]
    assert [p["tenant_id"] for p in pins] == [str(tid)]
    # Customers can't touch the rollout.
    assert (await alice.request("GET", "/admin/v1/agent-rollout")).status_code in (401, 403)


async def test_health_gate_rolls_back_a_silent_canary(clean_rollout, alice: User, monkeypatch):
    tid = await alice.tenant_id()
    hosts = [await insert_host(tid, f"gate-{i}") for i in range(12)]
    since = datetime.now(UTC) - timedelta(hours=2)
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text("UPDATE hosts SET last_seen_at = now() WHERE tenant_id = :t"), {"t": tid}
        )
        await rollout.save(
            db,
            rollout.Rollout(
                stable_version="1.0.0",
                candidate_version="1.1.0",
                candidate_percent=50,
                candidate_since=since,
            ),
            "test",
        )
    now = datetime.now(UTC)
    canary = {h for h in hosts if rollout.bucket(h) < 50}
    assert len(canary) >= 2 and len(canary) < len(hosts)

    async def seen(ids):
        # Every server offered the canary stopped reporting (other tests'
        # servers too: the gate looks at every account); the rest are fine.
        return {h: (None if rollout.bucket(h) < 50 else int(now.timestamp())) for h in ids}

    monkeypatch.setattr(heartbeats, "last_seen", seen)
    async with ServiceSession() as db, db.begin():
        reason = await rollout.health_gate(db, now)
        r = await rollout.current(db)
    assert reason and "rolled back automatically" in reason
    assert (r.candidate_version, r.rolled_back_version) == (None, "1.1.0")
