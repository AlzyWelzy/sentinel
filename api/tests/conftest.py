"""Tests run against the real Postgres and Redis from deploy/docker-compose.yml,
migrated to head. Tenant isolation lives in the database, so mocking it out
would test nothing.
"""

import os
import uuid

os.environ.update(
    ENVIRONMENT="testing",
    AUTH_SECRET="test-auth-secret-of-at-least-32-characters",
    COOKIE_SECURE="false",
    # Every contact type stays under test; the default enabled set is tested
    # by patching settings.
    ENABLED_CHANNEL_TYPES="email,sms,voice,webhook,slack,teams,discord,telegram,pagerduty,push",
    VAPID_PUBLIC_KEY="BPtest-public-key",
)

import httpx  # noqa: E402
import pytest  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.auth import native  # noqa: E402
from app.db import ServiceSession  # noqa: E402
from app.main import app  # noqa: E402

# One hash for every test user: argon2 is slow on purpose.
TEST_PASSWORD = "correct horse battery staple"
_TEST_HASH = native.hash_password(TEST_PASSWORD)


def access_token(
    uid: str,
    email: str | None = None,
    superadmin: bool = False,
    impersonation: tuple[str, str, bool] | None = None,
) -> str:
    """A Beyond access token, as /auth/login would issue it."""
    return native.issue_access_token(
        uid, None, email or "", "Test User", superadmin=superadmin, impersonation=impersonation
    )


async def ensure_user(uid: str, email: str, superadmin: bool = False) -> None:
    """The users row a token stands for (verified, with TEST_PASSWORD)."""
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "INSERT INTO users "
                "(id, email, name, password_hash, email_verified_at, is_superadmin) "
                "VALUES (:u, :e, 'Test User', :h, now(), :s) ON CONFLICT DO NOTHING"
            ),
            {"u": uid, "e": email.lower(), "h": _TEST_HASH, "s": superadmin},
        )


class User:
    def __init__(self, client: httpx.AsyncClient, uid: str, email: str):
        self.uid = uid
        self.email = email
        self._client = client
        self._created = False
        self.headers = {"Authorization": f"Bearer {access_token(uid, email)}"}

    async def request(self, method: str, url: str, **kw) -> httpx.Response:
        if not self._created:
            await ensure_user(self.uid, self.email)
            self._created = True
        headers = {**self.headers, **kw.pop("headers", {})}
        return await self._client.request(method, url, headers=headers, **kw)

    async def tenant_id(self) -> uuid.UUID:
        return uuid.UUID((await self.request("GET", "/v1/me")).json()["tenant_id"])


async def superadmin_headers(email: str = "admin@example.com") -> dict[str, str]:
    uid = str(uuid.uuid4())
    await ensure_user(uid, f"{uid[:8]}-{email}", superadmin=True)
    return {"Authorization": f"Bearer {access_token(uid, email, superadmin=True)}"}


async def impersonate(
    client: httpx.AsyncClient, tenant_id: uuid.UUID, writes: bool = False
) -> dict[str, str]:
    """Headers for a superadmin working inside an organisation."""
    r = await client.post(
        f"/admin/v1/tenants/{tenant_id}/impersonate",
        headers=await superadmin_headers(),
        json={"reason": "customer asked for help", "allow_writes": writes},
    )
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(autouse=True)
async def fresh_rate_limits():
    """Every test signs up from the same address: start each with clean counters."""
    from app.services.heartbeats import redis

    keys = [k async for k in redis.scan_iter("pg:rl:*")]
    if keys:
        await redis.delete(*keys)


@pytest.fixture
async def client():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


def _new_user(client: httpx.AsyncClient, name: str) -> User:
    uid = str(uuid.uuid4())
    return User(client, uid, f"{name}-{uid[:8]}@example.com")


@pytest.fixture
def alice(client) -> User:
    return _new_user(client, "alice")


@pytest.fixture
def bob(client) -> User:
    return _new_user(client, "bob")


async def insert_host(tenant_id: uuid.UUID, hostname: str = "web-1") -> uuid.UUID:
    """Create a host the way ingest does: as the service role."""
    async with ServiceSession() as db, db.begin():
        return (
            await db.execute(
                text(
                    "INSERT INTO hosts (tenant_id, machine_id, hostname, token_hash) "
                    "VALUES (:t, :m, :h, :th) RETURNING id"
                ),
                {"t": tenant_id, "m": uuid.uuid4().hex, "h": hostname, "th": uuid.uuid4().hex},
            )
        ).scalar_one()


async def latest_code(channel_id: str) -> str:
    """The newest verification code queued for a channel, read from the outbox
    the way the dispatcher reads it."""
    async with ServiceSession() as db, db.begin():
        return (
            await db.execute(
                text(
                    "SELECT payload->>'code' FROM outbound_messages "
                    "WHERE channel_id = :c AND kind = 'verification' "
                    "ORDER BY created_at DESC LIMIT 1"
                ),
                {"c": channel_id},
            )
        ).scalar_one()
