"""Tests run against the real Postgres and Redis from deploy/docker-compose.yml,
migrated to head. Tenant isolation lives in the database, so mocking it out
would test nothing.
"""

import os
import time
import uuid

os.environ.update(
    ENVIRONMENT="testing",
    ALLOW_AUTH_BYPASS="false",
    JWT_TOKEN_ISSUER="test-issuer",
    JWT_TOKEN_AUDIENCE="test-audience",
    JWT_ALGORITHMS="RS256",
)

import httpx  # noqa: E402
import pytest  # noqa: E402
from joserfc import jwt  # noqa: E402
from joserfc.jwk import KeySet, RSAKey  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.auth.console import admin_verifier, console_verifier  # noqa: E402
from app.db import ServiceSession  # noqa: E402
from app.main import app  # noqa: E402

_KEY = RSAKey.generate_key(2048, parameters={"kid": "test"})


@pytest.fixture(scope="session", autouse=True)
def trust_test_key():
    """Make the console verifier trust our test signing key instead of fetching JWKS."""
    for verifier in (console_verifier, admin_verifier):
        verifier._keys = KeySet([_KEY])
        verifier._expiry = float("inf")


def console_token(uid: str, email: str | None = None, **extra) -> str:
    claims = {
        "iss": "test-issuer",
        "aud": "test-audience",
        "exp": int(time.time()) + 600,
        "jti": uuid.uuid4().hex,
        "uid": uid,
        "email": email,
        "name": "Test User",
        **extra,
    }
    return jwt.encode({"alg": "RS256", "kid": "test"}, claims, _KEY)


class User:
    def __init__(self, client: httpx.AsyncClient, uid: str, email: str):
        self.uid = uid
        self.email = email
        self._client = client
        self.headers = {"Authorization": f"Bearer {console_token(uid, email)}"}

    async def request(self, method: str, url: str, **kw) -> httpx.Response:
        return await self._client.request(method, url, headers=self.headers, **kw)

    async def tenant_id(self) -> uuid.UUID:
        return uuid.UUID((await self.request("GET", "/v1/me")).json()["tenant_id"])


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
