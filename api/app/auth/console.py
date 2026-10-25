"""Verifies console JWTs. The only module that knows what a console token looks like.

Everything else works with a Principal. A second identity source later means
a second verifier that returns the same Principal, and nothing else changes.
"""

import asyncio
import time
from dataclasses import dataclass

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from app.config import settings

_JWKS_CACHE_TTL = 300  # seconds

# A console super admin "viewing as" a customer carries this claim. Those
# sessions are read-only, the same as in billing.
IMPERSONATION_CLAIM = "imp"


class InvalidToken(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    source: str
    external_account_id: str
    email: str | None
    name: str | None
    impersonated: bool = False
    # Present only on console staff tokens (admin, super_admin, ...).
    role: str | None = None
    # Set when the caller used a Pulsegrid API token instead of a console login.
    api_token_id: str | None = None
    read_only: bool = False
    # For API tokens: the tenant, already looked up, and its status.
    token_tenant_id: str | None = None
    token_tenant_status: str | None = None


class JWKSVerifier:
    def __init__(self, jwks_uri: str, issuer: str, audience: str, algorithms: list[str]):
        self.jwks_uri = jwks_uri
        self.issuer = issuer
        self.audience = audience
        self.algorithms = algorithms
        self._keys: KeySet | None = None
        self._expiry = 0.0
        self._lock = asyncio.Lock()

    async def _key_set(self) -> KeySet:
        if self._keys is not None and time.monotonic() < self._expiry:
            return self._keys
        async with self._lock:
            if self._keys is not None and time.monotonic() < self._expiry:
                return self._keys
            async with httpx.AsyncClient() as client:
                response = await client.get(self.jwks_uri, timeout=10)
                response.raise_for_status()
            self._keys = KeySet.import_key_set(response.json())
            self._expiry = time.monotonic() + _JWKS_CACHE_TTL
        return self._keys

    async def verify(self, token: str) -> Principal:
        try:
            decoded = jwt.decode(token, await self._key_set(), algorithms=self.algorithms)
            claims = dict(decoded.claims)
            # The console issues `sub` as an integer; joserfc rejects non-string
            # `sub`. Identity comes from `uid` anyway.
            if claims.get("sub") is not None and not isinstance(claims["sub"], str):
                claims["sub"] = str(claims["sub"])
            JWTClaimsRegistry(
                iss={"essential": True, "value": self.issuer},
                aud={"essential": True, "value": self.audience},
                exp={"essential": True},
                uid={"essential": True},
            ).validate(claims)
        except (JoseError, ValueError) as exc:
            raise InvalidToken(str(exc)) from exc

        uid = claims.get("uid")
        if not uid:
            raise InvalidToken("token has no uid")
        return Principal(
            source=settings.TENANT_SOURCE,
            external_account_id=str(uid),
            email=claims.get("email"),
            name=claims.get("name"),
            impersonated=bool(claims.get(IMPERSONATION_CLAIM)),
            role=claims.get("role"),
        )


console_verifier = JWKSVerifier(
    jwks_uri=settings.JWKS_URI,
    issuer=settings.JWT_TOKEN_ISSUER,
    audience=settings.JWT_TOKEN_AUDIENCE,
    algorithms=settings.JWT_ALGORITHMS,
)

# Staff tokens can use a different issuer/audience than customer tokens (as in
# billing-ms); the `role` claim is what marks a token as staff.
admin_verifier = JWKSVerifier(
    jwks_uri=settings.JWKS_URI,
    issuer=settings.ADMIN_JWT_TOKEN_ISSUER or settings.JWT_TOKEN_ISSUER,
    audience=settings.ADMIN_JWT_TOKEN_AUDIENCE or settings.JWT_TOKEN_AUDIENCE,
    algorithms=settings.JWT_ALGORITHMS,
)


def dev_principal() -> Principal:
    return Principal(
        source=settings.TENANT_SOURCE,
        external_account_id=settings.DEV_EXTERNAL_ACCOUNT_ID,
        email=settings.DEV_EMAIL,
        name="Local Developer",
    )
