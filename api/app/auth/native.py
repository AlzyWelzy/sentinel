"""Beyond's own credentials: access tokens, passwords and TOTP secrets.

- Access tokens are short-lived JWTs (HS256) that only this API issues and
  verifies. They carry the user and session, nothing about organisations:
  which organisation a request is for is checked against membership on
  every request (tenancy.py).
- Refresh tokens are opaque random strings, stored hashed in
  user_sessions and rotated by services/accounts.py.
- Keys are derived from AUTH_SECRET, one per purpose, so the token key
  can't decrypt TOTP secrets. AUTH_SECRET_PREVIOUS still verifies and
  decrypts during a rotation.
"""

import base64
import hashlib
import hmac
import secrets
import time
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from joserfc import jws, jwt
from joserfc.errors import JoseError
from joserfc.jwk import OctKey
from joserfc.jwt import JWTClaimsRegistry

from app.auth.principal import Principal
from app.config import settings

ISSUER = "pulsegrid-beyond"
_ALG = "HS256"

# A random secret per process when none is configured, outside production
# (where config.py refuses to start without one): tokens then end with the
# process, which is fine for development and tests.
_EPHEMERAL = secrets.token_urlsafe(48)


class InvalidToken(Exception):
    pass


def _secrets() -> list[str]:
    current = settings.AUTH_SECRET or _EPHEMERAL
    return [s for s in (current, settings.AUTH_SECRET_PREVIOUS) if s]


def _derive(secret: str, purpose: str) -> bytes:
    return hmac.new(secret.encode(), f"beyond:{purpose}".encode(), hashlib.sha256).digest()


def _kid(secret: str) -> str:
    return hashlib.sha256(_derive(secret, "kid")).hexdigest()[:12]


# ── Access tokens ─────────────────────────────────────────────────────────────


def issue_access_token(
    user_id: str,
    session_id: str | None,
    email: str,
    name: str | None,
    superadmin: bool = False,
    impersonation: tuple[str, str, bool] | None = None,
    ttl: int | None = None,
) -> str:
    secret = _secrets()[0]
    now = int(time.time())
    claims: dict = {
        "iss": ISSUER,
        "sub": user_id,
        "iat": now,
        "exp": now + (ttl or settings.ACCESS_TOKEN_TTL_SECONDS),
        "jti": uuid.uuid4().hex,
        "email": email,
        "name": name,
    }
    if session_id:
        claims["sid"] = session_id
    if superadmin:
        claims["sa"] = True
    if impersonation:
        claims["imp"], claims["imp_t"], claims["imp_w"] = impersonation
    key = OctKey.import_key(_derive(secret, "access-token"))
    return jwt.encode({"alg": _ALG, "kid": _kid(secret)}, claims, key)


def verify_access_token(token: str) -> Principal:
    try:
        header = jws.extract_compact(token.encode()).headers()
    except (JoseError, ValueError) as exc:
        raise InvalidToken(str(exc)) from exc
    secret = next((s for s in _secrets() if _kid(s) == header.get("kid")), None)
    if secret is None or header.get("alg") != _ALG:
        raise InvalidToken("unknown key")
    try:
        decoded = jwt.decode(
            token, OctKey.import_key(_derive(secret, "access-token")), algorithms=[_ALG]
        )
        JWTClaimsRegistry(
            iss={"essential": True, "value": ISSUER},
            exp={"essential": True},
            sub={"essential": True},
        ).validate(decoded.claims)
    except (JoseError, ValueError) as exc:
        raise InvalidToken(str(exc)) from exc
    c = decoded.claims
    return Principal(
        user_id=str(c["sub"]),
        email=c.get("email"),
        name=c.get("name"),
        superadmin=bool(c.get("sa")),
        session_id=c.get("sid"),
        impersonation_id=c.get("imp"),
        impersonation_tenant_id=c.get("imp_t"),
        impersonation_writes=bool(c.get("imp_w")),
    )


# ── Passwords ─────────────────────────────────────────────────────────────────

# argon2id with the library's defaults (RFC 9106 low-memory profile).
_hasher = PasswordHasher()
# Verified against when the email is unknown, so a login takes as long
# either way and doesn't reveal which emails have accounts.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 256


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def check_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


# ── Opaque tokens (refresh, email links, invitations) ────────────────────────


def new_opaque_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ── TOTP secrets, encrypted at rest ──────────────────────────────────────────


def encrypt_secret(plaintext: str) -> str:
    secret = _secrets()[0]
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(_derive(secret, "totp")).encrypt(nonce, plaintext.encode(), None)
    return f"{_kid(secret)}.{base64.urlsafe_b64encode(nonce + sealed).decode()}"


def decrypt_secret(stored: str) -> str:
    kid, _, blob = stored.partition(".")
    raw = base64.urlsafe_b64decode(blob)
    for secret in _secrets():
        if _kid(secret) != kid:
            continue
        try:
            return AESGCM(_derive(secret, "totp")).decrypt(raw[:12], raw[12:], None).decode()
        except InvalidTag:
            break
    raise ValueError("TOTP secret can't be decrypted with the configured AUTH_SECRET")
