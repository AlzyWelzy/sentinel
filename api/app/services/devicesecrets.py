"""Device credentials (SNMP communities, v3 users) encrypted at rest.

AES-256-GCM with a key derived from CREDENTIALS_KEY. Ingest (Go) reads the
same format to hand credentials to the polling agent:

    "v1:" + base64url(nonce[12] || ciphertext || tag)

They're never returned by the API: only whether each secret is set.
"""

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

PREFIX = "v1:"


class CredentialsKeyMissing(RuntimeError):
    pass


def _key() -> bytes:
    secret = settings.CREDENTIALS_KEY
    if not secret:
        raise CredentialsKeyMissing("CREDENTIALS_KEY is not set")
    return hashlib.sha256(b"sentinel-credentials\x00" + secret.encode()).digest()


def seal(values: dict) -> str:
    nonce = os.urandom(12)
    sealed = AESGCM(_key()).encrypt(nonce, json.dumps(values).encode(), None)
    return PREFIX + base64.urlsafe_b64encode(nonce + sealed).decode().rstrip("=")


def open_sealed(value: str) -> dict:
    if not value.startswith(PREFIX):
        raise ValueError("unknown credential format")
    raw = value[len(PREFIX) :]
    raw = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    return json.loads(AESGCM(_key()).decrypt(raw[:12], raw[12:], None))
