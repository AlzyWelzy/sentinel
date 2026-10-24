import hashlib
import secrets

# Install keys are shown once, then only their hash is stored. The ingest
# service hashes what an agent presents and looks the hash up.
AGENT_KEY_PREFIX = "pg_"
DISPLAY_PREFIX_LEN = 10


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_agent_key() -> tuple[str, str, str]:
    """Returns (plaintext, display prefix, hash)."""
    plaintext = AGENT_KEY_PREFIX + secrets.token_urlsafe(32)
    return plaintext, plaintext[:DISPLAY_PREFIX_LEN], hash_secret(plaintext)
