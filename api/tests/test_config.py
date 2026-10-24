"""Settings are read from the environment, exactly as in a deployment."""

import pytest
from pydantic import ValidationError

from app.config import Settings

PROD = {
    "ENVIRONMENT": "production",
    "INTERNAL_API_KEY": "k" * 40,
    "JWKS_URI": "https://console.example.com/api/.well-known/jwks.json/",
    "JWT_TOKEN_ISSUER": "console.example.com",
    "JWT_TOKEN_AUDIENCE": "console.example.com",
    "ALLOW_AUTH_BYPASS": "false",
}


@pytest.fixture
def prod_env(monkeypatch):
    for key, value in PROD.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def test_valid_production_config(prod_env):
    Settings()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ALLOW_AUTH_BYPASS", "true"),
        ("INTERNAL_API_KEY", "change-me-pulsegrid-internal-key"),
        ("INTERNAL_API_KEY", "short"),
        ("JWKS_URI", "http://localhost/.well-known/jwks.json"),
        ("JWT_TOKEN_ISSUER", "issuer.client.com"),
    ],
)
def test_production_refuses_unsafe_config(prod_env, key, value):
    prod_env.setenv(key, value)
    with pytest.raises(ValidationError):
        Settings()


def test_algorithms_from_comma_separated_env(monkeypatch):
    monkeypatch.setenv("JWT_ALGORITHMS", "RS256, RS512")
    assert Settings().JWT_ALGORITHMS == ["RS256", "RS512"]
