"""Settings are read from the environment, exactly as in a deployment."""

import pytest
from pydantic import ValidationError

from app.config import Settings

PROD = {
    "ENVIRONMENT": "production",
    "AUTH_SECRET": "s" * 48,
    "CREDENTIALS_KEY": "c" * 48,
    "COOKIE_SECURE": "true",
    "TURNSTILE_SECRET_KEY": "turnstile-secret",
    "PUBLIC_APP_URL": "https://sentinel.example.com",
}


@pytest.fixture
def prod_env(monkeypatch):
    for key, value in PROD.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def test_valid_production_config(prod_env):
    Settings()


def test_a_private_install_may_turn_the_captcha_off(prod_env):
    prod_env.delenv("TURNSTILE_SECRET_KEY")
    prod_env.setenv("CAPTCHA_DISABLED", "true")
    Settings()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("AUTH_SECRET", ""),
        ("AUTH_SECRET", "short"),
        ("CREDENTIALS_KEY", ""),
        ("CREDENTIALS_KEY", "short"),
        ("COOKIE_SECURE", "false"),
        ("TURNSTILE_SECRET_KEY", ""),
        ("PUBLIC_APP_URL", "http://sentinel.example.com"),
    ],
)
def test_production_refuses_unsafe_config(prod_env, key, value):
    prod_env.setenv(key, value)
    with pytest.raises(ValidationError):
        Settings()


def test_lists_from_comma_separated_env(monkeypatch):
    monkeypatch.setenv("SUPERADMIN_EMAILS", "Ops@Example.com, me@example.com")
    assert Settings().superadmin_emails == {"ops@example.com", "me@example.com"}
