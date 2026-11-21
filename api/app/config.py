from typing import Annotated, Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    ENVIRONMENT: Literal["development", "testing", "production"] = "development"

    # ── Postgres ─────────────────────────────────────────────────────────────
    # Customer requests run as the app role, so row-level security always applies.
    DATABASE_APP_URL: str = "postgresql+asyncpg://sentinel_app:sentinel_app@localhost:5442/sentinel"
    # Superadmin routes and the auth service work across tenants: BYPASSRLS service role.
    DATABASE_SERVICE_URL: str = (
        "postgresql+asyncpg://sentinel_service:sentinel_service@localhost:5442/sentinel"
    )

    REDIS_URL: str = "redis://localhost:6389/0"
    VICTORIAMETRICS_URL: str = "http://localhost:8438"
    # Long-term store of hourly rollups (written by the jobs worker). Empty:
    # no rollups, and charts only reach back as far as raw retention.
    VICTORIAMETRICS_LONG_URL: str = ""
    # Status pages on customers' domains behind a Cloudflare Tunnel: each
    # verified domain becomes a Cloudflare for SaaS custom hostname in this
    # zone, and customers point a CNAME at STATUS_DOMAIN_TARGET (the zone's
    # fallback origin). Empty: Caddy's on-demand TLS serves them instead.
    CF_API_TOKEN: str = ""
    CF_ZONE_ID: str = ""
    STATUS_DOMAIN_TARGET: str = ""
    # IPDR evidence store; empty turns IPDR off.
    CLICKHOUSE_URL: str = ""
    CLICKHOUSE_USER: str = "default"
    CLICKHOUSE_PASSWORD: str = ""
    CLICKHOUSE_DB: str = "sentinel"
    # Raw samples are kept this long (VictoriaMetrics -retentionPeriod);
    # older ranges are read from the rollups.
    RAW_RETENTION_DAYS: int = 90
    # VictoriaLogs for log search (ingest writes, the API and alerter read;
    # each account is its own VictoriaLogs AccountID). Empty: log search is off.
    VICTORIALOGS_URL: str = ""
    # Tempo's query API for APM (ingest writes OTLP to it). Empty: APM is off.
    TEMPO_URL: str = ""

    # ── Public URLs ──────────────────────────────────────────────────────────
    # Never hardcode these anywhere else: moving domains is a config change.
    # The web app; links in emails (verify, reset, invitations, alerts,
    # reports) point here.
    PUBLIC_APP_URL: str = "http://localhost:3000"
    PUBLIC_API_URL: str = "http://localhost:8010"
    PUBLIC_INGEST_URL: str = "http://localhost:8090"
    PUBLIC_DOWNLOAD_URL: str = "http://localhost:8010"
    # The agent version this release ships (agent/VERSION). A newer one than
    # the rollout's stable version starts as a candidate for this share of
    # servers; staff promote it (or the health gate rolls it back).
    AGENT_VERSION: str = "latest"
    AGENT_CANARY_PERCENT: int = 10
    # The self-updating agent container (deploy/agent-container).
    AGENT_IMAGE: str = "ghcr.io/alzywelzy/sentinel-agent:latest"
    # Local directory served at /agent/ when present (dev builds of the agent binary).
    AGENT_DIST_DIR: str = "dist"

    # Browser origins allowed to call the API directly. The web app is served
    # on the same origin as the API in production, so this is usually empty.
    CORS_ORIGINS: str = "http://localhost:3000"
    # Path prefix when served behind a proxy that passes it through unstripped.
    API_ROOT_PATH: str = ""

    # ── Accounts ─────────────────────────────────────────────────────────────
    # Signs access tokens and encrypts TOTP secrets (each through its own
    # derived key). Rotate by moving the old value to AUTH_SECRET_PREVIOUS:
    # tokens and secrets made with it keep working until they're renewed.
    AUTH_SECRET: str = ""
    AUTH_SECRET_PREVIOUS: str = ""
    # Encrypts SNMP credentials (and other device secrets) at rest. Ingest has
    # the same value: it hands them to the agent that polls the device.
    CREDENTIALS_KEY: str = ""
    ACCESS_TOKEN_TTL_SECONDS: int = 600
    REFRESH_TOKEN_TTL_DAYS: int = 30
    # Refresh cookies need HTTPS; only development over plain http turns it off.
    COOKIE_SECURE: bool = True
    SIGNUP_ENABLED: bool = True
    # Cloudflare Turnstile on sign-up and password reset. Required in
    # production unless CAPTCHA_DISABLED (for a private install).
    TURNSTILE_SITE_KEY: str = ""
    TURNSTILE_SECRET_KEY: str = ""
    CAPTCHA_DISABLED: bool = False
    # Verified accounts with these emails are superadmins (a bootstrap: the
    # flag is stored, and removing an address here revokes it at next sign-in).
    SUPERADMIN_EMAILS: Annotated[list[str], NoDecode] = []
    # Every new organisation gets the recommended alert rules.
    AUTO_RECOMMENDED_RULES: bool = True

    # Signs the one-click acknowledge links in alerts; the alerter has the
    # same value. Empty: alerts carry no acknowledge link.
    ACK_SIGNING_SECRET: str = ""

    # Organisations (tenant ids) whose agents superadmins may turn into public probes.
    # Probes receive every account's uptime check targets, so only our own
    # infrastructure may run them.
    PROBE_ACCOUNT_IDS: Annotated[list[str], NoDecode] = []

    # Contact types customers can add. Others already saved keep working.
    ENABLED_CHANNEL_TYPES: Annotated[list[str], NoDecode] = ["email", "push"]
    # The notification provider catalog (ntfy, Opsgenie, DingTalk, …): the
    # customer's own accounts, so nothing to set up here.
    CATALOG_CHANNELS: bool = True

    # Web Push (VAPID). The alerter holds the private key; browsers need the
    # public one to subscribe.
    VAPID_PUBLIC_KEY: str = ""

    # A host is shown offline once its last push is older than this.
    HOST_OFFLINE_AFTER_SECONDS: int = 120

    @field_validator(
        "SUPERADMIN_EMAILS", "ENABLED_CHANNEL_TYPES", "PROBE_ACCOUNT_IDS", mode="before"
    )
    @classmethod
    def _split_algorithms(cls, v: object) -> object:
        if isinstance(v, str):
            return [alg.strip() for alg in v.split(",") if alg.strip()]
        return v

    @model_validator(mode="after")
    def _validate_production(self) -> "Settings":
        if self.ENVIRONMENT != "production":
            return self
        if len(self.AUTH_SECRET) < 32:
            raise ValueError("Set AUTH_SECRET to a random value of at least 32 characters")
        if len(self.CREDENTIALS_KEY) < 32:
            raise ValueError("Set CREDENTIALS_KEY to a random value of at least 32 characters")
        if not self.COOKIE_SECURE:
            raise ValueError("COOKIE_SECURE must stay on in production")
        if not self.CAPTCHA_DISABLED and not self.TURNSTILE_SECRET_KEY:
            raise ValueError(
                "Set TURNSTILE_SECRET_KEY, or CAPTCHA_DISABLED=true for a private install"
            )
        if not self.PUBLIC_APP_URL.startswith("https://"):
            raise ValueError("PUBLIC_APP_URL must be https in production")
        return self

    @property
    def superadmin_emails(self) -> set[str]:
        return {e.lower() for e in self.SUPERADMIN_EMAILS}

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
