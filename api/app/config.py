from typing import Annotated, Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    ENVIRONMENT: Literal["development", "testing", "production"] = "development"

    # Accept requests without a verifiable console JWT and act as DEV_EXTERNAL_ACCOUNT_ID.
    # Local development only; refused in production by _validate_auth_bypass.
    ALLOW_AUTH_BYPASS: bool = False
    DEV_EXTERNAL_ACCOUNT_ID: str = "00000000-0000-0000-0000-000000000001"
    DEV_EMAIL: str = "dev@localhost"

    # ── Postgres ─────────────────────────────────────────────────────────────
    # Customer requests run as the app role, so row-level security always applies.
    DATABASE_APP_URL: str = (
        "postgresql+asyncpg://pulsegrid_app:pulsegrid_app@localhost:5432/pulsegrid"
    )
    # Internal routes work across tenants, so they use the BYPASSRLS service role.
    DATABASE_SERVICE_URL: str = (
        "postgresql+asyncpg://pulsegrid_service:pulsegrid_service@localhost:5432/pulsegrid"
    )

    REDIS_URL: str = "redis://localhost:6379/0"
    VICTORIAMETRICS_URL: str = "http://localhost:8428"
    # Long-term store of hourly rollups (written by the jobs worker). Empty:
    # no rollups, and charts only reach back as far as raw retention.
    VICTORIAMETRICS_LONG_URL: str = ""
    # Raw samples are kept this long (VictoriaMetrics -retentionPeriod);
    # older ranges are read from the rollups.
    RAW_RETENTION_DAYS: int = 90
    # VictoriaLogs for log search (ingest writes, the API and alerter read;
    # each account is its own VictoriaLogs AccountID). Empty: log search is off.
    VICTORIALOGS_URL: str = ""
    # Tempo's query API for APM (ingest writes OTLP to it). Empty: APM is off.
    TEMPO_URL: str = ""

    # Where links in report emails point (the console's Monitoring page).
    PUBLIC_DASHBOARD_URL: str = ""

    # ── Public URLs ──────────────────────────────────────────────────────────
    # Never hardcode these anywhere else: moving domains is a config change.
    PUBLIC_API_URL: str = "http://localhost:8000"
    PUBLIC_INGEST_URL: str = "http://localhost:8080"
    PUBLIC_DOWNLOAD_URL: str = "http://localhost:8000"
    # The agent version this release ships (agent/VERSION). A newer one than
    # the rollout's stable version starts as a candidate for this share of
    # servers; staff promote it (or the health gate rolls it back).
    AGENT_VERSION: str = "latest"
    AGENT_CANARY_PERCENT: int = 10
    # The self-updating agent container (deploy/agent-container).
    AGENT_IMAGE: str = "ghcr.io/example-org/pulsegrid-agent:latest"
    # Local directory served at /agent/ when present (dev builds of the agent binary).
    AGENT_DIST_DIR: str = "dist"

    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"
    # Path prefix when served behind a proxy that passes it through unstripped
    # (e.g. the console's nginx at /api/pulsegrid), like billing-ms.
    API_ROOT_PATH: str = ""

    # ── Console identity (shared JWKS, same as billing) ──────────────────────
    TENANT_SOURCE: str = "console"
    JWKS_URI: str = "http://localhost/.well-known/jwks.json"
    # NoDecode: env gives "RS256,RS384" (as in billing), split by the validator below.
    JWT_ALGORITHMS: Annotated[list[str], NoDecode] = ["RS256", "RS384", "RS512"]
    JWT_TOKEN_ISSUER: str = "issuer.client.com"
    JWT_TOKEN_AUDIENCE: str = "audience.client.com"
    # Staff tokens; empty means "same as customer tokens".
    ADMIN_JWT_TOKEN_ISSUER: str = ""
    ADMIN_JWT_TOKEN_AUDIENCE: str = ""
    STAFF_ROLES: Annotated[list[str], NoDecode] = ["admin", "super_admin"]
    # Customers only look: staff add servers and manage rules for them, and
    # customers may change nothing but their alert contacts.
    CUSTOMERS_READ_ONLY: bool = False

    # ── Service-to-service (console backend -> /internal/*) ──────────────────
    INTERNAL_API_KEY: str = "change-me-pulsegrid-internal-key"

    # Signs the one-click acknowledge links in alerts; the alerter has the
    # same value. Empty: alerts carry no acknowledge link.
    ACK_SIGNING_SECRET: str = ""

    # Console accounts (uids) whose agents staff may turn into public probes.
    # Probes receive every account's uptime check targets, so only our own
    # infrastructure may run them.
    PROBE_ACCOUNT_IDS: Annotated[list[str], NoDecode] = []

    # Contact types customers can add. Others already saved keep working.
    ENABLED_CHANNEL_TYPES: Annotated[list[str], NoDecode] = ["email", "push"]

    # Web Push (VAPID). The alerter holds the private key; browsers need the
    # public one to subscribe.
    VAPID_PUBLIC_KEY: str = ""

    # A host is shown offline once its last push is older than this.
    HOST_OFFLINE_AFTER_SECONDS: int = 120

    @field_validator(
        "JWT_ALGORITHMS", "STAFF_ROLES", "ENABLED_CHANNEL_TYPES", "PROBE_ACCOUNT_IDS", mode="before"
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
        if self.ALLOW_AUTH_BYPASS:
            raise ValueError("ALLOW_AUTH_BYPASS must never be enabled in production")
        if self.INTERNAL_API_KEY.startswith("change-me") or len(self.INTERNAL_API_KEY) < 32:
            raise ValueError("Set INTERNAL_API_KEY to a random value of at least 32 characters")
        if "localhost" in self.JWKS_URI or self.JWT_TOKEN_ISSUER == "issuer.client.com":
            raise ValueError(
                "Set JWKS_URI, JWT_TOKEN_ISSUER and JWT_TOKEN_AUDIENCE to the console's"
            )
        return self

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
