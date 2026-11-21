"""Real-browser checks: a page loaded in headless Chromium, with steps.

Revision ID: 0039
Revises: 0038
Create Date: 2026-11-21
"""

from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None

TYPES = (
    "tcp", "http", "tls", "dns", "file", "log", "ping",
    "websocket", "smtp", "ntp", "redis", "postgres", "mysql", "mongodb",
    "kafka", "mqtt", "grpc", "sip", "radius", "game", "snmp",
    "docker", "service", "push", "group",
)  # fmt: skip


PROBE = (
    "tcp", "http", "tls", "dns", "ping",
    "websocket", "smtp", "ntp", "redis", "postgres", "mysql", "mongodb",
    "kafka", "mqtt", "grpc", "sip", "radius", "game", "snmp",
)  # fmt: skip


def _probe(values: tuple[str, ...]) -> None:
    kinds = ", ".join(f"'{v}'" for v in values)
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_check1")
    op.execute(
        f"ALTER TABLE checks ADD CONSTRAINT checks_check1 CHECK (NOT on_probes OR type IN ({kinds}))"
    )


def _types(values: tuple[str, ...]) -> None:
    kinds = ", ".join(f"'{v}'" for v in values)
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_type_check")
    op.execute(f"ALTER TABLE checks ADD CONSTRAINT checks_type_check CHECK (type IN ({kinds}))")


def upgrade() -> None:
    _types((*TYPES, "browser"))
    _probe((*PROBE, "browser"))


def downgrade() -> None:
    op.execute("DELETE FROM checks WHERE type = 'browser'")
    _probe(PROBE)
    _types(TYPES)
