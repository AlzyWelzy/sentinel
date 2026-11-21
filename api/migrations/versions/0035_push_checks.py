"""Push checks: something else calls in (a cron job, a backup, an app) at
<ingest>/push/<push_token>, and silence for interval plus grace is down.
They run nowhere, so they're the one type with no host, tag or probes.

Revision ID: 0035
Revises: 0034
Create Date: 2026-11-21
"""

from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None

TYPES = (
    "tcp", "http", "tls", "dns", "file", "log", "ping",
    "websocket", "smtp", "ntp", "redis", "postgres", "mysql", "mongodb",
    "kafka", "mqtt", "grpc", "sip", "radius", "game", "snmp",
    "docker", "service",
)  # fmt: skip


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.execute("ALTER TABLE checks ADD COLUMN push_token text UNIQUE")
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_type_check")
    op.execute(
        "ALTER TABLE checks ADD CONSTRAINT checks_type_check"
        f" CHECK (type IN ({_in((*TYPES, 'push'))}))"
    )
    # A backup that runs daily pushes daily: push checks wait up to a week.
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_interval_seconds_check")
    op.execute(
        "ALTER TABLE checks ADD CONSTRAINT checks_interval_seconds_check CHECK ("
        " interval_seconds BETWEEN 10 AND 3600"
        " OR (type = 'push' AND interval_seconds BETWEEN 60 AND 604800))"
    )
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_check")
    op.execute(
        "ALTER TABLE checks ADD CONSTRAINT checks_check CHECK ("
        " CASE WHEN type = 'push'"
        "  THEN num_nonnulls(host_id, tag) = 0 AND NOT on_probes AND push_token IS NOT NULL"
        "  ELSE num_nonnulls(host_id, tag) + on_probes::int = 1 END)"
    )


def downgrade() -> None:
    op.execute("DELETE FROM checks WHERE type = 'push'")
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_interval_seconds_check")
    op.execute(
        "ALTER TABLE checks ADD CONSTRAINT checks_interval_seconds_check"
        " CHECK (interval_seconds BETWEEN 10 AND 3600)"
    )
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_check")
    op.execute(
        "ALTER TABLE checks ADD CONSTRAINT checks_check"
        " CHECK (num_nonnulls(host_id, tag) + on_probes::int = 1)"
    )
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_type_check")
    op.execute(
        f"ALTER TABLE checks ADD CONSTRAINT checks_type_check CHECK (type IN ({_in(TYPES)}))"
    )
    op.execute("ALTER TABLE checks DROP COLUMN push_token")
