"""Check groups: a group check runs nowhere; it is down while any of its
members has an open incident. Any check can belong to one group
(parent_id); groups nest, never in a loop (the API refuses one).

Revision ID: 0037
Revises: 0036
Create Date: 2026-11-21
"""

from alembic import op

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None

TYPES = (
    "tcp", "http", "tls", "dns", "file", "log", "ping",
    "websocket", "smtp", "ntp", "redis", "postgres", "mysql", "mongodb",
    "kafka", "mqtt", "grpc", "sip", "radius", "game", "snmp",
    "docker", "service", "push",
)  # fmt: skip


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _types(values: tuple[str, ...]) -> None:
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_type_check")
    op.execute(
        f"ALTER TABLE checks ADD CONSTRAINT checks_type_check CHECK (type IN ({_in(values)}))"
    )


def upgrade() -> None:
    op.execute(
        "ALTER TABLE checks ADD COLUMN parent_id uuid REFERENCES checks(id) ON DELETE SET NULL"
    )
    op.execute("ALTER TABLE checks ADD CONSTRAINT checks_parent_not_self CHECK (parent_id <> id)")
    op.execute("CREATE INDEX checks_parent_id ON checks (parent_id) WHERE parent_id IS NOT NULL")
    _types((*TYPES, "group"))
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_check")
    op.execute(
        "ALTER TABLE checks ADD CONSTRAINT checks_check CHECK ("
        " CASE WHEN type = 'push'"
        "  THEN num_nonnulls(host_id, tag) = 0 AND NOT on_probes AND push_token IS NOT NULL"
        "  WHEN type = 'group'"
        "  THEN num_nonnulls(host_id, tag, push_token) = 0 AND NOT on_probes"
        "  ELSE num_nonnulls(host_id, tag) + on_probes::int = 1 END)"
    )


def downgrade() -> None:
    op.execute("UPDATE checks SET parent_id = NULL")
    op.execute("DELETE FROM checks WHERE type = 'group'")
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_check")
    op.execute(
        "ALTER TABLE checks ADD CONSTRAINT checks_check CHECK ("
        " CASE WHEN type = 'push'"
        "  THEN num_nonnulls(host_id, tag) = 0 AND NOT on_probes AND push_token IS NOT NULL"
        "  ELSE num_nonnulls(host_id, tag) + on_probes::int = 1 END)"
    )
    _types(TYPES)
    op.execute("ALTER TABLE checks DROP COLUMN parent_id")
