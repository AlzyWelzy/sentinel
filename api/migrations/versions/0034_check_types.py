"""Protocol checks: WebSocket, SMTP, NTP, Redis, PostgreSQL, MySQL, MongoDB,
Kafka, MQTT, gRPC health, SIP, RADIUS, game servers and SNMP (anything over
the network can also run on the public probes), and Docker containers and
system services on the server itself. Any check can be inverted (params
invert=true: up means unreachable).

Revision ID: 0034
Revises: 0033
Create Date: 2026-11-21
"""

from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None

OLD = ("tcp", "http", "tls", "dns", "file", "log", "ping")
OLD_PROBE = ("tcp", "http", "tls", "dns", "ping")
NETWORK = (
    "websocket", "smtp", "ntp", "redis", "postgres", "mysql", "mongodb",
    "kafka", "mqtt", "grpc", "sip", "radius", "game", "snmp",
)  # fmt: skip
LOCAL = ("docker", "service")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _set(types: tuple[str, ...], probe: tuple[str, ...]) -> None:
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_type_check")
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_check1")
    op.execute(
        f"ALTER TABLE checks ADD CONSTRAINT checks_type_check CHECK (type IN ({_in(types)}))"
    )
    op.execute(
        "ALTER TABLE checks ADD CONSTRAINT checks_check1"
        f" CHECK (NOT on_probes OR type IN ({_in(probe)}))"
    )


def upgrade() -> None:
    _set(OLD + NETWORK + LOCAL, OLD_PROBE + NETWORK)


def downgrade() -> None:
    op.execute(f"DELETE FROM checks WHERE type NOT IN ({_in(OLD)})")  # noqa: S608 (constants)
    _set(OLD, OLD_PROBE)
