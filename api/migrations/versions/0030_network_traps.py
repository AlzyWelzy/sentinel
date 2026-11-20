"""SNMP traps the pollers receive from the devices they poll.

Each trap is classified by ingest with netmon/traps: the rule it opens or
clears (a network condition key such as trap_vpn_tunnel_down) and the
identity it concerns (one VPN tunnel, one BGP peer). The alerter reads the
latest trap per device, rule and identity. A burst of the same trap is one
row with a repeat count. Rows are kept 30 days.

Revision ID: 0030
Revises: 0029
Create Date: 2026-11-20
"""

from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE network_traps (
            id             bigserial PRIMARY KEY,
            tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            -- The device it came from; NULL for a sender that isn't one of the
            -- poller's devices (recorded, never alerting).
            host_id        uuid REFERENCES hosts(id) ON DELETE CASCADE,
            poller_host_id uuid REFERENCES hosts(id) ON DELETE SET NULL,
            source         text NOT NULL,
            version        text NOT NULL DEFAULT '',
            oid            text NOT NULL,
            name           text NOT NULL,
            title          text NOT NULL,
            action         text NOT NULL CHECK (action IN ('event', 'open', 'clear')),
            rule           text,
            identity       text NOT NULL DEFAULT '',
            severity       text NOT NULL DEFAULT 'info',
            labels         jsonb NOT NULL DEFAULT '{}',
            varbinds       jsonb NOT NULL DEFAULT '{}',
            repeats        integer NOT NULL DEFAULT 0,
            received_at    timestamptz NOT NULL,
            last_at        timestamptz NOT NULL
        )
        """
    )
    op.execute("CREATE INDEX ix_network_traps_host ON network_traps (host_id, received_at DESC)")
    op.execute(
        "CREATE INDEX ix_network_traps_rule ON network_traps (tenant_id, rule, host_id, identity, last_at DESC)"
        " WHERE rule IS NOT NULL"
    )
    op.execute("CREATE INDEX ix_network_traps_age ON network_traps (received_at)")
    op.execute("ALTER TABLE network_traps ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON network_traps "
        f"USING (tenant_id = {CURRENT_TENANT}) WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )
    op.execute("GRANT SELECT, DELETE ON network_traps TO sentinel_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON network_traps TO sentinel_service")
    op.execute("GRANT USAGE ON SEQUENCE network_traps_id_seq TO sentinel_service")
    # Where the poller receives traps (162, 1162, or none).
    op.execute("ALTER TABLE hosts ADD COLUMN trap_port integer")


def downgrade() -> None:
    op.execute("ALTER TABLE hosts DROP COLUMN trap_port")
    op.execute("DROP TABLE network_traps")
