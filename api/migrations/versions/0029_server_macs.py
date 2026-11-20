"""Servers' hardware addresses, so a switch's LLDP neighbour (a server NIC
announcing itself by MAC) can be matched to the server, and the server made
to depend on the switch it's cabled to.

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-20
"""

from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE hosts ADD COLUMN macs text[] NOT NULL DEFAULT '{}'")
    # Where a host is cabled, and deleting a host (the foreign key's SET NULL).
    op.execute(
        "CREATE INDEX ix_network_links_remote ON network_links (remote_host_id)"
        " WHERE remote_host_id IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_network_links_remote")
    op.execute("ALTER TABLE hosts DROP COLUMN macs")
