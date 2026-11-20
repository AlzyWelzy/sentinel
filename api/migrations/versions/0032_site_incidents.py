"""Site incidents: when five or more hosts behind one public IP (servers
sharing NAT) or one poller (network devices) stop reporting within 15
minutes, their incidents are merged into one incident for the site, which
stays open until every one of them reports again.

Revision ID: 0032
Revises: 0031
Create Date: 2026-11-20
"""

from alembic import op

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE incidents ADD COLUMN site_key text")
    op.execute(
        "CREATE INDEX ix_incidents_site ON incidents (tenant_id, site_key) WHERE site_key IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_incidents_site")
    op.execute("ALTER TABLE incidents DROP COLUMN site_key")
