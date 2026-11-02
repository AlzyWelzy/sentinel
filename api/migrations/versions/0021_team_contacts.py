"""Team contacts (the console account's team members, kept in sync by the
console) and recommended rules added once to every account.

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-30
"""

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_source_check, "
        "ADD CONSTRAINT notification_channels_source_check "
        "CHECK (source IN ('console', 'user', 'team'))"
    )
    op.execute("ALTER TABLE tenants ADD COLUMN recommended_rules_at timestamptz")
    op.execute("GRANT UPDATE (recommended_rules_at) ON tenants TO sentinel_service")


def downgrade() -> None:
    op.execute("REVOKE UPDATE (recommended_rules_at) ON tenants FROM sentinel_service")
    op.execute("ALTER TABLE tenants DROP COLUMN recommended_rules_at")
    op.execute("DELETE FROM notification_channels WHERE source = 'team'")
    op.execute(
        "ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_source_check, "
        "ADD CONSTRAINT notification_channels_source_check CHECK (source IN ('console', 'user'))"
    )
