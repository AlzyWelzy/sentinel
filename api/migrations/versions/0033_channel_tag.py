"""A contact can be limited to one tag's hosts (only_tag): an MSP adds its
customer's address with the customer's tag, and the customer gets alerts for
their own servers and devices only.

Revision ID: 0033
Revises: 0032
Create Date: 2026-11-20
"""

from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE notification_channels ADD COLUMN only_tag text"
        " CHECK (only_tag IS NULL OR length(only_tag) BETWEEN 1 AND 64)"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE notification_channels DROP COLUMN only_tag")
