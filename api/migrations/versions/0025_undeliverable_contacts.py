"""Contacts whose mail server permanently rejected them.

The alerter sets undeliverable_at (and clears verified_at, so nothing more
is sent there) when an SMTP server refuses the recipient; verifying the
address again clears it.

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-02
"""

from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE notification_channels "
        "ADD COLUMN undeliverable_at timestamptz, ADD COLUMN undeliverable_reason text"
    )
    op.execute(
        "GRANT UPDATE (verified_at, undeliverable_at, undeliverable_reason) "
        "ON notification_channels TO sentinel_service"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE notification_channels "
        "DROP COLUMN undeliverable_at, DROP COLUMN undeliverable_reason"
    )
