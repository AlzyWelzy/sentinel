"""Pausing a server's monitoring: no alerts or incidents until resumed.

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-29
"""

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE hosts ADD COLUMN paused_at timestamptz, ADD COLUMN paused_by text")


def downgrade() -> None:
    op.execute("ALTER TABLE hosts DROP COLUMN paused_at, DROP COLUMN paused_by")
