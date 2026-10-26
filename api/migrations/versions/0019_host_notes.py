"""A note on each server: what it is for, who owns it, how to reach it.

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-26
"""

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE hosts
            ADD COLUMN notes text CHECK (char_length(notes) <= 4000),
            ADD COLUMN notes_updated_at timestamptz,
            ADD COLUMN notes_updated_by text
    """)


def downgrade() -> None:
    op.execute(
        "ALTER TABLE hosts DROP COLUMN notes, DROP COLUMN notes_updated_at, DROP COLUMN notes_updated_by"
    )
