"""Two-factor recovery codes.

Ten single-use codes, shown once when two-factor sign-in is turned on and
stored as SHA-256 hashes. Each one stands in for an authenticator code, so a
lost phone doesn't lock the account for good.

Revision ID: 0026
Revises: 0025
Create Date: 2026-11-03
"""

from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN totp_recovery text[]")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN totp_recovery")
