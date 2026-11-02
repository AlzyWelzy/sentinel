"""The agent doctor (a customer request) reads which version the rollout
offers a server.

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-26
"""

from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("GRANT SELECT ON agent_rollout TO sentinel_app")


def downgrade() -> None:
    op.execute("REVOKE SELECT ON agent_rollout FROM sentinel_app")
