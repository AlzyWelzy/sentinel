"""Agent rollouts: which agent version each server is offered. Stable for
everyone, a candidate for a share of servers (picked by a hash of the host
id, so the same servers stay in the canary), and per-account pins. A
candidate that makes servers go silent is rolled back automatically.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-25
"""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

VERSION = r"'^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'"


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE agent_rollout (
            id                  smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            stable_version      text NOT NULL CHECK (stable_version ~ {VERSION}),
            candidate_version   text CHECK (candidate_version ~ {VERSION}),
            candidate_percent   smallint NOT NULL DEFAULT 0
                                CHECK (candidate_percent BETWEEN 0 AND 100),
            candidate_since     timestamptz,
            -- The last candidate taken back, and why; not offered again on its own.
            rolled_back_version text,
            rollback_reason     text,
            updated_at          timestamptz NOT NULL DEFAULT now(),
            updated_by          text,
            CHECK (candidate_version IS NOT NULL OR candidate_percent = 0)
        )
    """)
    op.execute("GRANT SELECT, INSERT, UPDATE ON agent_rollout TO pulsegrid_service")
    op.execute(
        f"ALTER TABLE tenants ADD COLUMN agent_version_pin text CHECK (agent_version_pin ~ {VERSION})"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE tenants DROP COLUMN agent_version_pin")
    op.execute("DROP TABLE agent_rollout")
