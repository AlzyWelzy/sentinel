"""Incidents can be assigned to a member of the organisation.

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-02
"""

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None

KINDS = [
    "opened",
    "notified",
    "escalated",
    "acknowledged",
    "resolved",
    "reopened",
    "note",
    "action",
    "flapping",
    "snoozed",
    "unsnoozed",
    "merged",
]


def _check(kinds: list[str]) -> str:
    listed = ", ".join(f"'{k}'" for k in kinds)
    return f"ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_check CHECK (kind IN ({listed}))"


def upgrade() -> None:
    op.execute("""
        ALTER TABLE incidents
            ADD COLUMN assigned_to uuid REFERENCES users (id) ON DELETE SET NULL,
            ADD COLUMN assigned_name text,
            ADD COLUMN assigned_at timestamptz
    """)
    op.execute("ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check")
    op.execute(_check([*KINDS, "assigned"]))


def downgrade() -> None:
    op.execute("DELETE FROM incident_events WHERE kind = 'assigned'")
    op.execute("ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check")
    op.execute(_check(KINDS))
    op.execute(
        "ALTER TABLE incidents DROP COLUMN assigned_to, DROP COLUMN assigned_name, "
        "DROP COLUMN assigned_at"
    )
