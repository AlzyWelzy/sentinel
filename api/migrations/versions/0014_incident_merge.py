"""Merging incidents: related incidents fold into one, which carries the
investigation; the merged ones close and point at it.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-26
"""

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

EVENT_KINDS = (
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
)


def _in(values) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.execute(
        "ALTER TABLE incidents ADD COLUMN merged_into uuid REFERENCES incidents(id) ON DELETE SET NULL"
    )
    op.execute(
        "CREATE INDEX ix_incidents_merged_into ON incidents (merged_into) "
        "WHERE merged_into IS NOT NULL"
    )
    op.execute("ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check")
    op.execute(
        "ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_check "
        f"CHECK (kind IN ({_in(EVENT_KINDS)}))"
    )


def downgrade() -> None:
    op.execute("UPDATE incident_events SET kind = 'note' WHERE kind = 'merged'")
    op.execute("ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check")
    op.execute(
        "ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_check "
        f"CHECK (kind IN ({_in(EVENT_KINDS[:-1])}))"
    )
    op.execute("ALTER TABLE incidents DROP COLUMN merged_into")
