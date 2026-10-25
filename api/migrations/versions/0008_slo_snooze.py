"""SLO targets on checks, and snoozing incidents.

- checks.slo_target: the availability the check promises, in percent; the
  insights page tracks the error budget against it.
- incidents.snoozed_until / snoozed_by: escalations and reminders hold off
  until then; the incident itself stays open.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-25
"""

from alembic import op

revision = "0008"
down_revision = "0007"
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
)


def _in(values) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.execute(
        "ALTER TABLE checks ADD COLUMN slo_target numeric(6,3) NOT NULL DEFAULT 99.9 "
        "CHECK (slo_target > 0 AND slo_target < 100)"
    )
    op.execute("ALTER TABLE incidents ADD COLUMN snoozed_until timestamptz")
    op.execute("ALTER TABLE incidents ADD COLUMN snoozed_by text")
    op.execute("ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check")
    op.execute(
        f"ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_check CHECK (kind IN ({_in(EVENT_KINDS)}))"
    )


def downgrade() -> None:
    op.execute("DELETE FROM incident_events WHERE kind IN ('snoozed', 'unsnoozed')")
    op.execute("ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check")
    op.execute(
        f"ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_check CHECK (kind IN ({_in(EVENT_KINDS[:-2])}))"
    )
    op.execute("ALTER TABLE incidents DROP COLUMN snoozed_by")
    op.execute("ALTER TABLE incidents DROP COLUMN snoozed_until")
    op.execute("ALTER TABLE checks DROP COLUMN slo_target")
