"""Reminders: an open incident nobody has acknowledged is sent again to the
rule's contacts every few hours (the organisation's reminder_minutes, 240 by
default; 0 turns reminders off).

Revision ID: 0031
Revises: 0030
Create Date: 2026-11-20
"""

from alembic import op

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None

MESSAGE_KINDS = [
    "alert_firing",
    "alert_resolved",
    "alert_escalation",
    "verification",
    "test",
    "report",
    "action",
    "digest",
]
EVENT_KINDS = [
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
    "assigned",
]


def _in(kinds: list[str]) -> str:
    return ", ".join(f"'{k}'" for k in kinds)


def upgrade() -> None:
    op.execute(
        "ALTER TABLE tenants ADD COLUMN reminder_minutes integer NOT NULL DEFAULT 240"
        " CHECK (reminder_minutes = 0 OR reminder_minutes BETWEEN 30 AND 10080)"
    )
    # The API updates tenants column by column.
    op.execute("GRANT UPDATE (reminder_minutes) ON tenants TO sentinel_app")
    op.execute(
        "ALTER TABLE incidents ADD COLUMN reminded_at timestamptz,"
        " ADD COLUMN reminders_sent integer NOT NULL DEFAULT 0"
    )
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_kind_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_kind_check"
        f" CHECK (kind IN ({_in([*MESSAGE_KINDS, 'alert_reminder'])}))"
    )
    op.execute("ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check")
    op.execute(
        "ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_check"
        f" CHECK (kind IN ({_in([*EVENT_KINDS, 'reminded'])}))"
    )


def downgrade() -> None:
    op.execute("DELETE FROM incident_events WHERE kind = 'reminded'")
    op.execute("ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check")
    op.execute(
        "ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_check"
        f" CHECK (kind IN ({_in(EVENT_KINDS)}))"
    )
    op.execute("DELETE FROM outbound_messages WHERE kind = 'alert_reminder'")
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_kind_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_kind_check"
        f" CHECK (kind IN ({_in(MESSAGE_KINDS)}))"
    )
    op.execute("ALTER TABLE incidents DROP COLUMN reminders_sent, DROP COLUMN reminded_at")
    op.execute("ALTER TABLE tenants DROP COLUMN reminder_minutes")
