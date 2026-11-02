"""On-call: rotating schedules of responders (each responder is one or more
alert contacts), temporary overrides, rules and escalation steps that notify
whoever is on call, quiet hours per contact, and when a held message is due.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-26
"""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def _rls(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {table} "
        f"USING (tenant_id = {CURRENT_TENANT}) WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO sentinel_app")
    op.execute(f"GRANT SELECT ON {table} TO sentinel_service")


def upgrade() -> None:
    # Shifts follow each other every shift_hours from start_at; responders
    # take turns in order: [{"name": "Asha", "channel_ids": ["…"]}].
    op.execute("""
        CREATE TABLE oncall_schedules (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
            timezone     text NOT NULL DEFAULT 'UTC',
            start_at     timestamptz NOT NULL,
            shift_hours  integer NOT NULL CHECK (shift_hours BETWEEN 1 AND 2160),
            responders   jsonb NOT NULL DEFAULT '[]',
            created_at   timestamptz NOT NULL DEFAULT now(),
            updated_at   timestamptz NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, name)
        )
    """)
    _rls("oncall_schedules")
    op.execute("""
        CREATE TABLE oncall_overrides (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            schedule_id  uuid NOT NULL REFERENCES oncall_schedules(id) ON DELETE CASCADE,
            starts_at    timestamptz NOT NULL,
            ends_at      timestamptz NOT NULL CHECK (ends_at > starts_at),
            responder    jsonb NOT NULL,
            note         text,
            created_by   text,
            created_at   timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ix_oncall_overrides ON oncall_overrides (schedule_id, ends_at)")
    _rls("oncall_overrides")

    op.execute("ALTER TABLE alert_rules ADD COLUMN schedule_ids uuid[] NOT NULL DEFAULT '{}'")
    op.execute(
        "ALTER TABLE alert_escalation_steps ADD COLUMN schedule_ids uuid[] NOT NULL DEFAULT '{}'"
    )
    # A step notifies contacts, a schedule, or both.
    op.execute(
        "ALTER TABLE alert_escalation_steps DROP CONSTRAINT alert_escalation_steps_channel_ids_check"
    )
    op.execute(
        "ALTER TABLE alert_escalation_steps ADD CONSTRAINT alert_escalation_steps_target_check "
        "CHECK (cardinality(channel_ids) > 0 OR cardinality(schedule_ids) > 0)"
    )
    # {"start": "22:00", "end": "07:00", "timezone": "Asia/Kolkata",
    #  "critical_breaks_through": true}: alerts wait until the end.
    op.execute("ALTER TABLE notification_channels ADD COLUMN quiet_hours jsonb")
    op.execute("ALTER TABLE outbound_messages ADD COLUMN held_until timestamptz")
    # skipped: held for quiet hours, and the incident resolved meanwhile.
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_status_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_status_check "
        "CHECK (status IN ('pending', 'sent', 'failed', 'skipped'))"
    )


def downgrade() -> None:
    op.execute("UPDATE outbound_messages SET status = 'failed' WHERE status = 'skipped'")
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_status_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_status_check "
        "CHECK (status IN ('pending', 'sent', 'failed'))"
    )
    op.execute("ALTER TABLE outbound_messages DROP COLUMN held_until")
    op.execute("ALTER TABLE notification_channels DROP COLUMN quiet_hours")
    op.execute("DELETE FROM alert_escalation_steps WHERE cardinality(channel_ids) = 0")
    op.execute(
        "ALTER TABLE alert_escalation_steps DROP CONSTRAINT alert_escalation_steps_target_check"
    )
    op.execute(
        "ALTER TABLE alert_escalation_steps ADD CONSTRAINT alert_escalation_steps_channel_ids_check "
        "CHECK (cardinality(channel_ids) > 0)"
    )
    op.execute("ALTER TABLE alert_escalation_steps DROP COLUMN schedule_ids")
    op.execute("ALTER TABLE alert_rules DROP COLUMN schedule_ids")
    op.execute("DROP TABLE oncall_overrides")
    op.execute("DROP TABLE oncall_schedules")
