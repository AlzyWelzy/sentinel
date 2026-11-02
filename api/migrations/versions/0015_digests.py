"""Digest emails: a daily or weekly summary (incidents, response times,
noisy rules, what's still open, SLOs) at the hour the account picks.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-26
"""

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE tenants
            ADD COLUMN digest text NOT NULL DEFAULT 'weekly'
                CHECK (digest IN ('off', 'daily', 'weekly')),
            -- When it goes out, in the account's own time zone.
            ADD COLUMN digest_hour smallint NOT NULL DEFAULT 9 CHECK (digest_hour BETWEEN 0 AND 23),
            ADD COLUMN digest_timezone text NOT NULL DEFAULT 'Asia/Kolkata',
            ADD COLUMN digest_sent_at timestamptz
    """)
    op.execute("GRANT UPDATE (digest, digest_hour, digest_timezone) ON tenants TO sentinel_app")
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_kind_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_kind_check CHECK (kind IN "
        "('alert_firing', 'alert_resolved', 'alert_escalation', 'verification', 'test', "
        "'report', 'action', 'digest'))"
    )


def downgrade() -> None:
    op.execute("DELETE FROM outbound_messages WHERE kind = 'digest'")
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_kind_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_kind_check CHECK (kind IN "
        "('alert_firing', 'alert_resolved', 'alert_escalation', 'verification', 'test', "
        "'report', 'action'))"
    )
    op.execute(
        "ALTER TABLE tenants DROP COLUMN digest, DROP COLUMN digest_hour, "
        "DROP COLUMN digest_timezone, DROP COLUMN digest_sent_at"
    )
