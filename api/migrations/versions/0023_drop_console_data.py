"""Drop what only the console used.

- external_monitors (Uptime Kuma monitors synced by the console) and status
  page items showing them. Status pages show servers and Sentinel's own
  probe checks.
- Contacts the console created are 'account' contacts now (the
  organisation's own email); 'team' contacts are members' emails, added
  when they join.

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-02
"""

from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM status_page_items WHERE external_key IS NOT NULL")
    op.execute("ALTER TABLE status_page_items DROP CONSTRAINT status_page_items_check")
    op.execute(
        "ALTER TABLE status_page_items ADD CONSTRAINT status_page_items_check "
        "CHECK (num_nonnulls(host_id, check_id) = 1)"
    )
    op.execute("ALTER TABLE status_page_items DROP COLUMN external_key")
    op.execute("DROP TABLE external_monitors")

    op.execute(
        "ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_source_check"
    )
    op.execute("UPDATE notification_channels SET source = 'account' WHERE source = 'console'")
    op.execute(
        "ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_source_check "
        "CHECK (source IN ('account', 'user', 'team'))"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_source_check"
    )
    op.execute("UPDATE notification_channels SET source = 'console' WHERE source = 'account'")
    op.execute(
        "ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_source_check "
        "CHECK (source IN ('console', 'user', 'team'))"
    )
    op.execute("""
        CREATE TABLE external_monitors (
            tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            key          text NOT NULL,
            name         text NOT NULL,
            kind         text,
            status       text NOT NULL,
            uptime_24h   double precision,
            uptime_30d   double precision,
            response_ms  double precision,
            daily        jsonb NOT NULL DEFAULT '[]',
            updated_at   timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, key)
        )
    """)
    op.execute("ALTER TABLE status_page_items ADD COLUMN external_key text")
    op.execute("ALTER TABLE status_page_items DROP CONSTRAINT status_page_items_check")
    op.execute(
        "ALTER TABLE status_page_items ADD CONSTRAINT status_page_items_check "
        "CHECK (num_nonnulls(host_id, check_id, external_key) = 1)"
    )
