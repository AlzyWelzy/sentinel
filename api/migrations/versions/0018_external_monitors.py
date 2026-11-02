"""Uptime monitors that run elsewhere (the console's Uptime Kuma monitors),
kept in step by the console, so one status page can show servers, probe
checks and those monitors together.

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-26
"""

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.execute("""
        CREATE TABLE external_monitors (
            tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            key          text NOT NULL CHECK (key ~ '^[a-z]+:[A-Za-z0-9_-]{1,64}$'),
            name         text NOT NULL,
            kind         text,
            status       text NOT NULL CHECK (status IN ('up', 'down', 'pending', 'maintenance', 'paused', 'unknown')),
            uptime_24h   double precision,
            uptime_30d   double precision,
            response_ms  double precision,
            -- [{"date": "2026-10-26", "uptime": 99.9}], oldest first, 90 days.
            daily        jsonb NOT NULL DEFAULT '[]',
            updated_at   timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (tenant_id, key)
        )
    """)
    op.execute("ALTER TABLE external_monitors ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON external_monitors "
        f"USING (tenant_id = {CURRENT_TENANT}) WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )
    op.execute("GRANT SELECT ON external_monitors TO sentinel_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON external_monitors TO sentinel_service")
    op.execute("ALTER TABLE status_page_items ADD COLUMN external_key text")
    op.execute("ALTER TABLE status_page_items DROP CONSTRAINT status_page_items_check")
    op.execute(
        "ALTER TABLE status_page_items ADD CONSTRAINT status_page_items_check "
        "CHECK (num_nonnulls(host_id, check_id, external_key) = 1)"
    )


def downgrade() -> None:
    op.execute("DELETE FROM status_page_items WHERE external_key IS NOT NULL")
    op.execute("ALTER TABLE status_page_items DROP CONSTRAINT status_page_items_check")
    op.execute(
        "ALTER TABLE status_page_items ADD CONSTRAINT status_page_items_check "
        "CHECK (num_nonnulls(host_id, check_id) = 1)"
    )
    op.execute("ALTER TABLE status_page_items DROP COLUMN external_key")
    op.execute("DROP TABLE external_monitors")
