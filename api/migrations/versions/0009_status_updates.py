"""Status page announcements: incident updates and planned maintenance that
the owner writes for their visitors.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-25
"""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.execute("""
        CREATE TABLE status_page_updates (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            page_id     uuid NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
            kind        text NOT NULL CHECK (kind IN ('incident', 'maintenance', 'info')),
            state       text NOT NULL CHECK (state IN (
                            'investigating', 'identified', 'monitoring', 'resolved',
                            'scheduled', 'in_progress', 'completed', 'posted')),
            title       text NOT NULL,
            body        text NOT NULL DEFAULT '',
            starts_at   timestamptz,
            ends_at     timestamptz,
            created_at  timestamptz NOT NULL DEFAULT now(),
            updated_at  timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ix_status_page_updates ON status_page_updates (page_id, created_at)")
    op.execute("ALTER TABLE status_page_updates ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON status_page_updates "
        f"USING (tenant_id = {CURRENT_TENANT}) WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON status_page_updates TO pulsegrid_app")
    op.execute("GRANT SELECT ON status_page_updates TO pulsegrid_service")


def downgrade() -> None:
    op.execute("DROP TABLE status_page_updates")
