"""Custom dashboards: named boards of charts, each comparing a metric across
chosen servers (or every server with a tag).

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-26
"""

from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.execute("""
        CREATE TABLE dashboards (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
            panels      jsonb NOT NULL DEFAULT '[]',
            created_by  text,
            created_at  timestamptz NOT NULL DEFAULT now(),
            updated_at  timestamptz NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, name)
        )
    """)
    op.execute("ALTER TABLE dashboards ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON dashboards "
        f"USING (tenant_id = {CURRENT_TENANT}) WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON dashboards TO sentinel_app")


def downgrade() -> None:
    op.execute("DROP TABLE dashboards")
