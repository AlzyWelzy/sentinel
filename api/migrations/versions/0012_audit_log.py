"""Audit log: every change made through the API or by staff, with who did
it. Tenants read their own events; staff events about no account
(rollouts, probes) have no tenant and only staff see them.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-26
"""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.execute("""
        CREATE TABLE audit_events (
            id          bigserial PRIMARY KEY,
            tenant_id   uuid REFERENCES tenants(id) ON DELETE CASCADE,
            actor       text NOT NULL,
            actor_kind  text NOT NULL
                        CHECK (actor_kind IN ('owner', 'member', 'api_token', 'staff', 'system')),
            action      text NOT NULL,
            summary     text NOT NULL,
            target_id   text,
            method      text,
            path        text,
            details     jsonb NOT NULL DEFAULT '{}',
            ip          text,
            created_at  timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ix_audit_tenant_time ON audit_events (tenant_id, created_at DESC)")
    op.execute("CREATE INDEX ix_audit_time ON audit_events (created_at DESC)")
    op.execute("ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON audit_events "
        f"USING (tenant_id = {CURRENT_TENANT}) WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )
    op.execute("GRANT SELECT, INSERT ON audit_events TO pulsegrid_app, pulsegrid_service")
    op.execute(
        "GRANT USAGE ON SEQUENCE audit_events_id_seq TO pulsegrid_app, pulsegrid_service"
    )
    op.execute("GRANT DELETE ON audit_events TO pulsegrid_service")  # retention cleanup


def downgrade() -> None:
    op.execute("DROP TABLE audit_events")
