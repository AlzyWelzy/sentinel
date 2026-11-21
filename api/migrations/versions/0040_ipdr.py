"""IPDR per organisation: settings on the tenant (on/off, retention, the
server that collects evidence, extra allowed senders), the investigator and
auditor roles, and the integrity records: a hash-chained audit of every
search and export, exports that may need a second person's approval, and
daily seals over each evidence table. Evidence itself is in ClickHouse.

The app role can add audit rows and seals but never change or delete them.

Revision ID: 0040
Revises: 0039
Create Date: 2026-11-21
"""

from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def _rls(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {table} "
        f"USING (tenant_id = {CURRENT_TENANT}) WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )


def upgrade() -> None:
    op.execute("""
        ALTER TABLE tenants
            ADD COLUMN ipdr_enabled boolean NOT NULL DEFAULT false,
            ADD COLUMN ipdr_retention_days integer NOT NULL DEFAULT 365
                CHECK (ipdr_retention_days BETWEEN 30 AND 2000),
            ADD COLUMN ipdr_collector_host_id uuid REFERENCES hosts (id) ON DELETE SET NULL,
            ADD COLUMN ipdr_allow text[] NOT NULL DEFAULT '{}',
            ADD COLUMN ipdr_export_approval_rows integer NOT NULL DEFAULT 100000
                CHECK (ipdr_export_approval_rows BETWEEN 1000 AND 5000000)
    """)
    op.execute(
        "GRANT UPDATE (ipdr_enabled, ipdr_retention_days, ipdr_collector_host_id, ipdr_allow,"
        " ipdr_export_approval_rows) ON tenants TO sentinel_app"
    )

    op.execute("ALTER TABLE tenant_members DROP CONSTRAINT tenant_members_role_check")
    op.execute(
        "ALTER TABLE tenant_members ADD CONSTRAINT tenant_members_role_check"
        " CHECK (role IN ('viewer', 'operator', 'admin', 'owner', 'investigator', 'auditor'))"
    )

    op.execute("""
        CREATE TABLE ipdr_audit (
            id          bigserial PRIMARY KEY,
            tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            seq         bigint NOT NULL,
            at          timestamptz NOT NULL DEFAULT now(),
            user_id     uuid,
            actor       text NOT NULL,
            action      text NOT NULL,
            reason      text NOT NULL DEFAULT '',
            params      jsonb NOT NULL DEFAULT '{}',
            result_rows bigint,
            prev_hash   text NOT NULL,
            hash        text NOT NULL,
            UNIQUE (tenant_id, seq)
        )
    """)
    _rls("ipdr_audit")
    op.execute("GRANT SELECT, INSERT ON ipdr_audit TO sentinel_app")
    op.execute("GRANT SELECT, INSERT ON ipdr_audit TO sentinel_service")
    op.execute("GRANT USAGE ON SEQUENCE ipdr_audit_id_seq TO sentinel_app, sentinel_service")

    op.execute("""
        CREATE TABLE ipdr_exports (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            requested_by  uuid,
            requester     text NOT NULL,
            reason        text NOT NULL,
            params        jsonb NOT NULL,
            row_count     bigint NOT NULL,
            status        text NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'ready', 'failed')),
            decided_by    text,
            decided_at    timestamptz,
            file          bytea,
            sha256        text,
            created_at    timestamptz NOT NULL DEFAULT now(),
            expires_at    timestamptz NOT NULL DEFAULT now() + interval '7 days'
        )
    """)
    _rls("ipdr_exports")
    op.execute("GRANT SELECT, INSERT, UPDATE ON ipdr_exports TO sentinel_app")
    op.execute("GRANT SELECT, UPDATE, DELETE ON ipdr_exports TO sentinel_service")

    op.execute("""
        CREATE TABLE ipdr_seals (
            id          bigserial PRIMARY KEY,
            tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            day         date NOT NULL,
            tbl         text NOT NULL,
            row_count   bigint NOT NULL,
            digest      text NOT NULL,
            audit_head  text NOT NULL,
            prev_hash   text NOT NULL,
            hash        text NOT NULL,
            created_at  timestamptz NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, day, tbl)
        )
    """)
    _rls("ipdr_seals")
    op.execute("GRANT SELECT ON ipdr_seals TO sentinel_app")
    op.execute("GRANT SELECT, INSERT ON ipdr_seals TO sentinel_service")
    op.execute("GRANT USAGE ON SEQUENCE ipdr_seals_id_seq TO sentinel_service")


def downgrade() -> None:
    op.execute("DROP TABLE ipdr_seals")
    op.execute("DROP TABLE ipdr_exports")
    op.execute("DROP TABLE ipdr_audit")
    op.execute(
        "UPDATE tenant_members SET role = 'viewer' WHERE role IN ('investigator', 'auditor')"
    )
    op.execute("ALTER TABLE tenant_members DROP CONSTRAINT tenant_members_role_check")
    op.execute(
        "ALTER TABLE tenant_members ADD CONSTRAINT tenant_members_role_check"
        " CHECK (role IN ('viewer', 'operator', 'admin', 'owner'))"
    )
    op.execute(
        "REVOKE UPDATE (ipdr_enabled, ipdr_retention_days, ipdr_collector_host_id, ipdr_allow,"
        " ipdr_export_approval_rows) ON tenants FROM sentinel_app"
    )
    op.execute("""
        ALTER TABLE tenants DROP COLUMN ipdr_enabled, DROP COLUMN ipdr_retention_days,
            DROP COLUMN ipdr_collector_host_id, DROP COLUMN ipdr_allow,
            DROP COLUMN ipdr_export_approval_rows
    """)
