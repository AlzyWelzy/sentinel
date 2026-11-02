"""Logs move to VictoriaLogs: each tenant gets a numeric VictoriaLogs account
(its AccountID header), log-count alert rules keep their filter, and saved
views remember a search or a list's filters by name.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-25
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
RULE_KINDS = (
    "metric",
    "host_down",
    "process_down",
    "service_down",
    "check",
    "anomaly",
    "forecast",
    "plugin_down",
    "container_down",
    "custom",
    "logs",
)


def _in(values) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    # AccountID 0 is VictoriaLogs' default account: never hand it out.
    op.execute("CREATE SEQUENCE tenants_logs_account_id_seq START 1 MAXVALUE 4294967295")
    op.execute(
        "ALTER TABLE tenants ADD COLUMN logs_account_id bigint NOT NULL "
        "DEFAULT nextval('tenants_logs_account_id_seq') UNIQUE"
    )
    op.execute("ALTER SEQUENCE tenants_logs_account_id_seq OWNED BY tenants.logs_account_id")
    op.execute("GRANT USAGE ON SEQUENCE tenants_logs_account_id_seq TO sentinel_service")

    # kind = 'logs': fires when more lines than the threshold match the filter
    # within window_seconds. log_filter is the validated filter as the
    # dashboard edits it; target holds the LogsQL built from it.
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check")
    op.execute(f"""
        ALTER TABLE alert_rules
            ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ({_in(RULE_KINDS)})),
            ADD COLUMN log_filter jsonb,
            ADD CONSTRAINT alert_rules_logs_check
                CHECK (kind <> 'logs' OR (log_filter IS NOT NULL AND target IS NOT NULL
                                          AND threshold IS NOT NULL))
    """)

    op.execute("""
        CREATE TABLE saved_views (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            kind        text NOT NULL CHECK (kind IN ('logs', 'servers', 'incidents', 'checks')),
            name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
            params      jsonb NOT NULL DEFAULT '{}',
            created_by  text,
            created_at  timestamptz NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, kind, name)
        )
    """)
    op.execute("ALTER TABLE saved_views ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON saved_views "
        f"USING (tenant_id = {CURRENT_TENANT}) WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON saved_views TO sentinel_app")


def downgrade() -> None:
    op.execute("DROP TABLE saved_views")
    op.execute("DELETE FROM alert_rules WHERE kind = 'logs'")
    op.execute("ALTER TABLE alert_rules DROP COLUMN log_filter")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check")
    op.execute(
        "ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_kind_check "
        f"CHECK (kind IN ({_in(RULE_KINDS[:-1])}))"
    )
    op.execute("ALTER TABLE tenants DROP COLUMN logs_account_id")
