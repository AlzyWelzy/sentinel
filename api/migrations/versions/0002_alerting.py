"""Alerting: rules, per-host alert state, incidents, an outbound message queue,
and contact verification for notification channels.

Same isolation model as 0001: every table has tenant_id and an RLS policy.
The alerter connects as pulsegrid_service (it evaluates every tenant's rules),
so its grants are listed explicitly at the bottom.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-24
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"

NEW_TABLES = (
    "alert_rules",
    "alert_rule_channels",
    "alert_states",
    "incidents",
    "outbound_messages",
)


def upgrade() -> None:
    op.execute("""
        CREATE TABLE alert_rules (
            id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id         uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            name              text NOT NULL,
            kind              text NOT NULL CHECK (kind IN ('metric', 'host_down')),
            metric            text CHECK (metric IN ('cpu', 'memory', 'swap', 'disk', 'load1', 'load5')),
            operator          text CHECK (operator IN ('>', '<')),
            threshold         double precision,
            duration_seconds  integer NOT NULL DEFAULT 300 CHECK (duration_seconds BETWEEN 0 AND 86400),
            -- NULL: applies to every host the tenant has, including ones added later.
            host_id           uuid REFERENCES hosts (id) ON DELETE CASCADE,
            enabled           boolean NOT NULL DEFAULT true,
            created_at        timestamptz NOT NULL DEFAULT now(),
            updated_at        timestamptz NOT NULL DEFAULT now(),
            CHECK (kind <> 'metric' OR (metric IS NOT NULL AND operator IS NOT NULL AND threshold IS NOT NULL))
        )
    """)
    op.execute("CREATE INDEX ix_alert_rules_tenant ON alert_rules (tenant_id)")

    op.execute("""
        CREATE TABLE alert_rule_channels (
            rule_id     uuid NOT NULL REFERENCES alert_rules (id) ON DELETE CASCADE,
            channel_id  uuid NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
            tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            PRIMARY KEY (rule_id, channel_id)
        )
    """)

    op.execute("""
        CREATE TABLE incidents (
            id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id        uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            rule_id          uuid REFERENCES alert_rules (id) ON DELETE SET NULL,
            host_id          uuid REFERENCES hosts (id) ON DELETE SET NULL,
            status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
            summary          text NOT NULL,
            rule_name        text NOT NULL,
            hostname         text NOT NULL,
            value            double precision,
            opened_at        timestamptz NOT NULL DEFAULT now(),
            acknowledged_at  timestamptz,
            resolved_at      timestamptz
        )
    """)
    op.execute("CREATE INDEX ix_incidents_tenant_opened ON incidents (tenant_id, opened_at DESC)")

    # One row per (rule, host) the alerter has evaluated: where it is in
    # OK -> PENDING -> FIRING, and since when.
    op.execute("""
        CREATE TABLE alert_states (
            rule_id      uuid NOT NULL REFERENCES alert_rules (id) ON DELETE CASCADE,
            host_id      uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
            tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            state        text NOT NULL CHECK (state IN ('ok', 'pending', 'firing')),
            since        timestamptz NOT NULL DEFAULT now(),
            last_value   double precision,
            incident_id  uuid REFERENCES incidents (id) ON DELETE SET NULL,
            updated_at   timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (rule_id, host_id)
        )
    """)

    # Outbox: everything Pulsegrid sends (alerts, verification codes, tests)
    # is a row here first, so a crash or a down mail server loses nothing and
    # the dispatcher can retry with backoff.
    op.execute("""
        CREATE TABLE outbound_messages (
            id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id        uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            channel_id       uuid REFERENCES notification_channels (id) ON DELETE CASCADE,
            incident_id      uuid REFERENCES incidents (id) ON DELETE SET NULL,
            kind             text NOT NULL
                             CHECK (kind IN ('alert_firing', 'alert_resolved', 'verification', 'test')),
            payload          jsonb NOT NULL,
            status           text NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending', 'sent', 'failed')),
            attempts         integer NOT NULL DEFAULT 0,
            last_error       text,
            next_attempt_at  timestamptz NOT NULL DEFAULT now(),
            created_at       timestamptz NOT NULL DEFAULT now(),
            sent_at          timestamptz
        )
    """)
    op.execute(
        "CREATE INDEX ix_outbound_pending ON outbound_messages (next_attempt_at) "
        "WHERE status = 'pending'"
    )

    op.execute("""
        ALTER TABLE notification_channels
            ADD COLUMN verification_code_hash text,
            ADD COLUMN verification_sent_at   timestamptz,
            ADD COLUMN verification_attempts  integer NOT NULL DEFAULT 0
    """)

    for table in NEW_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = {CURRENT_TENANT}) "
            f"WITH CHECK (tenant_id = {CURRENT_TENANT})"
        )

    # API (customer requests, RLS applies).
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON alert_rules, alert_rule_channels TO pulsegrid_app"
    )
    # DELETE: changing or disabling a rule clears its evaluation state.
    op.execute("GRANT SELECT, DELETE ON alert_states TO pulsegrid_app")
    op.execute("GRANT SELECT, UPDATE ON incidents TO pulsegrid_app")
    op.execute("GRANT SELECT, INSERT ON outbound_messages TO pulsegrid_app")

    # Alerter (pulsegrid_service, cross-tenant).
    op.execute("GRANT SELECT ON alert_rules, alert_rule_channels TO pulsegrid_service")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON alert_states, incidents, outbound_messages "
        "TO pulsegrid_service"
    )


def downgrade() -> None:
    op.execute("""
        ALTER TABLE notification_channels
            DROP COLUMN verification_code_hash,
            DROP COLUMN verification_sent_at,
            DROP COLUMN verification_attempts
    """)
    op.execute(
        "DROP TABLE outbound_messages, alert_states, incidents, alert_rule_channels, alert_rules"
    )
