"""Deeper monitoring and alerting.

- Hosts: tags, a host they depend on, and what the agent reports about the
  machine (IP addresses, CPU cores, memory).
- Alert rules: process and service checks (target = the name to watch), new
  metrics (iowait, steal, inodes, disk busy), scoping to a tag, and
  escalation steps for incidents nobody acknowledges.
- Incidents: escalation progress, and who acknowledged (the dashboard or the
  one-click link in an alert; that link is signed, not stored).
- Channels: Slack, Microsoft Teams, Telegram, Discord, PagerDuty and voice.
- Maintenance windows, one-off or weekly, that hold back alerts.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-24
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"

CHANNEL_TYPES = (
    "email",
    "sms",
    "webhook",
    "slack",
    "teams",
    "telegram",
    "discord",
    "pagerduty",
    "voice",
)
RULE_KINDS = ("metric", "host_down", "process_down", "service_down")
RULE_METRICS = (
    "cpu",
    "memory",
    "swap",
    "disk",
    "load1",
    "load5",
    "iowait",
    "steal",
    "inodes",
    "disk_busy",
)
MESSAGE_KINDS = ("alert_firing", "alert_resolved", "alert_escalation", "verification", "test")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _rls(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {table} "
        f"USING (tenant_id = {CURRENT_TENANT}) "
        f"WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )


def upgrade() -> None:
    # ── Hosts ────────────────────────────────────────────────────────────────
    op.execute("""
        ALTER TABLE hosts
            ADD COLUMN tags               text[] NOT NULL DEFAULT '{}',
            -- Alerts for this host are held back while that host is silent
            -- (a gateway or hypervisor: when it's down, everything behind it is).
            ADD COLUMN depends_on_host_id uuid REFERENCES hosts (id) ON DELETE SET NULL,
            ADD COLUMN ip_addresses       text[] NOT NULL DEFAULT '{}',
            ADD COLUMN cpu_cores          integer,
            ADD COLUMN memory_bytes       bigint,
            ADD CHECK (depends_on_host_id IS DISTINCT FROM id)
    """)
    op.execute("CREATE INDEX ix_hosts_tags ON hosts USING gin (tags)")

    # ── Alert rules ──────────────────────────────────────────────────────────
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check")
    op.execute(f"""
        ALTER TABLE alert_rules
            ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ({_in(RULE_KINDS)})),
            ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN ({_in(RULE_METRICS)})),
            -- The process or service a process_down / service_down rule watches.
            ADD COLUMN target text,
            -- Scope: every host (both NULL), one host, or every host with this tag.
            ADD COLUMN tag text,
            ADD CONSTRAINT alert_rules_target_check
                CHECK ((kind IN ('process_down', 'service_down')) = (target IS NOT NULL)),
            ADD CONSTRAINT alert_rules_scope_check CHECK (host_id IS NULL OR tag IS NULL)
    """)

    op.execute("""
        CREATE TABLE alert_escalation_steps (
            id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            rule_id        uuid NOT NULL REFERENCES alert_rules (id) ON DELETE CASCADE,
            tenant_id      uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            position       integer NOT NULL,
            -- Measured from when the incident opened.
            delay_seconds  integer NOT NULL CHECK (delay_seconds BETWEEN 60 AND 604800),
            -- Checked against notification_channels (same tenant, verified) at
            -- send time; a deleted channel is simply skipped.
            channel_ids    uuid[] NOT NULL CHECK (cardinality(channel_ids) > 0),
            UNIQUE (rule_id, position)
        )
    """)
    _rls("alert_escalation_steps")

    # ── Incidents ────────────────────────────────────────────────────────────
    op.execute("""
        ALTER TABLE incidents
            ADD COLUMN escalation_level integer NOT NULL DEFAULT 0,
            ADD COLUMN acknowledged_by  text
    """)
    op.execute(
        "CREATE INDEX ix_incidents_escalating ON incidents (opened_at) "
        "WHERE status = 'open' AND acknowledged_at IS NULL"
    )

    # ── Channels and the outbox ──────────────────────────────────────────────
    op.execute("ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_type_check")
    op.execute(
        "ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check "
        f"CHECK (type IN ({_in(CHANNEL_TYPES)}))"
    )
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_kind_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_kind_check "
        f"CHECK (kind IN ({_in(MESSAGE_KINDS)}))"
    )

    # ── Maintenance windows ──────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE maintenance_windows (
            id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id         uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            name              text NOT NULL,
            -- Scope, as for alert rules: every host, one host, or a tag.
            host_id           uuid REFERENCES hosts (id) ON DELETE CASCADE,
            tag               text,
            schedule          text NOT NULL CHECK (schedule IN ('once', 'weekly')),
            -- once: [starts_at, ends_at)
            starts_at         timestamptz,
            ends_at           timestamptz,
            -- weekly: on these ISO weekdays (1 = Monday) at start_time in
            -- timezone, for duration_minutes.
            weekdays          integer[],
            start_time        time,
            duration_minutes  integer CHECK (duration_minutes BETWEEN 1 AND 10080),
            timezone          text NOT NULL DEFAULT 'UTC',
            enabled           boolean NOT NULL DEFAULT true,
            created_at        timestamptz NOT NULL DEFAULT now(),
            CHECK (host_id IS NULL OR tag IS NULL),
            CHECK (schedule <> 'once' OR (starts_at IS NOT NULL AND ends_at > starts_at)),
            CHECK (schedule <> 'weekly' OR (cardinality(weekdays) > 0 AND start_time IS NOT NULL
                                            AND duration_minutes IS NOT NULL))
        )
    """)
    op.execute("CREATE INDEX ix_maintenance_tenant ON maintenance_windows (tenant_id)")
    _rls("maintenance_windows")

    # ── Grants ───────────────────────────────────────────────────────────────
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON alert_escalation_steps, maintenance_windows "
        "TO pulsegrid_app"
    )
    op.execute("GRANT SELECT ON alert_escalation_steps, maintenance_windows TO pulsegrid_service")


def downgrade() -> None:
    op.execute("DROP TABLE maintenance_windows")
    op.execute("DELETE FROM outbound_messages WHERE kind = 'alert_escalation'")
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_kind_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_kind_check "
        f"CHECK (kind IN ({_in(MESSAGE_KINDS[:2] + MESSAGE_KINDS[3:])}))"
    )
    op.execute("DELETE FROM notification_channels WHERE type NOT IN ('email', 'sms', 'webhook')")
    op.execute("ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_type_check")
    op.execute(
        "ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check "
        "CHECK (type IN ('email', 'sms', 'webhook'))"
    )
    op.execute("DROP INDEX ix_incidents_escalating")
    op.execute("ALTER TABLE incidents DROP COLUMN escalation_level, DROP COLUMN acknowledged_by")
    op.execute("DROP TABLE alert_escalation_steps")
    op.execute(
        "DELETE FROM alert_rules WHERE kind IN ('process_down', 'service_down') "
        "OR metric IN ('iowait', 'steal', 'inodes', 'disk_busy') OR tag IS NOT NULL"
    )
    op.execute(
        "ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_target_check, "
        "DROP CONSTRAINT alert_rules_scope_check, DROP COLUMN target, DROP COLUMN tag"
    )
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check")
    op.execute(
        "ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_kind_check "
        "CHECK (kind IN ('metric', 'host_down'))"
    )
    op.execute(
        "ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check "
        "CHECK (metric IN ('cpu', 'memory', 'swap', 'disk', 'load1', 'load5'))"
    )
    op.execute("DROP INDEX ix_hosts_tags")
    op.execute(
        "ALTER TABLE hosts DROP COLUMN tags, DROP COLUMN depends_on_host_id, "
        "DROP COLUMN ip_addresses, DROP COLUMN cpu_cores, DROP COLUMN memory_bytes"
    )
