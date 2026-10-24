"""Checks, probes, smarter alerting, incident timeline, push, actions,
inventory, API tokens, status pages and reports.

- checks: ports, URLs, certificates, DNS, files and log patterns. A check
  runs on one host, on every host with a tag, or (uptime checks) on the
  public probes, from several locations.
- hosts.probe_region: staff mark their own agents as probes.
- alert rules: kinds check, anomaly, forecast, plugin_down, container_down
  and custom; an aggregation over a window ("average over 5 minutes"), a
  recovery threshold (hysteresis), a severity, and an action to run on the
  host when the alert fires.
- incident_events: the incident timeline (fired, notified, escalated,
  acknowledged, resolved, reopened, notes, actions).
- notification_channels.config and type push (Web Push subscriptions).
- host_actions: actions requested from the dashboard or by a rule, and how
  they went. host_inventory: packages, listening ports, plugins.
- api_tokens: personal API tokens for the public API.
- status_pages / status_page_items: public pages showing hosts and checks.
- tenants: monthly report preference.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-25
"""

from alembic import op

revision = "0005"
down_revision = "0004"
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
    "push",
)
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
)
TARGET_KINDS = ("process_down", "service_down", "check", "container_down", "custom")
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
    "network_in",
    "network_out",
)
MESSAGE_KINDS = (
    "alert_firing",
    "alert_resolved",
    "alert_escalation",
    "verification",
    "test",
    "report",
    "action",
)
CHECK_TYPES = ("tcp", "http", "tls", "dns", "file", "log", "ping")
PROBE_CHECK_TYPES = ("tcp", "http", "tls", "dns", "ping")


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
    # ── Probes ───────────────────────────────────────────────────────────────
    op.execute("""
        ALTER TABLE hosts
            -- Non-null: this agent runs public uptime checks from that region.
            ADD COLUMN probe_region text,
            -- From the inventory: actions the host's allow-list permits.
            ADD COLUMN allowed_actions text[] NOT NULL DEFAULT '{}'
    """)
    op.execute("CREATE INDEX ix_hosts_probes ON hosts (probe_region) WHERE probe_region IS NOT NULL")

    # ── Checks ───────────────────────────────────────────────────────────────
    op.execute(f"""
        CREATE TABLE checks (
            id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id        uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
            type             text NOT NULL CHECK (type IN ({_in(CHECK_TYPES)})),
            target           text NOT NULL CHECK (length(target) BETWEEN 1 AND 2048),
            params           jsonb NOT NULL DEFAULT '{{}}',
            interval_seconds integer NOT NULL DEFAULT 60 CHECK (interval_seconds BETWEEN 10 AND 3600),
            -- Where it runs: one host, hosts with a tag, or the public probes.
            host_id          uuid REFERENCES hosts (id) ON DELETE CASCADE,
            tag              text,
            on_probes        boolean NOT NULL DEFAULT false,
            -- Probe checks: which regions (empty = all), and how many must
            -- fail before the check counts as down (stops one flaky route
            -- from paging anyone).
            probe_regions    text[] NOT NULL DEFAULT '{{}}',
            min_failing      integer NOT NULL DEFAULT 1 CHECK (min_failing BETWEEN 1 AND 10),
            enabled          boolean NOT NULL DEFAULT true,
            created_at       timestamptz NOT NULL DEFAULT now(),
            updated_at       timestamptz NOT NULL DEFAULT now(),
            CHECK (num_nonnulls(host_id, tag) + on_probes::int = 1),
            CHECK (NOT on_probes OR type IN ({_in(PROBE_CHECK_TYPES)}))
        )
    """)
    op.execute("CREATE INDEX ix_checks_tenant ON checks (tenant_id)")
    op.execute("CREATE INDEX ix_checks_host ON checks (host_id) WHERE host_id IS NOT NULL")
    op.execute("CREATE INDEX ix_checks_probes ON checks (tenant_id) WHERE on_probes")
    _rls("checks")

    # ── Alert rules ──────────────────────────────────────────────────────────
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_metric_check")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_target_check")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_check")
    op.execute(f"""
        ALTER TABLE alert_rules
            ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ({_in(RULE_KINDS)})),
            ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN ({_in(RULE_METRICS)})),
            ADD CONSTRAINT alert_rules_target_check
                CHECK ((kind IN ({_in(TARGET_KINDS)})) <= (target IS NOT NULL)),
            ADD CONSTRAINT alert_rules_metric_fields_check
                CHECK (kind NOT IN ('metric', 'custom')
                       OR (operator IS NOT NULL AND threshold IS NOT NULL
                           AND (kind = 'custom' OR metric IS NOT NULL))),
            ADD CONSTRAINT alert_rules_model_check
                CHECK (kind NOT IN ('anomaly', 'forecast') OR (metric IS NOT NULL AND threshold IS NOT NULL)),
            -- How the value is read: the latest sample, or the average,
            -- maximum or minimum over window_seconds ("CPU averaged over 5
            -- minutes above 90%" ignores short spikes).
            ADD COLUMN aggregation text NOT NULL DEFAULT 'last'
                CHECK (aggregation IN ('last', 'avg', 'max', 'min')),
            ADD COLUMN window_seconds integer NOT NULL DEFAULT 300
                CHECK (window_seconds BETWEEN 60 AND 86400),
            -- Hysteresis: once firing, resolve only past this value (e.g.
            -- fire above 90%, resolve below 80%), so it doesn't flap.
            ADD COLUMN recovery_threshold double precision,
            ADD COLUMN severity text NOT NULL DEFAULT 'critical'
                CHECK (severity IN ('critical', 'warning', 'info')),
            -- Run this allowed action on the host when the alert fires.
            ADD COLUMN action_name text CHECK (action_name ~ '^[a-z0-9][a-z0-9_.-]{{0,62}}$'),
            -- custom: label filters for the metric, {{"queue": "mail"}}.
            ADD COLUMN labels jsonb NOT NULL DEFAULT '{{}}',
            ADD COLUMN description text CHECK (length(description) <= 2000)
    """)

    # ── Alert states and incidents ───────────────────────────────────────────
    op.execute("""
        ALTER TABLE alert_states
            -- Recent transitions to firing, to detect flapping.
            ADD COLUMN flips timestamptz[] NOT NULL DEFAULT '{}'
    """)
    op.execute("""
        ALTER TABLE incidents
            ADD COLUMN severity text NOT NULL DEFAULT 'critical',
            ADD COLUMN detail text,
            ADD COLUMN flapping boolean NOT NULL DEFAULT false,
            ADD COLUMN reopened_count integer NOT NULL DEFAULT 0,
            ADD COLUMN resolved_by text
    """)
    op.execute("""
        CREATE TABLE incident_events (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            incident_id  uuid NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
            kind         text NOT NULL CHECK (kind IN ('opened', 'notified', 'escalated',
                             'acknowledged', 'resolved', 'reopened', 'note', 'action', 'flapping')),
            message      text NOT NULL CHECK (length(message) <= 5000),
            actor        text,
            created_at   timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ix_incident_events ON incident_events (incident_id, created_at)")
    _rls("incident_events")
    # Backfill a timeline for incidents that already exist.
    op.execute("""
        INSERT INTO incident_events (tenant_id, incident_id, kind, message, created_at)
        SELECT tenant_id, id, 'opened', summary, opened_at FROM incidents
        UNION ALL
        SELECT tenant_id, id, 'acknowledged', 'Acknowledged', acknowledged_at
          FROM incidents WHERE acknowledged_at IS NOT NULL
        UNION ALL
        SELECT tenant_id, id, 'resolved', 'Resolved', resolved_at
          FROM incidents WHERE resolved_at IS NOT NULL
    """)

    # ── Channels and the outbox ──────────────────────────────────────────────
    op.execute("ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_type_check")
    op.execute(
        "ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check "
        f"CHECK (type IN ({_in(CHANNEL_TYPES)}))"
    )
    op.execute("""
        ALTER TABLE notification_channels
            -- push: the subscription's keys ({"p256dh": ..., "auth": ...}).
            ADD COLUMN config jsonb NOT NULL DEFAULT '{}',
            -- Which severities this contact receives.
            ADD COLUMN min_severity text NOT NULL DEFAULT 'info'
                CHECK (min_severity IN ('critical', 'warning', 'info'))
    """)
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_kind_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_kind_check "
        f"CHECK (kind IN ({_in(MESSAGE_KINDS)}))"
    )

    # ── Actions and inventory ────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE host_actions (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            host_id       uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
            name          text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_.-]{0,62}$'),
            status        text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'succeeded', 'failed', 'refused', 'expired')),
            requested_by  text NOT NULL,
            incident_id   uuid REFERENCES incidents (id) ON DELETE SET NULL,
            exit_code     integer,
            output        text,
            created_at    timestamptz NOT NULL DEFAULT now(),
            finished_at   timestamptz
        )
    """)
    op.execute("CREATE INDEX ix_host_actions_pending ON host_actions (host_id) WHERE status = 'pending'")
    op.execute("CREATE INDEX ix_host_actions_host ON host_actions (host_id, created_at DESC)")
    _rls("host_actions")

    op.execute("""
        CREATE TABLE host_inventory (
            host_id     uuid PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
            tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            data        jsonb NOT NULL,
            -- Package changes since the previous inventory, newest first.
            changes     jsonb NOT NULL DEFAULT '[]',
            updated_at  timestamptz NOT NULL DEFAULT now()
        )
    """)
    _rls("host_inventory")

    # ── API tokens ───────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE api_tokens (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
            token_prefix  text NOT NULL,
            token_hash    text NOT NULL UNIQUE,
            read_only     boolean NOT NULL DEFAULT true,
            created_at    timestamptz NOT NULL DEFAULT now(),
            last_used_at  timestamptz,
            expires_at    timestamptz,
            revoked_at    timestamptz
        )
    """)
    _rls("api_tokens")

    # ── Status pages ─────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE status_pages (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            slug         text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{2,62}$'),
            title        text NOT NULL CHECK (length(title) BETWEEN 1 AND 100),
            description  text CHECK (length(description) <= 2000),
            -- Show values (response times, uptime %) or only up/down.
            show_values  boolean NOT NULL DEFAULT true,
            published    boolean NOT NULL DEFAULT true,
            created_at   timestamptz NOT NULL DEFAULT now(),
            updated_at   timestamptz NOT NULL DEFAULT now()
        )
    """)
    _rls("status_pages")
    op.execute("""
        CREATE TABLE status_page_items (
            id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id  uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            page_id    uuid NOT NULL REFERENCES status_pages (id) ON DELETE CASCADE,
            host_id    uuid REFERENCES hosts (id) ON DELETE CASCADE,
            check_id   uuid REFERENCES checks (id) ON DELETE CASCADE,
            label      text NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
            position   integer NOT NULL DEFAULT 0,
            CHECK (num_nonnulls(host_id, check_id) = 1)
        )
    """)
    op.execute("CREATE INDEX ix_status_page_items ON status_page_items (page_id, position)")
    _rls("status_page_items")

    # ── Reports ──────────────────────────────────────────────────────────────
    op.execute("""
        ALTER TABLE tenants
            ADD COLUMN monthly_report boolean NOT NULL DEFAULT true,
            ADD COLUMN report_sent_for date
    """)

    # ── Grants ───────────────────────────────────────────────────────────────
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON checks, host_actions, api_tokens, "
        "status_pages, status_page_items TO pulsegrid_app"
    )
    op.execute("GRANT SELECT, INSERT ON incident_events TO pulsegrid_app")
    op.execute("GRANT SELECT ON host_inventory TO pulsegrid_app")
    op.execute("GRANT INSERT ON incidents TO pulsegrid_app")
    op.execute("GRANT UPDATE (monthly_report) ON tenants TO pulsegrid_app")
    op.execute("GRANT SELECT, UPDATE ON checks, status_pages, status_page_items TO pulsegrid_service")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON incident_events, host_actions, host_inventory "
        "TO pulsegrid_service"
    )
    op.execute("GRANT SELECT, UPDATE ON api_tokens TO pulsegrid_service")
    op.execute("GRANT UPDATE ON alert_rules TO pulsegrid_service")


def downgrade() -> None:
    op.execute("ALTER TABLE tenants DROP COLUMN monthly_report, DROP COLUMN report_sent_for")
    op.execute("DROP TABLE status_page_items")
    op.execute("DROP TABLE status_pages")
    op.execute("DROP TABLE api_tokens")
    op.execute("DROP TABLE host_inventory")
    op.execute("DROP TABLE host_actions")
    op.execute("DELETE FROM outbound_messages WHERE kind IN ('report', 'action')")
    op.execute("ALTER TABLE outbound_messages DROP CONSTRAINT outbound_messages_kind_check")
    op.execute(
        "ALTER TABLE outbound_messages ADD CONSTRAINT outbound_messages_kind_check "
        f"CHECK (kind IN ({_in(MESSAGE_KINDS[:5])}))"
    )
    op.execute("ALTER TABLE notification_channels DROP COLUMN config, DROP COLUMN min_severity")
    op.execute("DELETE FROM notification_channels WHERE type = 'push'")
    op.execute("ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_type_check")
    op.execute(
        "ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check "
        f"CHECK (type IN ({_in(CHANNEL_TYPES[:-1])}))"
    )
    op.execute("DROP TABLE incident_events")
    op.execute(
        "ALTER TABLE incidents DROP COLUMN severity, DROP COLUMN detail, DROP COLUMN flapping, "
        "DROP COLUMN reopened_count, DROP COLUMN resolved_by"
    )
    op.execute("ALTER TABLE alert_states DROP COLUMN flips")
    op.execute(
        "DELETE FROM alert_rules WHERE kind NOT IN ('metric', 'host_down', 'process_down', 'service_down') "
        "OR metric IN ('network_in', 'network_out')"
    )
    op.execute(
        "ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_kind_check, "
        "DROP CONSTRAINT alert_rules_metric_check, DROP CONSTRAINT alert_rules_target_check, "
        "DROP CONSTRAINT alert_rules_metric_fields_check, DROP CONSTRAINT alert_rules_model_check, "
        "DROP COLUMN aggregation, DROP COLUMN window_seconds, DROP COLUMN recovery_threshold, "
        "DROP COLUMN severity, DROP COLUMN action_name, DROP COLUMN labels, DROP COLUMN description"
    )
    op.execute(
        "ALTER TABLE alert_rules "
        "ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ('metric', 'host_down', 'process_down', 'service_down')), "
        "ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN ('cpu', 'memory', 'swap', 'disk', 'load1', "
        "'load5', 'iowait', 'steal', 'inodes', 'disk_busy')), "
        "ADD CONSTRAINT alert_rules_target_check CHECK ((kind IN ('process_down', 'service_down')) = (target IS NOT NULL)), "
        "ADD CONSTRAINT alert_rules_check CHECK (kind <> 'metric' OR metric IS NOT NULL AND operator IS NOT NULL "
        "AND threshold IS NOT NULL)"
    )
    op.execute("DROP TABLE checks")
    op.execute("DROP INDEX ix_hosts_probes")
    op.execute("ALTER TABLE hosts DROP COLUMN probe_region, DROP COLUMN allowed_actions")
