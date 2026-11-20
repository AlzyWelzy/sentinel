"""Network devices: switches, firewalls and other gear polled over SNMP.

A device is a hosts row with kind 'network', so everything built for
servers (not-reporting alerts, maintenance, dependencies, incidents, tags,
pausing) works for it. It has no agent of its own: an agent at its site
polls it (poller_host_id) with a shared SNMP credential, and reports for it.

- snmp_credentials: v1/v2c communities and v3 users, encrypted with
  CREDENTIALS_KEY (shared by the API and ingest; ingest hands them to the
  poller in its config).
- network_interfaces: the device's interfaces from its last inventory poll.
  billing_tag groups ports for 95th-percentile bandwidth.
- network_links: LLDP neighbours, resolved to known devices where possible.
  Topology sets depends_on_host_id from them unless it was set by hand
  (depends_on_auto = false): each device's upstream is the neighbour one
  hop closer to a device with network_role 'core'.

Revision ID: 0027
Revises: 0026
Create Date: 2026-11-19
"""

from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"
KINDS = (
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


def _kinds(extra: tuple[str, ...] = ()) -> str:
    return ", ".join(f"'{k}'" for k in KINDS + extra)


def _tenant_table(name: str) -> None:
    op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {name} "
        f"USING (tenant_id = {CURRENT_TENANT}) WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE snmp_credentials (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
            version     text NOT NULL CHECK (version IN ('1', '2c', '3')),
            secret      text NOT NULL,
            created_at  timestamptz NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, name)
        )
        """
    )
    _tenant_table("snmp_credentials")

    op.execute(
        """
        ALTER TABLE hosts
            ADD COLUMN kind text NOT NULL DEFAULT 'server' CHECK (kind IN ('server', 'network')),
            ADD COLUMN address text,
            ADD COLUMN poller_host_id uuid REFERENCES hosts(id) ON DELETE SET NULL,
            ADD COLUMN snmp_credential_id uuid REFERENCES snmp_credentials(id) ON DELETE RESTRICT,
            ADD COLUMN profile text,
            ADD COLUMN network_role text CHECK (network_role IN
                ('core', 'distribution', 'access', 'firewall', 'router', 'wireless', 'other')),
            ADD COLUMN device jsonb NOT NULL DEFAULT '{}',
            ADD COLUMN device_error text,
            ADD COLUMN device_polled_at timestamptz,
            ADD COLUMN depends_on_auto boolean NOT NULL DEFAULT false,
            ALTER COLUMN token_hash DROP NOT NULL,
            ADD CONSTRAINT hosts_network_shape CHECK (
                (kind = 'server' AND token_hash IS NOT NULL)
                OR (kind = 'network' AND address IS NOT NULL AND poller_host_id IS DISTINCT FROM id)
            )
        """
    )
    op.execute(
        "CREATE INDEX ix_hosts_poller ON hosts (poller_host_id) WHERE poller_host_id IS NOT NULL"
    )

    op.execute(
        """
        CREATE TABLE network_interfaces (
            tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            host_id      uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            ifindex      integer NOT NULL,
            name         text NOT NULL,
            descr        text,
            alias        text,
            type         integer,
            speed_bps    bigint,
            mtu          integer,
            mac          text,
            admin_up     boolean,
            oper_status  integer,
            billing_tag  text CHECK (char_length(billing_tag) <= 100),
            updated_at   timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (host_id, ifindex)
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_network_interfaces_billing ON network_interfaces (tenant_id, billing_tag) WHERE billing_tag IS NOT NULL"
    )
    _tenant_table("network_interfaces")

    op.execute(
        """
        CREATE TABLE network_links (
            tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            host_id           uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            local_port        text NOT NULL,
            remote_sys_name   text NOT NULL DEFAULT '',
            remote_port_id    text NOT NULL DEFAULT '',
            remote_port_desc  text,
            remote_chassis_id text NOT NULL DEFAULT '',
            remote_mgmt_addr  text,
            remote_host_id    uuid REFERENCES hosts(id) ON DELETE SET NULL,
            seen_at           timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (host_id, local_port, remote_chassis_id, remote_port_id)
        )
        """
    )
    _tenant_table("network_links")

    # Network rules: a condition from the catalog (alerter/network.go) by name.
    op.execute(
        f"""
        ALTER TABLE alert_rules
            DROP CONSTRAINT alert_rules_kind_check,
            ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ({_kinds(("network",))})),
            ADD CONSTRAINT alert_rules_network_target CHECK (kind <> 'network' OR target IS NOT NULL)
        """
    )
    # When the network rules were added: once, with the first device.
    op.execute("ALTER TABLE tenants ADD COLUMN network_rules_at timestamptz")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON snmp_credentials, network_interfaces, "
        "network_links TO sentinel_app"
    )
    op.execute("GRANT SELECT ON snmp_credentials TO sentinel_service")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON network_interfaces, network_links "
        "TO sentinel_service"
    )


def downgrade() -> None:
    op.execute("DELETE FROM alert_rules WHERE kind = 'network'")
    op.execute(
        f"""
        ALTER TABLE alert_rules
            DROP CONSTRAINT alert_rules_network_target,
            DROP CONSTRAINT alert_rules_kind_check,
            ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ({_kinds()}))
        """
    )
    op.execute("ALTER TABLE tenants DROP COLUMN network_rules_at")
    op.execute("DROP TABLE network_links, network_interfaces")
    op.execute("DELETE FROM hosts WHERE kind = 'network'")
    op.execute(
        """
        ALTER TABLE hosts
            DROP CONSTRAINT hosts_network_shape,
            DROP COLUMN kind, DROP COLUMN address, DROP COLUMN poller_host_id,
            DROP COLUMN snmp_credential_id, DROP COLUMN profile, DROP COLUMN network_role,
            DROP COLUMN device,
            DROP COLUMN device_error, DROP COLUMN device_polled_at, DROP COLUMN depends_on_auto,
            ALTER COLUMN token_hash SET NOT NULL
        """
    )
    op.execute("DROP TABLE snmp_credentials")
