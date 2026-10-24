"""Identify hosts by machine id *and* hostname.

VMs cloned from one template (common on CloudStack) often share
/etc/machine-id. Keyed on machine id alone, every clone in an account
registered as the same host and took over its token. With the hostname in
the key, reinstalling on a machine still updates its host, and clones (which
get their own hostnames) become separate hosts.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-24
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE hosts DROP CONSTRAINT hosts_tenant_id_machine_id_key")
    op.execute(
        "ALTER TABLE hosts ADD CONSTRAINT hosts_tenant_machine_hostname_key "
        "UNIQUE (tenant_id, machine_id, hostname)"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE hosts DROP CONSTRAINT hosts_tenant_machine_hostname_key")
    op.execute(
        "ALTER TABLE hosts ADD CONSTRAINT hosts_tenant_id_machine_id_key "
        "UNIQUE (tenant_id, machine_id)"
    )
