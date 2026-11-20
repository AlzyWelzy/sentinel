"""Proxmox VE clusters as network devices.

A cluster is polled through its REST API by a site agent, like an SNMP
device: its credential is an API token (version 'proxmox': user,
token_name, token_value, and whether to accept the self-signed
certificate Proxmox installs by default).

Revision ID: 0028
Revises: 0027
Create Date: 2026-11-20
"""

from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE snmp_credentials
            DROP CONSTRAINT snmp_credentials_version_check,
            ADD CONSTRAINT snmp_credentials_version_check
                CHECK (version IN ('1', '2c', '3', 'proxmox'))
        """
    )


def downgrade() -> None:
    op.execute(
        "DELETE FROM hosts WHERE snmp_credential_id IN (SELECT id FROM snmp_credentials WHERE version = 'proxmox')"
    )
    op.execute("DELETE FROM snmp_credentials WHERE version = 'proxmox'")
    op.execute(
        """
        ALTER TABLE snmp_credentials
            DROP CONSTRAINT snmp_credentials_version_check,
            ADD CONSTRAINT snmp_credentials_version_check CHECK (version IN ('1', '2c', '3'))
        """
    )
