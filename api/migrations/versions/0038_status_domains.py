"""Status pages on the customer's own domain: the owner sets a domain, proves
it with a TXT record, and only then does Caddy get a certificate for it
(on-demand TLS asks /public/domain-check). One verified page per domain.

Revision ID: 0038
Revises: 0037
Create Date: 2026-11-21
"""

from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE status_pages ADD COLUMN domain text,"
        " ADD COLUMN domain_token text,"
        " ADD COLUMN domain_verified_at timestamptz,"
        " ADD CONSTRAINT status_pages_domain_check CHECK (domain = lower(domain))"
    )
    op.execute(
        "CREATE UNIQUE INDEX status_pages_verified_domain ON status_pages (domain)"
        " WHERE domain_verified_at IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX status_pages_verified_domain")
    op.execute(
        "ALTER TABLE status_pages DROP COLUMN domain, DROP COLUMN domain_token,"
        " DROP COLUMN domain_verified_at"
    )
