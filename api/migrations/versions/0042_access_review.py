"""Access reviews: when an owner or admin last confirmed who has access.

Revision ID: 0042
Revises: 0041
Create Date: 2026-11-24
"""

from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE tenants ADD COLUMN access_reviewed_at timestamptz,"
        " ADD COLUMN access_reviewed_by text"
    )
    op.execute("GRANT UPDATE (access_reviewed_at, access_reviewed_by) ON tenants TO sentinel_app")
    # Which members of the caller's organisation have two-factor on: only
    # that, for the review (the app role can't read users).
    op.execute("""
        CREATE FUNCTION sentinel_members_with_2fa()
        RETURNS SETOF uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT u.id FROM users u
              JOIN tenant_members m ON m.user_id = u.id
             WHERE m.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
               AND u.totp_enabled_at IS NOT NULL
        $$
    """)
    op.execute("REVOKE ALL ON FUNCTION sentinel_members_with_2fa() FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION sentinel_members_with_2fa() TO sentinel_app")


def downgrade() -> None:
    op.execute("DROP FUNCTION sentinel_members_with_2fa()")
    op.execute(
        "REVOKE UPDATE (access_reviewed_at, access_reviewed_by) ON tenants FROM sentinel_app"
    )
    op.execute("ALTER TABLE tenants DROP COLUMN access_reviewed_at, DROP COLUMN access_reviewed_by")
