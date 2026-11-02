"""Team members: an account owner shares their monitoring with other console
users as viewer, operator or admin.

- tenant_members: invited by email; the row is claimed (source and
  external_account_id filled in) the first time that console user, signed in
  with that verified email, opens the shared account.
- sentinel_member_tenant(): SECURITY DEFINER, because the caller's own
  tenant isn't the shared one and RLS would hide the row. Returns the role
  and the shared tenant's status, or nothing.
- sentinel_member_accounts(): the accounts a console user belongs to, for
  the account switcher.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-25
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"


def upgrade() -> None:
    op.execute("""
        CREATE TABLE tenant_members (
            id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id           uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            email               text NOT NULL CHECK (email = lower(email)),
            role                text NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
            source              text,
            external_account_id text,
            display_name        text,
            invited_at          timestamptz NOT NULL DEFAULT now(),
            joined_at           timestamptz,
            last_seen_at        timestamptz,
            UNIQUE (tenant_id, email)
        )
    """)
    op.execute(
        "CREATE INDEX tenant_members_identity ON tenant_members (source, external_account_id)"
    )
    op.execute("CREATE INDEX tenant_members_email ON tenant_members (email)")
    op.execute("ALTER TABLE tenant_members ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON tenant_members "
        f"USING (tenant_id = {CURRENT_TENANT}) "
        f"WITH CHECK (tenant_id = {CURRENT_TENANT})"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_members TO sentinel_app")

    # A row matches the caller by identity once claimed, or by verified email
    # while still an invitation. Claiming pins it to that console user, so a
    # later account with the same email can't take it over.
    op.execute("""
        CREATE FUNCTION sentinel_member_tenant(
            p_tenant uuid, p_source text, p_external_id text, p_email text, p_name text
        )
        RETURNS TABLE (out_role text, out_status text)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            v_id   uuid;
            v_role text;
        BEGIN
            SELECT m.id, m.role INTO v_id, v_role
              FROM tenant_members m
             WHERE m.tenant_id = p_tenant
               AND ((m.source = p_source AND m.external_account_id = p_external_id)
                    OR (m.external_account_id IS NULL AND p_email IS NOT NULL
                        AND m.email = lower(p_email)));
            IF v_id IS NULL THEN
                RETURN;
            END IF;
            UPDATE tenant_members
               SET source = p_source,
                   external_account_id = p_external_id,
                   display_name = COALESCE(p_name, display_name),
                   joined_at = COALESCE(joined_at, now()),
                   last_seen_at = now()
             WHERE id = v_id
               AND (last_seen_at IS NULL OR last_seen_at < now() - interval '1 minute'
                    OR external_account_id IS NULL);
            RETURN QUERY SELECT v_role, t.status FROM tenants t WHERE t.id = p_tenant;
        END
        $$
    """)
    op.execute("""
        CREATE FUNCTION sentinel_member_accounts(p_source text, p_external_id text, p_email text)
        RETURNS TABLE (out_tenant_id uuid, out_name text, out_email text, out_role text)
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT t.id, t.display_name, t.email, m.role
              FROM tenant_members m JOIN tenants t ON t.id = m.tenant_id
             WHERE t.status = 'active'
               AND ((m.source = p_source AND m.external_account_id = p_external_id)
                    OR (m.external_account_id IS NULL AND p_email IS NOT NULL
                        AND m.email = lower(p_email)))
             ORDER BY t.display_name NULLS LAST, t.email
        $$
    """)
    for fn in (
        "sentinel_member_tenant(uuid, text, text, text, text)",
        "sentinel_member_accounts(text, text, text)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {fn} TO sentinel_app")


def downgrade() -> None:
    op.execute("DROP FUNCTION sentinel_member_accounts(text, text, text)")
    op.execute("DROP FUNCTION sentinel_member_tenant(uuid, text, text, text, text)")
    op.execute("DROP TABLE tenant_members")
