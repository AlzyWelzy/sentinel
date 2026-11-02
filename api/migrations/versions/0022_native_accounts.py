"""Beyond's own accounts: users, sessions, organisations and superadmins.

- users: sign-up with email and password (argon2id), verified by email,
  optional TOTP. Not tenant-scoped: only the API's auth service reads them,
  as the service role.
- user_sessions: one row per signed-in browser. The refresh token rotates
  on every use; presenting an already-rotated one revokes the whole family
  (someone copied it).
- auth_tokens: single-use email links (verify, reset), stored hashed.
- tenant_members gains user_id and the 'owner' role: a tenant is an
  organisation, and every person in it, the owner too, is a member row.
  Invitations carry a hashed single-use token; a member row is matched by
  user_id only (no more claiming by email).
- impersonations: a superadmin working in a customer's organisation, with
  a reason, read-only unless they asked for writes.
- account_emails: the outbox for emails that belong to no tenant (verify,
  reset, invitations). The alerter sends them with the same retries as
  alerts.
- pulsegrid_resolve_tenant() is replaced by pulsegrid_default_tenant(user):
  the user's first organisation, created when they have none.

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-02
"""

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE users (
            id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            email             text NOT NULL UNIQUE CHECK (email = lower(email)),
            name              text,
            password_hash     text NOT NULL,
            email_verified_at timestamptz,
            totp_secret       text,
            totp_enabled_at   timestamptz,
            is_superadmin     boolean NOT NULL DEFAULT false,
            failed_logins     integer NOT NULL DEFAULT 0,
            locked_until      timestamptz,
            disabled_at       timestamptz,
            created_at        timestamptz NOT NULL DEFAULT now(),
            updated_at        timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("""
        CREATE TABLE user_sessions (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
            family_id     uuid NOT NULL,
            refresh_hash  text NOT NULL UNIQUE,
            rotated_at    timestamptz,
            revoked_at    timestamptz,
            created_at    timestamptz NOT NULL DEFAULT now(),
            last_used_at  timestamptz NOT NULL DEFAULT now(),
            expires_at    timestamptz NOT NULL,
            ip            text,
            user_agent    text
        )
    """)
    op.execute("CREATE INDEX user_sessions_user ON user_sessions (user_id)")
    op.execute("CREATE INDEX user_sessions_family ON user_sessions (family_id)")
    op.execute("""
        CREATE TABLE auth_tokens (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
            purpose     text NOT NULL CHECK (purpose IN ('verify', 'reset')),
            token_hash  text NOT NULL UNIQUE,
            expires_at  timestamptz NOT NULL,
            used_at     timestamptz,
            created_at  timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("""
        CREATE TABLE impersonations (
            id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id        uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
            tenant_id      uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            reason         text NOT NULL,
            allow_writes   boolean NOT NULL DEFAULT false,
            started_at     timestamptz NOT NULL DEFAULT now(),
            expires_at     timestamptz NOT NULL,
            ended_at       timestamptz
        )
    """)
    op.execute("""
        CREATE TABLE account_emails (
            id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            to_address       text NOT NULL,
            kind             text NOT NULL
                             CHECK (kind IN ('verify_email', 'reset_password', 'invitation',
                                             'password_changed', 'new_sign_in')),
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
        "CREATE INDEX account_emails_pending ON account_emails (next_attempt_at) "
        "WHERE status = 'pending'"
    )

    # Members: user_id, the owner role, and invitation tokens.
    op.execute("ALTER TABLE tenant_members DROP CONSTRAINT tenant_members_role_check")
    op.execute("""
        ALTER TABLE tenant_members
            ADD CONSTRAINT tenant_members_role_check
                CHECK (role IN ('viewer', 'operator', 'admin', 'owner')),
            ADD COLUMN user_id uuid REFERENCES users (id) ON DELETE CASCADE,
            ADD COLUMN invite_hash text UNIQUE,
            ADD COLUMN invite_expires_at timestamptz,
            ADD COLUMN invited_by uuid REFERENCES users (id) ON DELETE SET NULL
    """)
    op.execute(
        "CREATE UNIQUE INDEX tenant_members_user ON tenant_members (tenant_id, user_id) "
        "WHERE user_id IS NOT NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX tenant_members_one_owner ON tenant_members (tenant_id) "
        "WHERE role = 'owner'"
    )
    op.execute("ALTER TABLE tenants ALTER COLUMN source SET DEFAULT 'beyond'")
    op.execute("ALTER TABLE tenants ALTER COLUMN digest_timezone SET DEFAULT 'UTC'")

    op.execute("DROP FUNCTION pulsegrid_member_accounts(text, text, text)")
    op.execute("DROP FUNCTION pulsegrid_member_tenant(uuid, text, text, text, text)")
    op.execute("DROP FUNCTION pulsegrid_resolve_tenant(text, text, text, text)")

    # The caller's organisation when they name none: the one they own, else
    # the first they joined. A user with none gets one (onboarding names
    # it), with their verified email as its first alert contact.
    op.execute("""
        CREATE FUNCTION pulsegrid_default_tenant(p_user uuid, p_email text, p_name text)
        RETURNS TABLE (out_tenant_id uuid, out_status text, out_role text)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            v_id   uuid;
            v_role text;
        BEGIN
            SELECT m.tenant_id, m.role INTO v_id, v_role
              FROM tenant_members m
             WHERE m.user_id = p_user AND m.joined_at IS NOT NULL
             ORDER BY (m.role = 'owner') DESC, m.joined_at
             LIMIT 1;
            IF v_id IS NULL THEN
                -- One organisation per user at a time is created here.
                PERFORM pg_advisory_xact_lock(hashtext(p_user::text));
                SELECT m.tenant_id, m.role INTO v_id, v_role
                  FROM tenant_members m
                 WHERE m.user_id = p_user AND m.joined_at IS NOT NULL
                 ORDER BY (m.role = 'owner') DESC, m.joined_at
                 LIMIT 1;
            END IF;
            IF v_id IS NULL THEN
                v_id := gen_random_uuid();
                INSERT INTO tenants (id, source, external_account_id, email, display_name)
                VALUES (v_id, 'beyond', v_id::text, NULLIF(p_email, ''), NULLIF(p_name, ''));
                INSERT INTO tenant_members (tenant_id, email, role, user_id, display_name, joined_at)
                VALUES (v_id, lower(p_email), 'owner', p_user, NULLIF(p_name, ''), now());
                IF NULLIF(p_email, '') IS NOT NULL THEN
                    INSERT INTO notification_channels
                        (tenant_id, type, target, label, source, is_default, verified_at)
                    VALUES (v_id, 'email', lower(p_email), 'Account email', 'account', true, now());
                END IF;
                v_role := 'owner';
            END IF;
            RETURN QUERY SELECT v_id, t.status, v_role FROM tenants t WHERE t.id = v_id;
        END
        $$
    """)
    # Creating another organisation (from the organisation switcher).
    op.execute("""
        CREATE FUNCTION pulsegrid_create_tenant(p_user uuid, p_email text, p_name text)
        RETURNS uuid
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            v_id uuid := gen_random_uuid();
        BEGIN
            INSERT INTO tenants (id, source, external_account_id, email, display_name)
            VALUES (v_id, 'beyond', v_id::text, NULLIF(p_email, ''), p_name);
            INSERT INTO tenant_members (tenant_id, email, role, user_id, display_name, joined_at)
            VALUES (v_id, lower(p_email), 'owner', p_user, NULL, now());
            INSERT INTO notification_channels
                (tenant_id, type, target, label, source, is_default, verified_at)
            VALUES (v_id, 'email', lower(p_email), 'Account email', 'account', true, now());
            RETURN v_id;
        END
        $$
    """)
    op.execute("""
        CREATE FUNCTION pulsegrid_member_tenant(p_tenant uuid, p_user uuid)
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
             WHERE m.tenant_id = p_tenant AND m.user_id = p_user AND m.joined_at IS NOT NULL;
            IF v_id IS NULL THEN
                RETURN;
            END IF;
            UPDATE tenant_members SET last_seen_at = now()
             WHERE id = v_id AND (last_seen_at IS NULL OR last_seen_at < now() - interval '1 minute');
            RETURN QUERY SELECT v_role, t.status FROM tenants t WHERE t.id = p_tenant;
        END
        $$
    """)
    op.execute("""
        CREATE FUNCTION pulsegrid_member_accounts(p_user uuid)
        RETURNS TABLE (out_tenant_id uuid, out_name text, out_email text, out_role text)
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT t.id, t.display_name, t.email, m.role
              FROM tenant_members m JOIN tenants t ON t.id = m.tenant_id
             WHERE m.user_id = p_user AND m.joined_at IS NOT NULL AND t.status = 'active'
             ORDER BY (m.role = 'owner') DESC, t.display_name NULLS LAST, t.created_at
        $$
    """)
    for fn in (
        "pulsegrid_default_tenant(uuid, text, text)",
        "pulsegrid_create_tenant(uuid, text, text)",
        "pulsegrid_member_tenant(uuid, uuid)",
        "pulsegrid_member_accounts(uuid)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {fn} TO pulsegrid_app")

    # Owners rename their organisation.
    op.execute("GRANT UPDATE (display_name, updated_at) ON tenants TO pulsegrid_app")

    # Only the auth service (service role) touches accounts.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON users, user_sessions, auth_tokens, "
        "impersonations, account_emails TO pulsegrid_service"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_members TO pulsegrid_service")
    op.execute("GRANT INSERT ON tenants, notification_channels TO pulsegrid_service")


def downgrade() -> None:
    for fn in (
        "pulsegrid_default_tenant(uuid, text, text)",
        "pulsegrid_create_tenant(uuid, text, text)",
        "pulsegrid_member_tenant(uuid, uuid)",
        "pulsegrid_member_accounts(uuid)",
    ):
        op.execute(f"DROP FUNCTION {fn}")
    op.execute("REVOKE UPDATE (display_name, updated_at) ON tenants FROM pulsegrid_app")
    op.execute("DELETE FROM tenant_members WHERE role = 'owner'")
    op.execute("DROP INDEX tenant_members_one_owner")
    op.execute("DROP INDEX tenant_members_user")
    op.execute("""
        ALTER TABLE tenant_members
            DROP CONSTRAINT tenant_members_role_check,
            DROP COLUMN user_id,
            DROP COLUMN invite_hash,
            DROP COLUMN invite_expires_at,
            DROP COLUMN invited_by
    """)
    op.execute(
        "ALTER TABLE tenant_members ADD CONSTRAINT tenant_members_role_check "
        "CHECK (role IN ('viewer', 'operator', 'admin'))"
    )
    op.execute("ALTER TABLE tenants ALTER COLUMN source DROP DEFAULT")
    op.execute("ALTER TABLE tenants ALTER COLUMN digest_timezone SET DEFAULT 'Asia/Kolkata'")
    op.execute("DROP TABLE account_emails, impersonations, auth_tokens, user_sessions, users")
    # The console-identity functions no longer have anything to resolve
    # against. Earlier migrations' downgrades drop them by signature, so
    # empty versions are put back for a full downgrade (CI runs one).
    op.execute("""
        CREATE FUNCTION pulsegrid_member_tenant(
            p_tenant uuid, p_source text, p_external_id text, p_email text, p_name text
        ) RETURNS TABLE (out_role text, out_status text) LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, public AS $$ SELECT NULL::text, NULL::text WHERE false $$
    """)
    op.execute("""
        CREATE FUNCTION pulsegrid_member_accounts(p_source text, p_external_id text, p_email text)
        RETURNS TABLE (out_tenant_id uuid, out_name text, out_email text, out_role text)
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public
        AS $$ SELECT NULL::uuid, NULL::text, NULL::text, NULL::text WHERE false $$
    """)
    op.execute("""
        CREATE FUNCTION pulsegrid_resolve_tenant(
            p_source text, p_external_id text, p_email text, p_name text
        ) RETURNS TABLE (out_tenant_id uuid, out_status text) LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$ SELECT NULL::uuid, NULL::text WHERE false $$
    """)
