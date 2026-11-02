"""Initial schema: tenants, agent keys, hosts, notification channels, with row-level security.

How tenant isolation works in Postgres:

- Every table except `tenants` has a `tenant_id` column.
- Row-level security (RLS) is enabled on every table. Its policy compares the
  row's tenant to `app.tenant_id`, a per-transaction setting the API sets right
  after it works out who the caller is (see app/tenancy.py).
- If `app.tenant_id` isn't set, the policy matches nothing, so a forgotten
  setting returns no rows instead of everyone's rows.
- The API's `sentinel_app` role is not the table owner and has no BYPASSRLS,
  so the policies always apply to it, even if a query forgets `WHERE tenant_id`.
- The caller's tenant has to be looked up before `app.tenant_id` is known, so
  that lookup goes through `sentinel_resolve_tenant()`, a SECURITY DEFINER
  function that runs as the owner and does exactly one job.

Revision ID: 0001
Revises:
Create Date: 2026-10-24
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# NULLIF: once a transaction that set app.tenant_id ends, the setting reads as ''
# for the rest of the session rather than NULL, and ''::uuid would raise.
CURRENT_TENANT = "NULLIF(current_setting('app.tenant_id', true), '')::uuid"

TENANT_SCOPED_TABLES = ("agent_keys", "hosts", "notification_channels")


def upgrade() -> None:
    op.execute("""
        CREATE TABLE tenants (
            id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            source              text NOT NULL,
            external_account_id text NOT NULL,
            display_name        text,
            email               text,
            status              text NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'suspended')),
            created_at          timestamptz NOT NULL DEFAULT now(),
            updated_at          timestamptz NOT NULL DEFAULT now(),
            UNIQUE (source, external_account_id)
        )
    """)

    op.execute("""
        CREATE TABLE agent_keys (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            name        text NOT NULL,
            key_prefix  text NOT NULL,
            key_hash    text NOT NULL UNIQUE,
            created_at  timestamptz NOT NULL DEFAULT now(),
            revoked_at  timestamptz
        )
    """)
    op.execute("CREATE INDEX ix_agent_keys_tenant ON agent_keys (tenant_id)")

    op.execute("""
        CREATE TABLE hosts (
            id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id         uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            agent_key_id      uuid REFERENCES agent_keys (id) ON DELETE SET NULL,
            machine_id        text NOT NULL,
            hostname          text NOT NULL,
            os                text,
            platform          text,
            platform_version  text,
            arch              text,
            agent_version     text,
            token_hash        text NOT NULL UNIQUE,
            created_at        timestamptz NOT NULL DEFAULT now(),
            last_seen_at      timestamptz,
            revoked_at        timestamptz,
            UNIQUE (tenant_id, machine_id)
        )
    """)

    op.execute("""
        CREATE TABLE notification_channels (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
            type         text NOT NULL CHECK (type IN ('email', 'sms', 'webhook')),
            target       text NOT NULL,
            label        text,
            source       text NOT NULL CHECK (source IN ('console', 'user')),
            is_default   boolean NOT NULL DEFAULT false,
            verified_at  timestamptz,
            created_at   timestamptz NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, type, target)
        )
    """)
    op.execute(
        "CREATE UNIQUE INDEX uq_notification_channels_one_default "
        "ON notification_channels (tenant_id) WHERE is_default"
    )

    # ── Row-level security ───────────────────────────────────────────────────
    op.execute("ALTER TABLE tenants ENABLE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY tenant_isolation ON tenants USING (id = {CURRENT_TENANT})")
    for table in TENANT_SCOPED_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # USING filters what can be read, updated and deleted; WITH CHECK
        # rejects inserting or moving a row into another tenant.
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = {CURRENT_TENANT}) "
            f"WITH CHECK (tenant_id = {CURRENT_TENANT})"
        )

    # ── Tenant resolution ────────────────────────────────────────────────────
    # Find-or-create the caller's tenant from their console identity. On first
    # creation it also adds the console email as the default alert channel; on
    # later calls it keeps that channel in step if the console email changed.
    op.execute("""
        CREATE FUNCTION sentinel_resolve_tenant(
            p_source text, p_external_id text, p_email text, p_name text
        )
        RETURNS TABLE (out_tenant_id uuid, out_status text)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            v_id        uuid;
            v_status    text;
            v_old_email text;
            v_created   boolean := false;
        BEGIN
            SELECT id, status, email INTO v_id, v_status, v_old_email
              FROM tenants
             WHERE source = p_source AND external_account_id = p_external_id;

            IF v_id IS NULL THEN
                INSERT INTO tenants (source, external_account_id, email, display_name)
                VALUES (p_source, p_external_id, NULLIF(p_email, ''), NULLIF(p_name, ''))
                ON CONFLICT (source, external_account_id) DO NOTHING
                RETURNING id, status INTO v_id, v_status;

                IF v_id IS NULL THEN
                    -- Another request created it a moment ago.
                    SELECT id, status, email INTO v_id, v_status, v_old_email
                      FROM tenants
                     WHERE source = p_source AND external_account_id = p_external_id;
                ELSE
                    v_created := true;
                END IF;
            END IF;

            IF v_created AND NULLIF(p_email, '') IS NOT NULL THEN
                INSERT INTO notification_channels
                    (tenant_id, type, target, label, source, is_default, verified_at)
                VALUES (v_id, 'email', p_email, 'Account email', 'console', true, now());
            ELSIF NOT v_created AND NULLIF(p_email, '') IS NOT NULL
                  AND p_email IS DISTINCT FROM v_old_email THEN
                UPDATE tenants SET email = p_email, updated_at = now() WHERE id = v_id;
                -- Follow the console email, unless the user already added that
                -- address themselves (the unique constraint would reject it).
                UPDATE notification_channels SET target = p_email
                 WHERE tenant_id = v_id AND source = 'console' AND type = 'email'
                   AND NOT EXISTS (
                       SELECT 1 FROM notification_channels
                        WHERE tenant_id = v_id AND type = 'email' AND target = p_email
                   );
            END IF;

            RETURN QUERY SELECT v_id, v_status;
        END
        $$
    """)
    op.execute("REVOKE ALL ON FUNCTION sentinel_resolve_tenant(text, text, text, text) FROM PUBLIC")

    # ── Grants ───────────────────────────────────────────────────────────────
    # sentinel_app: customer requests. RLS applies to every statement.
    op.execute("GRANT SELECT ON tenants TO sentinel_app")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON agent_keys, hosts, notification_channels "
        "TO sentinel_app"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION sentinel_resolve_tenant(text, text, text, text) TO sentinel_app"
    )

    # sentinel_service: ingest and /internal/* routes. BYPASSRLS, so keep its
    # grants to what those two actually do.
    op.execute("GRANT SELECT, UPDATE, DELETE ON tenants TO sentinel_service")
    op.execute("GRANT SELECT ON agent_keys, notification_channels TO sentinel_service")
    op.execute("GRANT SELECT, INSERT, UPDATE ON hosts TO sentinel_service")


def downgrade() -> None:
    op.execute("DROP FUNCTION sentinel_resolve_tenant(text, text, text, text)")
    op.execute("DROP TABLE notification_channels, hosts, agent_keys, tenants")
