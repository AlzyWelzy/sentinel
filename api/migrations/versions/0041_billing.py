"""Plans and Razorpay subscriptions per organisation.

The plan catalog (proto/plans.json) is shared by the API and ingest; the
tenant row only says which plan it's on. Organisations that exist before
billing are grandfathered without limits. Limits apply only while billing
is on (Razorpay keys set).

Revision ID: 0041
Revises: 0040
Create Date: 2026-11-24
"""

from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None

COLUMNS = "plan, plan_status, razorpay_subscription_id, plan_renews_at"


def upgrade() -> None:
    op.execute("""
        ALTER TABLE tenants
            ADD COLUMN plan text NOT NULL DEFAULT 'free',
            ADD COLUMN plan_status text NOT NULL DEFAULT 'active'
                CHECK (plan_status IN ('active', 'pending', 'past_due', 'cancelled')),
            ADD COLUMN razorpay_subscription_id text,
            ADD COLUMN plan_renews_at timestamptz
    """)
    # Everyone here before billing keeps what they have.
    op.execute("UPDATE tenants SET plan = 'grandfathered'")
    op.execute(
        "CREATE UNIQUE INDEX tenants_razorpay_subscription"
        " ON tenants (razorpay_subscription_id) WHERE razorpay_subscription_id IS NOT NULL"
    )
    op.execute(f"GRANT UPDATE ({COLUMNS}) ON tenants TO sentinel_app")

    op.execute("""
        CREATE TABLE billing_events (
            id          text PRIMARY KEY,
            tenant_id   uuid REFERENCES tenants (id) ON DELETE SET NULL,
            event       text NOT NULL,
            payload     jsonb NOT NULL,
            received_at timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("GRANT SELECT, INSERT ON billing_events TO sentinel_service")


def downgrade() -> None:
    op.execute("DROP TABLE billing_events")
    op.execute(f"REVOKE UPDATE ({COLUMNS}) ON tenants FROM sentinel_app")
    op.execute("DROP INDEX tenants_razorpay_subscription")
    op.execute(
        "ALTER TABLE tenants DROP COLUMN plan, DROP COLUMN plan_status,"
        " DROP COLUMN razorpay_subscription_id, DROP COLUMN plan_renews_at"
    )
