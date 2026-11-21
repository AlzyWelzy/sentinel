"""Contacts for every service in the notification catalog (ntfy, Opsgenie,
DingTalk, …): their type is the provider's name and their form fields are in
config. The API checks types against the catalog, so the column only keeps
names well-formed.

Revision ID: 0036
Revises: 0035
Create Date: 2026-11-21
"""

from alembic import op

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None

BUILTIN = (
    "email", "sms", "webhook", "slack", "teams", "telegram", "discord", "pagerduty", "voice", "push",
)  # fmt: skip


def upgrade() -> None:
    op.execute("ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_type_check")
    op.execute(
        "ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check"
        " CHECK (type ~ '^[a-z0-9_]{2,40}$')"
    )


def downgrade() -> None:
    kinds = ", ".join(f"'{k}'" for k in BUILTIN)
    op.execute(f"DELETE FROM notification_channels WHERE type NOT IN ({kinds})")  # noqa: S608 (constants)
    op.execute("ALTER TABLE notification_channels DROP CONSTRAINT notification_channels_type_check")
    op.execute(
        "ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check"
        f" CHECK (type IN ({kinds}))"
    )
