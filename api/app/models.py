import uuid
from datetime import datetime, time

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, Text, Time, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    # Every timestamp column is timestamptz; without this SQLAlchemy binds
    # datetimes as "timestamp without time zone" and rejects aware values.
    type_annotation_map = {datetime: DateTime(timezone=True)}


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True)
    source: Mapped[str] = mapped_column(Text)
    external_account_id: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str | None] = mapped_column(Text)
    email: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class TenantScoped(Base):
    """Every table except tenants carries tenant_id, and RLS filters on it.

    Inserts still set tenant_id explicitly; the RLS WITH CHECK clause rejects
    any row whose tenant_id isn't the request's tenant.
    """

    __abstract__ = True

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("tenants.id", ondelete="CASCADE"))


class AgentKey(TenantScoped):
    __tablename__ = "agent_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    key_prefix: Mapped[str] = mapped_column(Text)
    key_hash: Mapped[str] = mapped_column(Text, unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    revoked_at: Mapped[datetime | None]


class Host(TenantScoped):
    __tablename__ = "hosts"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    agent_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("agent_keys.id", ondelete="SET NULL")
    )
    machine_id: Mapped[str] = mapped_column(Text)
    hostname: Mapped[str] = mapped_column(Text)
    os: Mapped[str | None] = mapped_column(Text)
    platform: Mapped[str | None] = mapped_column(Text)
    platform_version: Mapped[str | None] = mapped_column(Text)
    arch: Mapped[str | None] = mapped_column(Text)
    agent_version: Mapped[str | None] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    depends_on_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="SET NULL")
    )
    ip_addresses: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    cpu_cores: Mapped[int | None]
    memory_bytes: Mapped[int | None] = mapped_column(BigInteger)


class NotificationChannel(TenantScoped):
    __tablename__ = "notification_channels"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    type: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text)
    label: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)
    is_default: Mapped[bool] = mapped_column(default=False)
    verified_at: Mapped[datetime | None]
    verification_code_hash: Mapped[str | None] = mapped_column(Text)
    verification_sent_at: Mapped[datetime | None]
    verification_attempts: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AlertRule(TenantScoped):
    __tablename__ = "alert_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text)
    metric: Mapped[str | None] = mapped_column(Text)
    operator: Mapped[str | None] = mapped_column(Text)
    threshold: Mapped[float | None]
    duration_seconds: Mapped[int]
    host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="CASCADE")
    )
    tag: Mapped[str | None] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AlertEscalationStep(TenantScoped):
    __tablename__ = "alert_escalation_steps"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("alert_rules.id", ondelete="CASCADE")
    )
    position: Mapped[int]
    delay_seconds: Mapped[int]
    channel_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID))


class MaintenanceWindow(TenantScoped):
    __tablename__ = "maintenance_windows"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="CASCADE")
    )
    tag: Mapped[str | None] = mapped_column(Text)
    schedule: Mapped[str] = mapped_column(Text)
    starts_at: Mapped[datetime | None]
    ends_at: Mapped[datetime | None]
    weekdays: Mapped[list[int] | None] = mapped_column(ARRAY(Integer))
    start_time: Mapped[time | None] = mapped_column(Time)
    duration_minutes: Mapped[int | None]
    timezone: Mapped[str] = mapped_column(Text, default="UTC")
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AlertRuleChannel(TenantScoped):
    __tablename__ = "alert_rule_channels"

    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("alert_rules.id", ondelete="CASCADE"), primary_key=True
    )
    channel_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("notification_channels.id", ondelete="CASCADE"), primary_key=True
    )


class AlertState(TenantScoped):
    __tablename__ = "alert_states"

    rule_id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True)
    state: Mapped[str] = mapped_column(Text)
    since: Mapped[datetime]
    last_value: Mapped[float | None]
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    updated_at: Mapped[datetime]


class Incident(TenantScoped):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    host_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    status: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text)
    rule_name: Mapped[str] = mapped_column(Text)
    hostname: Mapped[str] = mapped_column(Text)
    value: Mapped[float | None]
    opened_at: Mapped[datetime]
    acknowledged_at: Mapped[datetime | None]
    acknowledged_by: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None]
    escalation_level: Mapped[int] = mapped_column(default=0)


class OutboundMessage(TenantScoped):
    __tablename__ = "outbound_messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    channel_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    kind: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(Text, default="pending")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
