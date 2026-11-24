import uuid
from datetime import date, datetime, time

from sqlalchemy import (
    BigInteger,
    DateTime,
    FetchedValue,
    ForeignKey,
    Integer,
    Numeric,
    Text,
    Time,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    # Every timestamp column is timestamptz; without this SQLAlchemy binds
    # datetimes as "timestamp without time zone" and rejects aware values.
    type_annotation_map = {datetime: DateTime(timezone=True)}


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True)
    source: Mapped[str] = mapped_column(Text, default="beyond")
    external_account_id: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str | None] = mapped_column(Text)
    email: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())
    monthly_report: Mapped[bool] = mapped_column(default=True)
    report_sent_for: Mapped[date | None]
    logs_account_id: Mapped[int] = mapped_column(BigInteger, server_default=FetchedValue())
    agent_version_pin: Mapped[str | None] = mapped_column(Text)
    digest: Mapped[str] = mapped_column(Text, default="weekly")
    digest_hour: Mapped[int] = mapped_column(default=9)
    digest_timezone: Mapped[str] = mapped_column(Text, default="UTC")
    # Open, unacknowledged incidents are sent again this often; 0 is off.
    reminder_minutes: Mapped[int] = mapped_column(Integer, default=240)
    plan: Mapped[str] = mapped_column(Text, default="free")
    plan_status: Mapped[str] = mapped_column(Text, default="active")
    razorpay_subscription_id: Mapped[str | None] = mapped_column(Text)
    plan_renews_at: Mapped[datetime | None]
    access_reviewed_at: Mapped[datetime | None]
    access_reviewed_by: Mapped[str | None] = mapped_column(Text)
    digest_sent_at: Mapped[datetime | None]


class TenantMember(Base):
    __tablename__ = "tenant_members"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID, primary_key=True, server_default=func.gen_random_uuid()
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID)
    email: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(Text)
    external_account_id: Mapped[str | None] = mapped_column(Text)
    display_name: Mapped[str | None] = mapped_column(Text)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    invite_expires_at: Mapped[datetime | None]
    invited_at: Mapped[datetime] = mapped_column(server_default=func.now())
    joined_at: Mapped[datetime | None]
    last_seen_at: Mapped[datetime | None]


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
    # None for network devices: they have no agent of their own.
    token_hash: Mapped[str | None] = mapped_column(Text, unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    depends_on_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="SET NULL")
    )
    ip_addresses: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    macs: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    trap_port: Mapped[int | None] = mapped_column(Integer)  # where this agent receives traps
    public_ip: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    notes_updated_at: Mapped[datetime | None]
    notes_updated_by: Mapped[str | None] = mapped_column(Text)
    # Paused: the alerter skips the server entirely (no incidents, no "not
    # reporting") until it's resumed. Metrics are still stored.
    paused_at: Mapped[datetime | None]
    paused_by: Mapped[str | None] = mapped_column(Text)
    cpu_cores: Mapped[int | None]
    memory_bytes: Mapped[int | None] = mapped_column(BigInteger)
    probe_region: Mapped[str | None] = mapped_column(Text)
    allowed_actions: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    # 'server' (an agent) or 'network' (a device an agent polls over SNMP).
    kind: Mapped[str] = mapped_column(Text, server_default="server", default="server")
    address: Mapped[str | None] = mapped_column(Text)
    poller_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="SET NULL")
    )
    snmp_credential_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("snmp_credentials.id", ondelete="RESTRICT")
    )
    profile: Mapped[str | None] = mapped_column(Text)
    network_role: Mapped[str | None] = mapped_column(Text)
    # The last poll: ok, profile, system group, inventory, last_ok_at.
    device: Mapped[dict] = mapped_column(JSONB, server_default="{}", default=dict)
    device_error: Mapped[str | None] = mapped_column(Text)
    device_polled_at: Mapped[datetime | None]
    # depends_on_host_id was set by topology (LLDP), not by hand.
    depends_on_auto: Mapped[bool] = mapped_column(server_default="false", default=False)


class NotificationChannel(TenantScoped):
    __tablename__ = "notification_channels"

    undeliverable_at: Mapped[datetime | None]
    undeliverable_reason: Mapped[str | None] = mapped_column(Text)

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
    config: Mapped[dict] = mapped_column(JSONB, server_default="{}", default=dict)
    min_severity: Mapped[str] = mapped_column(Text, default="info")
    quiet_hours: Mapped[dict | None] = mapped_column(JSONB)
    only_tag: Mapped[str | None] = mapped_column(Text)  # only alerts for hosts with this tag


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
    aggregation: Mapped[str] = mapped_column(Text, default="last")
    window_seconds: Mapped[int] = mapped_column(default=300)
    recovery_threshold: Mapped[float | None]
    severity: Mapped[str] = mapped_column(Text, default="critical")
    action_name: Mapped[str | None] = mapped_column(Text)
    labels: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    description: Mapped[str | None] = mapped_column(Text)
    log_filter: Mapped[dict | None] = mapped_column(JSONB)
    schedule_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID), default=list)


class AlertEscalationStep(TenantScoped):
    __tablename__ = "alert_escalation_steps"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("alert_rules.id", ondelete="CASCADE")
    )
    position: Mapped[int]
    delay_seconds: Mapped[int]
    channel_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID))
    schedule_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID), default=list)


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
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True)
    host_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    check_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
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
    severity: Mapped[str] = mapped_column(Text, default="critical")
    detail: Mapped[str | None] = mapped_column(Text)
    flapping: Mapped[bool] = mapped_column(default=False)
    reopened_count: Mapped[int] = mapped_column(default=0)
    resolved_by: Mapped[str | None] = mapped_column(Text)
    check_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    snoozed_until: Mapped[datetime | None]
    snoozed_by: Mapped[str | None] = mapped_column(Text)
    merged_into: Mapped[uuid.UUID | None] = mapped_column(UUID)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(UUID)
    assigned_name: Mapped[str | None] = mapped_column(Text)
    assigned_at: Mapped[datetime | None]
    reminded_at: Mapped[datetime | None]
    reminders_sent: Mapped[int] = mapped_column(default=0)


class IncidentEvent(TenantScoped):
    __tablename__ = "incident_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("incidents.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)
    actor: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Check(TenantScoped):
    __tablename__ = "checks"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text)
    params: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    interval_seconds: Mapped[int] = mapped_column(default=60)
    host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="CASCADE")
    )
    tag: Mapped[str | None] = mapped_column(Text)
    on_probes: Mapped[bool] = mapped_column(default=False)
    probe_regions: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list, server_default="{}")
    min_failing: Mapped[int] = mapped_column(default=1)
    enabled: Mapped[bool] = mapped_column(default=True)
    slo_target: Mapped[float] = mapped_column(Numeric(6, 3), default=99.9)
    push_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("checks.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class HostAction(TenantScoped):
    __tablename__ = "host_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    host_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("hosts.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="pending")
    requested_by: Mapped[str] = mapped_column(Text)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    exit_code: Mapped[int | None]
    output: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    finished_at: Mapped[datetime | None]


class HostInventory(TenantScoped):
    __tablename__ = "host_inventory"

    host_id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True)
    data: Mapped[dict] = mapped_column(JSONB)
    changes: Mapped[list] = mapped_column(JSONB)
    updated_at: Mapped[datetime]


class ApiToken(TenantScoped):
    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    token_prefix: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    read_only: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_used_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


class StatusPage(TenantScoped):
    __tablename__ = "status_pages"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(Text, unique=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    show_values: Mapped[bool] = mapped_column(default=True)
    published: Mapped[bool] = mapped_column(default=True)
    domain: Mapped[str | None] = mapped_column(Text)
    domain_token: Mapped[str | None] = mapped_column(Text)
    domain_verified_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class StatusPageUpdate(TenantScoped):
    __tablename__ = "status_page_updates"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    page_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("status_pages.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text, default="")
    starts_at: Mapped[datetime | None]
    ends_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class StatusPageItem(TenantScoped):
    __tablename__ = "status_page_items"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    page_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("status_pages.id", ondelete="CASCADE")
    )
    host_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    check_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    label: Mapped[str] = mapped_column(Text)
    position: Mapped[int] = mapped_column(default=0)


class OutboundMessage(TenantScoped):
    __tablename__ = "outbound_messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    channel_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID)
    kind: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(Text, default="pending")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    attempts: Mapped[int] = mapped_column(default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None]
    held_until: Mapped[datetime | None]


class SavedView(TenantScoped):
    """A named search or set of list filters (logs, servers, incidents, checks)."""

    __tablename__ = "saved_views"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    params: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    created_by: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class OncallSchedule(TenantScoped):
    __tablename__ = "oncall_schedules"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    timezone: Mapped[str] = mapped_column(Text, default="UTC")
    start_at: Mapped[datetime]
    shift_hours: Mapped[int]
    responders: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class OncallOverride(TenantScoped):
    __tablename__ = "oncall_overrides"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    schedule_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("oncall_schedules.id", ondelete="CASCADE")
    )
    starts_at: Mapped[datetime]
    ends_at: Mapped[datetime]
    responder: Mapped[dict] = mapped_column(JSONB)
    note: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Dashboard(TenantScoped):
    __tablename__ = "dashboards"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    panels: Mapped[list] = mapped_column(JSONB, default=list)
    created_by: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class SNMPCredential(TenantScoped):
    __tablename__ = "snmp_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    secret: Mapped[str] = mapped_column(Text)  # devicesecrets.seal(...)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class NetworkInterface(TenantScoped):
    __tablename__ = "network_interfaces"

    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True
    )
    ifindex: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    descr: Mapped[str | None] = mapped_column(Text)
    alias: Mapped[str | None] = mapped_column(Text)
    type: Mapped[int | None]
    speed_bps: Mapped[int | None] = mapped_column(BigInteger)
    mtu: Mapped[int | None]
    mac: Mapped[str | None] = mapped_column(Text)
    admin_up: Mapped[bool | None]
    oper_status: Mapped[int | None]
    billing_tag: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class NetworkTrap(TenantScoped):
    """An SNMP trap a poller received, classified by ingest (netmon/traps)."""

    __tablename__ = "network_traps"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="CASCADE")
    )
    poller_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="SET NULL")
    )
    source: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text, default="")
    oid: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    rule: Mapped[str | None] = mapped_column(Text)
    identity: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(Text, default="info")
    labels: Mapped[dict] = mapped_column(JSONB, default=dict)
    varbinds: Mapped[dict] = mapped_column(JSONB, default=dict)
    repeats: Mapped[int] = mapped_column(Integer, default=0)
    received_at: Mapped[datetime] = mapped_column()
    last_at: Mapped[datetime] = mapped_column()


class NetworkLink(TenantScoped):
    __tablename__ = "network_links"

    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True
    )
    local_port: Mapped[str] = mapped_column(Text, primary_key=True)
    remote_chassis_id: Mapped[str] = mapped_column(Text, primary_key=True, default="")
    remote_port_id: Mapped[str] = mapped_column(Text, primary_key=True, default="")
    remote_sys_name: Mapped[str] = mapped_column(Text, default="")
    remote_port_desc: Mapped[str | None] = mapped_column(Text)
    remote_mgmt_addr: Mapped[str | None] = mapped_column(Text)
    remote_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID, ForeignKey("hosts.id", ondelete="SET NULL")
    )
    seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
