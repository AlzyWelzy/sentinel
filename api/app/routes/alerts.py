"""Alert rules and incidents.

Rules are evaluated by the alerter service every 30 seconds. Incidents are
opened and resolved by the alerter; customers can list them, read their
timeline, add notes, acknowledge, resolve by hand, and reopen them.
"""

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import delete, func, select, update

from app.models import (
    AlertEscalationStep,
    AlertRule,
    AlertRuleChannel,
    AlertState,
    Check,
    Host,
    Incident,
    IncidentEvent,
    NotificationChannel,
)
from app.tenancy import Tenant, TenantContext
from app.validation import normalize_tag, validate_target

router = APIRouter(prefix="/v1")

# A host pushes every 30s; anything shorter than two missed pushes is noise.
MIN_HOST_DOWN_SECONDS = 60
MAX_ESCALATION_STEPS = 5

Metric = Literal[
    "cpu",
    "memory",
    "swap",
    "disk",
    "load1",
    "load5",
    "iowait",
    "steal",
    "inodes",
    "disk_busy",
    "network_in",
    "network_out",
]
Kind = Literal[
    "metric",
    "host_down",
    "process_down",
    "service_down",
    "check",
    "anomaly",
    "forecast",
    "plugin_down",
    "container_down",
    "custom",
]
FORECAST_METRICS = ("disk", "inodes", "memory", "swap")
# Metrics an anomaly rule can watch: ones with a meaningful "usual level".
ANOMALY_METRICS = (
    "cpu",
    "memory",
    "load1",
    "load5",
    "iowait",
    "disk_busy",
    "network_in",
    "network_out",
)
CUSTOM_METRIC_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,150}$")
LABEL_KEY_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,49}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PLUGIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
ACTION_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")


class EscalationStepIn(BaseModel):
    delay_minutes: int = Field(ge=1, le=10080, description="after the incident opened")
    channel_ids: list[uuid.UUID] = Field(min_length=1, max_length=10)


class EscalationStepOut(EscalationStepIn):
    pass


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: Kind
    metric: Metric | None = None
    operator: Literal[">", "<"] | None = None
    threshold: float | None = None
    target: str | None = Field(
        default=None, description="process or service name, for process_down / service_down"
    )
    duration_seconds: int = Field(default=300, ge=0, le=86400)
    host_id: uuid.UUID | None = Field(default=None, description="omit (and tag) for every host")
    tag: str | None = Field(default=None, description="every host with this tag")
    channel_ids: list[uuid.UUID] = Field(
        default_factory=list, description="omit to use the default channel"
    )
    escalations: list[EscalationStepIn] = Field(
        default_factory=list,
        max_length=MAX_ESCALATION_STEPS,
        description="who else to notify while nobody acknowledges",
    )
    enabled: bool = True
    aggregation: Literal["last", "avg", "max", "min"] = Field(
        default="last", description="metric and custom rules: how the window is summarised"
    )
    window_seconds: int = Field(default=300, ge=60, le=86400)
    recovery_threshold: float | None = Field(
        default=None, description="once firing, resolve only past this value"
    )
    severity: Literal["critical", "warning", "info"] = "critical"
    action_name: str | None = Field(
        default=None, description="an action the host allows, run when the alert fires"
    )
    labels: dict[str, str] = Field(default_factory=dict, description="custom: label filters")
    description: str | None = Field(
        default=None, max_length=2000, description="runbook text included in alerts"
    )

    @field_validator("tag")
    @classmethod
    def _tag(cls, v: str | None) -> str | None:
        return None if v is None or v.strip() == "" else normalize_tag(v)

    @field_validator("action_name")
    @classmethod
    def _action(cls, v: str | None) -> str | None:
        if v is None or v.strip() == "":
            return None
        if not ACTION_RE.match(v):
            raise ValueError("action names are lowercase letters, digits, '.', '_' and '-'")
        return v

    @model_validator(mode="after")
    def _check_kind(self) -> "RuleIn":
        if self.host_id is not None and self.tag is not None:
            raise ValueError("choose one host or one tag, not both")
        k = self.kind
        if k not in ("metric", "custom"):
            self.recovery_threshold = None
            self.aggregation = "last"
        if k != "custom":
            self.labels = {}
        if k == "metric":
            if self.metric is None or self.operator is None or self.threshold is None:
                raise ValueError("metric rules need metric, operator and threshold")
            self.target = None
        elif k == "custom":
            if not self.target or not CUSTOM_METRIC_RE.match(self.target):
                raise ValueError("custom rules need target: the metric name a plugin reports")
            if self.operator is None or self.threshold is None:
                raise ValueError("custom rules need operator and threshold")
            if len(self.labels) > 5 or any(not LABEL_KEY_RE.match(k2) for k2 in self.labels):
                raise ValueError("at most 5 label filters, with names like queue or status_code")
            self.target = self.target.removeprefix("pulsegrid_custom_")
            self.metric = None
        elif k in ("process_down", "service_down"):
            if not self.target:
                raise ValueError(f"{k} rules need a target (the name to watch)")
            self.target = validate_target(k, self.target)
            self.metric = self.operator = self.threshold = None
        elif k == "container_down":
            if not self.target or not CONTAINER_RE.match(self.target.strip()):
                raise ValueError("container_down rules need the container's name")
            self.target = self.target.strip()
            self.metric = self.operator = self.threshold = None
        elif k == "plugin_down":
            if self.target is not None and self.target.strip() == "":
                self.target = None
            if self.target is not None and not PLUGIN_RE.match(self.target):
                raise ValueError("plugin names are the plugin file's name, e.g. mysql")
            self.metric = self.operator = self.threshold = None
        elif k == "check":
            try:
                self.target = str(uuid.UUID(str(self.target)))
            except ValueError:
                raise ValueError("check rules need target: the check's id") from None
            self.metric = self.operator = self.threshold = None
            self.host_id = self.tag = None  # the check decides where it runs
        elif k == "anomaly":
            if self.metric not in ANOMALY_METRICS:
                raise ValueError(f"anomaly rules watch one of: {', '.join(ANOMALY_METRICS)}")
            if self.threshold is None:
                self.threshold = 3
            if not 2 <= self.threshold <= 10:
                raise ValueError("anomaly sensitivity (threshold) is 2-10 standard deviations")
            self.operator, self.target = ">", None
        elif k == "forecast":
            if self.metric not in FORECAST_METRICS:
                raise ValueError(f"forecast rules watch one of: {', '.join(FORECAST_METRICS)}")
            if self.threshold is None or not 1 <= self.threshold <= 720:
                raise ValueError("forecast rules need threshold: the horizon in hours (1-720)")
            self.operator, self.target = ">", None
        else:  # host_down
            self.metric = self.operator = self.threshold = self.target = None
            if self.duration_seconds < MIN_HOST_DOWN_SECONDS:
                raise ValueError(f"host_down needs duration_seconds >= {MIN_HOST_DOWN_SECONDS}")
        if self.recovery_threshold is not None and self.threshold is not None:
            wrong_side = (self.operator == ">" and self.recovery_threshold > self.threshold) or (
                self.operator == "<" and self.recovery_threshold < self.threshold
            )
            if wrong_side:
                raise ValueError(
                    "recovery_threshold must be on the healthy side of threshold "
                    "(e.g. alert above 90, recover below 80)"
                )
        delays = [e.delay_minutes for e in self.escalations]
        if delays != sorted(set(delays)):
            raise ValueError("escalation steps must come later and later (increasing delay)")
        return self


class RuleOut(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    metric: str | None
    operator: str | None
    threshold: float | None
    target: str | None
    duration_seconds: int
    host_id: uuid.UUID | None
    tag: str | None
    channel_ids: list[uuid.UUID]
    escalations: list[EscalationStepOut]
    enabled: bool
    aggregation: str
    window_seconds: int
    recovery_threshold: float | None
    severity: str
    action_name: str | None
    labels: dict[str, str]
    description: str | None
    firing_hosts: int
    created_at: datetime
    updated_at: datetime


class IncidentOut(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID | None
    host_id: uuid.UUID | None
    status: str
    summary: str
    rule_name: str
    hostname: str
    value: float | None
    opened_at: datetime
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    resolved_at: datetime | None
    escalation_level: int
    severity: str
    detail: str | None
    flapping: bool
    reopened_count: int
    resolved_by: str | None
    check_id: uuid.UUID | None
    duration_seconds: int
    snoozed_until: datetime | None = None
    snoozed_by: str | None = None


class IncidentEventOut(BaseModel):
    id: uuid.UUID
    kind: str
    message: str
    actor: str | None
    created_at: datetime


class IncidentDetail(IncidentOut):
    events: list[IncidentEventOut]


class NoteIn(BaseModel):
    message: str = Field(min_length=1, max_length=5000)


class SnoozeIn(BaseModel):
    minutes: int = Field(ge=5, le=7 * 24 * 60, description="hold escalations and reminders")
    reason: str | None = Field(default=None, max_length=500)


def _incident_out(i: Incident) -> IncidentOut:
    return IncidentOut(
        id=i.id,
        rule_id=i.rule_id,
        host_id=i.host_id,
        status=i.status,
        summary=i.summary,
        rule_name=i.rule_name,
        hostname=i.hostname,
        value=i.value,
        opened_at=i.opened_at,
        acknowledged_at=i.acknowledged_at,
        acknowledged_by=i.acknowledged_by,
        resolved_at=i.resolved_at,
        escalation_level=i.escalation_level,
        severity=i.severity,
        detail=i.detail,
        flapping=i.flapping,
        reopened_count=i.reopened_count,
        resolved_by=i.resolved_by,
        check_id=i.check_id,
        duration_seconds=int(((i.resolved_at or datetime.now(UTC)) - i.opened_at).total_seconds()),
        snoozed_until=i.snoozed_until
        if i.snoozed_until and i.snoozed_until > datetime.now(UTC)
        else None,
        snoozed_by=i.snoozed_by,
    )


async def _rule_out(t: TenantContext, r: AlertRule) -> RuleOut:
    channel_ids = list(
        await t.db.scalars(
            select(AlertRuleChannel.channel_id).where(
                AlertRuleChannel.rule_id == r.id, AlertRuleChannel.tenant_id == t.tenant_id
            )
        )
    )
    firing = await t.db.scalar(
        select(func.count())
        .select_from(AlertState)
        .where(
            AlertState.rule_id == r.id,
            AlertState.tenant_id == t.tenant_id,
            AlertState.state == "firing",
        )
    )
    steps = await t.db.scalars(
        select(AlertEscalationStep)
        .where(AlertEscalationStep.rule_id == r.id, AlertEscalationStep.tenant_id == t.tenant_id)
        .order_by(AlertEscalationStep.position)
    )
    return RuleOut(
        id=r.id,
        name=r.name,
        kind=r.kind,
        metric=r.metric,
        operator=r.operator,
        threshold=r.threshold,
        target=r.target,
        duration_seconds=r.duration_seconds,
        host_id=r.host_id,
        tag=r.tag,
        channel_ids=channel_ids,
        escalations=[
            EscalationStepOut(delay_minutes=s.delay_seconds // 60, channel_ids=list(s.channel_ids))
            for s in steps
        ],
        enabled=r.enabled,
        aggregation=r.aggregation,
        window_seconds=r.window_seconds,
        recovery_threshold=r.recovery_threshold,
        severity=r.severity,
        action_name=r.action_name,
        labels=r.labels or {},
        description=r.description,
        firing_hosts=firing or 0,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


async def _get_rule(t: TenantContext, rule_id: uuid.UUID) -> AlertRule:
    rule = await t.db.scalar(
        select(AlertRule).where(AlertRule.id == rule_id, AlertRule.tenant_id == t.tenant_id)
    )
    if rule is None:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return rule


async def _check_refs(t: TenantContext, body: RuleIn) -> None:
    """Hosts and channels must be the caller's own. RLS would hide anyone
    else's anyway, which is exactly why a missing one reads as 'not found'."""
    if body.host_id is not None:
        found = await t.db.scalar(
            select(Host.id).where(Host.id == body.host_id, Host.tenant_id == t.tenant_id)
        )
        if found is None:
            raise HTTPException(status_code=422, detail="host_id not found")
    if body.kind == "check":
        found = await t.db.scalar(
            select(Check.id).where(
                Check.id == uuid.UUID(body.target or ""), Check.tenant_id == t.tenant_id
            )
        )
        if found is None:
            raise HTTPException(status_code=422, detail="check not found")
    wanted = set(body.channel_ids) | {c for e in body.escalations for c in e.channel_ids}
    if wanted:
        found = set(
            await t.db.scalars(
                select(NotificationChannel.id).where(
                    NotificationChannel.id.in_(wanted),
                    NotificationChannel.tenant_id == t.tenant_id,
                )
            )
        )
        if found != wanted:
            raise HTTPException(status_code=422, detail="unknown notification channels")


async def _set_channels(t: TenantContext, rule_id: uuid.UUID, channel_ids: list[uuid.UUID]) -> None:
    await t.db.execute(
        delete(AlertRuleChannel).where(
            AlertRuleChannel.rule_id == rule_id, AlertRuleChannel.tenant_id == t.tenant_id
        )
    )
    for channel_id in dict.fromkeys(channel_ids):
        t.db.add(AlertRuleChannel(tenant_id=t.tenant_id, rule_id=rule_id, channel_id=channel_id))


async def _set_escalations(
    t: TenantContext, rule_id: uuid.UUID, steps: list[EscalationStepIn]
) -> None:
    await t.db.execute(
        delete(AlertEscalationStep).where(
            AlertEscalationStep.rule_id == rule_id, AlertEscalationStep.tenant_id == t.tenant_id
        )
    )
    for position, step in enumerate(steps):
        t.db.add(
            AlertEscalationStep(
                tenant_id=t.tenant_id,
                rule_id=rule_id,
                position=position,
                delay_seconds=step.delay_minutes * 60,
                channel_ids=list(dict.fromkeys(step.channel_ids)),
            )
        )


async def _reset_rule(t: TenantContext, rule_id: uuid.UUID) -> None:
    """Forget the alerter's progress on a rule and close its open incidents.
    Used when a rule is disabled, deleted, or its condition changes, so no
    incident is left open forever by a rule that can no longer resolve it."""
    closed = await t.db.scalars(
        update(Incident)
        .where(
            Incident.rule_id == rule_id,
            Incident.tenant_id == t.tenant_id,
            Incident.status == "open",
        )
        .values(status="resolved", resolved_at=datetime.now(UTC), resolved_by=_actor(t))
        .returning(Incident.id)
    )
    for incident_id in closed:
        t.db.add(
            IncidentEvent(
                tenant_id=t.tenant_id,
                incident_id=incident_id,
                kind="resolved",
                message="Closed because its alert rule was changed, disabled or deleted",
                actor=_actor(t),
            )
        )
    await t.db.execute(
        delete(AlertState).where(AlertState.rule_id == rule_id, AlertState.tenant_id == t.tenant_id)
    )


@router.get("/alert-rules")
async def list_rules(t: Tenant) -> list[RuleOut]:
    rules = await t.db.scalars(
        select(AlertRule).where(AlertRule.tenant_id == t.tenant_id).order_by(AlertRule.created_at)
    )
    return [await _rule_out(t, r) for r in rules]


@router.post("/alert-rules", status_code=status.HTTP_201_CREATED)
async def create_rule(body: RuleIn, t: Tenant) -> RuleOut:
    await _check_refs(t, body)
    rule = AlertRule(
        tenant_id=t.tenant_id,
        **body.model_dump(exclude={"channel_ids", "escalations"}),
    )
    t.db.add(rule)
    await t.db.flush()
    await _set_channels(t, rule.id, body.channel_ids)
    await _set_escalations(t, rule.id, body.escalations)
    await t.db.flush()
    await t.db.refresh(rule)
    return await _rule_out(t, rule)


# A sensible starting point for a new account: one click in the dashboard.
RECOMMENDED: list[dict] = [
    {"name": "Server not reporting", "kind": "host_down", "duration_seconds": 180},
    {
        "name": "CPU above 90%",
        "kind": "metric",
        "metric": "cpu",
        "operator": ">",
        "threshold": 90,
        "recovery_threshold": 80,
        "aggregation": "avg",
        "window_seconds": 300,
        "duration_seconds": 300,
    },
    {
        "name": "Memory above 90%",
        "kind": "metric",
        "metric": "memory",
        "operator": ">",
        "threshold": 90,
        "duration_seconds": 600,
    },
    {
        "name": "Disk above 90%",
        "kind": "metric",
        "metric": "disk",
        "operator": ">",
        "threshold": 90,
        "duration_seconds": 300,
    },
    {
        "name": "Inodes above 90%",
        "kind": "metric",
        "metric": "inodes",
        "operator": ">",
        "threshold": 90,
        "duration_seconds": 300,
    },
    {
        "name": "Disk will be full within 2 days",
        "kind": "forecast",
        "metric": "disk",
        "threshold": 48,
        "duration_seconds": 1800,
        "severity": "warning",
    },
    {
        "name": "A plugin stopped collecting",
        "kind": "plugin_down",
        "duration_seconds": 300,
        "severity": "warning",
    },
    {
        "name": "CPU steal above 20%",
        "kind": "metric",
        "metric": "steal",
        "operator": ">",
        "threshold": 20,
        "duration_seconds": 900,
    },
]


@router.post("/alert-rules/recommended", status_code=status.HTTP_201_CREATED)
async def add_recommended_rules(t: Tenant) -> list[RuleOut]:
    """Adds the recommended rules for every server (current and future),
    skipping any whose name the account already uses. Returns the new ones."""
    existing = set(
        await t.db.scalars(select(AlertRule.name).where(AlertRule.tenant_id == t.tenant_id))
    )
    created = []
    for spec in RECOMMENDED:
        if spec["name"] in existing:
            continue
        body = RuleIn(**spec)
        rule = AlertRule(
            tenant_id=t.tenant_id, **body.model_dump(exclude={"channel_ids", "escalations"})
        )
        t.db.add(rule)
        created.append(rule)
    await t.db.flush()
    out = []
    for rule in created:
        await t.db.refresh(rule)
        out.append(await _rule_out(t, rule))
    return out


@router.get("/alert-rules/{rule_id}")
async def get_rule(rule_id: uuid.UUID, t: Tenant) -> RuleOut:
    return await _rule_out(t, await _get_rule(t, rule_id))


@router.put("/alert-rules/{rule_id}")
async def update_rule(rule_id: uuid.UUID, body: RuleIn, t: Tenant) -> RuleOut:
    rule = await _get_rule(t, rule_id)
    await _check_refs(t, body)
    condition = (
        "kind",
        "metric",
        "operator",
        "threshold",
        "target",
        "host_id",
        "tag",
        "aggregation",
        "window_seconds",
        "labels",
    )
    changed = any(getattr(rule, f) != getattr(body, f) for f in condition)
    if changed or (rule.enabled and not body.enabled):
        await _reset_rule(t, rule.id)
    for field, value in body.model_dump(exclude={"channel_ids", "escalations"}).items():
        setattr(rule, field, value)
    rule.updated_at = datetime.now(UTC)
    await _set_channels(t, rule.id, body.channel_ids)
    await _set_escalations(t, rule.id, body.escalations)
    await t.db.flush()
    return await _rule_out(t, rule)


@router.delete("/alert-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: uuid.UUID, t: Tenant) -> None:
    rule = await _get_rule(t, rule_id)
    await _reset_rule(t, rule.id)
    await t.db.delete(rule)


def _actor(t: TenantContext) -> str:
    return t.principal.email or t.principal.name or "dashboard"


@router.get("/incidents")
async def list_incidents(
    t: Tenant,
    status_: Annotated[Literal["open", "resolved"] | None, Query(alias="status")] = None,
    host_id: uuid.UUID | None = None,
    check_id: uuid.UUID | None = None,
    severity: Literal["critical", "warning", "info"] | None = None,
    before: Annotated[datetime | None, Query(description="opened before this (paging)")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[IncidentOut]:
    q = select(Incident).where(Incident.tenant_id == t.tenant_id)
    if status_:
        q = q.where(Incident.status == status_)
    if host_id:
        q = q.where(Incident.host_id == host_id)
    if check_id:
        q = q.where(Incident.check_id == check_id)
    if severity:
        q = q.where(Incident.severity == severity)
    if before:
        q = q.where(Incident.opened_at < before)
    rows = await t.db.scalars(q.order_by(Incident.opened_at.desc()).limit(limit))
    return [_incident_out(i) for i in rows]


async def _get_incident(t: TenantContext, incident_id: uuid.UUID) -> Incident:
    incident = await t.db.scalar(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == t.tenant_id)
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


async def _detail(t: TenantContext, incident: Incident) -> IncidentDetail:
    events = await t.db.scalars(
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == incident.id, IncidentEvent.tenant_id == t.tenant_id)
        .order_by(IncidentEvent.created_at, IncidentEvent.id)
    )
    return IncidentDetail(
        **_incident_out(incident).model_dump(),
        events=[
            IncidentEventOut(
                id=e.id, kind=e.kind, message=e.message, actor=e.actor, created_at=e.created_at
            )
            for e in events
        ],
    )


def _event(t: TenantContext, incident: Incident, kind: str, message: str) -> None:
    t.db.add(
        IncidentEvent(
            tenant_id=t.tenant_id,
            incident_id=incident.id,
            kind=kind,
            message=message,
            actor=_actor(t),
        )
    )


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: uuid.UUID, t: Tenant) -> IncidentDetail:
    return await _detail(t, await _get_incident(t, incident_id))


@router.post("/incidents/{incident_id}/acknowledge")
async def acknowledge(incident_id: uuid.UUID, t: Tenant) -> IncidentDetail:
    incident = await _get_incident(t, incident_id)
    if incident.acknowledged_at is None and incident.status == "open":
        incident.acknowledged_at = datetime.now(UTC)
        incident.acknowledged_by = _actor(t)
        _event(t, incident, "acknowledged", "Acknowledged: escalation stopped")
    await t.db.flush()
    return await _detail(t, incident)


@router.post("/incidents/{incident_id}/notes", status_code=status.HTTP_201_CREATED)
async def add_note(incident_id: uuid.UUID, body: NoteIn, t: Tenant) -> IncidentDetail:
    incident = await _get_incident(t, incident_id)
    _event(t, incident, "note", body.message.strip())
    await t.db.flush()
    return await _detail(t, incident)


@router.post("/incidents/{incident_id}/resolve")
async def resolve(incident_id: uuid.UUID, t: Tenant, body: NoteIn | None = None) -> IncidentDetail:
    """Close an incident by hand. If the problem is still there, the alerter
    opens a new incident once the rule's duration has passed again."""
    incident = await _get_incident(t, incident_id)
    if incident.status == "open":
        incident.status = "resolved"
        incident.resolved_at = datetime.now(UTC)
        incident.resolved_by = _actor(t)
        message = "Resolved by hand"
        if body is not None:
            message += ": " + body.message.strip()
        _event(t, incident, "resolved", message)
        await t.db.execute(
            delete(AlertState).where(
                AlertState.incident_id == incident.id, AlertState.tenant_id == t.tenant_id
            )
        )
    await t.db.flush()
    return await _detail(t, incident)


@router.post("/incidents/{incident_id}/reopen")
async def reopen(incident_id: uuid.UUID, t: Tenant, body: NoteIn | None = None) -> IncidentDetail:
    """Reopen a resolved incident ("it's not actually fixed"). A reopened
    incident is closed by hand: the alert rule already moved on."""
    incident = await _get_incident(t, incident_id)
    if incident.status == "resolved":
        incident.status = "open"
        incident.resolved_at = None
        incident.resolved_by = None
        incident.acknowledged_at = datetime.now(UTC)
        incident.acknowledged_by = _actor(t)
        incident.reopened_count += 1
        message = "Reopened"
        if body is not None:
            message += ": " + body.message.strip()
        _event(t, incident, "reopened", message)
    await t.db.flush()
    return await _detail(t, incident)


@router.post("/incidents/{incident_id}/snooze")
async def snooze(incident_id: uuid.UUID, body: SnoozeIn, t: Tenant) -> IncidentDetail:
    """ "I know, I'm on it": hold escalations and reminders for a while
    without resolving. The incident stays open and visible; when the snooze
    runs out, escalation picks up where it left off."""
    incident = await _get_incident(t, incident_id)
    if incident.status != "open":
        raise HTTPException(status_code=409, detail="Only open incidents can be snoozed")
    incident.snoozed_until = datetime.now(UTC) + timedelta(minutes=body.minutes)
    incident.snoozed_by = _actor(t)
    message = f"Snoozed for {_human_minutes(body.minutes)}"
    if body.reason:
        message += ": " + body.reason.strip()
    _event(t, incident, "snoozed", message)
    await t.db.flush()
    return await _detail(t, incident)


@router.delete("/incidents/{incident_id}/snooze")
async def unsnooze(incident_id: uuid.UUID, t: Tenant) -> IncidentDetail:
    incident = await _get_incident(t, incident_id)
    if incident.snoozed_until is not None:
        incident.snoozed_until = None
        _event(t, incident, "unsnoozed", "Snooze ended early")
    await t.db.flush()
    return await _detail(t, incident)


def _human_minutes(minutes: int) -> str:
    if minutes % 1440 == 0:
        return f"{minutes // 1440} day{'s' if minutes > 1440 else ''}"
    if minutes % 60 == 0:
        return f"{minutes // 60} hour{'s' if minutes > 60 else ''}"
    return f"{minutes} minutes"


def _span(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    h, m = divmod(seconds // 60, 60)
    return f"{h}h {m}m" if h else f"{m}m"


def _when(d: datetime | None) -> str:
    return d.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC") if d else "—"


@router.get("/incidents/{incident_id}/postmortem", response_class=PlainTextResponse)
async def postmortem(incident_id: uuid.UUID, t: Tenant) -> str:
    """A postmortem draft in Markdown: the facts filled in from the incident
    (times, timeline, notes, related alerts on the same server), with the
    sections people write themselves left as prompts."""
    incident = await _get_incident(t, incident_id)
    detail = await _detail(t, incident)
    opened = incident.opened_at
    tta = (incident.acknowledged_at - opened).total_seconds() if incident.acknowledged_at else None
    ttr = (incident.resolved_at - opened).total_seconds() if incident.resolved_at else None
    related = []
    if incident.host_id is not None:
        related = list(
            await t.db.scalars(
                select(Incident)
                .where(
                    Incident.tenant_id == t.tenant_id,
                    Incident.host_id == incident.host_id,
                    Incident.id != incident.id,
                    Incident.opened_at >= opened - timedelta(hours=2),
                    Incident.opened_at <= (incident.resolved_at or datetime.now(UTC)),
                )
                .order_by(Incident.opened_at)
                .limit(20)
            )
        )
    lines = [
        f"# Postmortem: {incident.summary}",
        "",
        f"_Draft generated by Pulsegrid on {_when(datetime.now(UTC))}. "
        "Facts are filled in; edit the sections in italics._",
        "",
        "## Summary",
        "",
        "| | |",
        "|---|---|",
        f"| Status | {incident.status} |",
        f"| Severity | {incident.severity} |",
        f"| Server | {incident.hostname or '—'} |",
        f"| Alert rule | {incident.rule_name} |",
        f"| Value when it fired | {incident.value if incident.value is not None else '—'} |",
        f"| Opened | {_when(opened)} |",
        f"| Acknowledged | {_when(incident.acknowledged_at)}"
        + (f" by {incident.acknowledged_by}" if incident.acknowledged_by else "")
        + " |",
        f"| Resolved | {_when(incident.resolved_at)}"
        + (f" by {incident.resolved_by}" if incident.resolved_by else "")
        + " |",
        f"| Time to acknowledge | {_span(tta)} |",
        f"| Time to resolve | {_span(ttr)} |",
        f"| Reopened | {incident.reopened_count} time(s) |",
        "",
    ]
    if incident.detail:
        lines += ["## What the alert said", "", incident.detail, ""]
    lines += ["## Timeline", ""]
    lines += [f"- **{_when(opened)}** — Incident opened: {incident.summary}"]
    lines += [
        f"- **{_when(e.created_at)}** — {e.kind.replace('_', ' ').capitalize()}: {e.message}"
        + (f" ({e.actor})" if e.actor else "")
        for e in detail.events
        if e.kind != "note"
    ]
    notes = [e for e in detail.events if e.kind == "note"]
    if notes:
        lines += ["", "## Notes from responders", ""]
        lines += [f"- {_when(e.created_at)}, {e.actor or 'someone'}: {e.message}" for e in notes]
    if related:
        lines += ["", "## Other alerts on this server around the same time", ""]
        lines += [
            f"- {_when(r.opened_at)} — {r.summary} ({r.severity}, {r.status})" for r in related
        ]
    lines += [
        "",
        "## Impact",
        "",
        "_Who was affected, how, and for how long?_",
        "",
        "## Root cause",
        "",
        '_What actually went wrong? Ask "why" until the answer is something you can change._',
        "",
        "## What went well / what didn't",
        "",
        "_Detection, response, communication._",
        "",
        "## Action items",
        "",
        "- [ ] _Prevent it:_",
        "- [ ] _Detect it sooner:_ (an alert rule, a lower threshold, a check)",
        "- [ ] _Recover faster:_ (a runbook in the rule's description, a self-healing action)",
        "",
    ]
    return "\n".join(lines)
