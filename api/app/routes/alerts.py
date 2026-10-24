"""Alert rules and incidents.

Rules are evaluated by the alerter service every 30 seconds. Incidents are
opened and resolved by the alerter; customers can list and acknowledge them.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import delete, func, select, update

from app.models import (
    AlertEscalationStep,
    AlertRule,
    AlertRuleChannel,
    AlertState,
    Host,
    Incident,
    NotificationChannel,
)
from app.tenancy import Tenant, TenantContext
from app.validation import normalize_tag, validate_target

router = APIRouter(prefix="/v1")

# A host pushes every 30s; anything shorter than two missed pushes is noise.
MIN_HOST_DOWN_SECONDS = 60
MAX_ESCALATION_STEPS = 5

Metric = Literal[
    "cpu", "memory", "swap", "disk", "load1", "load5", "iowait", "steal", "inodes", "disk_busy"
]
Kind = Literal["metric", "host_down", "process_down", "service_down"]


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

    @field_validator("tag")
    @classmethod
    def _tag(cls, v: str | None) -> str | None:
        return None if v is None or v.strip() == "" else normalize_tag(v)

    @model_validator(mode="after")
    def _check_kind(self) -> "RuleIn":
        if self.host_id is not None and self.tag is not None:
            raise ValueError("choose one host or one tag, not both")
        if self.kind == "metric":
            if self.metric is None or self.operator is None or self.threshold is None:
                raise ValueError("metric rules need metric, operator and threshold")
            self.target = None
        elif self.kind in ("process_down", "service_down"):
            if not self.target:
                raise ValueError(f"{self.kind} rules need a target (the name to watch)")
            self.target = validate_target(self.kind, self.target)
            self.metric = self.operator = self.threshold = None
        else:
            self.metric = self.operator = self.threshold = self.target = None
            if self.duration_seconds < MIN_HOST_DOWN_SECONDS:
                raise ValueError(f"host_down needs duration_seconds >= {MIN_HOST_DOWN_SECONDS}")
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
    await t.db.execute(
        update(Incident)
        .where(
            Incident.rule_id == rule_id,
            Incident.tenant_id == t.tenant_id,
            Incident.status == "open",
        )
        .values(status="resolved", resolved_at=datetime.now(UTC))
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
        "duration_seconds": 600,
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
    condition = ("kind", "metric", "operator", "threshold", "target", "host_id", "tag")
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


@router.get("/incidents")
async def list_incidents(
    t: Tenant,
    status_: Annotated[Literal["open", "resolved"] | None, Query(alias="status")] = None,
    host_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[IncidentOut]:
    q = select(Incident).where(Incident.tenant_id == t.tenant_id)
    if status_:
        q = q.where(Incident.status == status_)
    if host_id:
        q = q.where(Incident.host_id == host_id)
    rows = await t.db.scalars(q.order_by(Incident.opened_at.desc()).limit(limit))
    return [_incident_out(i) for i in rows]


async def _get_incident(t: TenantContext, incident_id: uuid.UUID) -> Incident:
    incident = await t.db.scalar(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == t.tenant_id)
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: uuid.UUID, t: Tenant) -> IncidentOut:
    return _incident_out(await _get_incident(t, incident_id))


@router.post("/incidents/{incident_id}/acknowledge")
async def acknowledge(incident_id: uuid.UUID, t: Tenant) -> IncidentOut:
    incident = await _get_incident(t, incident_id)
    if incident.acknowledged_at is None:
        incident.acknowledged_at = datetime.now(UTC)
        incident.acknowledged_by = t.principal.email or t.principal.name or "dashboard"
    return _incident_out(incident)
