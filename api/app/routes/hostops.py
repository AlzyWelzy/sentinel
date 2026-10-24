"""Per-host operations: remote actions and the software inventory.

Actions only ever run what the server's own allow-list permits (see the
agent's actions.go); the dashboard can ask for one by name, and the host
reports how it went with its next push.
"""

import re
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.models import Host, HostAction, HostInventory
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1/hosts")

ACTION_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
# Actions are for occasional fixes, not a remote shell.
MAX_PENDING_PER_HOST = 5


class ActionIn(BaseModel):
    name: str = Field(min_length=1, max_length=63)


class ActionOut(BaseModel):
    id: uuid.UUID
    host_id: uuid.UUID
    name: str
    status: str
    requested_by: str
    incident_id: uuid.UUID | None
    exit_code: int | None
    output: str | None
    created_at: datetime
    finished_at: datetime | None


class ActionsOut(BaseModel):
    allowed: list[str]
    history: list[ActionOut]


def _out(a: HostAction) -> ActionOut:
    return ActionOut(
        id=a.id,
        host_id=a.host_id,
        name=a.name,
        status=a.status,
        requested_by=a.requested_by,
        incident_id=a.incident_id,
        exit_code=a.exit_code,
        output=a.output,
        created_at=a.created_at,
        finished_at=a.finished_at,
    )


async def _host(t: TenantContext, host_id: uuid.UUID) -> Host:
    host = await t.db.scalar(
        select(Host).where(
            Host.id == host_id, Host.tenant_id == t.tenant_id, Host.revoked_at.is_(None)
        )
    )
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


@router.get("/{host_id}/actions")
async def list_actions(
    host_id: uuid.UUID, t: Tenant, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> ActionsOut:
    host = await _host(t, host_id)
    rows = await t.db.scalars(
        select(HostAction)
        .where(HostAction.host_id == host.id, HostAction.tenant_id == t.tenant_id)
        .order_by(HostAction.created_at.desc())
        .limit(limit)
    )
    return ActionsOut(allowed=sorted(host.allowed_actions or []), history=[_out(a) for a in rows])


@router.post("/{host_id}/actions", status_code=status.HTTP_202_ACCEPTED)
async def run_action(host_id: uuid.UUID, body: ActionIn, t: Tenant) -> ActionOut:
    host = await _host(t, host_id)
    if not ACTION_RE.match(body.name) or body.name not in (host.allowed_actions or []):
        raise HTTPException(
            status_code=422,
            detail=(
                f"This server doesn't allow {body.name!r}. An administrator can allow it "
                f"on the server with: sudo pulsegrid-agent allow-action {body.name} "
                "-- /full/path/to/command"
            ),
        )
    pending = await t.db.scalar(
        select(func.count())
        .select_from(HostAction)
        .where(
            HostAction.host_id == host.id,
            HostAction.status == "pending",
            HostAction.tenant_id == t.tenant_id,
        )
    )
    if (pending or 0) >= MAX_PENDING_PER_HOST:
        raise HTTPException(
            status_code=429, detail="This server already has actions waiting to run"
        )
    action = HostAction(
        tenant_id=t.tenant_id,
        host_id=host.id,
        name=body.name,
        requested_by=t.principal.email or t.principal.name or "dashboard",
    )
    t.db.add(action)
    await t.db.flush()
    await t.db.refresh(action)
    return _out(action)


class InventoryOut(BaseModel):
    updated_at: datetime | None
    kernel_version: str | None = None
    boot_time: int | None = None
    cpu_model: str | None = None
    virtualization: str | None = None
    packages: list[dict] = []
    listening_ports: list[dict] = []
    plugins: list[dict] = []
    allowed_actions: list[str] = []
    changes: list[dict] = []


@router.get("/{host_id}/inventory")
async def inventory(
    host_id: uuid.UUID,
    t: Tenant,
    search: Annotated[
        str | None, Query(max_length=100, description="filter packages by name")
    ] = None,
) -> InventoryOut:
    host = await _host(t, host_id)
    inv = await t.db.scalar(
        select(HostInventory).where(
            HostInventory.host_id == host.id, HostInventory.tenant_id == t.tenant_id
        )
    )
    if inv is None:
        return InventoryOut(updated_at=None)
    data = inv.data or {}
    packages = data.get("packages") or []
    if search:
        needle = search.lower()
        packages = [p for p in packages if needle in str(p.get("name", "")).lower()]
    return InventoryOut(
        updated_at=inv.updated_at,
        kernel_version=data.get("kernel_version"),
        boot_time=data.get("boot_time"),
        cpu_model=data.get("cpu_model"),
        virtualization=data.get("virtualization"),
        packages=packages,
        listening_ports=data.get("listening_ports") or [],
        plugins=data.get("plugins") or [],
        allowed_actions=data.get("allowed_actions") or [],
        changes=inv.changes or [],
    )
