"""Saved views: a log search, or a list's filters, kept under a name so the
team can open it again in one click."""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models import SavedView
from app.tenancy import Tenant, TenantContext

router = APIRouter(prefix="/v1/saved-views", tags=["saved views"])

Kind = Literal["logs", "servers", "incidents", "checks"]
MAX_PER_KIND = 100


class ViewIn(BaseModel):
    kind: Kind
    name: str = Field(min_length=1, max_length=100)
    # The page's own filter keys (q, level, tag, status...): small, flat values.
    params: dict[str, str | int | float | bool | list[str] | None] = Field(default_factory=dict)


class ViewOut(BaseModel):
    id: uuid.UUID
    kind: str
    name: str
    params: dict
    created_by: str | None
    created_at: datetime


def _out(v: SavedView) -> ViewOut:
    return ViewOut(
        id=v.id,
        kind=v.kind,
        name=v.name,
        params=v.params,
        created_by=v.created_by,
        created_at=v.created_at,
    )


def _actor(t: TenantContext) -> str:
    return t.principal.email or t.principal.name or "dashboard"


def _check_size(params: dict) -> None:
    if len(params) > 30 or len(repr(params)) > 4000:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Too many filters to save")


@router.get("")
async def list_views(t: Tenant, kind: Annotated[Kind | None, Query()] = None) -> list[ViewOut]:
    q = select(SavedView).where(SavedView.tenant_id == t.tenant_id)
    if kind:
        q = q.where(SavedView.kind == kind)
    rows = await t.db.scalars(q.order_by(SavedView.kind, SavedView.name))
    return [_out(v) for v in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_view(body: ViewIn, t: Tenant) -> ViewOut:
    _check_size(body.params)
    count = len(
        list(
            await t.db.scalars(
                select(SavedView.id).where(
                    SavedView.tenant_id == t.tenant_id, SavedView.kind == body.kind
                )
            )
        )
    )
    if count >= MAX_PER_KIND:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "At most 100 saved views here")
    view = SavedView(
        tenant_id=t.tenant_id,
        kind=body.kind,
        name=body.name.strip(),
        params=body.params,
        created_by=_actor(t),
    )
    t.db.add(view)
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "A view with that name exists") from None
    await t.db.refresh(view)
    return _out(view)


@router.put("/{view_id}")
async def update_view(view_id: uuid.UUID, body: ViewIn, t: Tenant) -> ViewOut:
    _check_size(body.params)
    view = await t.db.get(SavedView, view_id)
    if view is None or view.tenant_id != t.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Saved view not found")
    view.name, view.params = body.name.strip(), body.params
    try:
        await t.db.flush()
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "A view with that name exists") from None
    return _out(view)


@router.delete("/{view_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_view(view_id: uuid.UUID, t: Tenant) -> None:
    view = await t.db.get(SavedView, view_id)
    if view is None or view.tenant_id != t.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Saved view not found")
    await t.db.delete(view)
