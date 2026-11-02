"""API tokens: personal tokens for scripts and automation (Terraform, CI,
your own dashboards). A token acts as its account; read-only tokens can
only GET. The token itself is shown once, at creation."""

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.models import ApiToken
from app.services.secrets import hash_secret
from app.tenancy import API_TOKEN_PREFIX, UserTenant
from app.validation import Trimmed

router = APIRouter(prefix="/v1/api-tokens")

MAX_TOKENS = 20


class TokenIn(BaseModel):
    name: Annotated[str, Trimmed, Field(min_length=1, max_length=100)]
    read_only: bool = True
    expires_in_days: int | None = Field(default=None, ge=1, le=730)


class TokenOut(BaseModel):
    id: uuid.UUID
    name: str
    token_prefix: str
    read_only: bool
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked: bool


class TokenCreated(TokenOut):
    token: str = Field(description="shown only now; store it somewhere safe")


def _out(t: ApiToken) -> TokenOut:
    return TokenOut(
        id=t.id,
        name=t.name,
        token_prefix=t.token_prefix,
        read_only=t.read_only,
        created_at=t.created_at,
        last_used_at=t.last_used_at,
        expires_at=t.expires_at,
        revoked=t.revoked_at is not None,
    )


@router.get("")
async def list_tokens(t: UserTenant) -> list[TokenOut]:
    rows = await t.db.scalars(
        select(ApiToken).where(ApiToken.tenant_id == t.tenant_id).order_by(ApiToken.created_at)
    )
    return [_out(r) for r in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_token(body: TokenIn, t: UserTenant) -> TokenCreated:
    active = await t.db.scalar(
        select(func.count())
        .select_from(ApiToken)
        .where(ApiToken.tenant_id == t.tenant_id, ApiToken.revoked_at.is_(None))
    )
    if (active or 0) >= MAX_TOKENS:
        raise HTTPException(status_code=422, detail=f"at most {MAX_TOKENS} active tokens")
    token = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(
        tenant_id=t.tenant_id,
        name=body.name,
        token_prefix=token[:12],
        token_hash=hash_secret(token),
        read_only=body.read_only,
        expires_at=datetime.now(UTC) + timedelta(days=body.expires_in_days)
        if body.expires_in_days
        else None,
    )
    t.db.add(row)
    await t.db.flush()
    await t.db.refresh(row)
    return TokenCreated(**_out(row).model_dump(), token=token)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(token_id: uuid.UUID, t: UserTenant) -> None:
    row = await t.db.scalar(
        select(ApiToken).where(ApiToken.id == token_id, ApiToken.tenant_id == t.tenant_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Token not found")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
