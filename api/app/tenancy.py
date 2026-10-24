"""Turns a request into a tenant-scoped database session.

This is the one place tenant identity is decided:

1. The caller is identified from their console JWT (never from the request body).
2. Their tenant is found or created by pulsegrid_resolve_tenant().
3. `app.tenant_id` is set for this transaction, and RLS does the rest.

`set_config(..., true)` is transaction-local: the setting disappears at commit
or rollback, so a pooled connection can't carry one tenant's id into the next
request.
"""

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.console import InvalidToken, Principal, console_verifier, dev_principal
from app.config import settings
from app.db import AppSession

bearer = HTTPBearer(auto_error=False)

READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class TenantContext:
    tenant_id: uuid.UUID
    principal: Principal
    db: AsyncSession


async def current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if credentials is not None:
        # A presented token is always verified, bypass or not: a bad token
        # silently becoming the dev user would hide real auth bugs.
        try:
            return await console_verifier.verify(credentials.credentials)
        except InvalidToken:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
    if settings.ALLOW_AUTH_BYPASS:
        return dev_principal()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def bind_tenant(db: AsyncSession, principal: Principal) -> tuple[uuid.UUID, str]:
    """Resolve the principal's tenant and scope this transaction to it."""
    row = (
        await db.execute(
            text("SELECT out_tenant_id, out_status FROM pulsegrid_resolve_tenant(:s, :e, :m, :n)"),
            {
                "s": principal.source,
                "e": principal.external_account_id,
                "m": principal.email,
                "n": principal.name,
            },
        )
    ).one()
    await db.execute(
        text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(row.out_tenant_id)}
    )
    return row.out_tenant_id, row.out_status


async def tenant_context(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
) -> AsyncIterator[TenantContext]:
    if principal.impersonated and request.method.upper() not in READ_ONLY_METHODS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This is a read-only view-as-customer session.",
        )
    async with AppSession() as db, db.begin():
        tenant_id, tenant_status = await bind_tenant(db, principal)
        if tenant_status != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Monitoring is suspended"
            )
        yield TenantContext(tenant_id=tenant_id, principal=principal, db=db)


Tenant = Annotated[TenantContext, Depends(tenant_context)]
