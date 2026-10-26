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
from app.db import AppSession, ServiceSession
from app.services import audit
from app.services.secrets import hash_secret

API_TOKEN_PREFIX = "pgt_"  # noqa: S105 (a prefix, not a secret)


bearer = HTTPBearer(auto_error=False)

READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


ACCOUNT_HEADER = "X-Pulsegrid-Account"

ROLES = ("viewer", "operator", "admin", "owner")

# What a team member may change, by route. Viewers only read; everyone may
# register their own browser for push; owners alone manage members and
# API tokens (see OWNER_ONLY).
ANY_MEMBER_WRITES = frozenset({"/v1/channels/push", "/v1/saved-views", "/v1/saved-views/{view_id}"})
OPERATOR_WRITES = frozenset(
    {
        "/v1/incidents/{incident_id}/acknowledge",
        "/v1/incidents/{incident_id}/notes",
        "/v1/incidents/{incident_id}/resolve",
        "/v1/incidents/{incident_id}/reopen",
        "/v1/incidents/{incident_id}/snooze",
        "/v1/incidents/merge",
        "/v1/maintenance",
        "/v1/maintenance/{window_id}",
        "/v1/hosts/{host_id}/actions",
    }
)
OWNER_ONLY_PREFIXES = ("/v1/members", "/v1/api-tokens")


@dataclass(frozen=True)
class TenantContext:
    tenant_id: uuid.UUID
    principal: Principal
    db: AsyncSession
    # "owner" for the account's own console user and its API tokens;
    # otherwise the team member's role.
    role: str = "owner"


async def current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if credentials is not None and credentials.credentials.startswith(API_TOKEN_PREFIX):
        return await _api_token_principal(credentials.credentials)
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


async def _api_token_principal(token: str) -> Principal:
    """An API token stands for its tenant. Looked up with the service role
    (there's no tenant yet to scope by); last_used_at is updated at most
    once a minute."""
    async with ServiceSession() as db, db.begin():
        row = (
            await db.execute(
                text(
                    "UPDATE api_tokens SET last_used_at = now() "
                    "WHERE token_hash = :h AND revoked_at IS NULL "
                    "AND (expires_at IS NULL OR expires_at > now()) "
                    "RETURNING id, tenant_id, read_only, "
                    "(SELECT status FROM tenants WHERE id = api_tokens.tenant_id) AS status"
                ),
                {"h": hash_secret(token)},
            )
        ).one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired or revoked API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Principal(
        source="api_token",
        external_account_id=str(row.tenant_id),
        email=None,
        name="API token",
        api_token_id=str(row.id),
        read_only=row.read_only,
        token_tenant_id=str(row.tenant_id),
        token_tenant_status=row.status,
    )


async def bind_tenant(db: AsyncSession, principal: Principal) -> tuple[uuid.UUID, str]:
    """Resolve the principal's tenant and scope this transaction to it."""
    if principal.token_tenant_id is not None:
        await db.execute(
            text("SELECT set_config('app.tenant_id', :t, true)"), {"t": principal.token_tenant_id}
        )
        return uuid.UUID(principal.token_tenant_id), principal.token_tenant_status or "suspended"
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


async def bind_member_tenant(
    db: AsyncSession, principal: Principal, shared: str
) -> tuple[uuid.UUID, str, str]:
    """Scope this transaction to an account the caller was invited to."""
    try:
        tenant_id = uuid.UUID(shared)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Bad {ACCOUNT_HEADER}") from None
    row = (
        await db.execute(
            text("SELECT out_role, out_status FROM pulsegrid_member_tenant(:t, :s, :e, :m, :n)"),
            {
                "t": tenant_id,
                "s": principal.source,
                "e": principal.external_account_id,
                "m": principal.email,
                "n": principal.name,
            },
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="You're not a member of that account"
        )
    await db.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})
    return tenant_id, row.out_status, row.out_role


def check_member_write(request: Request, role: str) -> None:
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    if path.startswith(OWNER_ONLY_PREFIXES):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Only the account owner can do that"
        )
    if request.method.upper() in READ_ONLY_METHODS or path in ANY_MEMBER_WRITES:
        return
    if role == "admin" or (role == "operator" and path in OPERATOR_WRITES):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail=f"Your role ({role}) can't change this"
    )


async def tenant_context(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
) -> AsyncIterator[TenantContext]:
    if principal.impersonated and request.method.upper() not in READ_ONLY_METHODS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This is a read-only view-as-customer session.",
        )
    if principal.read_only and request.method.upper() not in READ_ONLY_METHODS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="This API token is read-only"
        )
    shared = request.headers.get(ACCOUNT_HEADER)
    async with AppSession() as db, db.begin():
        role = "owner"
        if shared and principal.api_token_id is None:
            tenant_id, tenant_status, role = await bind_member_tenant(db, principal, shared)
            check_member_write(request, role)
        else:
            tenant_id, tenant_status = await bind_tenant(db, principal)
        if tenant_status != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Monitoring is suspended"
            )
        yield TenantContext(tenant_id=tenant_id, principal=principal, db=db, role=role)
        # Reached only when the request succeeded: record it in the same
        # transaction as the change.
        if request.method.upper() not in READ_ONLY_METHODS:
            await audit.record_safely(
                db,
                request,
                tenant_id=tenant_id,
                actor=actor_of(principal),
                actor_kind=actor_kind(principal, role),
            )


def actor_of(principal: Principal) -> str:
    if principal.api_token_id:
        return f"API token {principal.name or principal.api_token_id}"
    return principal.email or principal.name or principal.external_account_id


def actor_kind(principal: Principal, role: str) -> str:
    if principal.api_token_id:
        return "api_token"
    return "owner" if role == "owner" else "member"


# scope="function": the transaction commits before the response is sent, so
# a client that reads right after a change sees it.
Tenant = Annotated[TenantContext, Depends(tenant_context, scope="function")]


async def console_tenant_context(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
) -> AsyncIterator[TenantContext]:
    """Like Tenant, but refuses API tokens: for managing the tokens
    themselves, so a leaked token can't mint more."""
    if principal.api_token_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sign in to the console to manage API tokens",
        )
    async for ctx in tenant_context(request, principal):
        yield ctx


ConsoleTenant = Annotated[TenantContext, Depends(console_tenant_context, scope="function")]
