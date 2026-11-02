"""Turns a request into a tenant-scoped database session.

This is the one place tenant identity is decided:

1. The caller is identified from Beyond's own access token or an API token
   (never from the request body).
2. The organisation is the one named in X-Pulsegrid-Account, which must be
   one the user is a member of; otherwise their default organisation
   (pulsegrid_default_tenant(), which creates one for a new user). A
   superadmin reaches another organisation only through an impersonation,
   which is audited and read-only unless they asked for writes.
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

from app.auth.native import InvalidToken, verify_access_token
from app.auth.principal import Principal
from app.db import AppSession, ServiceSession
from app.services import audit
from app.services.secrets import hash_secret

API_TOKEN_PREFIX = "pgt_"  # noqa: S105 (a prefix, not a secret)


bearer = HTTPBearer(auto_error=False)

READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


ACCOUNT_HEADER = "X-Pulsegrid-Account"

# Stored role names; the web app shows operator as "member" and viewer as
# "read-only".
ROLES = ("viewer", "operator", "admin", "owner")

# What a member may change, by route. Viewers only read; everyone may
# register their own browser for push; admins change everything except API
# tokens and the organisation's deletion (owner only, see OWNER_ONLY).
# Leaving an organisation and creating your own are checked in members.py.
ANY_MEMBER_WRITES = frozenset(
    {
        "/v1/channels/push",
        "/v1/saved-views",
        "/v1/saved-views/{view_id}",
        "/v1/members/{member_id}",
        "/v1/organisations",
    }
)
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
OWNER_ONLY_PREFIXES = ("/v1/api-tokens", "/v1/organisation/delete")


@dataclass(frozen=True)
class TenantContext:
    tenant_id: uuid.UUID
    principal: Principal
    db: AsyncSession
    # The member's role; "owner" for API tokens too; "staff" for a
    # superadmin working in the organisation through an impersonation.
    role: str = "owner"


async def current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    request.state.session_id = None
    if credentials is not None and credentials.credentials.startswith(API_TOKEN_PREFIX):
        return await _api_token_principal(credentials.credentials)
    if credentials is not None:
        try:
            principal = verify_access_token(credentials.credentials)
        except InvalidToken:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        request.state.session_id = principal.session_id
        return principal
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
        user_id=None,
        email=None,
        name="API token",
        api_token_id=str(row.id),
        read_only=row.read_only,
        token_tenant_id=str(row.tenant_id),
        token_tenant_status=row.status,
    )


async def bind_default_tenant(db: AsyncSession, principal: Principal) -> tuple[uuid.UUID, str, str]:
    """The API token's organisation, or the user's default one."""
    if principal.token_tenant_id is not None:
        await db.execute(
            text("SELECT set_config('app.tenant_id', :t, true)"), {"t": principal.token_tenant_id}
        )
        return (
            uuid.UUID(principal.token_tenant_id),
            principal.token_tenant_status or "suspended",
            "owner",
        )
    row = (
        await db.execute(
            text(
                "SELECT out_tenant_id, out_status, out_role "
                "FROM pulsegrid_default_tenant(:u, :m, :n)"
            ),
            {"u": principal.user_id, "m": principal.email, "n": principal.name},
        )
    ).one()
    await db.execute(
        text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(row.out_tenant_id)}
    )
    return row.out_tenant_id, row.out_status, row.out_role


def _tenant_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Bad {ACCOUNT_HEADER}") from None


async def bind_member_tenant(
    db: AsyncSession, principal: Principal, shared: str
) -> tuple[uuid.UUID, str, str]:
    """Scope this transaction to an organisation the user is a member of."""
    tenant_id = _tenant_uuid(shared)
    row = (
        await db.execute(
            text("SELECT out_role, out_status FROM pulsegrid_member_tenant(:t, :u)"),
            {"t": tenant_id, "u": principal.user_id},
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="You're not a member of that organisation"
        )
    await db.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})
    return tenant_id, row.out_status, row.out_role


async def bind_impersonated_tenant(db: AsyncSession, principal: Principal) -> tuple[uuid.UUID, str]:
    """A superadmin's impersonation, checked against its row on every
    request so ending it takes effect at once."""
    async with ServiceSession() as sdb:
        row = (
            await sdb.execute(
                text(
                    "SELECT i.tenant_id, t.status FROM impersonations i "
                    "JOIN tenants t ON t.id = i.tenant_id "
                    "WHERE i.id = :i AND i.user_id = :u AND i.ended_at IS NULL "
                    "AND i.expires_at > now()"
                ),
                {"i": principal.impersonation_id, "u": principal.user_id},
            )
        ).one_or_none()
    if row is None or not principal.superadmin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Impersonation ended")
    await db.execute(
        text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(row.tenant_id)}
    )
    return row.tenant_id, str(row.status)


def check_member_write(request: Request, role: str) -> None:
    if role == "owner":
        return
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    if path.startswith(OWNER_ONLY_PREFIXES):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the organisation's owner can do that",
        )
    if request.method.upper() in READ_ONLY_METHODS or path in ANY_MEMBER_WRITES:
        return
    if role == "admin" or (role == "operator" and path in OPERATOR_WRITES):
        return
    labels = {"operator": "member", "viewer": "read-only"}
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Your role ({labels.get(role, role)}) can't change this",
    )


async def tenant_context(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
) -> AsyncIterator[TenantContext]:
    writing = request.method.upper() not in READ_ONLY_METHODS
    if principal.impersonated and writing and not principal.impersonation_writes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This is a read-only impersonation. "
            "Start one with writes allowed to change things.",
        )
    if principal.read_only and writing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="This API token is read-only"
        )
    shared = request.headers.get(ACCOUNT_HEADER)
    async with AppSession() as db, db.begin():
        if principal.impersonated:
            tenant_id, tenant_status = await bind_impersonated_tenant(db, principal)
            role = "staff"
        elif shared and principal.api_token_id is None:
            tenant_id, tenant_status, role = await bind_member_tenant(db, principal, shared)
        else:
            tenant_id, tenant_status, role = await bind_default_tenant(db, principal)
        if role != "staff":
            check_member_write(request, role)
        if tenant_status != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Monitoring is suspended"
            )
        yield TenantContext(tenant_id=tenant_id, principal=principal, db=db, role=role)
        # Reached only when the request succeeded: record it in the same
        # transaction as the change.
        if writing:
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
    if principal.impersonated:
        return f"{principal.email} (superadmin)"
    return principal.email or principal.name or str(principal.user_id)


def actor_kind(principal: Principal, role: str) -> str:
    if principal.api_token_id:
        return "api_token"
    if role == "staff":
        return "staff"
    return "owner" if role == "owner" else "member"


# scope="function": the transaction commits before the response is sent, so
# a client that reads right after a change sees it.
Tenant = Annotated[TenantContext, Depends(tenant_context, scope="function")]


async def user_tenant_context(
    request: Request,
    principal: Annotated[Principal, Depends(current_principal)],
) -> AsyncIterator[TenantContext]:
    """Like Tenant, but refuses API tokens: for managing the tokens
    themselves, so a leaked token can't mint more."""
    if principal.api_token_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Sign in to manage API tokens"
        )
    async for ctx in tenant_context(request, principal):
        yield ctx


UserTenant = Annotated[TenantContext, Depends(user_tenant_context, scope="function")]
