"""Who is calling. Everything outside app/auth works with a Principal and
never with a token."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    # A Beyond user, or the tenant an API token belongs to.
    user_id: str | None
    email: str | None
    name: str | None
    superadmin: bool = False
    session_id: str | None = None
    # A superadmin working in a customer's organisation (impersonations.id).
    impersonation_id: str | None = None
    impersonation_tenant_id: str | None = None
    impersonation_writes: bool = False
    # Set when the caller used an API token instead of signing in.
    api_token_id: str | None = None
    read_only: bool = False
    token_tenant_id: str | None = None
    token_tenant_status: str | None = None

    @property
    def impersonated(self) -> bool:
        return self.impersonation_id is not None
