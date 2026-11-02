"""Database-level isolation: what RLS guarantees even when application code is wrong.

These queries deliberately leave out `WHERE tenant_id = ...`, the mistake RLS
exists to survive.
"""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.auth.principal import Principal
from app.db import AppSession
from app.tenancy import bind_default_tenant

from .conftest import ensure_user, insert_host


async def new_tenant() -> uuid.UUID:
    uid = str(uuid.uuid4())
    email = f"{uid[:8]}@example.com"
    await ensure_user(uid, email)
    async with AppSession() as db, db.begin():
        tenant_id, _, _ = await bind_default_tenant(
            db, Principal(user_id=uid, email=email, name="X")
        )
        return tenant_id


async def as_tenant(tenant_id: uuid.UUID, sql: str, **params):
    async with AppSession() as db, db.begin():
        await db.execute(
            text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)}
        )
        return await db.execute(text(sql), params)


async def test_unfiltered_select_only_sees_own_rows():
    a, b = await new_tenant(), await new_tenant()
    host_a = await insert_host(a, "a-host")
    await insert_host(b, "b-host")

    rows = (await as_tenant(a, "SELECT id, tenant_id FROM hosts")).all()
    assert [r.id for r in rows] == [host_a]
    assert {r.tenant_id for r in rows} == {a}


async def test_no_tenant_set_sees_nothing():
    a = await new_tenant()
    await insert_host(a)
    async with AppSession() as db, db.begin():
        assert (await db.execute(text("SELECT count(*) FROM hosts"))).scalar_one() == 0
        assert (await db.execute(text("SELECT count(*) FROM tenants"))).scalar_one() == 0


async def test_tenant_setting_does_not_leak_to_next_transaction():
    """set_config(..., true) ends with the transaction, so a pooled connection
    reused by the next request starts with no tenant."""
    a = await new_tenant()
    await insert_host(a)
    async with AppSession() as db:
        async with db.begin():
            await db.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(a)})
            assert (await db.execute(text("SELECT count(*) FROM hosts"))).scalar_one() == 1
        async with db.begin():
            assert (await db.execute(text("SELECT count(*) FROM hosts"))).scalar_one() == 0


async def test_cannot_insert_into_another_tenant():
    a, b = await new_tenant(), await new_tenant()
    with pytest.raises(DBAPIError, match="row-level security"):
        await as_tenant(
            b,
            "INSERT INTO agent_keys (tenant_id, name, key_prefix, key_hash) "
            "VALUES (:t, 'sneaky', 'pg_x', :h)",
            t=a,
            h=uuid.uuid4().hex,
        )


async def test_cannot_update_or_delete_another_tenants_rows():
    a, b = await new_tenant(), await new_tenant()
    host_a = await insert_host(a, "keep-me")

    updated = await as_tenant(b, "UPDATE hosts SET hostname = 'pwned' WHERE id = :h", h=host_a)
    deleted = await as_tenant(b, "DELETE FROM hosts WHERE id = :h", h=host_a)
    assert updated.rowcount == 0
    assert deleted.rowcount == 0

    row = (await as_tenant(a, "SELECT hostname FROM hosts WHERE id = :h", h=host_a)).one()
    assert row.hostname == "keep-me"


async def test_cannot_move_row_into_another_tenant():
    a, b = await new_tenant(), await new_tenant()
    host_a = await insert_host(a)
    with pytest.raises(DBAPIError, match="row-level security"):
        await as_tenant(a, "UPDATE hosts SET tenant_id = :b WHERE id = :h", b=b, h=host_a)


async def test_default_tenant_is_idempotent_and_prefills_the_email():
    uid = str(uuid.uuid4())
    email = f"owner-{uid[:8]}@example.com"
    await ensure_user(uid, email)
    p = Principal(user_id=uid, email=email, name="Owner")
    async with AppSession() as db, db.begin():
        first, _, role = await bind_default_tenant(db, p)
    async with AppSession() as db, db.begin():
        second, _, _ = await bind_default_tenant(db, p)
    assert first == second and role == "owner"

    rows = (
        await as_tenant(first, "SELECT type, target, source, is_default FROM notification_channels")
    ).all()
    assert [(r.type, r.target, r.source, r.is_default) for r in rows] == [
        ("email", email, "account", True)
    ]
    members = (await as_tenant(first, "SELECT user_id, role FROM tenant_members")).all()
    assert [(str(m.user_id), m.role) for m in members] == [(uid, "owner")]


async def test_member_lookup_needs_a_joined_membership():
    """sentinel_member_tenant() answers only for the user's own memberships."""
    a = await new_tenant()
    stranger = str(uuid.uuid4())
    await ensure_user(stranger, f"{stranger[:8]}@example.com")
    async with AppSession() as db, db.begin():
        rows = (
            await db.execute(
                text("SELECT * FROM sentinel_member_tenant(:t, :u)"), {"t": a, "u": stranger}
            )
        ).all()
    assert rows == []
