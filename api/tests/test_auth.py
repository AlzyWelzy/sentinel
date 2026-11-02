"""Beyond's own accounts, end to end through the HTTP API: sign-up, the
emailed link, sign-in, refresh rotation, reset, two-factor, sessions."""

import uuid

import pyotp
from sqlalchemy import text

from app.db import ServiceSession

from .conftest import emailed_token

CSRF = {"X-Requested-With": "pulsegrid"}
PASSWORD = "a long enough password"


async def emails_to(email: str) -> list[str]:
    async with ServiceSession() as db:
        return list(
            await db.scalars(
                text("SELECT kind FROM account_emails WHERE to_address = :e ORDER BY created_at"),
                {"e": email},
            )
        )


def new_email() -> str:
    return f"user-{uuid.uuid4().hex[:10]}@example.com"


async def sign_up_and_verify(client, email: str) -> dict:
    r = await client.post(
        "/auth/signup", json={"email": email, "password": PASSWORD, "name": "Ann"}
    )
    assert r.status_code == 202, r.text
    r = await client.post(
        "/auth/verify", json={"token": await emailed_token(email, "verify_email")}
    )
    assert r.status_code == 200, r.text
    return r.json()


async def test_sign_up_verify_and_use_the_product(client):
    email = new_email()
    session = await sign_up_and_verify(client, email)
    assert session["user"]["email"] == email and session["user"]["email_verified"]
    # The refresh token is only in an httpOnly cookie scoped to /auth.
    assert "pg_refresh" in client.cookies
    assert "refresh" not in str(session).replace("refresh_token", "")
    h = {"Authorization": f"Bearer {session['access_token']}"}
    me = (await client.get("/v1/me", headers=h)).json()
    assert me["role"] == "owner" and me["email"] == email
    contacts = (await client.get("/v1/channels", headers=h)).json()
    assert [(c["target"], c["source"]) for c in contacts] == [(email, "account")]
    # A verify link is single use.
    r = await client.post(
        "/auth/verify", json={"token": await emailed_token(email, "verify_email")}
    )
    assert r.status_code == 400


async def test_unverified_accounts_cannot_sign_in(client):
    email = new_email()
    await client.post("/auth/signup", json={"email": email, "password": PASSWORD})
    r = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "email_unverified"


async def test_sign_up_does_not_reveal_existing_accounts(client):
    email = new_email()
    await sign_up_and_verify(client, email)
    again = await client.post(
        "/auth/signup", json={"email": email, "password": "another password!"}
    )
    fresh = await client.post("/auth/signup", json={"email": new_email(), "password": PASSWORD})
    assert again.status_code == fresh.status_code == 202
    assert again.json() == fresh.json()
    # The owner gets told instead; the password didn't change.
    assert (await emails_to(email))[-1] == "verify_email"
    r = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200


async def test_short_passwords_are_refused(client):
    r = await client.post("/auth/signup", json={"email": new_email(), "password": "short"})
    assert r.status_code == 422


async def test_wrong_password_and_unknown_email_look_the_same(client):
    email = new_email()
    await sign_up_and_verify(client, email)
    wrong = await client.post("/auth/login", json={"email": email, "password": "not the password"})
    unknown = await client.post("/auth/login", json={"email": new_email(), "password": PASSWORD})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


async def test_repeated_failures_slow_the_account_down(client):
    email = new_email()
    await sign_up_and_verify(client, email)
    for _ in range(5):
        r = await client.post("/auth/login", json={"email": email, "password": "wrong password!"})
        assert r.status_code == 401
    # Locked for a while, even with the right password.
    r = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    # A reset clears it.
    await client.post("/auth/password/forgot", json={"email": email})
    token = await emailed_token(email, "reset_password")
    r = await client.post(
        "/auth/password/reset", json={"token": token, "password": "brand new password"}
    )
    assert r.status_code == 204
    r = await client.post("/auth/login", json={"email": email, "password": "brand new password"})
    assert r.status_code == 200


async def test_refresh_rotates_and_a_reused_token_ends_the_session(client):
    email = new_email()
    await sign_up_and_verify(client, email)
    first = client.cookies["pg_refresh"]
    # The header a cross-site form can't send is required.
    assert (await client.post("/auth/refresh")).status_code == 403
    r = await client.post("/auth/refresh", headers=CSRF)
    assert r.status_code == 200 and r.json()["access_token"]
    second = client.cookies["pg_refresh"]
    assert second != first
    # An old token presented again (after the grace for racing tabs) means
    # someone copied it: the whole session ends.
    async with ServiceSession() as db, db.begin():
        await db.execute(
            text(
                "UPDATE user_sessions SET rotated_at = now() - interval '1 minute' "
                "WHERE rotated_at IS NOT NULL AND user_id = (SELECT id FROM users WHERE email = :e)"
            ),
            {"e": email},
        )
    client.cookies.set("pg_refresh", first, path="/auth")
    assert (await client.post("/auth/refresh", headers=CSRF)).status_code == 401
    client.cookies.set("pg_refresh", second, path="/auth")
    assert (await client.post("/auth/refresh", headers=CSRF)).status_code == 401


async def test_sign_out_ends_the_refresh_token(client):
    await sign_up_and_verify(client, new_email())
    token = client.cookies["pg_refresh"]
    assert (await client.post("/auth/logout", headers=CSRF)).status_code == 204
    client.cookies.set("pg_refresh", token, path="/auth")
    assert (await client.post("/auth/refresh", headers=CSRF)).status_code == 401


async def test_password_reset_signs_every_browser_out(client):
    email = new_email()
    await sign_up_and_verify(client, email)
    old = client.cookies["pg_refresh"]
    # Unknown addresses get the same answer.
    unknown = await client.post("/auth/password/forgot", json={"email": new_email()})
    known = await client.post("/auth/password/forgot", json={"email": email})
    assert unknown.json() == known.json()
    token = await emailed_token(email, "reset_password")
    r = await client.post("/auth/password/reset", json={"token": token, "password": "x" * 12})
    assert r.status_code == 204
    client.cookies.set("pg_refresh", old, path="/auth")
    assert (await client.post("/auth/refresh", headers=CSRF)).status_code == 401
    assert "password_changed" in await emails_to(email)
    # Used once.
    r = await client.post("/auth/password/reset", json={"token": token, "password": "y" * 12})
    assert r.status_code == 400


async def test_two_factor(client):
    email = new_email()
    session = await sign_up_and_verify(client, email)
    h = {"Authorization": f"Bearer {session['access_token']}"}
    setup = (await client.post("/auth/totp/setup", headers=h)).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    totp = pyotp.TOTP(setup["secret"])
    wrong = "000000" if totp.now() != "000000" else "111111"
    r = await client.post("/auth/totp/enable", headers=h, json={"code": wrong})
    assert r.status_code == 400
    r = await client.post("/auth/totp/enable", headers=h, json={"code": totp.now()})
    assert r.status_code == 204
    assert (await client.get("/auth/me", headers=h)).json()["totp_enabled"]
    # The secret is stored encrypted.
    async with ServiceSession() as db:
        stored = await db.scalar(
            text("SELECT totp_secret FROM users WHERE email = :e"), {"e": email}
        )
    assert setup["secret"] not in stored

    r = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "totp_required"
    r = await client.post(
        "/auth/login", json={"email": email, "password": PASSWORD, "totp_code": "123456"}
    )
    assert r.status_code == 401
    r = await client.post(
        "/auth/login", json={"email": email, "password": PASSWORD, "totp_code": totp.now()}
    )
    assert r.status_code == 200
    r = await client.post(
        "/auth/totp/disable", headers=h, json={"password": PASSWORD, "code": totp.now()}
    )
    assert r.status_code == 204
    assert not (await client.get("/auth/me", headers=h)).json()["totp_enabled"]


async def test_sessions_are_listed_and_revocable(client):
    email = new_email()
    first = await sign_up_and_verify(client, email)
    r = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    sessions = (await client.get("/auth/sessions", headers=h)).json()
    assert len(sessions) == 2 and sum(s["current"] for s in sessions) == 1
    other = next(s for s in sessions if not s["current"])
    assert (await client.delete(f"/auth/sessions/{other['id']}", headers=h)).status_code == 204
    assert len((await client.get("/auth/sessions", headers=h)).json()) == 1
    # Someone else's session id is 404.
    stranger = await sign_up_and_verify(client, new_email())
    sh = {"Authorization": f"Bearer {stranger['access_token']}"}
    mine = (await client.get("/auth/sessions", headers=h)).json()[0]["id"]
    assert (await client.delete(f"/auth/sessions/{mine}", headers=sh)).status_code == 404
    assert first  # the first sign-in's access token stays valid until it expires


async def test_sign_in_is_rate_limited_per_address(client):
    email = new_email()
    codes = []
    for _ in range(16):
        r = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
        codes.append(r.status_code)
    assert codes[-1] == 429 and set(codes[:15]) == {401}


async def test_superadmins_come_from_the_configured_emails(client, monkeypatch):
    from app.config import settings

    email = new_email()
    monkeypatch.setattr(settings, "SUPERADMIN_EMAILS", [email.upper()])
    session = await sign_up_and_verify(client, email)
    assert session["user"]["superadmin"]
    h = {"Authorization": f"Bearer {session['access_token']}"}
    assert (await client.get("/admin/v1/overview", headers=h)).status_code == 200
    # Taken off the list: no longer at the next sign-in.
    monkeypatch.setattr(settings, "SUPERADMIN_EMAILS", [])
    r = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert not r.json()["user"]["superadmin"]
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert (await client.get("/admin/v1/overview", headers=h)).status_code == 403


async def test_disabled_users_cannot_sign_in(client, monkeypatch):
    from .conftest import superadmin_headers

    email = new_email()
    session = await sign_up_and_verify(client, email)
    admin = await superadmin_headers()
    r = await client.put(
        f"/admin/v1/users/{session['user']['id']}/disabled", headers=admin, json={"disabled": True}
    )
    assert r.status_code == 204
    r = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 401 and r.json()["detail"]["code"] == "disabled"
    assert (await client.post("/auth/refresh", headers=CSRF)).status_code == 401


async def test_api_tokens_cannot_use_account_routes(client, alice):
    r = await alice.request("POST", "/v1/api-tokens", json={"name": "ci"})
    token = r.json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    assert (await client.get("/auth/me", headers=h)).status_code == 403
    assert (
        await client.post("/v1/organisations", headers=h, json={"name": "x"})
    ).status_code == 403
