"""Catalog contacts (ntfy, Opsgenie, DingTalk, …): fields are checked the way
the alerter uses them, secrets never come back, an edit that changes where
alerts go needs verifying again, and the API's copy of the catalog is the
alerter's."""

from pathlib import Path

from sqlalchemy import text

from app.db import ServiceSession
from app.services import notifiers

from .conftest import User

ROOT = Path(__file__).resolve().parents[2]


def test_api_catalog_is_the_alerters():
    assert (ROOT / "proto/notifiers.json").read_bytes() == notifiers.PATH.read_bytes(), (
        "run python3 scripts/notifiers.py"
    )
    assert len(notifiers.catalog()) >= 90


async def test_catalog_lists_providers(alice: User):
    r = await alice.request("GET", "/v1/channels/catalog")
    assert r.status_code == 200
    types = {p["type"] for p in r.json()}
    assert {"ntfy", "opsgenie", "dingtalk", "matrix", "pushover", "signal"} <= types
    assert "email" not in types and "slack" not in types


async def test_create_mask_edit_reverify(alice: User, bob: User):
    r = await alice.request(
        "POST",
        "/v1/channels",
        json={
            "type": "pushover",
            "fields": {
                "user_key": "uQiRzpo4DXghDmr9QzzfQu27cmVRsG",
                "app_token": "azGDORePK8gMaC0QOYAMyEEuzJnyUi",
            },
            "label": "Ops phones",
        },
    )
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["provider"] == "Pushover" and not c["verified"]
    assert "azGDORe" not in r.text and c["fields"]["app_token"] == notifiers.MASK
    # The same destination twice is refused.
    r2 = await alice.request(
        "POST",
        "/v1/channels",
        json={
            "type": "pushover",
            "fields": {
                "user_key": "uQiRzpo4DXghDmr9QzzfQu27cmVRsG",
                "app_token": "azGDORePK8gMaC0QOYAMyEEuzJnyUi",
            },
        },
    )
    assert r2.status_code == 409
    # A verification code went out through the provider.
    async with ServiceSession() as db:
        kinds = (
            (
                await db.execute(
                    text("SELECT kind FROM outbound_messages WHERE channel_id = :c"), {"c": c["id"]}
                )
            )
            .scalars()
            .all()
        )
        await db.execute(
            text("UPDATE notification_channels SET verified_at = now() WHERE id = :c"),
            {"c": c["id"]},
        )
        await db.commit()
    assert kinds == ["verification"]

    # Changing only the label keeps it verified; masked fields are kept.
    r = await alice.request(
        "PATCH", f"/v1/channels/{c['id']}", json={"label": "x", "fields": c["fields"]}
    )
    assert r.status_code == 200 and r.json()["verified"], r.text
    # A new destination needs verifying again.
    r = await alice.request(
        "PATCH",
        f"/v1/channels/{c['id']}",
        json={"fields": {**c["fields"], "user_key": "gznej3rKEVAvPUxu9vvNnqpmZpokzF"}},
    )
    assert r.status_code == 200 and not r.json()["verified"], r.text
    async with ServiceSession() as db:
        stored = (
            await db.execute(
                text("SELECT config FROM notification_channels WHERE id = :c"), {"c": c["id"]}
            )
        ).scalar_one()
    assert stored["app_token"] == "azGDORePK8gMaC0QOYAMyEEuzJnyUi"
    assert stored["user_key"] == "gznej3rKEVAvPUxu9vvNnqpmZpokzF"

    # Nobody else sees or edits it; secrets aren't in the export or audit log.
    assert (
        await bob.request("PATCH", f"/v1/channels/{c['id']}", json={"label": "y"})
    ).status_code == 404
    assert "azGDORe" not in (await alice.request("GET", "/v1/organisation/export")).text
    assert "azGDORe" not in (await alice.request("GET", "/v1/audit-log")).text


async def bad(user: User, type_: str, fields: dict, why: str):
    r = await user.request("POST", "/v1/channels", json={"type": type_, "fields": fields})
    assert r.status_code == 422, r.text
    assert why in r.text, r.text


async def test_fields_are_checked(alice: User):
    await bad(alice, "ntfy", {}, "Topic is required")
    await bad(alice, "ntfy", {"topic": "a b"}, "doesn't look right")
    await bad(alice, "ntfy", {"topic": "ok", "nope": "1"}, "unknown fields")
    await bad(alice, "ntfy", {"topic": "ok", "server": "ftp://x"}, "URL")
    await bad(
        alice,
        "google_chat",
        {"webhook_url": "https://evil.example.com/hook"},
        "chat.googleapis.com",
    )
    await bad(
        alice, "google_chat", {"webhook_url": "http://chat.googleapis.com/x"}, "chat.googleapis.com"
    )
    await bad(alice, "opsgenie", {"api_key": "k", "region": "mars"}, "one of")
    await bad(alice, "pushover", {"user_key": notifiers.MASK, "app_token": "t"}, "itself")
    await bad(alice, "telegrm", {}, "unknown contact type")
    await bad(alice, "email", {"x": "y"}, "not fields")
    r = await alice.request(
        "POST", "/v1/channels", json={"type": "ntfy", "fields": {"topic": "sentinel-alerts"}}
    )
    assert r.status_code == 201, r.text
    assert r.json()["target"] == "sentinel-alerts"
