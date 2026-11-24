import json
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from app.config import settings
from app.db import ServiceSession
from app.services import ai_summary
from tests.conftest import User, insert_host


async def make_incident(user: User) -> str:
    tenant_id = await user.tenant_id()
    host_id = await insert_host(tenant_id, "db-1")
    async with ServiceSession() as db, db.begin():
        return str(
            (
                await db.execute(
                    text(
                        "INSERT INTO incidents (tenant_id, host_id, summary, rule_name, hostname, detail)"
                        " VALUES (:t, :h, 'Disk almost full on db-1', 'Disk', 'db-1',"
                        " '/var 96% used, 2.1 GB free') RETURNING id"
                    ),
                    {"t": tenant_id, "h": host_id},
                )
            ).scalar_one()
        )


class FakeMessages:
    def __init__(self):
        self.calls = []

    async def create(self, **kw):
        self.calls.append(kw)
        answer = {
            "what_changed": "/var on db-1 reached 96%.",
            "likely_cause": "Log growth; not certain.",
            "next_steps": ["Check du -sh /var/log/*", "Rotate logs"],
        }
        return SimpleNamespace(
            stop_reason="end_turn",
            model="claude-opus-5-5",
            content=[SimpleNamespace(type="text", text=json.dumps(answer))],
        )


@pytest.fixture
def fake_claude(monkeypatch):
    msgs = FakeMessages()
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr(
        ai_summary.anthropic,
        "AsyncAnthropic",
        lambda **kw: SimpleNamespace(beta=SimpleNamespace(messages=msgs)),
    )
    return msgs


async def test_off_without_key(alice: User):
    incident = await make_incident(alice)
    assert (await alice.request("GET", "/v1/ai/status")).json() == {"enabled": False}
    r = await alice.request("POST", f"/v1/incidents/{incident}/ai-summary")
    assert r.status_code == 404


async def test_summary_is_made_once_and_kept(alice: User, fake_claude):
    incident = await make_incident(alice)
    r = await alice.request(
        "POST", f"/v1/incidents/{incident}/ai-summary", params={"refresh": True}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["next_steps"][0].startswith("Check du")
    sent = json.loads(fake_claude.calls[0]["messages"][0]["content"])
    assert sent["incident"]["detail"] == "/var 96% used, 2.1 GB free"
    assert fake_claude.calls[0]["model"] == "claude-opus-5-5"
    again = await alice.request("POST", f"/v1/incidents/{incident}/ai-summary")
    assert again.json() == body and len(fake_claude.calls) == 1


async def test_other_organisations_incident_is_hidden(alice: User, bob: User, fake_claude):
    incident = await make_incident(alice)
    r = await bob.request("POST", f"/v1/incidents/{incident}/ai-summary")
    assert r.status_code == 404 and not fake_claude.calls
