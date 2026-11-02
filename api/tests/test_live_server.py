"""Changes through a real HTTP server (uvicorn), not the in-process test
client: a request with no body must still commit. The audit step once read
the body after the response had gone out; under uvicorn that raised
ClientDisconnect and silently rolled back every DELETE."""

import asyncio
import socket
import uuid

import httpx
import pytest
import uvicorn

from app.main import app

from .conftest import access_token, ensure_user


@pytest.fixture
async def live_url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:  # noqa: ASYNC110 (uvicorn offers no event to wait on)
        await asyncio.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await task


async def test_bodyless_changes_commit(live_url):
    uid = str(uuid.uuid4())
    await ensure_user(uid, f"live-{uid[:8]}@example.com")
    h = {"Authorization": f"Bearer {access_token(uid, f'live-{uid[:8]}@example.com')}"}
    async with httpx.AsyncClient(base_url=live_url, headers=h) as c:
        rule = {"name": "Live", "kind": "host_down", "duration_seconds": 120}
        created = (await c.post("/v1/alert-rules", json=rule)).json()
        assert (await c.delete(f"/v1/alert-rules/{created['id']}")).status_code == 204
        # Gone for real, and the audit log says so.
        assert (await c.get(f"/v1/alert-rules/{created['id']}")).status_code == 404
        log = (await c.get("/v1/audit-log")).json()
        assert [e["action"] for e in log[:2]] == ["alert_rule.delete", "alert_rule.create"]
