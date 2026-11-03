"""Refuses JSON bodies containing NaN or Infinity.

Python's json module accepts them, though JSON doesn't. A rule threshold of
NaN would be saved and then never fire, and Infinity fails JSON columns.
This runs before any route, so no field anywhere can receive one.
"""

import json
import math

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_REFUSED = json.dumps({"detail": "Numbers must be finite (no NaN or Infinity)"}).encode()


class _NotFinite(ValueError):
    pass


def _no_constants(token: str) -> None:
    raise _NotFinite(token)


def _finite(text: str) -> float:
    # "1e999" is a valid number that overflows to infinity.
    value = float(text)
    if not math.isfinite(value):
        raise _NotFinite(text)
    return value


class FiniteJSON:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        if b"json" not in headers.get(b"content-type", b""):
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        body = b"".join(chunks)
        try:
            json.loads(body, parse_constant=_no_constants, parse_float=_finite)
        except _NotFinite:
            await send(
                {
                    "type": "http.response.start",
                    "status": 422,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": _REFUSED})
            return
        except ValueError:
            pass  # malformed JSON: FastAPI answers it with its own 422

        sent = False

        async def replay() -> Message:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
