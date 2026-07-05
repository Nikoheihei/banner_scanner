"""Small ASGI guards applied around SDK-provided HTTP transports."""

from __future__ import annotations

import hmac
from typing import Any, Awaitable, Callable


class RequestBodyTooLarge(Exception):
    pass


class MCPHttpGuard:
    def __init__(self, app, *, max_body_bytes: int,
                 allowed_origins: tuple[str, ...] = (), bearer_token: str = ""):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.allowed_origins = allowed_origins
        self.bearer_token = bearer_token

    async def __call__(self, scope: dict[str, Any], receive: Callable[[], Awaitable],
                       send: Callable[[dict[str, Any]], Awaitable]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        try:
            content_length = int(headers.get("content-length", "0") or 0)
        except ValueError:
            await self._reject(send, 400, b"Invalid Content-Length")
            return
        if content_length > self.max_body_bytes:
            await self._reject(send, 413, b"MCP request body is too large")
            return
        origin = headers.get("origin")
        if origin and origin not in self.allowed_origins:
            await self._reject(send, 403, b"Origin is not allowed")
            return
        if scope.get("method") == "OPTIONS" and origin:
            await self._preflight(send, origin)
            return
        if self.bearer_token:
            expected = f"Bearer {self.bearer_token}"
            if not hmac.compare_digest(headers.get("authorization", ""), expected):
                await self._reject(send, 401, b"Bearer authentication is required")
                return
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise RequestBodyTooLarge
            return message

        async def guarded_send(message: dict[str, Any]) -> None:
            if origin and message.get("type") == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.append((b"access-control-allow-origin", origin.encode("latin-1")))
                response_headers.append((
                    b"access-control-expose-headers", b"Mcp-Session-Id"
                ))
                response_headers.append((b"vary", b"Origin"))
                message["headers"] = response_headers
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except RequestBodyTooLarge:
            await self._reject(send, 413, b"MCP request body is too large")

    @staticmethod
    async def _reject(send, status: int, body: bytes) -> None:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        })
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _preflight(send, origin: str) -> None:
        await send({
            "type": "http.response.start",
            "status": 204,
            "headers": [
                (b"access-control-allow-origin", origin.encode("latin-1")),
                (b"access-control-allow-methods", b"GET, POST, DELETE, OPTIONS"),
                (
                    b"access-control-allow-headers",
                    b"Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id",
                ),
                (b"access-control-expose-headers", b"Mcp-Session-Id"),
                (b"vary", b"Origin"),
            ],
        })
        await send({"type": "http.response.body", "body": b""})
