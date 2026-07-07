"""Small ASGI guards applied around SDK-provided HTTP transports."""

from __future__ import annotations

import hmac
import json
import logging
from typing import Any, Awaitable, Callable


logger = logging.getLogger("uvicorn.error")


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
        client = scope.get("client") or ("unknown", None)
        remote = str(client[0])
        if len(client) > 1 and client[1] is not None:
            remote = f"{remote}:{client[1]}"
        path = scope.get("path", "")
        query = scope.get("query_string", b"")
        if query:
            path = f"{path}?{query.decode('latin-1')}"
        logger.info(
            "MCP HTTP request method=%s path=%s remote=%s user_agent=%s",
            scope.get("method", ""),
            path,
            remote,
            headers.get("user-agent", ""),
        )
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
        request_body = bytearray()
        rpc_logged = False

        async def limited_receive():
            nonlocal received, rpc_logged
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                received += len(chunk)
                if received > self.max_body_bytes:
                    raise RequestBodyTooLarge
                request_body.extend(chunk)
                if not message.get("more_body", False) and not rpc_logged:
                    self._log_rpc_request(bytes(request_body))
                    rpc_logged = True
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
    def _log_rpc_request(body: bytes) -> None:
        if not body:
            return
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        messages = payload if isinstance(payload, list) else [payload]
        for message in messages:
            if not isinstance(message, dict):
                continue
            method = message.get("method")
            if method not in {"initialize", "tools/list", "tools/call"}:
                continue
            tool_name = ""
            if method == "tools/call":
                params = message.get("params")
                if isinstance(params, dict):
                    tool_name = str(params.get("name") or "")
            logger.info(
                "MCP protocol request entered method=%s tool=%s",
                method,
                tool_name,
            )

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
