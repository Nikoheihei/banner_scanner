"""ASGI-level tests for the MCP HTTP guard."""

from banner_scanner.server.http_middleware import MCPHttpGuard


async def _invoke(guard, *, method="POST", headers=(), body=b""):
    sent = []
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    await guard({
        "type": "http",
        "method": method,
        "path": "/mcp",
        "headers": list(headers),
    }, receive, send)
    return sent


async def _ok_app(_scope, _receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def test_http_guard_rejects_oversized_declared_body():
    guard = MCPHttpGuard(_ok_app, max_body_bytes=4)
    messages = await _invoke(guard, headers=((b"content-length", b"5"),))
    assert messages[0]["status"] == 413


async def test_http_guard_handles_cors_preflight_without_bearer_token():
    guard = MCPHttpGuard(
        _ok_app,
        max_body_bytes=100,
        allowed_origins=("https://client.example",),
        bearer_token="secret",
    )
    messages = await _invoke(
        guard,
        method="OPTIONS",
        headers=((b"origin", b"https://client.example"),),
    )
    assert messages[0]["status"] == 204
    headers = dict(messages[0]["headers"])
    assert headers[b"access-control-expose-headers"] == b"Mcp-Session-Id"


async def test_http_guard_requires_bearer_and_exposes_session_header():
    guard = MCPHttpGuard(
        _ok_app,
        max_body_bytes=100,
        allowed_origins=("https://client.example",),
        bearer_token="secret",
    )
    denied = await _invoke(guard)
    assert denied[0]["status"] == 401

    allowed = await _invoke(guard, headers=(
        (b"origin", b"https://client.example"),
        (b"authorization", b"Bearer secret"),
    ))
    assert allowed[0]["status"] == 200
    headers = dict(allowed[0]["headers"])
    assert headers[b"access-control-expose-headers"] == b"Mcp-Session-Id"
