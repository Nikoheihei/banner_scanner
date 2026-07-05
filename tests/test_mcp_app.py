"""MCP application registration tests without importing the optional SDK."""

import sys
import types

from banner_scanner.server.mcp_app import create_mcp


class _FakeFastMCP:
    def __init__(self, name, **settings):
        self.name = name
        self.settings = settings
        self.tools = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function
        return register


class _FakeService:
    async def probe_banner(self, **arguments):
        return arguments

    async def scan_batch(self, **arguments):
        return arguments

    async def health_check(self):
        return {"service": "ok"}


def test_mcp_app_exposes_only_three_peer_tools():
    saved = {name: sys.modules.get(name) for name in (
        "mcp", "mcp.server", "mcp.server.fastmcp",
    )}
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = _FakeFastMCP
    sys.modules["mcp"] = types.ModuleType("mcp")
    sys.modules["mcp.server"] = types.ModuleType("mcp.server")
    sys.modules["mcp.server.fastmcp"] = fastmcp
    try:
        app = create_mcp(
            service=_FakeService(),
            transport_name="streamable_http",
            host="127.0.0.1",
            port=8877,
        )
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    assert set(app.tools) == {"probe_banner", "scan_batch", "health_check"}
    assert "identify_banner" not in app.tools
    assert app.settings["host"] == "127.0.0.1"
    assert app.settings["port"] == 8877
    assert app.settings["json_response"] is True
