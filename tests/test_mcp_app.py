"""MCP application registration tests without importing the optional SDK."""

import ipaddress
import sys
import types

from banner_scanner.server.policy import TargetPolicy
from banner_scanner.server.mcp_app import create_mcp
from banner_scanner.server.service import BannerScannerService


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


class _NoProbeEngine:
    def __init__(self):
        self.last_call = None

    async def probe_hosts(self, hosts, protocols, concurrency, max_retries,
                          global_semaphore):
        self.last_call = {
            "hosts": hosts,
            "protocols": protocols,
            "concurrency": concurrency,
            "max_retries": max_retries,
            "global_semaphore": global_semaphore,
        }
        raise AssertionError("Probe engine must not be called for denied targets")

    async def health_check(self):
        return {"healthy": True}


def _with_fake_sdk(callback):
    saved = {name: sys.modules.get(name) for name in (
        "mcp", "mcp.server", "mcp.server.fastmcp",
    )}
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = _FakeFastMCP
    sys.modules["mcp"] = types.ModuleType("mcp")
    sys.modules["mcp.server"] = types.ModuleType("mcp.server")
    sys.modules["mcp.server.fastmcp"] = fastmcp
    try:
        return callback()
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def test_mcp_app_exposes_only_three_peer_tools():
    app = _with_fake_sdk(lambda: create_mcp(
        service=_FakeService(),
        transport_name="streamable_http",
        host="127.0.0.1",
        port=8877,
    ))

    assert set(app.tools) == {"probe_banner", "scan_batch", "health_check"}
    assert "identify_banner" not in app.tools
    assert app.settings["host"] == "127.0.0.1"
    assert app.settings["port"] == 8877
    assert app.settings["json_response"] is True


async def test_mcp_scan_batch_denylist_rejects_before_probe_engine():
    engine = _NoProbeEngine()
    service = BannerScannerService(
        engine=engine,
        target_policy=TargetPolicy(
            denylist=(ipaddress.ip_network("1.2.3.4/32"),),
        ),
    )
    app = _with_fake_sdk(lambda: create_mcp(
        service=service,
        transport_name="sse",
        host="127.0.0.1",
        port=8877,
    ))

    result = await app.tools["scan_batch"](
        hosts=["1.2.3.4"],
        protocol="ssh",
    )

    assert result["rejected"] is True
    assert result["tool"] == "scan_batch"
    assert result["error"]["code"] == "request_validation_error"
    assert "denied by server policy" in result["error"]["message"]
    assert engine.last_call is None
