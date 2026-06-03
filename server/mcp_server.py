"""MCP 服务。"""

import asyncio
import json
import sys

from ..core.engine import ProbeEngine
from ..core.models import ProbeConfig
from ..core.log import setup_logging

try:
    from mcp.server import Server, NotificationOptions
    from mcp.server.models import InitializationOptions
    import mcp.server.stdio
    import mcp.types as types
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False


def _to_dict(result) -> dict:
    from ..core.models import BannerResult, HostResult
    if isinstance(result, HostResult):
        return {
            "host": result.host,
            "total_time_ms": round(result.total_time_ms, 1),
            "results": {p: _to_dict(r) for p, r in result.results.items()},
        }
    if isinstance(result, BannerResult):
        d = {
            "protocol": result.protocol, "host": result.host, "port": result.port,
            "accessible": result.accessible, "banner": result.banner,
            "response_time_ms": round(result.response_time_ms, 1),
            "error": result.error,
        }
        if result.ssh:
            d["ssh"] = {"software": result.ssh.software, "version": result.ssh.version,
                        "protocol_version": result.ssh.protocol_version}
        if result.ftp:
            d["ftp"] = {"features": result.ftp.features, "utf8": result.ftp.utf8,
                        "auth_tls": result.ftp.auth_tls}
        if result.vendor:
            d["vendor"] = result.vendor
        return d
    return {}


async def serve() -> None:
    if not MCP_AVAILABLE:
        print("MCP SDK not installed. Install with: pip install mcp", file=sys.stderr)
        sys.exit(1)

    setup_logging(level="INFO")
    engine = ProbeEngine()

    server = Server("banner-scanner")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="probe_banner",
                description="探测指定 IP 的 SSH/FTP/Telnet Banner，可选指纹匹配",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "hosts": {
                            "type": "array", "items": {"type": "string"},
                            "description": "目标 IP 列表",
                        },
                        "protocols": {
                            "type": "array",
                            "items": {"type": "string", "enum": ["ssh", "ftp", "telnet"]},
                        },
                        "fingerprint": {
                            "type": "string",
                            "description": "指纹库文件路径",
                        },
                    },
                    "required": ["hosts"],
                },
            ),
            types.Tool(
                name="health_check",
                description="引擎健康状态",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        if name == "probe_banner":
            hosts = arguments.get("hosts", [])
            protocols = arguments.get("protocols")
            fingerprint = arguments.get("fingerprint")
            if fingerprint:
                engine.config.fingerprint_path = fingerprint
                from ..core.matcher import FingerprintMatcher
                engine.set_matcher(FingerprintMatcher.load(fingerprint))
            results = await engine.probe_hosts(hosts, protocols=protocols)
            output = {r.host: _to_dict(r) for r in results}
            return [types.TextContent(type="text", text=json.dumps(output, indent=2, ensure_ascii=False))]

        elif name == "health_check":
            health = await engine.health_check()
            return [types.TextContent(type="text", text=json.dumps(health, indent=2, ensure_ascii=False))]

        raise ValueError(f"Unknown tool: {name}")

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, InitializationOptions(
            server_name="banner-scanner",
            server_version="0.3.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(),
                experimental_capabilities={},
            ),
        ))


def main():
    asyncio.run(serve())


if __name__ == "__main__":
    main()
