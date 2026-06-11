"""MCP 服务 — 为 Cherry Studio / Claude Desktop 提供 Banner 扫描能力。"""

import asyncio
import json
import os
import sys
from pathlib import Path

# 项目根
_project_root = str(Path(__file__).parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from banner_scanner.core.engine import ProbeEngine
from banner_scanner.core.models import ProbeConfig, BannerResult, HostResult
from banner_scanner.core.log import setup_logging
from banner_scanner.core.matcher import FingerprintMatcher

try:
    from mcp.server import Server, NotificationOptions
    from mcp.server.models import InitializationOptions
    import mcp.server.stdio
    import mcp.types as types
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False


# 自动加载同级目录下的 vendors.json
_DEFAULT_FINGERPRINT = str(Path(__file__).parent.parent / "vendors.json")


def _banner_to_dict(br: BannerResult) -> dict:
    """将 BannerResult 转为前端友好的 JSON"""
    d = {
        "protocol": br.protocol,
        "host": br.host,
        "port": br.port,
        "accessible": br.accessible,
        "banner": br.banner,
        "response_time_ms": round(br.response_time_ms, 1),
        "error": br.error,
    }
    # SSH
    if br.ssh:
        d["ssh"] = {
            "software": br.ssh.software,
            "version": br.ssh.version,
            "protocol_version": br.ssh.protocol_version,
            "os": br.ssh.os_type,
            "os_version": br.ssh.os_version,
        }
    # FTP
    if br.ftp:
        d["ftp"] = {
            "software": br.ftp.software,
            "version": br.ftp.version,
            "features": br.ftp.features,
            "utf8": br.ftp.utf8,
            "auth_tls": br.ftp.auth_tls,
            "mldst": br.ftp.mldst,
        }
    # Telnet
    if br.telnet:
        d["telnet"] = {
            "detected_service": br.telnet.detected_service,
            "has_login_prompt": br.telnet.has_login_prompt,
            "has_iac": br.telnet.has_iac_negotiation,
        }
    # 指纹/分类
    if br.vendor:
        d["fingerprint"] = br.vendor
        d["fingerprint_id"] = br.vendor_id
        d["confidence"] = br.vendor_confidence
    # 统一 info
    if br.info:
        d["info"] = {
            "service_name": br.info.get("service_name", ""),
            "service_version": br.info.get("service_version", ""),
            "os": br.info.get("os", ""),
            "iac_signature": br.info.get("iac_signature", ""),
        }
    # 重试
    if br.retry_count:
        d["retries"] = br.retry_count
    return d


async def serve() -> None:
    if not MCP_AVAILABLE:
        print("MCP SDK not installed. Install with: pip install mcp", file=sys.stderr)
        sys.exit(1)

    setup_logging(level="INFO")
    config = ProbeConfig()

    # 自动加载指纹库
    matcher = None
    if os.path.exists(_DEFAULT_FINGERPRINT):
        matcher = FingerprintMatcher.load(_DEFAULT_FINGERPRINT)

    engine = ProbeEngine(config)
    if matcher:
        engine._matcher = matcher
        engine.config.fingerprint_path = _DEFAULT_FINGERPRINT

    server = Server("banner-scanner")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="probe_banner",
                description="探测 IP 的 SSH/FTP/Telnet Banner，自动指纹识别。"
                            "返回 Banner 文本、服务商、版本号、操作系统、设备分类。",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "hosts": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "目标 IP 或域名列表",
                        },
                        "protocols": {
                            "type": "array",
                            "items": {"type": "string", "enum": ["ssh", "ftp", "telnet"]},
                            "description": "协议列表，默认全部",
                        },
                        "retries": {
                            "type": "integer",
                            "description": "最大重试次数，默认 2",
                        },
                    },
                    "required": ["hosts"],
                },
            ),
            types.Tool(
                name="scan_batch",
                description="批量扫描多个 IP（适合一次性大量探测）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "hosts": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "目标 IP 列表",
                        },
                        "protocol": {
                            "type": "string",
                            "enum": ["ssh", "ftp", "telnet"],
                            "description": "协议，默认 SSH",
                        },
                        "concurrency": {
                            "type": "integer",
                            "description": "并发数，默认 100",
                        },
                    },
                    "required": ["hosts"],
                },
            ),
            types.Tool(
                name="health_check",
                description="引擎健康状态和指纹库信息",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        if name == "probe_banner":
            hosts = arguments.get("hosts", [])
            protocols = arguments.get("protocols")
            retries = arguments.get("retries", 2)

            config.max_retries = retries
            results = await engine.probe_hosts(hosts, protocols=protocols)

            output = []
            for hr in results:
                for proto, br in hr.results.items():
                    output.append(_banner_to_dict(br))

            summary = {
                "total_hosts": len(hosts),
                "total_probes": len(output),
                "accessible": sum(1 for o in output if o["accessible"]),
                "fingerprint_matched": sum(1 for o in output if o.get("fingerprint")),
                "results": output,
            }
            return [types.TextContent(
                type="text",
                text=json.dumps(summary, indent=2, ensure_ascii=False),
            )]

        elif name == "scan_batch":
            hosts = arguments.get("hosts", [])
            protocol = arguments.get("protocol", "ssh")
            results = await engine.probe_hosts(hosts, protocols=[protocol])

            output = []
            for hr in results:
                br = hr.results.get(protocol)
                if br:
                    d = _banner_to_dict(br)
                    output.append(d)

            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "protocol": protocol.upper(),
                    "total": len(hosts),
                    "accessible": sum(1 for o in output if o["accessible"]),
                    "matched": sum(1 for o in output if o.get("fingerprint")),
                    "results": output,
                }, indent=2, ensure_ascii=False),
            )]

        elif name == "health_check":
            health = await engine.health_check()
            health["fingerprint_rules"] = matcher.rule_count if matcher else 0
            health["fingerprint_path"] = _DEFAULT_FINGERPRINT
            return [types.TextContent(
                type="text",
                text=json.dumps(health, indent=2, ensure_ascii=False),
            )]

        raise ValueError(f"Unknown tool: {name}")

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, InitializationOptions(
            server_name="banner-scanner",
            server_version="0.4.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(),
                experimental_capabilities={},
            ),
        ))


def main():
    asyncio.run(serve())


if __name__ == "__main__":
    main()
