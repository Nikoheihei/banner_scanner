"""Standalone FastMCP entrypoint.

This module follows the common ``from fastmcp import FastMCP`` style used by
teaching examples, while reusing the project's existing service, policy, probe,
and fingerprint-matching logic.
"""

from __future__ import annotations

import argparse
import os
from typing import Any

from fastmcp import FastMCP

from .policy import RequestValidationError, TargetPolicy
from .service import BannerScannerService


mcp = FastMCP(
    "BannerScannerServer",
    instructions=(
        "Authorized six-protocol Banner probing and fingerprint identification "
        "service. Use probe_banner for small multi-protocol checks, scan_batch "
        "for one-protocol batch checks, and health_check for service status."
    ),
)
service = BannerScannerService()


def _tool_error(tool: str, code: str, exc: Exception) -> dict[str, Any]:
    return {
        "tool": tool,
        "rejected": True,
        "error": {
            "code": code,
            "message": str(exc),
        },
    }


@mcp.tool()
async def probe_banner(
    hosts: list[str],
    protocols: list[str] | None = None,
    retries: int = 2,
    concurrency: int | None = None,
    detail_level: str = "evidence",
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Actively probe up to 20 authorized targets using one or more protocols."""
    try:
        return await service.probe_banner(
            hosts=hosts,
            protocols=protocols,
            retries=retries,
            concurrency=concurrency,
            detail_level=detail_level,
            authorization_confirmed=authorization_confirmed,
            transport="fastmcp",
        )
    except RequestValidationError as exc:
        return _tool_error("probe_banner", "request_validation_error", exc)
    except TimeoutError as exc:
        return _tool_error("probe_banner", "request_timeout", exc)


@mcp.tool()
async def scan_batch(
    hosts: list[str] | None = None,
    compressed_hosts: str | None = None,
    protocol: str = "ssh",
    retries: int = 2,
    concurrency: int | None = None,
    detail_level: str = "summary",
    result_mode: str = "full",
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Probe up to 100 targets for one protocol."""
    try:
        return await service.scan_batch(
            hosts=hosts,
            compressed_hosts=compressed_hosts,
            protocol=protocol,
            retries=retries,
            concurrency=concurrency,
            detail_level=detail_level,
            result_mode=result_mode,
            authorization_confirmed=authorization_confirmed,
            transport="fastmcp",
        )
    except RequestValidationError as exc:
        return _tool_error("scan_batch", "request_validation_error", exc)
    except TimeoutError as exc:
        return _tool_error("scan_batch", "request_timeout", exc)


@mcp.tool()
async def health_check() -> dict[str, Any]:
    """Return service, transport, rule-library, policy, and runtime-limit status."""
    return await service.health_check()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Banner Scanner standalone FastMCP server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http", "streamable-http", "sse"),
        default=os.environ.get("MCP_TRANSPORT", "sse"),
        help="FastMCP transport. Use http/streamable-http for /mcp, sse for /sse.",
    )
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT", "8877")))
    return parser


def _check_remote_bind(host: str) -> None:
    if host in {"127.0.0.1", "::1", "localhost"}:
        return
    if os.environ.get("BANNER_SCANNER_ALLOW_REMOTE_BIND") != "1":
        raise SystemExit(
            "Non-loopback FastMCP binding requires BANNER_SCANNER_ALLOW_REMOTE_BIND=1 "
            "and a target allowlist."
        )
    if not TargetPolicy.from_env().allowlist_enabled:
        raise SystemExit("Non-loopback FastMCP binding requires a target allowlist")


def main() -> None:
    args = _build_parser().parse_args()
    _check_remote_bind(args.host)
    transport = "http" if args.transport == "streamable-http" else args.transport
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport=transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
