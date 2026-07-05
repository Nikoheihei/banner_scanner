"""Official-SDK MCP application factory.

The SDK import is intentionally delayed so core scanning and rule regression
tests remain usable before optional MCP dependencies are installed.
"""

from __future__ import annotations

from typing import Any

from .service import BannerScannerService


SDK_INSTALL_HINT = 'Install the locked dependency with: pip install "mcp[cli]==1.28.1"'


def create_mcp(service: BannerScannerService | None = None,
               transport_name: str = "stdio",
               host: str = "127.0.0.1", port: int = 8877) -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(SDK_INSTALL_HINT) from exc

    service = service or BannerScannerService()
    mcp = FastMCP(
        "banner-scanner",
        instructions=(
            "Probe only explicitly authorized SSH, FTP, Telnet, Redis, MySQL, "
            "and PostgreSQL targets. probe_banner is for a small multi-protocol "
            "set; scan_batch is for up to 100 targets of one protocol."
        ),
        host=host,
        port=port,
        json_response=True,
    )

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
        return await service.probe_banner(
            hosts=hosts,
            protocols=protocols,
            retries=retries,
            concurrency=concurrency,
            detail_level=detail_level,
            authorization_confirmed=authorization_confirmed,
            transport=transport_name,
        )

    @mcp.tool()
    async def scan_batch(
        hosts: list[str],
        protocol: str = "ssh",
        retries: int = 2,
        concurrency: int | None = None,
        detail_level: str = "summary",
        authorization_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Actively probe up to 100 authorized targets using exactly one protocol."""
        return await service.scan_batch(
            hosts=hosts,
            protocol=protocol,
            retries=retries,
            concurrency=concurrency,
            detail_level=detail_level,
            authorization_confirmed=authorization_confirmed,
            transport=transport_name,
        )

    @mcp.tool()
    async def health_check() -> dict[str, Any]:
        """Return service, transport, rule-library, policy, and runtime-limit status."""
        return await service.health_check()

    return mcp
