"""Official-SDK MCP application factory.

The SDK import is intentionally delayed so core scanning and rule regression
tests remain usable before optional MCP dependencies are installed.
"""

from __future__ import annotations

import logging
from typing import Any

from .policy import RequestValidationError
from .service import BannerScannerService


SDK_INSTALL_HINT = 'Install the locked dependency with: pip install "mcp[cli]==1.28.1"'
logger = logging.getLogger("uvicorn.error")


def _tool_error(tool: str, code: str, phase: str, exc: Exception) -> dict[str, Any]:
    return {
        "tool": tool,
        "rejected": True,
        "error": {
            "code": code,
            "phase": phase,
            "message": str(exc),
        },
    }


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
    ) -> dict[str, Any]:
        """Actively probe up to 20 authorized targets using one or more protocols."""
        try:
            return await service.probe_banner(
                hosts=hosts,
                protocols=protocols,
                retries=retries,
                concurrency=concurrency,
                detail_level=detail_level,
                transport=transport_name,
            )
        except RequestValidationError as exc:
            return _tool_error(
                "probe_banner", "request_validation_error", "request_validation", exc,
            )
        except TimeoutError as exc:
            return _tool_error("probe_banner", "request_timeout", "request_timeout", exc)
        except Exception as exc:
            logger.exception("Unexpected probe_banner tool error")
            return _tool_error("probe_banner", "internal_error", "internal", exc)

    @mcp.tool()
    async def scan_batch(
        hosts: list[str] | None = None,
        compressed_hosts: str | None = None,
        protocol: str = "ssh",
        retries: int = 2,
        concurrency: int | None = None,
        detail_level: str = "summary",
        result_mode: str = "full",
    ) -> dict[str, Any]:
        """Probe up to 100 targets; compressed_hosts is gzip+base64 JSON."""
        try:
            return await service.scan_batch(
                hosts=hosts,
                compressed_hosts=compressed_hosts,
                protocol=protocol,
                retries=retries,
                concurrency=concurrency,
                detail_level=detail_level,
                result_mode=result_mode,
                transport=transport_name,
            )
        except RequestValidationError as exc:
            return _tool_error(
                "scan_batch", "request_validation_error", "request_validation", exc,
            )
        except TimeoutError as exc:
            return _tool_error("scan_batch", "request_timeout", "request_timeout", exc)
        except Exception as exc:
            logger.exception("Unexpected scan_batch tool error")
            return _tool_error("scan_batch", "internal_error", "internal", exc)

    @mcp.tool()
    async def health_check() -> dict[str, Any]:
        """Return service, transport, rule-library, policy, and runtime-limit status."""
        logger.info("MCP health_check request received")
        response = await service.health_check()
        logger.info("MCP health_check response ready")
        return response

    return mcp
