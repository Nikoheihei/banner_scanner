"""Privacy-conscious audit records for active MCP probe calls."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from typing import Iterable

from ..core.models import BannerResult


logger = logging.getLogger("banner_scanner.audit")


def new_request_id() -> str:
    return uuid.uuid4().hex


def _log_params_enabled() -> bool:
    """Return whether target parameters are persisted in the service audit log.

    Target addresses are operational data needed to correlate an MCP request
    with its per-endpoint outcome.  They are therefore recorded by default.
    Deployments that must redact targets from their local log can explicitly
    set ``BANNER_SCANNER_LOG_PARAMS=0``.
    """
    return os.environ.get("BANNER_SCANNER_LOG_PARAMS", "1").lower() not in {
        "0", "false", "no", "off",
    }


def audit_tool_request(*, request_id: str, tool: str, transport: str,
                       hosts: list[str] | None, compressed_hosts_present: bool,
                       protocols: list[str] | None, retries: int | None,
                       concurrency: int | None, detail_level: str,
                       result_mode: str | None,
                       authorization_confirmed: bool) -> None:
    record = {
        "event": "mcp_tool_request",
        "request_id": request_id,
        "tool": tool,
        "transport": transport,
        "target_count": len(hosts or []),
        "compressed_hosts_present": bool(compressed_hosts_present),
        "protocols": protocols or [],
        "retries": retries,
        "concurrency": concurrency,
        "detail_level": detail_level,
        "result_mode": result_mode,
        "authorization_confirmed": authorization_confirmed,
    }
    if _log_params_enabled():
        # The service limits host counts, so storing the whole list is bounded
        # and makes a later result record traceable to the original request.
        record["hosts"] = [str(host) for host in (hosts or [])]
    logger.info(json.dumps(record, ensure_ascii=False, separators=(",", ":")))


def audit_tool_rejection(*, request_id: str, tool: str, transport: str,
                         code: str, error: Exception) -> None:
    logger.info(json.dumps({
        "event": "mcp_tool_rejected",
        "request_id": request_id,
        "tool": tool,
        "transport": transport,
        "code": code,
        "message": str(error),
    }, ensure_ascii=False, separators=(",", ":")))


def banner_hash(result: BannerResult) -> str:
    if result.response_sha256:
        return result.response_sha256
    if result.banner_raw_hex:
        try:
            raw = bytes.fromhex(result.banner_raw_hex)
        except ValueError:
            raw = result.banner_raw_hex.encode("ascii", errors="replace")
    else:
        raw = result.banner.encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def audit_probe(*, request_id: str | None = None, tool: str, transport: str, target_count: int,
                protocols: list[str], authorization_confirmed: bool,
                results: Iterable[BannerResult], elapsed_ms: float,
                preview_limit: int = 160) -> str:
    request_id = request_id or new_request_id()
    samples = []
    for result in results:
        preview = result.banner.replace("\r", "\\r").replace("\n", "\\n")[:preview_limit]
        samples.append({
            "host": result.host,
            "port": result.port,
            "protocol": result.protocol,
            "accessible": result.accessible,
            "response_time_ms": round(result.response_time_ms, 1),
            "retry_attempts": result.retry_attempts,
            "error": result.error,
            "banner_preview": preview,
            "banner_hash": banner_hash(result),
        })
    logger.info(json.dumps({
        "request_id": request_id,
        "tool": tool,
        "transport": transport,
        "target_count": target_count,
        "protocols": protocols,
        "authorization_confirmed": authorization_confirmed,
        "elapsed_ms": round(elapsed_ms, 1),
        "results": samples,
    }, ensure_ascii=False, separators=(",", ":")))
    return request_id
