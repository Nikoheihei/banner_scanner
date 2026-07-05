"""Privacy-conscious audit records for active MCP probe calls."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Iterable

from ..core.models import BannerResult


logger = logging.getLogger("banner_scanner.audit")


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


def audit_probe(*, tool: str, transport: str, target_count: int,
                protocols: list[str], authorization_confirmed: bool,
                results: Iterable[BannerResult], elapsed_ms: float,
                preview_limit: int = 160) -> str:
    request_id = uuid.uuid4().hex
    samples = []
    for result in results:
        preview = result.banner.replace("\r", "\\r").replace("\n", "\\n")[:preview_limit]
        samples.append({
            "protocol": result.protocol,
            "accessible": result.accessible,
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
