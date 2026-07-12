"""Audit records use the full captured-response digest when available."""

import io
import json
import logging
import os

from banner_scanner.core.models import BannerResult
from banner_scanner.server.audit import audit_tool_request, banner_hash


def _capture_audit_log(callback) -> str:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("banner_scanner.audit")
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        callback()
        return stream.getvalue()
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


def test_audit_prefers_probe_computed_response_hash():
    result = BannerResult(
        protocol="TELNET",
        host="192.0.2.60",
        port=23,
        accessible=True,
        banner="truncated preview",
        banner_raw_hex="00",
        response_sha256="a" * 64,
    )
    assert banner_hash(result) == "a" * 64


def test_audit_request_logs_all_hosts_by_default():
    old_value = os.environ.pop("BANNER_SCANNER_LOG_PARAMS", None)
    try:
        text = _capture_audit_log(lambda: audit_tool_request(
            request_id="req1",
            tool="scan_batch",
            transport="sse",
            hosts=["192.0.2.1", "192.0.2.2"],
            compressed_hosts_present=False,
            protocols=["ssh"],
            retries=1,
            concurrency=5,
            detail_level="summary",
            result_mode="full",
        ))
    finally:
        if old_value is not None:
            os.environ["BANNER_SCANNER_LOG_PARAMS"] = old_value

    payload = json.loads(text)
    assert payload["target_count"] == 2
    assert payload["hosts"] == ["192.0.2.1", "192.0.2.2"]


def test_audit_request_can_redact_hosts():
    old_value = os.environ.get("BANNER_SCANNER_LOG_PARAMS")
    os.environ["BANNER_SCANNER_LOG_PARAMS"] = "0"
    try:
        text = _capture_audit_log(lambda: audit_tool_request(
            request_id="req2",
            tool="probe_banner",
            transport="fastmcp",
            hosts=[f"192.0.2.{index}" for index in range(1, 8)],
            compressed_hosts_present=False,
            protocols=["ssh", "ftp"],
            retries=2,
            concurrency=5,
            detail_level="evidence",
            result_mode="full",
        ))
    finally:
        if old_value is None:
            os.environ.pop("BANNER_SCANNER_LOG_PARAMS", None)
        else:
            os.environ["BANNER_SCANNER_LOG_PARAMS"] = old_value

    payload = json.loads(text)
    assert payload["target_count"] == 7
    assert "hosts" not in payload
