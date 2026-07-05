"""Audit records use the full captured-response digest when available."""

from banner_scanner.core.models import BannerResult
from banner_scanner.server.audit import banner_hash


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
