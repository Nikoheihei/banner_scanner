"""MCP output exposes parsed evidence without per-rule match details."""

from banner_scanner.core.identification import finalize_identification
from banner_scanner.core.models import (
    BannerResult,
    FingerprintMatch,
    FtpFeatures,
    ProbeFailure,
    RedisInfo,
    SshBanner,
    TelnetBanner,
)
from banner_scanner.server.mcp_http_server import _banner_to_dict as http_banner_to_dict
from banner_scanner.server.mcp_server import _banner_to_dict as stdio_banner_to_dict


def _serialize_with_both(result: BannerResult) -> tuple[dict, dict]:
    stdio = stdio_banner_to_dict(result)
    http = http_banner_to_dict(result)
    assert stdio == http
    return stdio, http


def _matches() -> list[FingerprintMatch]:
    return [
        FingerprintMatch(
            vendor_id=401,
            vendor_name="OpenSSH",
            pattern=r"OpenSSH[_-]([0-9.]+)",
            confidence=0.98,
            source="ssh.version_string",
            category="implementation",
            labels={"implementation": "OpenSSH"},
            extracted={"version": "8.9"},
            result_type="software",
            match_level="software_version",
            evidence_strength="conclusive",
            primary_eligible=True,
            explanation="Explicit OpenSSH version marker.",
        ),
        FingerprintMatch(
            vendor_id=490,
            vendor_name="SSH-Generic",
            pattern=r"^SSH-2\\.0-",
            confidence=0.55,
            source="banner",
            category="fallback",
            result_type="protocol_identity",
            match_level="protocol_only",
            evidence_strength="weak",
            primary_eligible=False,
        ),
    ]


def test_ssh_mcp_output_contains_parsed_information_without_matched_rules():
    result = BannerResult(
        protocol="SSH",
        host="192.0.2.10",
        port=22,
        accessible=True,
        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        ssh=SshBanner(
            version_string="OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
            protocol_version="2.0",
            software="OpenSSH",
            version="8.9p1",
            os_type="Ubuntu",
            os_version="3ubuntu0.10",
            os_distro="Ubuntu-3ubuntu0.10",
            comments="Ubuntu-3ubuntu0.10",
        ),
        vendor="OpenSSH",
        vendor_id=401,
        vendor_confidence=0.98,
        matched_rules=_matches(),
    )

    finalize_identification(result)
    payload, _ = _serialize_with_both(result)

    assert payload["observations"]["ssh"]["version_string"] == result.ssh.version_string
    assert payload["observations"]["ssh"]["os_distro"] == "Ubuntu-3ubuntu0.10"
    assert payload["observations"]["ssh"]["comments"] == "Ubuntu-3ubuntu0.10"
    assert payload["primary_identification"]["name"] == "OpenSSH"
    assert payload["primary_identification"]["evidence_strength"] == "conclusive"
    assert "matched_rules" not in payload
    assert "matched_rule_ids" not in str(payload)
    assert payload["findings"]["protocol_identity"][0]["name"] == "SSH-Generic"


def test_ftp_mcp_output_contains_all_feature_flags_and_full_banner():
    result = BannerResult(
        protocol="FTP",
        host="192.0.2.20",
        port=21,
        accessible=True,
        banner="220 FileZilla Server 1.7.3",
        ftp=FtpFeatures(
            features="UTF8\nAUTH TLS\nSIZE\nMDTM\nMLST\nTVFS\nXCRC\nXCUP",
            utf8=True,
            auth_tls=True,
            auth_ssl=True,
            size_cmd=True,
            mdtm=True,
            mldst=True,
            tvfs=True,
            xcrc=True,
            xcup=True,
            software="FileZilla Server",
            version="1.7.3",
            full_banner="220 FileZilla Server 1.7.3\r\n211-Features...",
        ),
    )

    payload, _ = _serialize_with_both(result)

    for field in ("auth_ssl", "size_cmd", "mdtm", "mldst", "tvfs", "xcrc", "xcup"):
        assert payload["observations"]["ftp"][field] is True
    assert payload["observations"]["ftp"]["full_banner"].startswith("220 FileZilla")
    assert "matched_rules" not in payload


def test_telnet_mcp_output_contains_text_raw_bytes_and_all_matches():
    result = BannerResult(
        protocol="TELNET",
        host="192.0.2.30",
        port=23,
        accessible=True,
        banner="User Access Verification\nUsername:",
        banner_raw_hex="fffb01fffb03",
        telnet=TelnetBanner(
            banner="User Access Verification\nUsername:",
            banner_raw_hex="fffb01fffb03",
            has_login_prompt=True,
            has_iac_negotiation=True,
            extracted_text="User Access Verification\nUsername:",
            detected_service="Cisco IOS telnetd",
        ),
    )

    payload, _ = _serialize_with_both(result)

    assert payload["observations"]["raw_hex_preview"] == "fffb01fffb03"
    assert payload["observations"]["telnet"]["banner_raw_hex"] == "fffb01fffb03"
    assert payload["observations"]["telnet"]["extracted_text"].endswith("Username:")
    assert payload["observations"]["telnet"]["has_iac_negotiation"] is True
    assert "matched_rules" not in payload


def test_no_protocol_returns_matched_rules():
    for protocol in ("SSH", "FTP", "TELNET", "REDIS", "MYSQL", "PGSQL"):
        result = BannerResult(
            protocol=protocol,
            host="192.0.2.40",
            port=0,
            accessible=True,
            matched_rules=_matches(),
        )
        payload, _ = _serialize_with_both(result)
        assert "matched_rules" not in payload
        serialized = str(payload)
        assert "matched_rule_ids" not in serialized
        assert "pattern" not in serialized


def test_summary_output_omits_large_protocol_payloads():
    result = BannerResult(
        protocol="REDIS",
        host="192.0.2.41",
        port=6379,
        accessible=True,
        redis=RedisInfo(
            implementation="Redis",
            version="7.2.4",
            mode="standalone",
            os="Linux",
            info_response="x" * 10000,
            fields={"large": "y" * 10000},
        ),
    )

    payload = stdio_banner_to_dict(result, detail_level="summary")
    redis = payload["observations"]["redis"]
    assert redis == {
        "implementation": "Redis",
        "version": "7.2.4",
        "mode": "standalone",
        "os": "Linux",
    }


def test_timeout_output_identifies_the_network_phase_without_changing_base_code():
    result = BannerResult(
        protocol="FTP",
        host="192.0.2.50",
        port=21,
        error="connect to 192.0.2.50:21 timed out",
        failure=ProbeFailure(
            phase="tcp_connect",
            detail_code="tcp_connect_timeout",
            message="connect to 192.0.2.50:21 timed out",
            elapsed_ms=3001.2,
            context={
                "endpoint": {"host": "192.0.2.50", "port": 21},
                "address_family": "ipv4",
                "connect_timeout_ms": 3000.0,
            },
        ),
        retry_attempts=1,
        retry_elapsed_ms=3001.2,
        retry_history=[{
            "attempt": 1,
            "phase": "tcp_connect",
            "detail_code": "tcp_connect_timeout",
            "elapsed_ms": 3001.2,
            "context": {
                "endpoint": {"host": "192.0.2.50", "port": 21},
                "address_family": "ipv4",
                "connect_timeout_ms": 3000.0,
            },
        }],
    )

    payload, _ = _serialize_with_both(result)

    assert payload["network_status"] == "timeout"
    assert payload["error"] == {
        "code": "probe_timeout",
        "message": "connect to 192.0.2.50:21 timed out",
        "phase": "tcp_connect",
        "detail_code": "tcp_connect_timeout",
        "elapsed_ms": 3001.2,
        "context": {
            "endpoint": {"host": "192.0.2.50", "port": 21},
            "address_family": "ipv4",
            "connect_timeout_ms": 3000.0,
        },
        "retry_summary": {"attempts": 1, "total_elapsed_ms": 3001.2},
        "attempt_history": [{
            "attempt": 1,
            "phase": "tcp_connect",
            "detail_code": "tcp_connect_timeout",
            "elapsed_ms": 3001.2,
            "context": {
                "endpoint": {"host": "192.0.2.50", "port": 21},
                "address_family": "ipv4",
                "connect_timeout_ms": 3000.0,
            },
        }],
    }


def test_summary_timeout_keeps_phase_but_omits_attempt_history():
    result = BannerResult(
        protocol="MYSQL",
        host="192.0.2.51",
        port=3306,
        error="read timed out after 3s",
        failure=ProbeFailure(
            phase="protocol_read",
            detail_code="protocol_read_timeout",
            message="read timed out after 3s",
            elapsed_ms=3000.0,
        ),
        retry_history=[{
            "attempt": 1,
            "phase": "protocol_read",
            "detail_code": "protocol_read_timeout",
            "elapsed_ms": 3000.0,
        }],
    )

    payload = stdio_banner_to_dict(result, detail_level="summary")

    assert payload["network_status"] == "timeout"
    assert payload["error"]["phase"] == "protocol_read"
    assert payload["error"]["detail_code"] == "protocol_read_timeout"
    assert "attempt_history" not in payload["error"]


def test_legacy_result_errors_receive_conservative_phase():
    cases = (
        ("DNS resolution for host failed", "dns_resolution"),
        ("connect to host:22 timed out", "connect"),
        ("read timed out after 3s", "read"),
        ("connection closed before SSH banner", "protocol_probe"),
        ("Unexpected: parser crashed", "internal"),
    )
    for message, expected_phase in cases:
        result = BannerResult(
            protocol="SSH", host="192.0.2.60", port=22, error=message,
        )
        payload, _ = _serialize_with_both(result)
        assert payload["error"]["phase"] == expected_phase
