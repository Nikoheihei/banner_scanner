"""MCP output exposes parsed evidence without per-rule match details."""

from banner_scanner.core.models import (
    BannerResult,
    FingerprintMatch,
    FtpFeatures,
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
        ),
        FingerprintMatch(
            vendor_id=490,
            vendor_name="SSH-Generic",
            pattern=r"^SSH-2\\.0-",
            confidence=0.55,
            source="banner",
            category="fallback",
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

    payload, _ = _serialize_with_both(result)

    assert payload["ssh"]["version_string"] == result.ssh.version_string
    assert payload["ssh"]["os_distro"] == "Ubuntu-3ubuntu0.10"
    assert payload["ssh"]["comments"] == "Ubuntu-3ubuntu0.10"
    assert "matched_rules" not in payload
    assert payload["matches_by_category"] == {
        "implementation": ["OpenSSH"],
        "fallback": ["SSH-Generic"],
    }


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
        matched_rules=_matches(),
    )

    payload, _ = _serialize_with_both(result)

    for field in ("auth_ssl", "size_cmd", "mdtm", "mldst", "tvfs", "xcrc", "xcup"):
        assert payload["ftp"][field] is True
    assert payload["ftp"]["full_banner"].startswith("220 FileZilla")
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
        matched_rules=_matches(),
    )

    payload, _ = _serialize_with_both(result)

    assert payload["banner_raw_hex"] == "fffb01fffb03"
    assert payload["telnet"]["banner_raw_hex"] == "fffb01fffb03"
    assert payload["telnet"]["extracted_text"].endswith("Username:")
    assert payload["telnet"]["has_iac"] is True
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
