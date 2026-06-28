"""Tests for physically and logically isolated SSH/FTP/Telnet libraries."""

from __future__ import annotations

import json

from banner_scanner.core.matcher import (
    DEFAULT_PROTOCOL_LIBRARY_DIR,
    FingerprintMatcher,
)
from banner_scanner.core.models import BannerResult


EXPECTED_RULE_COUNTS = {"SSH": 55, "FTP": 52, "TELNET": 102}


def _load_library(protocol: str) -> dict:
    path = DEFAULT_PROTOCOL_LIBRARY_DIR / f"{protocol.lower()}_fingerprints.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_protocol_libraries_are_physically_separate():
    for protocol, expected_count in EXPECTED_RULE_COUNTS.items():
        payload = _load_library(protocol)
        assert payload["protocol"] == protocol
        assert payload["rule_count"] == expected_count
        assert len(payload["vendors"]) == expected_count
        assert {rule["protocol"] for rule in payload["vendors"]} == {protocol}


def test_protocol_library_ids_are_globally_unique():
    ids = []
    for protocol in EXPECTED_RULE_COUNTS:
        ids.extend(rule["id"] for rule in _load_library(protocol)["vendors"])
    assert len(ids) == len(set(ids))


def test_directory_loader_reports_protocol_counts():
    matcher = FingerprintMatcher.load(DEFAULT_PROTOCOL_LIBRARY_DIR)
    stats = matcher.stats()
    assert stats["total_rules"] == sum(EXPECTED_RULE_COUNTS.values())
    assert stats["rules_by_protocol"] == EXPECTED_RULE_COUNTS


def test_ssh_rule_cannot_match_ftp_result():
    matcher = FingerprintMatcher.load(DEFAULT_PROTOCOL_LIBRARY_DIR)
    result = BannerResult(
        protocol="FTP", host="127.0.0.1", port=21, accessible=True,
        banner="SSH-2.0-OpenSSH_9.8",
    )
    matcher.match(result)
    assert result.vendor == ""


def test_ftp_rule_cannot_match_ssh_result():
    matcher = FingerprintMatcher.load(DEFAULT_PROTOCOL_LIBRARY_DIR)
    result = BannerResult(
        protocol="SSH", host="127.0.0.1", port=22, accessible=True,
        banner="220 vsFTPd 3.0.5 ready",
    )
    matcher.match(result)
    assert result.vendor == ""


def test_cross_protocol_software_has_independent_rule_ids():
    ftp_rules = _load_library("FTP")["vendors"]
    telnet_rules = _load_library("TELNET")["vendors"]
    ftp_id = next(rule["id"] for rule in ftp_rules if rule["name"] == "FileZilla Server")
    telnet_id = next(
        rule["id"] for rule in telnet_rules if rule["name"] == "FileZilla Server"
    )
    assert ftp_id != telnet_id


def test_xlight_ftp_server_banner_matches():
    matcher = FingerprintMatcher.load(DEFAULT_PROTOCOL_LIBRARY_DIR)
    result = BannerResult(
        protocol="FTP", host="127.0.0.1", port=21, accessible=True,
        banner="220 Xlight FTP Server 3.9 ready...",
    )
    matcher.match(result)
    assert result.vendor == "xlightftpd"


def test_windows_telnet_text_outranks_generic_iac():
    matcher = FingerprintMatcher.load(DEFAULT_PROTOCOL_LIBRARY_DIR)
    result = BannerResult(
        protocol="TELNET", host="127.0.0.1", port=23, accessible=True,
        banner="Welcome to the Windows CE Telnet Service on device",
        banner_raw_hex="fffb01fffb03",
    )
    matcher.match(result)
    assert result.vendor == "Windows telnetd"


def test_ws_ftp_does_not_match_aws_sftp():
    matcher = FingerprintMatcher.load(DEFAULT_PROTOCOL_LIBRARY_DIR)
    result = BannerResult(
        protocol="SSH", host="127.0.0.1", port=22, accessible=True,
        banner="SSH-2.0-AWS_SFTP_1.2",
    )
    matcher.match(result)
    assert result.vendor == "AWS SFTP"
    assert all(match.vendor_name != "WS_FTP" for match in result.matched_rules)


def test_serv_u_rule_does_not_match_core_ftp():
    matcher = FingerprintMatcher.load(DEFAULT_PROTOCOL_LIBRARY_DIR)
    result = BannerResult(
        protocol="FTP", host="127.0.0.1", port=21, accessible=True,
        banner="220 Core FTP Server Version 2.0, build 694, 64-bit Unregistered",
    )
    matcher.match(result)
    assert result.vendor == "Core FTP Server"
    assert all(match.vendor_name != "Serv-U FTP" for match in result.matched_rules)
