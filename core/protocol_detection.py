"""Detect clear wire-protocol mismatches before fingerprint matching."""

from __future__ import annotations

import re

from .models import BannerResult


FTP_MARKER = re.compile(
    r"(?im)^(?:120|220)[- ][^\r\n]*(?:\bFTP\b|FileZilla|vsFTPd|ProFTPD|"
    r"Pure-FTPd|Serv-U|Xlight|Wing FTP|Core FTP)"
)
SMTP_MARKER = re.compile(r"(?im)^220[- ][^\r\n]*\b(?:ESMTP|SMTP)\b")
HTTP_MARKER = re.compile(r"(?im)^HTTP/[0-9](?:\.[0-9])?\s+[1-5][0-9]{2}\b")


def canonical_protocol(value: str) -> str:
    normalized = value.upper()
    return "PGSQL" if normalized in {"POSTGRES", "POSTGRESQL"} else normalized


def detect_observed_protocol(result: BannerResult) -> str:
    """Return a protocol only when the available evidence is distinctive."""
    banner = result.banner or ""
    if re.match(r"^SSH-[12]\.[0-9]+-", banner):
        return "SSH"
    if FTP_MARKER.search(banner):
        return "FTP"
    if SMTP_MARKER.search(banner):
        return "SMTP"
    if HTTP_MARKER.search(banner):
        return "HTTP"
    if result.redis and (
        result.redis.ping_response or result.redis.info_response or result.redis.fields
    ):
        return "REDIS"
    if re.search(
        r"(?im)^(?:redis|valkey|keydb|dragonfly|memurai)_version:", banner
    ):
        return "REDIS"
    if result.mysql and result.mysql.protocol_version == 10 and result.mysql.version:
        return "MYSQL"
    if result.pgsql and (
        result.pgsql.ssl_response
        or result.pgsql.fields
        or result.pgsql.auth_code is not None
        or result.pgsql.message_types
    ):
        return "PGSQL"

    expected = canonical_protocol(result.protocol)
    if expected == "FTP" and re.match(r"^(?:120|220)[- ]", banner):
        return "FTP"
    if expected == "TELNET" and (
        result.banner_raw_hex
        or (result.telnet and result.telnet.has_iac_negotiation)
        or re.search(r"(?i)(?:login|username|password)\s*:", banner)
    ):
        return "TELNET"
    return ""


def prepare_protocol_status(result: BannerResult) -> BannerResult:
    """Set expected/observed protocol state before any implementation match."""
    if not result.accessible:
        result.protocol_status = "not_observed"
        result.observed_protocol = ""
        return result

    expected = canonical_protocol(result.protocol)
    observed = detect_observed_protocol(result)
    result.observed_protocol = observed
    if observed and observed != expected:
        result.protocol_status = "mismatch"
    elif observed == expected:
        result.protocol_status = "confirmed"
    else:
        result.protocol_status = "observed"
    return result


def confirm_protocol_from_fingerprint(result: BannerResult) -> BannerResult:
    if (
        result.protocol_status == "observed"
        and (result.fingerprint_details or {}).get("protocol_match")
    ):
        result.protocol_status = "confirmed"
        result.observed_protocol = canonical_protocol(result.protocol)
    return result
