"""Internal offline identification entry point used by rule regression tests."""

from __future__ import annotations

from dataclasses import fields
from functools import lru_cache
from typing import Any, Optional, TypeVar

from .database_matcher import DatabaseFingerprintMatcher
from .matcher import FingerprintMatcher
from .models import (
    BannerResult,
    EvidenceStep,
    FtpFeatures,
    MysqlInfo,
    PgsqlInfo,
    RedisInfo,
    SshBanner,
    TelnetBanner,
)
from .parsers import (
    extract_banner_info,
    parse_ftp_banner_info,
    parse_redis_response,
    parse_ssh_banner,
    parse_telnet_banner,
)
from .protocol_detection import confirm_protocol_from_fingerprint, prepare_protocol_status


T = TypeVar("T")


def _dataclass_from(cls: type[T], values: dict[str, Any]) -> T:
    allowed = {item.name for item in fields(cls)}
    return cls(**{key: value for key, value in values.items() if key in allowed})


class OfflineIdentifier:
    """Identify existing evidence without opening a network connection."""

    def __init__(self, matcher: Optional[FingerprintMatcher] = None,
                 database_matcher: Optional[DatabaseFingerprintMatcher] = None):
        from .matcher import DEFAULT_PROTOCOL_LIBRARY_DIR

        self.matcher = matcher or FingerprintMatcher.load(DEFAULT_PROTOCOL_LIBRARY_DIR)
        self.database_matcher = database_matcher or DatabaseFingerprintMatcher.load_default()

    @classmethod
    def load_default(cls) -> "OfflineIdentifier":
        from .matcher import DEFAULT_PROTOCOL_LIBRARY_DIR

        return cls(
            matcher=FingerprintMatcher.load(DEFAULT_PROTOCOL_LIBRARY_DIR),
            database_matcher=DatabaseFingerprintMatcher.load_default(),
        )

    def identify(self, protocol: str, raw_banner: str = "",
                 structured_fields: Optional[dict[str, Any]] = None,
                 raw_hex: str = "") -> BannerResult:
        protocol_key = protocol.lower()
        if protocol_key == "postgresql":
            protocol_key = "pgsql"
        if protocol_key not in {"ssh", "ftp", "telnet", "redis", "mysql", "pgsql"}:
            raise ValueError(f"Unsupported protocol: {protocol}")

        if structured_fields is None:
            if protocol_key == "ssh":
                structured_fields = vars(parse_ssh_banner(raw_banner))
            elif protocol_key == "ftp":
                structured_fields = vars(parse_ftp_banner_info(raw_banner))
            elif protocol_key == "telnet":
                try:
                    raw_bytes = bytes.fromhex(raw_hex) if raw_hex else raw_banner.encode()
                except ValueError:
                    raw_bytes = raw_banner.encode()
                structured_fields = vars(parse_telnet_banner(raw_bytes, raw_banner))
            elif protocol_key == "redis":
                structured_fields = vars(parse_redis_response("", raw_banner))
            else:
                structured_fields = {}
        result = BannerResult(
            protocol=protocol_key.upper(),
            host="offline",
            port=0,
            accessible=True,
            banner=raw_banner,
            banner_raw_hex=raw_hex,
        )
        if protocol_key == "ssh":
            result.ssh = _dataclass_from(SshBanner, structured_fields)
        elif protocol_key == "ftp":
            result.ftp = _dataclass_from(FtpFeatures, structured_fields)
        elif protocol_key == "telnet":
            result.telnet = _dataclass_from(TelnetBanner, structured_fields)
        elif protocol_key == "redis":
            result.redis = _dataclass_from(RedisInfo, structured_fields)
        elif protocol_key == "mysql":
            result.mysql = _dataclass_from(MysqlInfo, structured_fields)
        elif protocol_key == "pgsql":
            result.pgsql = _dataclass_from(PgsqlInfo, structured_fields)

        preview = raw_banner[:1024] or raw_hex[:2048]
        result.evidence_trace.append(EvidenceStep(
            operation="offline_evidence",
            direction="input",
            byte_count=(
                len(raw_banner.encode("utf-8", errors="replace"))
                if raw_banner else len(raw_hex) // 2
            ),
            preview=preview,
        ))
        prepare_protocol_status(result)
        if result.protocol_status != "mismatch":
            self.matcher.match(result)
            self.database_matcher.match(result)
            confirm_protocol_from_fingerprint(result)
        result.info = extract_banner_info(result)
        return result


@lru_cache(maxsize=1)
def _default_identifier() -> OfflineIdentifier:
    return OfflineIdentifier.load_default()


def identify(protocol: str, raw_banner: str = "",
             structured_fields: Optional[dict[str, Any]] = None,
             raw_hex: str = "") -> BannerResult:
    """Convenience wrapper for internal tests and rule-review tooling."""
    return _default_identifier().identify(
        protocol=protocol,
        raw_banner=raw_banner,
        structured_fields=structured_fields,
        raw_hex=raw_hex,
    )
