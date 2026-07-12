"""Single MCP result serializer shared by every transport."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ..core.models import BannerResult


def _network_status(result: BannerResult) -> str:
    if result.accessible:
        return "connected"
    if result.failure is not None:
        mapping = {
            "tcp_connect_timeout": "timeout",
            "protocol_read_timeout": "timeout",
            "tls_handshake_timeout": "timeout",
            "tcp_connection_refused": "refused",
            "dns_resolution_failed": "dns_error",
            "request_cancelled": "cancelled",
        }
        return mapping.get(result.failure.detail_code, "unreachable")
    error = result.error.casefold()
    if "timed out" in error or "timeout" in error:
        return "timeout"
    if "refused" in error:
        return "refused"
    if "name or service" in error or "nodename" in error or "dns" in error:
        return "dns_error"
    if "cancel" in error:
        return "cancelled"
    return "unreachable"


def _protocol_status(result: BannerResult) -> str:
    if result.protocol_status in {"confirmed", "observed", "mismatch"}:
        return result.protocol_status
    if not result.accessible:
        return "not_observed"
    details = result.fingerprint_details or {}
    if result.protocol.upper() in {"REDIS", "MYSQL", "PGSQL"}:
        return "confirmed" if details.get("protocol_match") else "observed"
    if result.banner or result.banner_raw_hex:
        return "confirmed"
    return "observed"


def _error_code(result: BannerResult) -> str:
    if result.failure is not None:
        mapping = {
            "tcp_connect_timeout": "probe_timeout",
            "protocol_read_timeout": "probe_timeout",
            "tls_handshake_timeout": "probe_timeout",
            "tcp_connection_refused": "connection_refused",
            "dns_resolution_failed": "dns_error",
            "request_cancelled": "request_cancelled",
        }
        return mapping.get(result.failure.detail_code, "network_error")
    status = _network_status(result)
    mapping = {
        "timeout": "probe_timeout",
        "refused": "connection_refused",
        "dns_error": "dns_error",
        "cancelled": "request_cancelled",
        "unreachable": "network_error",
    }
    return mapping.get(status, "")


def _fallback_error_phase(result: BannerResult) -> str:
    """Classify legacy string-only errors without overstating certainty."""
    error = result.error.casefold()
    code = _error_code(result)
    if code == "dns_error":
        return "dns_resolution"
    if "read" in error:
        return "read"
    if "connection closed" in error or "banner" in error:
        return "protocol_probe"
    if code in {"probe_timeout", "connection_refused"} or "connect" in error:
        return "connect"
    if "unexpected" in error or "probe failed" in error:
        return "internal"
    return "protocol_probe" if result.accessible else "internal"


def _protocol_observations(result: BannerResult) -> dict[str, Any]:
    if result.ssh:
        return {"ssh": asdict(result.ssh)}
    if result.ftp:
        return {"ftp": asdict(result.ftp)}
    if result.telnet:
        return {"telnet": asdict(result.telnet)}
    if result.redis:
        return {"redis": asdict(result.redis)}
    if result.mysql:
        return {"mysql": asdict(result.mysql)}
    if result.pgsql:
        return {"pgsql": asdict(result.pgsql)}
    return {}


def _summary_protocol_observations(result: BannerResult) -> dict[str, Any]:
    if result.ssh:
        return {"ssh": {
            "protocol_version": result.ssh.protocol_version,
            "software": result.ssh.software,
            "version": result.ssh.version,
            "os_type": result.ssh.os_type,
            "os_version": result.ssh.os_version,
        }}
    if result.ftp:
        return {"ftp": {
            "software": result.ftp.software,
            "version": result.ftp.version,
            "utf8": result.ftp.utf8,
            "auth_tls": result.ftp.auth_tls,
            "auth_ssl": result.ftp.auth_ssl,
        }}
    if result.telnet:
        return {"telnet": {
            "detected_service": result.telnet.detected_service,
            "has_login_prompt": result.telnet.has_login_prompt,
            "has_iac_negotiation": result.telnet.has_iac_negotiation,
        }}
    if result.redis:
        return {"redis": {
            "implementation": result.redis.implementation,
            "version": result.redis.version,
            "mode": result.redis.mode,
            "os": result.redis.os,
        }}
    if result.mysql:
        return {"mysql": {
            "protocol_version": result.mysql.protocol_version,
            "version": result.mysql.version,
            "capability_flags": result.mysql.capability_flags,
            "character_set": result.mysql.character_set,
            "auth_plugin": result.mysql.auth_plugin,
            "implementation": result.mysql.implementation,
            "error_code": result.mysql.error_code,
            "sqlstate": result.mysql.sqlstate,
        }}
    if result.pgsql:
        return {"pgsql": {
            "protocol_version": result.pgsql.protocol_version,
            "ssl_response": result.pgsql.ssl_response,
            "auth_method": result.pgsql.auth_method,
            "implementation": result.pgsql.implementation,
            "server_version": result.pgsql.parameters.get("server_version", ""),
            "sqlstate": (
                result.pgsql.fields.get("sqlstate", "")
                or result.pgsql.fields.get("C", "")
            ),
            "message_types": result.pgsql.message_types,
        }}
    return {}


def banner_result_to_dict(result: BannerResult, *, detail_level: str = "evidence",
                          banner_limit: int = 4096,
                          evidence_preview_limit: int = 1024) -> dict[str, Any]:
    """Serialize semantic results without exposing regexes or rule-hit lists."""
    payload: dict[str, Any] = {
        "network_status": _network_status(result),
        "protocol_status": _protocol_status(result),
        "identification_status": result.identification_status,
        "endpoint": {
            "host": result.input_host or result.host,
            "port": result.port,
            "protocol": result.protocol,
        },
        "response_time_ms": round(result.response_time_ms, 1),
        "primary_identification": (
            asdict(result.primary_identification)
            if result.primary_identification is not None else None
        ),
    }
    if result.resolved_ip:
        payload["endpoint"]["resolved_ip"] = result.resolved_ip
    if result.input_host or result.resolved_ips or result.attempted_ips:
        payload["target_resolution"] = {
            "input_host": result.input_host or result.host,
            "resolved_ips": result.resolved_ips or [result.resolved_ip or result.host],
            "attempted_ips": result.attempted_ips,
            "selected_ip": result.selected_ip,
        }
    if _protocol_status(result) == "mismatch":
        payload["expected_protocol"] = result.protocol.upper()
        payload["observed_protocol"] = result.observed_protocol
    if result.identification_status == "conflict":
        payload["candidates"] = [asdict(item) for item in result.identification_candidates]
    if result.error:
        error: dict[str, Any] = {
            "code": _error_code(result),
            "message": result.error,
        }
        if result.failure is not None:
            error.update({
                "phase": result.failure.phase,
                "detail_code": result.failure.detail_code,
                "elapsed_ms": round(result.failure.elapsed_ms, 1),
            })
            if result.failure.os_error is not None:
                error["os_error"] = result.failure.os_error
            if result.failure.context:
                error["context"] = result.failure.context
        else:
            error["phase"] = _fallback_error_phase(result)
        if result.retry_attempts > 1 or result.retry_history:
            error["retry_summary"] = {
                "attempts": result.retry_attempts,
                "total_elapsed_ms": round(result.retry_elapsed_ms, 1),
            }
            if detail_level == "evidence" and result.retry_history:
                error["attempt_history"] = result.retry_history[:6]
        payload["error"] = error

    observations: dict[str, Any] = {}
    if detail_level == "evidence":
        observations["banner"] = result.banner[:banner_limit]
        observations["banner_truncated"] = (
            result.banner_truncated or len(result.banner) > banner_limit
        )
        if result.banner_raw_hex:
            observations["raw_hex_preview"] = result.banner_raw_hex[:banner_limit * 2]
        observations.update(_protocol_observations(result))
        payload["evidence_trace"] = [
            {
                **asdict(step),
                "preview": step.preview[:evidence_preview_limit],
            }
            for step in result.evidence_trace
        ]
    else:
        observations.update(_summary_protocol_observations(result))
    if observations:
        payload["observations"] = observations
    if result.findings:
        payload["findings"] = result.findings
    if result.retry_count:
        payload["retries"] = result.retry_count
    return payload
