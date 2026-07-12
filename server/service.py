"""Transport-independent MCP tool implementation."""

from __future__ import annotations

import asyncio
import base64
import json
import ipaddress
import logging
import socket
import time
import zlib
from dataclasses import dataclass, field
from typing import Any

from ..core.engine import ProbeEngine
from ..core.models import BannerResult
from .audit import audit_probe, audit_tool_rejection, audit_tool_request, new_request_id
from .policy import (
    RateLimiter,
    RequestValidationError,
    RuntimeLimits,
    TargetPolicy,
    validate_probe_request,
)
from .serialization import banner_result_to_dict


logger = logging.getLogger("banner_scanner.mcp")


_DEFAULT_PORTS = {
    "ssh": [22],
    "ftp": [21, 990],
    "telnet": [23],
    "redis": [6379],
    "mysql": [3306],
    "pgsql": [5432],
}


@dataclass
class ResolvedTarget:
    """One caller target and its ordered, policy-checked IP candidates."""

    input_host: str
    resolved_ips: list[str]
    allowed_ips: list[str]
    policy_attempts: list[dict[str, str]] = field(default_factory=list)


class BannerScannerService:
    """Business layer shared by stdio, Streamable HTTP, and legacy SSE."""

    def __init__(self, engine: ProbeEngine | None = None,
                 limits: RuntimeLimits | None = None,
                 target_policy: TargetPolicy | None = None):
        self.engine = engine or ProbeEngine()
        self.limits = limits or RuntimeLimits()
        self.target_policy = target_policy or TargetPolicy.from_env()
        self._global_budget = asyncio.Semaphore(self.limits.global_max_concurrency)
        self._rate_limiter = RateLimiter(self.limits.max_requests_per_minute)

    async def probe_banner(self, *, hosts: list[str], protocols: list[str] | None = None,
                           retries: int = 2, concurrency: int | None = None,
                           detail_level: str = "evidence",
                           transport: str = "unknown") -> dict[str, Any]:
        request_id = new_request_id()
        concurrency = (
            self.limits.probe_banner_default_concurrency
            if concurrency is None else concurrency
        )
        audit_tool_request(
            request_id=request_id,
            tool="probe_banner",
            transport=transport,
            hosts=hosts,
            compressed_hosts_present=False,
            protocols=protocols,
            retries=retries,
            concurrency=concurrency,
            detail_level=detail_level,
            result_mode="full",
        )
        try:
            self._rate_limiter.check()
            request = validate_probe_request(
                hosts=hosts,
                protocols=protocols,
                concurrency=concurrency,
                retries=retries,
                detail_level=detail_level,
                batch=False,
                limits=self.limits,
                target_policy=self.target_policy,
            )
            return await self._execute_request(
                request_id=request_id,
                tool="probe_banner",
                request=request,
                transport=transport,
            )
        except RequestValidationError as exc:
            audit_tool_rejection(
                request_id=request_id, tool="probe_banner", transport=transport,
                code="request_validation_error", error=exc,
            )
            raise
        except TimeoutError as exc:
            audit_tool_rejection(
                request_id=request_id, tool="probe_banner", transport=transport,
                code="request_timeout", error=exc,
            )
            raise

    async def scan_batch(self, *, hosts: list[str] | None = None,
                         compressed_hosts: str | None = None,
                         protocol: str = "ssh",
                         retries: int = 2, concurrency: int | None = None,
                         detail_level: str = "summary",
                         result_mode: str = "full",
                         transport: str = "unknown") -> dict[str, Any]:
        request_id = new_request_id()
        concurrency = (
            self.limits.scan_batch_default_concurrency
            if concurrency is None else concurrency
        )
        raw_hosts = hosts
        audit_logged = False
        try:
            self._rate_limiter.check()
            hosts = self._decode_hosts(hosts, compressed_hosts)
            audit_tool_request(
                request_id=request_id,
                tool="scan_batch",
                transport=transport,
                hosts=hosts,
                compressed_hosts_present=bool(compressed_hosts),
                protocols=[protocol],
                retries=retries,
                concurrency=concurrency,
                detail_level=detail_level,
                result_mode=result_mode,
            )
            audit_logged = True
            request = validate_probe_request(
                hosts=hosts,
                protocols=[protocol],
                concurrency=concurrency,
                retries=retries,
                detail_level=detail_level,
                batch=True,
                limits=self.limits,
                target_policy=self.target_policy,
                result_mode=result_mode,
            )
            return await self._execute_request(
                request_id=request_id,
                tool="scan_batch",
                request=request,
                transport=transport,
            )
        except RequestValidationError as exc:
            # A malformed compressed host list has no safely decodable targets,
            # but every rejected call should still leave an audit trail.
            if not audit_logged:
                audit_tool_request(
                    request_id=request_id,
                    tool="scan_batch",
                    transport=transport,
                    hosts=raw_hosts,
                    compressed_hosts_present=bool(compressed_hosts),
                    protocols=[protocol],
                    retries=retries,
                    concurrency=concurrency,
                    detail_level=detail_level,
                    result_mode=result_mode,
                )
            audit_tool_rejection(
                request_id=request_id, tool="scan_batch", transport=transport,
                code="request_validation_error", error=exc,
            )
            raise
        except TimeoutError as exc:
            audit_tool_rejection(
                request_id=request_id, tool="scan_batch", transport=transport,
                code="request_timeout", error=exc,
            )
            raise

    @staticmethod
    def _decode_hosts(hosts: list[str] | None,
                      compressed_hosts: str | None) -> list[str]:
        """Decode a bounded gzip+base64 JSON host list for agent batch calls."""
        if compressed_hosts:
            if hosts:
                raise RequestValidationError(
                    "use hosts or compressed_hosts, not both"
                )
            try:
                compressed = base64.b64decode(compressed_hosts, validate=True)
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                raw = decoder.decompress(compressed, 32769)
                if len(raw) > 32768 or decoder.unconsumed_tail or not decoder.eof:
                    raise ValueError("decompressed host list is too large")
                decoded = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError,
                    zlib.error) as exc:
                raise RequestValidationError(
                    "compressed_hosts must be gzip+base64 encoded JSON"
                ) from exc
            if not isinstance(decoded, list) or not all(
                isinstance(host, str) for host in decoded
            ):
                raise RequestValidationError(
                    "compressed_hosts must decode to an array of host strings"
                )
            return decoded
        return hosts or []

    async def _execute_request(self, *, request_id: str, tool: str, request,
                               transport: str) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            targets = await self._resolve_targets(request.hosts)
            return await self._run_probe(
                request_id=request_id,
                tool=tool,
                request=request,
                targets=targets,
                transport=transport,
            )

        try:
            return await asyncio.wait_for(
                operation(), timeout=self.limits.request_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"MCP probe request exceeded "
                f"{self.limits.request_timeout_seconds:g} seconds"
            ) from exc

    async def _run_probe(self, *, request_id: str, tool: str, request,
                         targets: list[ResolvedTarget], transport: str) -> dict[str, Any]:
        started = time.monotonic()
        semaphore = asyncio.Semaphore(request.concurrency)

        async def probe_target(target: ResolvedTarget) -> list[BannerResult]:
            async with semaphore:
                async with self._global_budget:
                    return await self._probe_target(target, request.protocols, request.retries)

        target_results = await asyncio.gather(*(probe_target(target) for target in targets))
        banner_results = [result for results in target_results for result in results]
        elapsed_ms = (time.monotonic() - started) * 1000
        request_id = audit_probe(
            request_id=request_id,
            tool=tool,
            transport=transport,
            target_count=len(request.hosts),
            protocols=request.protocols,
            results=banner_results,
            elapsed_ms=elapsed_ms,
        )
        output = [
            banner_result_to_dict(
                result,
                detail_level=request.detail_level,
                banner_limit=self.limits.max_banner_preview_bytes,
                evidence_preview_limit=self.limits.max_evidence_preview_bytes,
            )
            for result in banner_results
        ]
        payload = {
            "request_id": request_id,
            "tool": tool,
            "total_hosts": len(request.hosts),
            "total_results": len(output),
            "connected": sum(item["network_status"] == "connected" for item in output),
            "identified": sum(
                item["identification_status"] == "identified" for item in output
            ),
            "conflicts": sum(
                item["identification_status"] == "conflict" for item in output
            ),
            "elapsed_ms": round(elapsed_ms, 1),
            "result_mode": request.result_mode,
        }
        if request.result_mode == "unique":
            payload["unique_results"] = self._unique_results(output)
            payload["returned_results"] = len(payload["unique_results"])
        else:
            payload["results"] = output
            payload["returned_results"] = len(output)
        return payload

    async def _probe_target(self, target: ResolvedTarget, protocols: list[str],
                            retries: int) -> list[BannerResult]:
        return [
            await self._probe_protocol_with_fallback(target, protocol, retries)
            for protocol in protocols
        ]

    def _ports_for_protocol(self, protocol: str) -> list[int]:
        config = getattr(self.engine, "config", None)
        protocol_config = getattr(config, "protocol_config", {}).get(protocol)
        if protocol_config and protocol_config.ports:
            return list(protocol_config.ports)
        return list(_DEFAULT_PORTS[protocol])

    @staticmethod
    def _attempt_status(result: BannerResult) -> str:
        if result.accessible:
            return "connected" if not result.error else "connected_without_banner"
        error = result.error.casefold()
        if "timed out" in error or "timeout" in error:
            return "timeout"
        if "refused" in error:
            return "refused"
        return "unreachable"

    @staticmethod
    def _attach_resolution(result: BannerResult, target: ResolvedTarget,
                           attempts: list[dict[str, Any]], selected_ip: str) -> BannerResult:
        result.input_host = target.input_host
        result.resolved_ips = list(target.resolved_ips)
        result.attempted_ips = attempts
        result.resolved_ip = result.host
        result.selected_ip = selected_ip
        return result

    async def _probe_protocol_with_fallback(self, target: ResolvedTarget,
                                            protocol: str, retries: int) -> BannerResult:
        attempts: list[dict[str, Any]] = [dict(item) for item in target.policy_attempts]
        last_result: BannerResult | None = None
        for address in target.allowed_ips:
            for port in self._ports_for_protocol(protocol):
                result = await self.engine.probe_single(
                    address, port, protocol, max_retries=retries,
                )
                attempts.append({
                    "ip": address,
                    "port": port,
                    "status": self._attempt_status(result),
                    **({"error": result.error} if result.error else {}),
                })
                last_result = result
                # A TCP connection with no usable protocol response is not a
                # useful Banner result, so the next candidate should be tried.
                if result.accessible and not result.error:
                    return self._attach_resolution(result, target, attempts, address)

        if last_result is None:
            last_result = BannerResult(
                protocol=protocol.upper(),
                host=target.input_host,
                port=self._ports_for_protocol(protocol)[0],
                error="No resolved address is permitted by the server policy",
            )
        return self._attach_resolution(last_result, target, attempts, "")

    @staticmethod
    def _unique_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Group equivalent outcomes while keeping one inspectable representative."""
        grouped: dict[tuple, dict[str, Any]] = {}
        for result in results:
            primary = result.get("primary_identification") or {}
            error = result.get("error") or {}
            candidate_names = tuple(sorted(
                candidate.get("name", "")
                for candidate in result.get("candidates", [])
            ))
            signature = (
                result.get("network_status", ""),
                result.get("protocol_status", ""),
                result.get("identification_status", ""),
                result.get("expected_protocol", ""),
                result.get("observed_protocol", ""),
                primary.get("result_type", ""),
                primary.get("name", ""),
                error.get("code", ""),
                candidate_names,
            )
            host = result.get("endpoint", {}).get("host", "")
            group = grouped.get(signature)
            if group is None:
                grouped[signature] = {
                    "occurrences": 1,
                    "sample_hosts": [host] if host else [],
                    "representative": result,
                }
            else:
                group["occurrences"] += 1
                if host and len(group["sample_hosts"]) < 3:
                    group["sample_hosts"].append(host)
        return list(grouped.values())

    async def health_check(self) -> dict[str, Any]:
        logger.info("MCP health_check request received")
        health = await self.engine.health_check()
        text_rules = {
            str(protocol).lower(): count
            for protocol, count in health.get("fingerprint_rules_by_protocol", {}).items()
        }
        database_rules = {
            str(protocol).lower(): count
            for protocol, count in health.get("config", {}).get(
                "database_fingerprint_rules_by_protocol", {}
            ).items()
        }
        response = {
            "service": "ok" if health.get("healthy") else "degraded",
            "mcp_transport": ["stdio", "streamable_http", "sse"],
            "rules": {
                **text_rules,
                **database_rules,
            },
            "limits": self.limits.to_dict(),
            "network_access": {
                "active_probe_enabled": True,
                **self.target_policy.to_dict(),
            },
            "engine": {
                "total_probes": health.get("total_probes", 0),
                "total_errors": health.get("total_errors", 0),
                "error_rate_pct": health.get("error_rate_pct", 0.0),
            },
        }
        logger.info("MCP health_check response ready")
        return response

    async def _lookup_addresses(self, host: str) -> list[str]:
        loop = asyncio.get_running_loop()
        try:
            records = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise RequestValidationError(f"Domain did not resolve to an address: {host}") from exc
        addresses: list[str] = []
        for record in records:
            address = str(ipaddress.ip_address(record[4][0]))
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise RequestValidationError(f"Domain did not resolve to an address: {host}")
        return addresses

    async def _resolve_targets(self, hosts: list[str]) -> list[ResolvedTarget]:
        targets: list[ResolvedTarget] = []
        for host in hosts:
            try:
                address = str(ipaddress.ip_address(host))
            except ValueError:
                addresses = await self._lookup_addresses(host)
                if len(addresses) > self.limits.max_resolved_ips_per_host:
                    raise RequestValidationError(
                        f"Domain resolves to more than {self.limits.max_resolved_ips_per_host} addresses: {host}"
                    )
                allowed: list[str] = []
                policy_attempts: list[dict[str, str]] = []
                for value in addresses:
                    try:
                        self.target_policy.validate_address(ipaddress.ip_address(value))
                    except RequestValidationError as exc:
                        policy_attempts.append({
                            "ip": value,
                            "status": "policy_rejected",
                            "error": str(exc),
                        })
                    else:
                        allowed.append(value)
                if not allowed:
                    raise RequestValidationError(
                        f"No resolved address is permitted by the server policy: {host}"
                    )
                targets.append(ResolvedTarget(
                    input_host=host,
                    resolved_ips=addresses,
                    allowed_ips=allowed,
                    policy_attempts=policy_attempts,
                ))
            else:
                targets.append(ResolvedTarget(
                    input_host=address,
                    resolved_ips=[address],
                    allowed_ips=[address],
                ))
        return targets
