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
from typing import Any

from ..core.engine import ProbeEngine
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
                           authorization_confirmed: bool = False,
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
            authorization_confirmed=authorization_confirmed,
        )
        try:
            self._rate_limiter.check()
            request = validate_probe_request(
                hosts=hosts,
                protocols=protocols,
                concurrency=concurrency,
                retries=retries,
                detail_level=detail_level,
                authorization_confirmed=authorization_confirmed,
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
                         authorization_confirmed: bool = False,
                         transport: str = "unknown") -> dict[str, Any]:
        request_id = new_request_id()
        concurrency = (
            self.limits.scan_batch_default_concurrency
            if concurrency is None else concurrency
        )
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
            authorization_confirmed=authorization_confirmed,
        )
        try:
            self._rate_limiter.check()
            hosts = self._decode_hosts(hosts, compressed_hosts)
            request = validate_probe_request(
                hosts=hosts,
                protocols=[protocol],
                concurrency=concurrency,
                retries=retries,
                detail_level=detail_level,
                authorization_confirmed=authorization_confirmed,
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
            await self._validate_resolved_targets(request.hosts)
            return await self._run_probe(
                request_id=request_id,
                tool=tool,
                request=request,
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
                         transport: str) -> dict[str, Any]:
        started = time.monotonic()
        host_results = await self.engine.probe_hosts(
            request.hosts,
            protocols=request.protocols,
            concurrency=request.concurrency,
            max_retries=request.retries,
            global_semaphore=self._global_budget,
        )

        banner_results = [
            result
            for host_result in host_results
            for result in host_result.results.values()
        ]
        elapsed_ms = (time.monotonic() - started) * 1000
        request_id = audit_probe(
            request_id=request_id,
            tool=tool,
            transport=transport,
            target_count=len(request.hosts),
            protocols=request.protocols,
            authorization_confirmed=True,
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

    async def _validate_resolved_targets(self, hosts: list[str]) -> None:
        restrictive = (
            self.target_policy.allowlist_enabled
            or bool(self.target_policy.denylist)
            or self.target_policy.private_network_policy != "allow"
        )
        if not restrictive:
            return
        loop = asyncio.get_running_loop()
        for host in hosts:
            try:
                ipaddress.ip_address(host)
                continue
            except ValueError:
                pass
            records = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            addresses = {
                ipaddress.ip_address(record[4][0])
                for record in records
            }
            if not addresses:
                raise ValueError(f"Domain did not resolve to an address: {host}")
            for address in addresses:
                self.target_policy.validate_address(address)
