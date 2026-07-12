"""Transport-independent MCP service tests."""

import asyncio
import base64
import gzip
import ipaddress
import json

from banner_scanner.core.models import BannerResult, HostResult
from banner_scanner.server.policy import RequestValidationError, RuntimeLimits, TargetPolicy
from banner_scanner.server.service import BannerScannerService


class FakeEngine:
    def __init__(self):
        self.last_call = None
        self.calls = []

    async def probe_single(self, host, port, protocol, max_retries=None):
        self.last_call = {
            "host": host,
            "port": port,
            "protocol": protocol,
            "max_retries": max_retries,
        }
        self.calls.append(self.last_call)
        return BannerResult(
            protocol=protocol.upper(),
            host=host,
            port=port,
            accessible=True,
            banner="SSH-2.0-Test",
        )

    async def health_check(self):
        return {
            "healthy": True,
            "total_probes": 0,
            "total_errors": 0,
            "error_rate_pct": 0.0,
            "fingerprint_rules_by_protocol": {"SSH": 56},
            "config": {
                "database_fingerprint_rules": 61,
                "database_fingerprint_rules_by_protocol": {
                    "REDIS": 24,
                    "MYSQL": 16,
                    "PGSQL": 21,
                },
            },
        }


async def test_service_denylist_overrides_authorization_before_probe():
    engine = FakeEngine()
    service = BannerScannerService(
        engine=engine,
        target_policy=TargetPolicy(
            denylist=(ipaddress.ip_network("1.2.3.4/32"),),
        ),
    )

    try:
        await service.scan_batch(
            hosts=["1.2.3.4"],
            protocol="ssh",
            transport="sse",
        )
        assert False, "Expected denylist failure"
    except RequestValidationError as exc:
        assert "denied by server policy" in str(exc)
    assert engine.last_call is None


async def test_service_uses_tool_defaults_and_structured_output():
    engine = FakeEngine()
    service = BannerScannerService(engine=engine, target_policy=TargetPolicy())
    output = await service.probe_banner(
        hosts=["192.0.2.1"],
        protocols=["ssh"],
        transport="stdio",
    )

    assert engine.last_call["max_retries"] == 2
    assert engine.last_call["host"] == "192.0.2.1"
    assert output["connected"] == 1
    assert output["results"][0]["network_status"] == "connected"
    assert "matched_rules" not in str(output)


async def test_scan_batch_unique_mode_groups_equivalent_results():
    engine = FakeEngine()
    service = BannerScannerService(engine=engine, target_policy=TargetPolicy())
    output = await service.scan_batch(
        hosts=["192.0.2.1", "192.0.2.2"],
        protocol="ssh",
        result_mode="unique",
    )

    assert output["total_hosts"] == 2
    assert output["total_results"] == 2
    assert output["returned_results"] == 1
    assert "results" not in output
    assert output["unique_results"][0]["occurrences"] == 2
    assert output["unique_results"][0]["sample_hosts"] == [
        "192.0.2.1", "192.0.2.2",
    ]


async def test_scan_batch_accepts_compressed_host_list():
    engine = FakeEngine()
    service = BannerScannerService(engine=engine, target_policy=TargetPolicy())
    encoded = base64.b64encode(gzip.compress(json.dumps([
        "192.0.2.1", "192.0.2.2",
    ]).encode("utf-8"))).decode("ascii")

    output = await service.scan_batch(
        compressed_hosts=encoded,
        protocol="ssh",
        result_mode="unique",
    )

    assert output["total_hosts"] == 2
    assert [call["host"] for call in engine.calls] == ["192.0.2.1", "192.0.2.2"]


async def test_health_check_reports_transports_rules_and_limits():
    limits = RuntimeLimits(scan_batch_max_hosts=99)
    service = BannerScannerService(
        engine=FakeEngine(), limits=limits, target_policy=TargetPolicy(),
    )
    health = await service.health_check()

    assert health["mcp_transport"] == ["stdio", "streamable_http", "sse"]
    assert health["rules"]["ssh"] == 56
    assert health["rules"]["redis"] == 24
    assert health["rules"]["mysql"] == 16
    assert health["rules"]["pgsql"] == 21
    assert health["limits"]["scan_batch_max_hosts"] == 99


async def test_request_timeout_covers_target_resolution():
    engine = FakeEngine()
    service = BannerScannerService(
        engine=engine,
        limits=RuntimeLimits(request_timeout_seconds=0.01),
        target_policy=TargetPolicy(),
    )

    async def slow_resolution(_hosts):
        await asyncio.sleep(1)

    service._resolve_targets = slow_resolution
    try:
        await service.probe_banner(
            hosts=["192.0.2.1"],
            protocols=["ssh"],
        )
        assert False, "Expected request timeout"
    except TimeoutError as exc:
        assert "exceeded" in str(exc)
    assert engine.last_call is None


async def test_domain_uses_ordered_ip_fallback_and_reports_resolution():
    class FallbackEngine(FakeEngine):
        async def probe_single(self, host, port, protocol, max_retries=None):
            self.last_call = {
                "host": host, "port": port, "protocol": protocol,
                "max_retries": max_retries,
            }
            self.calls.append(self.last_call)
            if host == "203.0.113.10":
                return BannerResult(
                    protocol="SSH", host=host, port=port,
                    error=f"connect to {host}:{port} timed out",
                )
            return BannerResult(
                protocol="SSH", host=host, port=port,
                accessible=True, banner="SSH-2.0-Test",
            )

    engine = FallbackEngine()
    service = BannerScannerService(engine=engine, target_policy=TargetPolicy())

    async def lookup(_host):
        return ["203.0.113.10", "203.0.113.11"]

    service._lookup_addresses = lookup
    output = await service.probe_banner(
        hosts=["ftp.example.test"], protocols=["ssh"], retries=0,
    )

    result = output["results"][0]
    assert [call["host"] for call in engine.calls] == ["203.0.113.10", "203.0.113.11"]
    assert result["endpoint"] == {
        "host": "ftp.example.test",
        "resolved_ip": "203.0.113.11",
        "port": 22,
        "protocol": "SSH",
    }
    assert result["target_resolution"] == {
        "input_host": "ftp.example.test",
        "resolved_ips": ["203.0.113.10", "203.0.113.11"],
        "attempted_ips": [
            {
                "ip": "203.0.113.10", "port": 22, "status": "timeout",
                "error": "connect to 203.0.113.10:22 timed out",
            },
            {"ip": "203.0.113.11", "port": 22, "status": "connected"},
        ],
        "selected_ip": "203.0.113.11",
    }


async def test_domain_skips_policy_rejected_addresses_and_uses_allowed_candidate():
    engine = FakeEngine()
    service = BannerScannerService(
        engine=engine,
        target_policy=TargetPolicy(
            allowlist=(ipaddress.ip_network("203.0.113.0/24"),),
        ),
    )

    async def lookup(_host):
        return ["198.51.100.10", "203.0.113.20"]

    service._lookup_addresses = lookup
    output = await service.probe_banner(
        hosts=["mixed.example.test"], protocols=["ssh"], retries=0,
    )

    result = output["results"][0]
    assert [call["host"] for call in engine.calls] == ["203.0.113.20"]
    assert result["target_resolution"]["attempted_ips"][0]["status"] == "policy_rejected"
    assert result["target_resolution"]["selected_ip"] == "203.0.113.20"


async def test_domain_resolution_limit_rejects_before_any_probe():
    engine = FakeEngine()
    service = BannerScannerService(
        engine=engine,
        limits=RuntimeLimits(max_resolved_ips_per_host=1),
        target_policy=TargetPolicy(),
    )

    async def lookup(_host):
        return ["203.0.113.10", "203.0.113.11"]

    service._lookup_addresses = lookup
    try:
        await service.probe_banner(
            hosts=["many.example.test"], protocols=["ssh"],
        )
        assert False, "Expected resolved-address limit failure"
    except RequestValidationError as exc:
        assert "more than 1 addresses" in str(exc)
    assert engine.last_call is None
