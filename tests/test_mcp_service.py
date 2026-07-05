"""Transport-independent MCP service tests."""

import asyncio

from banner_scanner.core.models import BannerResult, HostResult
from banner_scanner.server.policy import RequestValidationError, RuntimeLimits, TargetPolicy
from banner_scanner.server.service import BannerScannerService


class FakeEngine:
    def __init__(self):
        self.last_call = None

    async def probe_hosts(self, hosts, protocols, concurrency, max_retries,
                          global_semaphore):
        self.last_call = {
            "hosts": hosts,
            "protocols": protocols,
            "concurrency": concurrency,
            "max_retries": max_retries,
            "global_semaphore": global_semaphore,
        }
        return [
            HostResult(host=host, results={
                protocols[0]: BannerResult(
                    protocol=protocols[0].upper(),
                    host=host,
                    port=22,
                    accessible=True,
                    banner="SSH-2.0-Test",
                )
            })
            for host in hosts
        ]

    async def health_check(self):
        return {
            "healthy": True,
            "total_probes": 0,
            "total_errors": 0,
            "error_rate_pct": 0.0,
            "fingerprint_rules_by_protocol": {"SSH": 56},
            "config": {
                "database_fingerprint_rules": 59,
                "database_fingerprint_rules_by_protocol": {
                    "REDIS": 24,
                    "MYSQL": 14,
                    "PGSQL": 21,
                },
            },
        }


async def test_service_enforces_authorization_before_probe():
    engine = FakeEngine()
    service = BannerScannerService(engine=engine, target_policy=TargetPolicy())
    try:
        await service.probe_banner(hosts=["192.0.2.1"], authorization_confirmed=False)
        assert False, "Expected authorization failure"
    except RequestValidationError:
        pass
    assert engine.last_call is None


async def test_service_uses_tool_defaults_and_structured_output():
    engine = FakeEngine()
    service = BannerScannerService(engine=engine, target_policy=TargetPolicy())
    output = await service.probe_banner(
        hosts=["192.0.2.1"],
        protocols=["ssh"],
        authorization_confirmed=True,
        transport="stdio",
    )

    assert engine.last_call["concurrency"] == 5
    assert engine.last_call["max_retries"] == 2
    assert output["connected"] == 1
    assert output["results"][0]["network_status"] == "connected"
    assert "matched_rules" not in str(output)


async def test_health_check_reports_transports_rules_and_limits():
    limits = RuntimeLimits(scan_batch_max_hosts=99)
    service = BannerScannerService(
        engine=FakeEngine(), limits=limits, target_policy=TargetPolicy(),
    )
    health = await service.health_check()

    assert health["mcp_transport"] == ["stdio", "streamable_http", "sse"]
    assert health["rules"]["ssh"] == 56
    assert health["rules"]["redis"] == 24
    assert health["rules"]["mysql"] == 14
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

    service._validate_resolved_targets = slow_resolution
    try:
        await service.probe_banner(
            hosts=["192.0.2.1"],
            protocols=["ssh"],
            authorization_confirmed=True,
        )
        assert False, "Expected request timeout"
    except TimeoutError as exc:
        assert "exceeded" in str(exc)
    assert engine.last_call is None
