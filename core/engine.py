"""核心探测引擎。"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Optional

from .models import BannerResult, HostResult, ProbeConfig
from .matcher import FingerprintMatcher
from ..probes import PROTOCOL_PROBES
from ..probes.ssh import probe_ssh
from ..probes.ftp import probe_ftp
from ..probes.telnet import probe_telnet

logger = logging.getLogger("banner_scanner.engine")


class ProbeEngine:
    """探测引擎"""

    def __init__(self, config: Optional[ProbeConfig] = None):
        self.config = config or ProbeConfig()
        self._total_probes = 0
        self._total_errors = 0
        self._start_time = time.time()

        # 可选挂载指纹匹配器
        self._matcher: Optional[FingerprintMatcher] = None
        if self.config.fingerprint_path:
            fp_path = Path(self.config.fingerprint_path)
            if fp_path.exists():
                self._matcher = FingerprintMatcher.load(fp_path)
                logger.info(
                    "Fingerprint matcher loaded (%d rules from %s)",
                    self._matcher.rule_count, fp_path,
                )

    async def probe_host(
        self,
        host: str,
        protocols: Optional[list[str]] = None,
    ) -> HostResult:
        if protocols is None:
            protocols = list(PROTOCOL_PROBES.keys())

        start = time.time()
        results: dict[str, BannerResult] = {}

        for proto in protocols:
            probe_fn = PROTOCOL_PROBES.get(proto)
            if probe_fn is None:
                continue
            ports = self._get_ports(proto)
            for port in ports:
                try:
                    result = await probe_fn(host, port=port, config=self.config)
                    results[proto] = result
                    self._total_probes += 1
                    if not result.accessible:
                        self._total_errors += 1
                except Exception as e:
                    results[proto] = BannerResult(
                        protocol=proto.upper(), host=host, port=port,
                        error=f"Probe failed: {e}",
                    )
                    self._total_errors += 1

        # 指纹匹配
        if self._matcher is not None:
            for br in results.values():
                self._matcher.match(br)

        total_time = (time.time() - start) * 1000
        return HostResult(host=host, results=results, total_time_ms=total_time)

    async def probe_hosts(
        self,
        hosts: list[str],
        protocols: Optional[list[str]] = None,
    ) -> list[HostResult]:
        results = []
        for host in hosts:
            result = await self.probe_host(host, protocols)
            results.append(result)
        return results

    async def health_check(self) -> dict:
        return {
            "healthy": True,
            "total_probes": self._total_probes,
            "total_errors": self._total_errors,
            "error_rate_pct": round(
                (self._total_errors / max(self._total_probes, 1)) * 100, 2
            ),
            "config": {
                "connect_timeout": self.config.connect_timeout,
                "read_timeout": self.config.read_timeout,
                "max_banner_bytes": self.config.max_banner_bytes,
                "fingerprint_path": str(self.config.fingerprint_path)
                if self.config.fingerprint_path else None,
            },
        }

    def _get_ports(self, proto: str) -> list[int]:
        cfg = self.config.protocol_config.get(proto)
        return cfg.ports if cfg else [22]


# 便捷方法
_engine: Optional[ProbeEngine] = None


def _get_engine() -> ProbeEngine:
    global _engine
    if _engine is None:
        _engine = ProbeEngine()
    return _engine


async def probe_host(host: str, protocols: Optional[list[str]] = None) -> HostResult:
    return await _get_engine().probe_host(host, protocols)


async def probe_ssh(host: str, port: int = 22) -> BannerResult:
    return await probe_ssh(host, port=port, config=_get_engine().config)


async def probe_ftp(host: str, port: int = 21) -> BannerResult:
    return await probe_ftp(host, port=port, config=_get_engine().config)


async def probe_telnet(host: str, port: int = 23) -> BannerResult:
    return await probe_telnet(host, port=port, config=_get_engine().config)
