"""核心探测引擎。"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Optional

from .models import BannerResult, HostResult, ProbeConfig
from .matcher import FingerprintMatcher
from .retry import RetryExecutor, RetryConfig, RETRYABLE_EXCEPTIONS
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
                    result = await self._probe_with_retry(probe_fn, host, port, proto)
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

        # 指纹匹配 + 更新 info
        if self._matcher is not None:
            from .parsers import extract_banner_info
            for br in results.values():
                self._matcher.match(br)
                if br.accessible:
                    br.info = extract_banner_info(br)

        total_time = (time.time() - start) * 1000
        return HostResult(host=host, results=results, total_time_ms=total_time)

    async def probe_single(self, host: str, port: int, protocol: str) -> BannerResult:
        """探测单个 IP:端口:协议（不走端口遍历，直接对指定端口探测）"""
        probe_fn = PROTOCOL_PROBES.get(protocol.lower())
        if probe_fn is None:
            return BannerResult(protocol=protocol.upper(), host=host, port=port,
                                error=f"Unknown protocol: {protocol}")

        try:
            result = await self._probe_with_retry(probe_fn, host, port, protocol)
            self._total_probes += 1
            if not result.accessible:
                self._total_errors += 1
        except Exception as e:
            result = BannerResult(protocol=protocol.upper(), host=host, port=port,
                                  error=f"Probe failed: {e}")
            self._total_errors += 1

        # 指纹匹配 + 更新 info
        if self._matcher is not None:
            from .parsers import extract_banner_info
            self._matcher.match(result)
            if result.accessible:
                result.info = extract_banner_info(result)

        return result

    async def _probe_with_retry(self, probe_fn, host: str, port: int,
                                 proto: str) -> BannerResult:
        """执行单次探测（带重试策略）"""
        if self.config.max_retries < 1:
            return await probe_fn(host, port=port, config=self.config)

        retry_cfg = RetryConfig(
            max_retries=self.config.max_retries,
            base_delay=self.config.retry_base_delay,
        )
        executor = RetryExecutor(retry_cfg)

        try:
            result, retry_result = await executor.execute(
                lambda: probe_fn(host, port=port, config=self.config)
            )
            # 填充重试统计
            result.retry_count = retry_result.total_attempts - 1
            result.retry_attempts = retry_result.total_attempts
            result.retry_elapsed_ms = retry_result.total_elapsed_ms
            return result
        except RETRYABLE_EXCEPTIONS as e:
            # 所有重试耗尽
            retry_result = executor.result
            return BannerResult(
                protocol=proto.upper(), host=host, port=port,
                error=f"All {retry_result.total_attempts} attempts failed: {e}",
                retry_count=retry_result.total_attempts - 1,
                retry_attempts=retry_result.total_attempts,
                retry_elapsed_ms=retry_result.total_elapsed_ms,
            )

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
