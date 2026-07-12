"""核心探测引擎。"""

import asyncio
from collections import Counter
import logging
import time
from pathlib import Path
from typing import Optional

from .models import BannerResult, EvidenceStep, HostResult, ProbeConfig
from .matcher import DEFAULT_PROTOCOL_LIBRARY_DIR, FingerprintMatcher
from .database_matcher import DEFAULT_LIBRARY_DIR, DatabaseFingerprintMatcher
from .retry import RetryExecutor, RetryConfig, RETRYABLE_EXCEPTIONS
from .protocol_detection import confirm_protocol_from_fingerprint, prepare_protocol_status
from ..probes import PROTOCOL_PROBES
from ..probes.ssh import probe_ssh as _probe_ssh
from ..probes.ftp import probe_ftp as _probe_ftp
from ..probes.telnet import probe_telnet as _probe_telnet
from ..probes.redis import probe_redis as _probe_redis
from ..probes.mysql import probe_mysql as _probe_mysql
from ..probes.pgsql import probe_pgsql as _probe_pgsql

logger = logging.getLogger("banner_scanner.engine")


class ProbeEngine:
    """探测引擎"""

    def __init__(self, config: Optional[ProbeConfig] = None):
        self.config = config or ProbeConfig()
        self._total_probes = 0
        self._total_errors = 0
        self._failure_counts: Counter[str] = Counter()
        self._start_time = time.time()

        # 可选挂载指纹匹配器
        self._matcher: Optional[FingerprintMatcher] = None
        fp_path = Path(self.config.fingerprint_path or DEFAULT_PROTOCOL_LIBRARY_DIR)
        if fp_path.exists():
            self._matcher = FingerprintMatcher.load(fp_path)
            self.config.fingerprint_path = str(fp_path)
            logger.info(
                "Fingerprint matcher loaded (%d rules from %s)",
                self._matcher.rule_count, fp_path,
            )
        database_path = self.config.database_fingerprint_path or DEFAULT_LIBRARY_DIR
        self._database_matcher = DatabaseFingerprintMatcher.load_directory(database_path)

    async def probe_host(
        self,
        host: str,
        protocols: Optional[list[str]] = None,
        max_retries: Optional[int] = None,
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
                    result = await self._probe_with_retry(
                        probe_fn, host, port, proto, max_retries=max_retries,
                    )
                    self._total_probes += 1
                    self._record_failure(result)
                    if result.accessible:
                        results[proto] = result
                        break  # 成功则不再尝试其他端口
                    # 失败时仅在没有更早结果时记录
                    if proto not in results:
                        results[proto] = result
                        self._total_errors += 1
                except Exception as e:
                    if proto not in results:
                        results[proto] = BannerResult(
                            protocol=proto.upper(), host=host, port=port,
                            error=f"Probe failed: {e}",
                        )
                        self._total_errors += 1

        # 指纹匹配 + 更新 info
        from .parsers import extract_banner_info
        for br in results.values():
            self._ensure_evidence_trace(br)
            prepare_protocol_status(br)
            if br.protocol_status != "mismatch":
                if self._matcher is not None:
                    self._matcher.match(br)
                self._database_matcher.match(br)
                confirm_protocol_from_fingerprint(br)
            if br.accessible:
                br.info = extract_banner_info(br)

        total_time = (time.time() - start) * 1000
        return HostResult(host=host, results=results, total_time_ms=total_time)

    async def probe_single(self, host: str, port: int, protocol: str,
                           max_retries: Optional[int] = None) -> BannerResult:
        """探测单个 IP:端口:协议（不走端口遍历，直接对指定端口探测）"""
        probe_fn = PROTOCOL_PROBES.get(protocol.lower())
        if probe_fn is None:
            return BannerResult(protocol=protocol.upper(), host=host, port=port,
                                error=f"Unknown protocol: {protocol}")

        try:
            result = await self._probe_with_retry(
                probe_fn, host, port, protocol, max_retries=max_retries,
            )
            self._total_probes += 1
            self._record_failure(result)
            if not result.accessible:
                self._total_errors += 1
        except Exception as e:
            result = BannerResult(protocol=protocol.upper(), host=host, port=port,
                                  error=f"Probe failed: {e}")
            self._total_errors += 1

        # 指纹匹配 + 更新 info
        from .parsers import extract_banner_info
        self._ensure_evidence_trace(result)
        prepare_protocol_status(result)
        if result.protocol_status != "mismatch":
            if self._matcher is not None:
                self._matcher.match(result)
            self._database_matcher.match(result)
            confirm_protocol_from_fingerprint(result)
        if result.accessible:
            result.info = extract_banner_info(result)

        return result

    async def _probe_with_retry(self, probe_fn, host: str, port: int,
                                 proto: str,
                                 max_retries: Optional[int] = None) -> BannerResult:
        """执行单次探测（带重试策略）"""
        retry_limit = self.config.max_retries if max_retries is None else max_retries
        if retry_limit < 1:
            return await probe_fn(host, port=port, config=self.config)

        retry_cfg = RetryConfig(
            max_retries=retry_limit,
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
        concurrency: int = 1,
        max_retries: Optional[int] = None,
        global_semaphore: Optional[asyncio.Semaphore] = None,
    ) -> list[HostResult]:
        """Probe multiple hosts while preserving input order.

        ``concurrency=1`` keeps the original sequential behavior.  Higher
        values are bounded with a semaphore so MCP batch calls and evaluation
        runs can make progress without creating an unbounded number of sockets.
        """
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")

        semaphore = asyncio.Semaphore(concurrency)

        async def probe_one(host: str) -> HostResult:
            async with semaphore:
                if global_semaphore is None:
                    return await self.probe_host(host, protocols, max_retries=max_retries)
                async with global_semaphore:
                    return await self.probe_host(host, protocols, max_retries=max_retries)

        return list(await asyncio.gather(*(probe_one(host) for host in hosts)))

    async def health_check(self) -> dict:
        return {
            "healthy": True,
            "total_probes": self._total_probes,
            "total_errors": self._total_errors,
            "error_rate_pct": round(
                (self._total_errors / max(self._total_probes, 1)) * 100, 2
            ),
            "failure_counts": dict(sorted(self._failure_counts.items())),
            "config": {
                "connect_timeout": self.config.connect_timeout,
                "read_timeout": self.config.read_timeout,
                "max_banner_bytes": self.config.max_banner_bytes,
                "fingerprint_path": str(self.config.fingerprint_path)
                if self.config.fingerprint_path else None,
                "database_fingerprint_rules": self._database_matcher.rule_count,
                "database_fingerprint_rules_by_protocol": self._database_matcher.stats(),
                "database_fingerprint_path": str(
                    self.config.database_fingerprint_path or DEFAULT_LIBRARY_DIR
                ),
            },
            "fingerprint_rules": self._matcher.rule_count if self._matcher else 0,
            "fingerprint_rules_by_protocol": (
                self._matcher.stats()["rules_by_protocol"] if self._matcher else {}
            ),
        }

    def _get_ports(self, proto: str) -> list[int]:
        cfg = self.config.protocol_config.get(proto)
        return cfg.ports if cfg else [22]

    def _record_failure(self, result: BannerResult) -> None:
        if result.failure is not None:
            self._failure_counts[result.failure.detail_code] += 1

    @staticmethod
    def _ensure_evidence_trace(result: BannerResult) -> None:
        if not result.accessible or result.evidence_trace:
            return
        preview = result.banner[:1024]
        byte_count = len(result.banner.encode("utf-8", errors="replace"))
        if not preview and result.banner_raw_hex:
            preview = result.banner_raw_hex[:2048]
            byte_count = len(result.banner_raw_hex) // 2
        result.evidence_trace.append(EvidenceStep(
            operation="protocol_response",
            direction="receive",
            byte_count=byte_count,
            preview=preview,
            elapsed_ms=round(result.response_time_ms, 1),
        ))


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
    return await _probe_ssh(host, port=port, config=_get_engine().config)


async def probe_ftp(host: str, port: int = 21) -> BannerResult:
    return await _probe_ftp(host, port=port, config=_get_engine().config)


async def probe_telnet(host: str, port: int = 23) -> BannerResult:
    return await _probe_telnet(host, port=port, config=_get_engine().config)


async def probe_redis(host: str, port: int = 6379) -> BannerResult:
    return await _probe_redis(host, port=port, config=_get_engine().config)


async def probe_mysql(host: str, port: int = 3306) -> BannerResult:
    return await _probe_mysql(host, port=port, config=_get_engine().config)


async def probe_pgsql(host: str, port: int = 5432) -> BannerResult:
    return await _probe_pgsql(host, port=port, config=_get_engine().config)
