"""核心探测引擎：并发调度、限流、熔断、健康检查。"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Optional, Callable, Awaitable

from .models import BannerResult, HostResult, ProbeConfig, FingerprintMatch
from .breaker import CircuitBreaker
from .matcher import FingerprintMatcher
from ..probes import PROTOCOL_PROBES

logger = logging.getLogger("banner_scanner.engine")


class ProbeEngine:
    """探测引擎，管理并发、限流、熔断、指纹匹配"""

    def __init__(self, config: Optional[ProbeConfig] = None):
        self.config = config or ProbeConfig()
        self._breaker = CircuitBreaker()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_hosts)
        self._total_probes = 0
        self._total_errors = 0
        self._start_time = time.time()
        self._healthy = True

        # 可选：挂载指纹匹配器
        self._matcher: Optional[FingerprintMatcher] = None
        if self.config.fingerprint_path:
            fp_path = Path(self.config.fingerprint_path)
            if fp_path.exists():
                self._matcher = FingerprintMatcher.load(fp_path)
                logger.info(
                    "Fingerprint matcher loaded (%d rules from %s)",
                    self._matcher.rule_count, fp_path,
                )
            else:
                logger.warning(
                    "Fingerprint file configured but not found: %s", fp_path,
                )

    # ---- 对外接口 ----

    async def probe_host(
        self,
        host: str,
        protocols: Optional[list[str]] = None,
    ) -> HostResult:
        """并发探测一个主机的全部协议"""
        if protocols is None:
            protocols = list(PROTOCOL_PROBES.keys())

        if self._breaker.is_open(host):
            logger.info("[ENGINE] %s skipped (circuit breaker open)", host)
            br = BannerResult(protocol="BREAKER", host=host, port=0,
                              error="circuit breaker open")
            return HostResult(host=host, results={p: br for p in protocols})

        start = time.time()

        async with self._semaphore:
            async with asyncio.TaskGroup() as tg:
                tasks = {}
                for proto in protocols:
                    probe_fn = PROTOCOL_PROBES.get(proto)
                    if probe_fn is None:
                        continue
                    ports = self._get_ports(proto)
                    for port in ports:
                        tasks[f"{proto}:{port}"] = tg.create_task(
                            probe_fn(host, port=port, config=self.config)
                        )

        results = {}
        for key, task in tasks.items():
            proto = key.split(":")[0]
            try:
                result = task.result()
                results[proto] = result
                self._total_probes += 1
                if result.accessible:
                    self._breaker.record_success(host)
                else:
                    self._breaker.record_failure(host)
                    self._total_errors += 1
            except Exception as e:
                results[proto] = BannerResult(
                    protocol=proto.upper(), host=host, port=0,
                    error=f"Task failed: {e}",
                )
                self._total_errors += 1

        # ---- 指纹匹配（可选） ----
        if self._matcher is not None:
            for br in results.values():
                self._matcher.match(br)

        total_time = (time.time() - start) * 1000
        return HostResult(host=host, results=results, total_time_ms=total_time)

    async def probe_hosts(
        self,
        hosts: list[str],
        protocols: Optional[list[str]] = None,
        progress_cb: Optional[Callable[[int, int], Awaitable[None]]] = None,
    ) -> list[HostResult]:
        """并发探测多个主机"""
        results = []
        total = len(hosts)

        batch = []
        for i, host in enumerate(hosts):
            batch.append(self.probe_host(host, protocols))
            if len(batch) >= self.config.max_concurrent_hosts or i == total - 1:
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                for br in batch_results:
                    if isinstance(br, Exception):
                        results.append(HostResult(
                            host="unknown",
                            results={"error": BannerResult(
                                protocol="ERROR", host="unknown", port=0,
                                error=str(br),
                            )},
                        ))
                    else:
                        results.append(br)
                batch = []
                if progress_cb:
                    await progress_cb(len(results), total)

        return results

    # ---- 指纹匹配器 ----

    @property
    def matcher(self) -> Optional[FingerprintMatcher]:
        return self._matcher

    def set_matcher(self, matcher: FingerprintMatcher) -> None:
        """运行时替换/挂载指纹匹配器"""
        self._matcher = matcher
        logger.info("Fingerprint matcher set (%d rules)", matcher.rule_count)

    # ---- 健康检查 ----

    @property
    def healthy(self) -> bool:
        return self._healthy

    async def health_check(self) -> dict:
        """返回引擎健康状态"""
        info = {
            "healthy": self._healthy,
            "uptime_s": time.time() - self._start_time,
            "total_probes": self._total_probes,
            "total_errors": self._total_errors,
            "error_rate_pct": round(
                (self._total_errors / max(self._total_probes, 1)) * 100, 2
            ),
            "circuit_breaker_open_hosts": len(self._breaker.open_hosts),
            "max_concurrent_hosts": self.config.max_concurrent_hosts,
            "config": {
                "connect_timeout": self.config.connect_timeout,
                "read_timeout": self.config.read_timeout,
                "max_banner_bytes": self.config.max_banner_bytes,
                "fingerprint_path": self.config.fingerprint_path,
            },
        }

        if self._matcher:
            info["fingerprint"] = {
                "total_rules": self._matcher.rule_count,
                "vendors": list(set(r.name for r in self._matcher._rules)),
            }

        return info

    # ---- 内部 ----

    def _get_ports(self, proto: str) -> list[int]:
        cfg = self.config.protocol_config.get(proto)
        return cfg.ports if cfg else [22]


# ---- 模块级便捷方法 ----

_engine: Optional[ProbeEngine] = None


def _get_engine() -> ProbeEngine:
    global _engine
    if _engine is None:
        _engine = ProbeEngine()
    return _engine


async def probe_host(
    host: str,
    protocols: Optional[list[str]] = None,
) -> HostResult:
    return await _get_engine().probe_host(host, protocols)


async def probe_ssh(host: str, port: int = 22) -> BannerResult:
    from ..probes.ssh import probe_ssh as _ssh
    return await _ssh(host, port=port, config=_get_engine().config)


async def probe_ftp(host: str, port: int = 21) -> BannerResult:
    from ..probes.ftp import probe_ftp as _ftp
    return await _ftp(host, port=port, config=_get_engine().config)


async def probe_telnet(host: str, port: int = 23) -> BannerResult:
    from ..probes.telnet import probe_telnet as _telnet
    return await _telnet(host, port=port, config=_get_engine().config)
