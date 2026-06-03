"""熔断器。连续失败超过阈值后自动切断流量一段时间。"""

import time
import logging
from .models import CircuitBreakerState

logger = logging.getLogger("banner_scanner.breaker")


class CircuitBreaker:
    """主机级熔断器"""

    def __init__(self, max_failures: int = 10, cooldown: float = 30.0):
        self._max_failures = max_failures
        self._cooldown = cooldown
        self._states: dict[str, CircuitBreakerState] = {}

    def _get(self, host: str) -> CircuitBreakerState:
        if host not in self._states:
            self._states[host] = CircuitBreakerState(
                max_failures=self._max_failures,
                cooldown_seconds=self._cooldown,
            )
        return self._states[host]

    def is_open(self, host: str) -> bool:
        """主机当前是否熔断"""
        state = self._get(host)
        now = time.time()
        if now < state.open_until:
            return True
        if state.open_until > 0 and now >= state.open_until:
            # 冷却结束，自动半开
            state.failures = 0
            state.open_until = 0
        return False

    def record_success(self, host: str) -> None:
        """记录成功，重置失败计数"""
        state = self._get(host)
        state.failures = 0

    def record_failure(self, host: str) -> None:
        """记录失败，超过阈值则打开熔断器"""
        state = self._get(host)
        now = time.time()
        state.failures += 1
        state.last_failure_time = now
        if state.failures >= self._max_failures:
            state.open_until = now + self._cooldown
            logger.warning(
                "[BREAKER] %s opened for %.0fs (%d consecutive failures)",
                host, self._cooldown, self._max_failures,
            )

    def reset(self, host: str) -> None:
        self._states.pop(host, None)

    @property
    def open_hosts(self) -> list[str]:
        now = time.time()
        return [h for h, s in self._states.items() if now < s.open_until]

    def stats(self) -> dict:
        now = time.time()
        return {
            h: {
                "failures": s.failures,
                "open": now < s.open_until,
                "remaining_s": max(0, s.open_until - now) if s.open_until > 0 else 0,
            }
            for h, s in self._states.items()
        }
