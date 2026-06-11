"""
重试策略模块：为探测提供自动重试 + 指数退避。

使用方式:
    async for attempt in RetryExecutor(max_retries=3, base_delay=1.0):
        async with attempt:
            result = await probe_fn(host, port, config)
"""
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

from .transport import TransportError, ConnectionTimeout, ReadTimeout

logger = logging.getLogger("banner_scanner.retry")

# 默认可重试的异常类型
RETRYABLE_EXCEPTIONS = (
    ConnectionTimeout,
    ReadTimeout,
    TransportError,
    OSError,
    asyncio.TimeoutError,
    ConnectionRefusedError,
    ConnectionResetError,
)


@dataclass
class RetryConfig:
    """重试配置"""
    max_retries: int = 2           # 最大重试次数 (0 = 不重试)
    base_delay: float = 1.0        # 基础退避延迟 (秒)
    max_delay: float = 10.0        # 最大退避延迟 (秒)
    backoff_multiplier: float = 2.0  # 退避乘数
    jitter: bool = True            # 是否添加随机抖动
    retryable_exceptions: tuple = RETRYABLE_EXCEPTIONS


@dataclass
class RetryAttempt:
    """单次重试尝试的结果"""
    attempt_number: int       # 第几次尝试 (从 1 开始)
    success: bool
    elapsed_ms: float
    error: Optional[str] = None


@dataclass
class RetryResult:
    """重试过程的汇总信息"""
    total_attempts: int
    successful: bool
    attempts: list[RetryAttempt] = field(default_factory=list)
    total_elapsed_ms: float = 0.0


class RetryExecutor:
    """异步重试执行器，可作为上下文管理器 / 异步迭代器"""

    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self._result = RetryResult(total_attempts=0, successful=False)

    @property
    def result(self) -> RetryResult:
        return self._result

    async def execute(self, coro_factory):
        """执行带重试的协程。

        Args:
            coro_factory: 无参 async callable，每次调用返回一个新的协程对象

        Returns:
            (返回值, RetryResult)
        """
        start = time.time()

        for attempt_num in range(1, self.config.max_retries + 2):  # +2 因为第一次不算 retry
            attempt_start = time.time()
            try:
                result = await coro_factory()
                elapsed = (time.time() - attempt_start) * 1000
                self._result.attempts.append(
                    RetryAttempt(attempt_number=attempt_num, success=True,
                                 elapsed_ms=round(elapsed, 1))
                )
                self._result.successful = True
                self._result.total_attempts = attempt_num
                self._result.total_elapsed_ms = round((time.time() - start) * 1000, 1)
                return result, self._result

            except RETRYABLE_EXCEPTIONS as e:
                elapsed = (time.time() - attempt_start) * 1000
                self._result.attempts.append(
                    RetryAttempt(attempt_number=attempt_num, success=False,
                                 elapsed_ms=round(elapsed, 1), error=str(e))
                )
                if attempt_num <= self.config.max_retries:
                    delay = self._calc_delay(attempt_num)
                    logger.warning(
                        "Retry attempt %d/%d for probe failed (%s), "
                        "retrying in %.1fs",
                        attempt_num, self.config.max_retries + 1,
                        type(e).__name__, delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        "All %d attempts exhausted, last error: %s",
                        attempt_num, e,
                    )
                    self._result.total_elapsed_ms = round(
                        (time.time() - start) * 1000, 1
                    )
                    raise

            except Exception:
                # 不可重试的异常，直接抛出
                self._result.total_elapsed_ms = round(
                    (time.time() - start) * 1000, 1
                )
                raise

        # 不应到达此处
        self._result.total_elapsed_ms = round((time.time() - start) * 1000, 1)
        raise RuntimeError("Retry exhausted but no exception raised")

    def _calc_delay(self, attempt: int) -> float:
        """计算退避延迟"""
        delay = self.config.base_delay * (
            self.config.backoff_multiplier ** (attempt - 1)
        )
        delay = min(delay, self.config.max_delay)
        if self.config.jitter:
            import random
            delay *= 0.5 + random.random()  # 0.5 ~ 1.5 倍随机抖动
        return delay
