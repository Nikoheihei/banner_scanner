"""结构化日志配置。参考 C++ 版 Logger（spdlog）的分级行为。"""

import logging
import sys
from typing import Optional


_initialized = False


def setup_logging(
    level: str = "INFO",
    json_format: bool = False,
    log_file: Optional[str] = None,
) -> None:
    """初始化日志。

    Args:
        level: 日志级别 (DEBUG/INFO/WARNING/ERROR)
        json_format: 是否使用 JSON 格式（生产环境推荐）
        log_file: 日志文件路径（留空则只输出到 stderr）
    """
    global _initialized
    if _initialized:
        return

    logger = logging.getLogger("banner_scanner")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    formatter = _JsonFormatter() if json_format else _TextFormatter()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    _initialized = True


class _TextFormatter(logging.Formatter):
    """文本格式日志

    格式: [LEVEL] [MODULE] message
    与 C++ InfoRelease 的 INFO + ERROR 输出风格一致。
    """
    def format(self, record: logging.LogRecord) -> str:
        return f"[{record.levelname}] [{record.name}] {record.getMessage()}"


class _JsonFormatter(logging.Formatter):
    """JSON 格式日志，适合生产环境聚合到 ELK/Loki"""
    import json as _json

    def format(self, record: logging.LogRecord) -> str:
        return self._json.dumps({
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
        }, ensure_ascii=False)
