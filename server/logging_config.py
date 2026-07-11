"""MCP service logging configuration."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path


_CONFIGURED = False


def _level_from_env() -> int:
    level_name = os.environ.get("BANNER_SCANNER_LOG_LEVEL", "INFO").upper()
    return getattr(logging, level_name, logging.INFO)


def _has_equivalent_file_handler(logger: logging.Logger, path: Path) -> bool:
    target = str(path.resolve())
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            try:
                if str(Path(handler.baseFilename).resolve()) == target:
                    return True
            except OSError:
                continue
    return False


def _add_handler_once(logger: logging.Logger, handler: logging.Handler) -> None:
    marker = getattr(handler, "_banner_scanner_handler", "")
    if marker:
        for existing in logger.handlers:
            if getattr(existing, "_banner_scanner_handler", "") == marker:
                return
    logger.addHandler(handler)


def configure_mcp_logging(default_log_file: str = "logs/mcp_server.log") -> None:
    """Configure console and optional file logging for MCP entrypoints.

    Environment variables:
    - BANNER_SCANNER_LOG_FILE: file path for persisted service logs. Defaults to
      logs/mcp_server.log for MCP entrypoints. Set to an empty string to disable
      file logging.
    - BANNER_SCANNER_LOG_LEVEL: logging level, default INFO.
    """

    global _CONFIGURED

    level = _level_from_env()
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)
    stream_handler._banner_scanner_handler = "stderr"  # type: ignore[attr-defined]

    loggers = [
        logging.getLogger("banner_scanner"),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("fastmcp"),
        logging.getLogger("mcp"),
    ]
    for logger in loggers:
        logger.setLevel(level)
        _add_handler_once(logger, stream_handler)

    log_file = os.environ.get("BANNER_SCANNER_LOG_FILE", default_log_file)
    if log_file:
        path = Path(log_file).expanduser()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            for logger in loggers:
                if _has_equivalent_file_handler(logger, path):
                    continue
                file_handler = logging.FileHandler(path, encoding="utf-8")
                file_handler.setFormatter(formatter)
                file_handler.setLevel(level)
                file_handler._banner_scanner_handler = f"file:{path}"  # type: ignore[attr-defined]
                logger.addHandler(file_handler)
        except OSError as exc:
            logging.getLogger("banner_scanner.audit").warning(
                "MCP log file disabled path=%s error=%s", path, exc,
            )

    _CONFIGURED = True
    logging.getLogger("banner_scanner.audit").info(
        "MCP logging configured level=%s log_file=%s",
        logging.getLevelName(level),
        log_file or "",
    )
