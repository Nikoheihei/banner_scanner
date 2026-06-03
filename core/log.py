"""日志配置"""

import logging
import sys
from typing import Optional

_initialized = False


def setup_logging(level: str = "INFO"):
    global _initialized
    if _initialized:
        return
    logger = logging.getLogger("banner_scanner")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    _initialized = True
