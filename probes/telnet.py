"""Telnet 协议 Banner 探测。对应 C++ 版 TelnetProtocol::async_probe。"""

import asyncio
import logging
from typing import Optional

from ..core.models import BannerResult, ProbeConfig
import banner_scanner.core.transport as _transport

logger = logging.getLogger("banner_scanner.probe.telnet")

_TELNET_BANNER_MAX = 256


async def probe_telnet(
    host: str,
    port: int = 23,
    config: Optional[ProbeConfig] = None,
) -> BannerResult:
    if config is None:
        config = ProbeConfig()

    result = BannerResult(protocol="TELNET", host=host, port=port)
    start = asyncio.get_event_loop().time()
    writer = None

    try:
        reader, writer = await _transport.connect_tcp(
            host, port,
            connect_timeout=config.connect_timeout,
        )

        try:
            data, truncated = await _transport.read_exact(
                reader,
                max_bytes=1024,
                read_timeout=config.read_timeout,
            )

            elapsed = (asyncio.get_event_loop().time() - start) * 1000
            result.response_time_ms = elapsed

            if len(data) >= 1024:
                result.banner_truncated = True

            # 过滤 IAC 控制字节
            clean = bytearray()
            skip = False
            for b in data:
                if b == 0xFF:
                    skip = True
                    continue
                if skip:
                    skip = False
                    continue
                if b >= 0x20 or b in (0x0A, 0x0D):
                    clean.append(b)

            if not clean:
                clean = bytearray(data[:_TELNET_BANNER_MAX])

            banner_len = min(len(clean), _TELNET_BANNER_MAX)
            result.banner = clean[:banner_len].decode("utf-8", errors="replace")
            result.accessible = True

        except _transport.ReadTimeout:
            elapsed = (asyncio.get_event_loop().time() - start) * 1000
            result.response_time_ms = elapsed
            result.accessible = True

    except (_transport.ConnectionTimeout, _transport.TransportError) as e:
        result.error = str(e)
        logger.debug("[TELNET] %s:%d %s", host, port, e)
    except Exception as e:
        result.error = f"Unexpected: {e}"
        logger.warning("[TELNET] %s:%d unexpected error: %s", host, port, e)
    finally:
        await _transport.safe_close(writer)

    return result
