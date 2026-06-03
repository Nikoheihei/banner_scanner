"""SSH 协议 Banner 探测。对应 C++ 版 SshProtocol::async_probe。"""

import asyncio
import logging
from typing import Optional

from ..core.models import BannerResult, SshBanner, ProbeConfig
from ..core.parsers import parse_ssh_banner
import banner_scanner.core.transport as _transport

logger = logging.getLogger("banner_scanner.probe.ssh")


async def probe_ssh(
    host: str,
    port: int = 22,
    config: Optional[ProbeConfig] = None,
) -> BannerResult:
    if config is None:
        config = ProbeConfig()

    result = BannerResult(protocol="SSH", host=host, port=port)
    start = asyncio.get_event_loop().time()
    writer = None

    try:
        reader, writer = await _transport.connect_tcp(
            host, port,
            connect_timeout=config.connect_timeout,
        )

        data, truncated = await _transport.read_exact(
            reader,
            max_bytes=config.max_banner_bytes,
            read_timeout=config.read_timeout,
        )

        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        result.response_time_ms = elapsed

        banner_bytes = data.split(b"\n")[0]
        banner = banner_bytes.decode("utf-8", errors="replace").rstrip("\r")
        result.banner = banner
        result.banner_truncated = truncated
        result.ssh = parse_ssh_banner(banner)
        result.accessible = True

    except (_transport.ConnectionTimeout,
            _transport.ReadTimeout,
            _transport.TransportError) as e:
        result.error = str(e)
        logger.debug("[SSH] %s:%d %s", host, port, e)
    except Exception as e:
        result.error = f"Unexpected: {e}"
        logger.warning("[SSH] %s:%d unexpected error: %s", host, port, e)
    finally:
        await _transport.safe_close(writer)

    return result
