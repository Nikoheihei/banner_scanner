"""SSH 协议 Banner 探测。对应 C++ 版 SshProtocol::async_probe。"""

import asyncio
import logging
from typing import Optional

from ..core.models import BannerResult, SshBanner, ProbeConfig, get_effective_timeout
from ..core.evidence import captured_response_sha256
from ..core.parsers import parse_ssh_banner, extract_banner_info
import banner_scanner.core.transport as _transport

logger = logging.getLogger("banner_scanner.probe.ssh")

_CLIENT_VERSION_LINE = b"SSH-2.0-banner_scanner\r\n"


async def _read_server_banner(
    reader,
    writer,
    *,
    max_bytes: int,
    read_timeout: float,
) -> tuple[bytes, bool]:
    try:
        return await _transport.read_exact(
            reader,
            max_bytes=max_bytes,
            read_timeout=read_timeout,
        )
    except _transport.ReadTimeout:
        # Some SSH stacks stay silent until the client sends its own version
        # string. Reuse the existing socket and try once more after a harmless
        # identification line.
        writer.write(_CLIENT_VERSION_LINE)
        await writer.drain()
        return await _transport.read_exact(
            reader,
            max_bytes=max_bytes,
            read_timeout=read_timeout,
        )


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
        ct, rt = get_effective_timeout(config, "ssh")
        reader, writer, _tcp = await _transport.connect_tcp(
            host, port,
            connect_timeout=ct,
        )

        data, truncated = await _read_server_banner(
            reader,
            writer,
            max_bytes=config.max_banner_bytes,
            read_timeout=rt,
        )

        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        result.response_time_ms = elapsed

        if not data:
            raise _transport.TransportError("connection closed before SSH banner")

        banner_bytes = data.split(b"\n")[0]
        banner = banner_bytes.decode("utf-8", errors="replace").rstrip("\r")
        result.banner = banner
        result.response_sha256 = captured_response_sha256(data)
        result.banner_truncated = truncated
        result.ssh = parse_ssh_banner(banner)
        result.accessible = True
        # 统一提取有效信息
        result.info = extract_banner_info(result)

    except (_transport.ConnectionTimeout,
            _transport.ReadTimeout,
            _transport.TransportError) as e:
        _transport.record_failure(
            result, e,
            elapsed_ms=(asyncio.get_event_loop().time() - start) * 1000,
        )
        logger.debug("[SSH] %s:%d %s", host, port, e)
    except Exception as e:
        _transport.record_failure(
            result, e,
            elapsed_ms=(asyncio.get_event_loop().time() - start) * 1000,
        )
        logger.warning("[SSH] %s:%d unexpected error: %s", host, port, e)
    finally:
        await _transport.safe_close(writer)

    return result
