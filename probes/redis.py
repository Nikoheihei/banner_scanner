"""Redis-compatible RESP probe using PING and INFO server."""

import asyncio
import logging
from typing import Optional

from ..core.models import BannerResult, ProbeConfig, get_effective_timeout
from ..core.parsers import decode_resp_payload, extract_banner_info, parse_redis_response
import banner_scanner.core.transport as _transport

logger = logging.getLogger("banner_scanner.probe.redis")

PING_COMMAND = b"*1\r\n$4\r\nPING\r\n"
INFO_SERVER_COMMAND = b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"


async def _read_resp(reader: asyncio.StreamReader, timeout: float,
                     max_bytes: int) -> tuple[bytes, bool]:
    header = b""
    try:
        header = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not header:
            return b"", False
        if header[:1] != b"$":
            return header[:max_bytes], len(header) > max_bytes

        try:
            payload_length = int(header[1:].strip())
        except ValueError:
            return header[:max_bytes], len(header) > max_bytes
        if payload_length < 0:
            return header, False

        remaining = max(0, max_bytes - len(header))
        wanted = payload_length + 2
        to_read = min(wanted, remaining)
        payload = await asyncio.wait_for(reader.readexactly(to_read), timeout=timeout)
        return header + payload, wanted > remaining
    except asyncio.IncompleteReadError as exc:
        return header + exc.partial, True
    except asyncio.TimeoutError as exc:
        raise _transport.ReadTimeout(f"read timed out after {timeout}s") from exc


async def probe_redis(
    host: str,
    port: int = 6379,
    config: Optional[ProbeConfig] = None,
) -> BannerResult:
    """Actively identify a Redis-compatible endpoint without authenticating."""
    config = config or ProbeConfig()
    result = BannerResult(protocol="REDIS", host=host, port=port)
    start = asyncio.get_running_loop().time()
    writer = None
    ct, rt = get_effective_timeout(config, "redis")

    try:
        reader, writer, _tcp = await _transport.connect_tcp(
            host, port, connect_timeout=ct,
        )
        writer.write(PING_COMMAND)
        await writer.drain()
        ping_bytes, ping_truncated = await _read_resp(
            reader, rt, min(config.max_banner_bytes, 4096),
        )

        info_bytes = b""
        info_truncated = False
        if ping_bytes:
            writer.write(INFO_SERVER_COMMAND)
            await writer.drain()
            info_bytes, info_truncated = await _read_resp(
                reader, rt, config.max_banner_bytes,
            )

        ping_response = ping_bytes.decode("utf-8", errors="replace")
        info_response = info_bytes.decode("utf-8", errors="replace")
        result.redis = parse_redis_response(ping_response, info_response)
        info_payload = decode_resp_payload(info_response)

        if result.redis.fields:
            result.banner = info_response
        else:
            result.banner = "".join(filter(None, (ping_response, info_response)))
        result.banner_raw_hex = (ping_bytes + info_bytes)[:64].hex()
        result.banner_truncated = ping_truncated or info_truncated
        result.accessible = True
        if not result.banner:
            result.error = "TCP connected but no Redis response received"
        elif info_payload and info_payload.startswith("-"):
            logger.debug("[REDIS] %s:%d INFO denied: %s", host, port, info_payload.strip())
        result.info = extract_banner_info(result)
    except (_transport.ConnectionTimeout, _transport.ReadTimeout,
            _transport.TransportError) as exc:
        result.error = str(exc)
        logger.debug("[REDIS] %s:%d %s", host, port, exc)
    except Exception as exc:
        result.error = f"Unexpected: {exc}"
        logger.warning("[REDIS] %s:%d unexpected error: %s", host, port, exc)
    finally:
        result.response_time_ms = (asyncio.get_running_loop().time() - start) * 1000
        await _transport.safe_close(writer)
    return result
