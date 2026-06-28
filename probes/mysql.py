"""MySQL-compatible initial handshake probe."""

import asyncio
import logging
from typing import Optional

from ..core.models import BannerResult, ProbeConfig, get_effective_timeout
from ..core.parsers import extract_banner_info, parse_mysql_handshake
import banner_scanner.core.transport as _transport

logger = logging.getLogger("banner_scanner.probe.mysql")


async def _read_packet(reader: asyncio.StreamReader, timeout: float,
                       max_bytes: int) -> tuple[bytes, bool]:
    header = b""
    try:
        header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        packet_length = int.from_bytes(header[:3], "little")
        remaining = max(0, max_bytes - len(header))
        to_read = min(packet_length, remaining)
        payload = await asyncio.wait_for(reader.readexactly(to_read), timeout=timeout)
        return header + payload, packet_length > remaining
    except asyncio.IncompleteReadError as exc:
        return header + exc.partial, True
    except asyncio.TimeoutError as exc:
        raise _transport.ReadTimeout(f"read timed out after {timeout}s") from exc


async def probe_mysql(
    host: str,
    port: int = 3306,
    config: Optional[ProbeConfig] = None,
) -> BannerResult:
    """Read the server handshake only; never send credentials or SQL."""
    config = config or ProbeConfig()
    result = BannerResult(protocol="MYSQL", host=host, port=port)
    start = asyncio.get_running_loop().time()
    writer = None
    ct, rt = get_effective_timeout(config, "mysql")

    try:
        reader, writer, _tcp = await _transport.connect_tcp(
            host, port, connect_timeout=ct,
        )
        data, truncated = await _read_packet(reader, rt, config.max_banner_bytes)
        result.mysql = parse_mysql_handshake(data)
        result.banner_raw_hex = data[:64].hex()
        result.banner_truncated = truncated
        result.accessible = True

        if result.mysql.version:
            result.banner = result.mysql.version
        elif result.mysql.error_message:
            result.banner = result.mysql.error_message
        else:
            result.error = "TCP connected but MySQL handshake was not recognized"
        result.info = extract_banner_info(result)
    except (_transport.ConnectionTimeout, _transport.ReadTimeout,
            _transport.TransportError) as exc:
        result.error = str(exc)
        logger.debug("[MYSQL] %s:%d %s", host, port, exc)
    except Exception as exc:
        result.error = f"Unexpected: {exc}"
        logger.warning("[MYSQL] %s:%d unexpected error: %s", host, port, exc)
    finally:
        result.response_time_ms = (asyncio.get_running_loop().time() - start) * 1000
        await _transport.safe_close(writer)
    return result
