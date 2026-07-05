"""PostgreSQL SSLRequest and minimal StartupMessage probe."""

import asyncio
import logging
import struct
from typing import Optional

from ..core.models import BannerResult, ProbeConfig, get_effective_timeout
from ..core.evidence import captured_response_sha256
from ..core.parsers import extract_banner_info, parse_pgsql_messages
import banner_scanner.core.transport as _transport

logger = logging.getLogger("banner_scanner.probe.pgsql")

SSL_REQUEST = struct.pack("!II", 8, 80877103)
# Matches the historical scanner corpus: a startup header encoded with the
# wrong byte order.  Some compatible servers expose implementation-specific
# decoder errors for it, without authentication or SQL execution.
MALFORMED_STARTUP_HEADER = struct.pack("<II", 22, 196608)


def build_startup_message() -> bytes:
    params = (
        b"user\x00probe\x00database\x00probe\x00"
        b"application_name\x00banner_scanner\x00\x00"
    )
    body = struct.pack("!I", 196608) + params
    return struct.pack("!I", len(body) + 4) + body


async def _read_startup_messages(reader: asyncio.StreamReader, timeout: float,
                                 max_bytes: int) -> tuple[bytes, bool]:
    data = bytearray()
    first = True
    truncated = False
    while len(data) < max_bytes:
        wait = timeout if first else min(timeout, 0.2)
        try:
            header = await asyncio.wait_for(reader.readexactly(5), timeout=wait)
        except asyncio.TimeoutError:
            break
        except asyncio.IncompleteReadError as exc:
            data.extend(exc.partial)
            truncated = True
            break

        first = False
        length = struct.unpack("!I", header[1:5])[0]
        if length < 4:
            data.extend(header)
            truncated = True
            break
        payload_length = length - 4
        if len(data) + 5 + payload_length > max_bytes:
            remaining = max(0, max_bytes - len(data) - 5)
            payload = await asyncio.wait_for(reader.readexactly(remaining), timeout=wait)
            data.extend(header)
            data.extend(payload)
            truncated = True
            break

        try:
            payload = await asyncio.wait_for(reader.readexactly(payload_length), timeout=wait)
        except asyncio.TimeoutError:
            data.extend(header)
            truncated = True
            break
        except asyncio.IncompleteReadError as exc:
            data.extend(header)
            data.extend(exc.partial)
            truncated = True
            break
        data.extend(header)
        data.extend(payload)

        message_type = chr(header[0])
        if message_type == "E":
            break
        if message_type == "R" and payload_length >= 4:
            auth_code = struct.unpack("!I", payload[:4])[0]
            if auth_code != 0:
                break
    return bytes(data), truncated


async def _read_message_after_type(
    reader: asyncio.StreamReader,
    message_type: bytes,
    timeout: float,
    max_bytes: int,
) -> tuple[bytes, bool]:
    """Read a PostgreSQL message after its one-byte type was already consumed."""
    length_bytes = b""
    try:
        length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        length = struct.unpack("!I", length_bytes)[0]
        if length < 4:
            return message_type + length_bytes, True
        payload_length = length - 4
        remaining = max(0, max_bytes - 5)
        to_read = min(payload_length, remaining)
        payload = await asyncio.wait_for(reader.readexactly(to_read), timeout=timeout)
        return message_type + length_bytes + payload, payload_length > remaining
    except asyncio.IncompleteReadError as exc:
        return message_type + length_bytes + exc.partial, True
    except asyncio.TimeoutError as exc:
        raise _transport.ReadTimeout(f"read timed out after {timeout}s") from exc


async def _probe_decoder_error(
    host: str,
    port: int,
    connect_timeout: float,
    read_timeout: float,
    max_bytes: int,
) -> tuple[str, bytes, bool]:
    """Use a second connection to request an implementation-specific error."""
    writer = None
    try:
        reader, writer, _tcp = await _transport.connect_tcp(
            host, port, connect_timeout=connect_timeout,
        )
        writer.write(SSL_REQUEST)
        await writer.drain()
        ssl_byte = await asyncio.wait_for(
            reader.readexactly(1), timeout=read_timeout,
        )
        ssl_response = ssl_byte.decode("ascii", errors="replace")
        if ssl_response == "S":
            reader, writer = await _transport.upgrade_tls(
                reader,
                writer,
                host,
                handshake_timeout=max(connect_timeout, read_timeout),
            )
        elif ssl_response != "N":
            return ssl_response, b"", False

        writer.write(MALFORMED_STARTUP_HEADER)
        await writer.drain()
        data, truncated = await _read_startup_messages(
            reader, read_timeout, max_bytes,
        )
        return ssl_response, data, truncated
    finally:
        await _transport.safe_close(writer)


async def probe_pgsql(
    host: str,
    port: int = 5432,
    config: Optional[ProbeConfig] = None,
) -> BannerResult:
    """Identify PostgreSQL without sending a password or executing SQL."""
    config = config or ProbeConfig()
    result = BannerResult(protocol="PGSQL", host=host, port=port)
    start = asyncio.get_running_loop().time()
    writer = None
    ct, rt = get_effective_timeout(config, "pgsql")

    try:
        reader, writer, _tcp = await _transport.connect_tcp(
            host, port, connect_timeout=ct,
        )
        writer.write(SSL_REQUEST)
        await writer.drain()
        try:
            ssl_byte = await asyncio.wait_for(reader.readexactly(1), timeout=rt)
        except asyncio.TimeoutError as exc:
            raise _transport.ReadTimeout(f"read timed out after {rt}s") from exc
        ssl_response = ssl_byte.decode("ascii", errors="replace")
        captured_chunks = [ssl_byte]

        data = b""
        truncated = False
        if ssl_response == "S":
            reader, writer = await _transport.upgrade_tls(
                reader,
                writer,
                host,
                handshake_timeout=max(ct, rt),
            )
            writer.write(build_startup_message())
            await writer.drain()
            data, truncated = await _read_startup_messages(
                reader, rt, config.max_banner_bytes,
            )
        elif ssl_response == "N":
            writer.write(build_startup_message())
            await writer.drain()
            data, truncated = await _read_startup_messages(
                reader, rt, config.max_banner_bytes,
            )
        elif ssl_response == "E":
            data, truncated = await _read_message_after_type(
                reader, ssl_byte, rt, config.max_banner_bytes,
            )
        if ssl_response == "E":
            captured_chunks = [data]
        else:
            captured_chunks.append(data)

        result.pgsql = parse_pgsql_messages(data, ssl_response=ssl_response)
        if not result.pgsql.implementation and ssl_response in {"S", "N"}:
            try:
                _decoder_ssl, decoder_data, decoder_truncated = (
                    await _probe_decoder_error(
                        host,
                        port,
                        ct,
                        rt,
                        config.max_banner_bytes,
                    )
                )
                decoder_info = parse_pgsql_messages(
                    decoder_data, ssl_response=ssl_response,
                )
                if decoder_info.fields:
                    result.pgsql.fields = decoder_info.fields
                    result.pgsql.message_types.extend(decoder_info.message_types)
                    result.pgsql.implementation = decoder_info.implementation
                    data = decoder_data
                    truncated = truncated or decoder_truncated
                captured_chunks.extend((
                    _decoder_ssl.encode("ascii", errors="replace"),
                    decoder_data,
                ))
            except (_transport.TransportError, asyncio.TimeoutError) as exc:
                logger.debug(
                    "[PGSQL] %s:%d decoder probe failed: %s", host, port, exc,
                )
        if ssl_response not in {"S", "N"} and not result.pgsql.message_types:
            result.pgsql.protocol_version = 0
        raw_preview = data if ssl_response == "E" else ssl_byte + data
        result.banner_raw_hex = raw_preview[:64].hex()
        result.response_sha256 = captured_response_sha256(*captured_chunks)
        result.banner_truncated = truncated
        result.accessible = True

        if result.pgsql.fields:
            severity = result.pgsql.fields.get("severity", "")
            sqlstate = result.pgsql.fields.get("sqlstate", "")
            message = result.pgsql.fields.get("message", "")
            result.banner = " ".join(filter(None, (severity, sqlstate, message)))
        elif result.pgsql.auth_method:
            result.banner = f"Authentication:{result.pgsql.auth_method}"
        elif ssl_response in {"S", "N"}:
            result.banner = f"SSLRequest:{ssl_response}"
        else:
            result.error = f"Unexpected PostgreSQL SSL response: {ssl_response!r}"
        result.info = extract_banner_info(result)
    except (_transport.ConnectionTimeout, _transport.ReadTimeout,
            _transport.TransportError) as exc:
        result.error = str(exc)
        logger.debug("[PGSQL] %s:%d %s", host, port, exc)
    except Exception as exc:
        result.error = f"Unexpected: {exc}"
        logger.warning("[PGSQL] %s:%d unexpected error: %s", host, port, exc)
    finally:
        result.response_time_ms = (asyncio.get_running_loop().time() - start) * 1000
        await _transport.safe_close(writer)
    return result
