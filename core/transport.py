"""传输层：TCP/TLS 连接管理"""

import asyncio
import logging
import socket
import ssl
from typing import Optional, Tuple

logger = logging.getLogger("banner_scanner.transport")

class TransportError(Exception): pass
class ConnectionTimeout(TransportError): pass
class ReadTimeout(TransportError): pass


async def connect_tcp(
    host: str, port: int, *, connect_timeout: float, use_tls: bool = False,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=connect_timeout,
        )
        if use_tls and port == 990:
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            transport = writer.transport
            reader, writer = await asyncio.wait_for(
                asyncio.start_tls(transport, transport.get_protocol(), ctx,
                                  server_side=False, server_hostname=host),
                timeout=connect_timeout * 0.5,
            )
        return reader, writer
    except asyncio.TimeoutError:
        raise ConnectionTimeout(f"connect to {host}:{port} timed out")
    except (OSError, ConnectionRefusedError) as e:
        raise TransportError(str(e))


async def read_exact(reader: asyncio.StreamReader, max_bytes: int, *, read_timeout: float) -> Tuple[bytes, bool]:
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=read_timeout)
        return data, len(data) >= max_bytes
    except asyncio.TimeoutError:
        raise ReadTimeout(f"read timed out after {read_timeout}s")


async def safe_close(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except Exception:
        pass
