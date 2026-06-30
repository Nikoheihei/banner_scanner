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


def _make_tls_context() -> ssl.SSLContext:
    """Create a scanner TLS context without trusting the remote certificate."""
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Internet-facing FTP services still include legacy TLS deployments.  The
    # lower security level is acceptable here because the scanner does not send
    # credentials or rely on transport authenticity.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (AttributeError, ssl.SSLError):
        pass
    return ctx


async def upgrade_tls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    *,
    handshake_timeout: float = 5.0,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Upgrade an established stream after a protocol-level TLS negotiation."""
    ctx = _make_tls_context()
    try:
        writer_start_tls = getattr(writer, "start_tls", None)
        if callable(writer_start_tls):
            await writer_start_tls(
                ctx,
                server_hostname=host,
                ssl_handshake_timeout=handshake_timeout,
            )
            return reader, writer

        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()
        new_transport = await loop.start_tls(
            transport,
            protocol,
            ctx,
            server_side=False,
            server_hostname=host,
            ssl_handshake_timeout=handshake_timeout,
        )
        new_writer = asyncio.StreamWriter(new_transport, protocol, reader, loop)
        return reader, new_writer
    except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
        raise TransportError(f"TLS handshake with {host} failed: {exc}") from exc


async def connect_tcp(
    host: str, port: int, *, connect_timeout: float, use_tls: bool = False,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, dict]:
    """返回 (reader, writer, tcp_info) 其中 tcp_info 含 TCP 层元数据"""
    tcp_info = {}
    try:
        if use_tls:
            try:
                connection = asyncio.open_connection(
                    host,
                    port,
                    ssl=_make_tls_context(),
                    server_hostname=host,
                    ssl_handshake_timeout=connect_timeout,
                )
                reader, writer = await asyncio.wait_for(
                    connection, timeout=connect_timeout,
                )
                tcp_info["tls_mode"] = "implicit"
            except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
                logger.debug(
                    "Implicit TLS failed for %s:%d: %s; retrying plaintext",
                    host, port, exc,
                )
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=connect_timeout,
                )
                tcp_info["tls_mode"] = "plaintext_fallback"
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=connect_timeout,
            )
        # TCP_NODELAY: 关闭 Nagle 算法，减少小包延迟（C++ 原版优化）
        try:
            transport = writer.transport
            sock = transport.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # 抓 TCP 层元数据
                try: tcp_info['sndbuf'] = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                except: pass
                try: tcp_info['rcvbuf'] = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                except: pass
                try: tcp_info['mss'] = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
                except: pass
        except Exception:
            pass
        return reader, writer, tcp_info
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
