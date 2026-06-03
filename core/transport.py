"""底层传输层：TCP/TLS 连接管理、Socket tuning、超时控制。"""

import asyncio
import logging
import socket
import ssl
from typing import Optional, Tuple

logger = logging.getLogger("banner_scanner.transport")


class TransportError(Exception):
    """传输层异常基类"""
    pass


class ConnectionTimeout(TransportError):
    """连接超时"""
    pass


class ReadTimeout(TransportError):
    """读取超时"""
    pass


class TlsError(TransportError):
    """TLS 协商失败"""
    pass


def _tune_socket(sock: socket.socket) -> None:
    """对应 C++ 版 setsockopt 调用"""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    except (OSError, AttributeError):
        pass


async def connect_tcp(
    host: str,
    port: int,
    *,
    connect_timeout: float,
    use_tls: bool = False,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        loop = asyncio.get_running_loop()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _tune_socket(sock)
        sock.setblocking(False)

        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (host, port)),
                timeout=connect_timeout,
            )
        except asyncio.TimeoutError:
            sock.close()
            raise ConnectionTimeout(
                f"connect to {host}:{port} timed out after {connect_timeout}s"
            )
        except OSError as e:
            sock.close()
            raise TransportError(f"connect to {host}:{port} failed: {e}") from e

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await loop.create_connection(
            lambda: protocol, sock=sock,
        )
        writer = asyncio.StreamWriter(transport, protocol, reader, loop)

        if use_tls:
            if ssl_context is None:
                ssl_context = ssl.create_default_context(
                    purpose=ssl.Purpose.SERVER_AUTH
                )
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.start_tls(
                        transport, protocol, ssl_context,
                        server_side=False,
                        server_hostname=host,
                    ),
                    timeout=connect_timeout * 0.5,
                )
            except (asyncio.TimeoutError, OSError, ssl.SSLError) as e:
                writer.close()
                raise TlsError(f"TLS handshake with {host}:{port} failed: {e}") from e

        return reader, writer

    except (ConnectionTimeout, TransportError, TlsError):
        raise
    except OSError as e:
        raise TransportError(str(e)) from e


async def read_exact(
    reader: asyncio.StreamReader,
    max_bytes: int,
    *,
    read_timeout: float,
) -> Tuple[bytes, bool]:
    truncated = False
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=read_timeout)
        if len(data) >= max_bytes:
            truncated = True
        return data, truncated
    except asyncio.TimeoutError as e:
        raise ReadTimeout(
            f"read timed out after {read_timeout}s (max_bytes={max_bytes})"
        ) from e
    except OSError as e:
        raise TransportError(f"read failed: {e}") from e


async def safe_close(writer: Optional[asyncio.StreamWriter]) -> None:
    """安全关闭连接。不 wait_closed 以防止 mock/异常场景下 hang。"""
    if writer is None:
        return
    try:
        writer.close()
        # 短暂等待关闭确认，但不阻塞
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except (asyncio.TimeoutError, Exception):
            pass
    except Exception:
        pass
