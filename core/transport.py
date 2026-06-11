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


async def _upgrade_tls(reader, writer, host: str) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """TLS 升级，兼容不同 Python 版本"""
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    transport = writer.transport

    # 优先用 loop.start_tls (Python 3.7+ 通用)
    try:
        loop = asyncio.get_running_loop()
        if hasattr(loop, 'start_tls'):
            reader, writer = await loop.start_tls(
                transport, transport.get_protocol(), ctx,
                server_side=False, ssl_handshake_timeout=5.0,
            )
            return reader, writer, {}
    except Exception:
        pass

    # 备选: asyncio.start_tls (Python 3.11+)
    if hasattr(asyncio, 'start_tls'):
        reader, writer = await asyncio.start_tls(
            transport, transport.get_protocol(), ctx,
            server_side=False, server_hostname=host,
        )
        return reader, writer, {}

    logger.warning("TLS upgrade not supported on this Python version, using plain connection")
    return reader, writer, {}


async def connect_tcp(
    host: str, port: int, *, connect_timeout: float, use_tls: bool = False,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, dict]:
    """返回 (reader, writer, tcp_info) 其中 tcp_info 含 TCP 层元数据"""
    tcp_info = {}
    try:
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
        if use_tls and port == 990:
            try:
                reader, writer = await asyncio.wait_for(
                    _upgrade_tls(reader, writer, host),
                    timeout=connect_timeout * 0.5,
                )
            except Exception as e:
                logger.debug("TLS upgrade failed for %s:%d: %s, using plain", host, port, e)
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
