"""传输层：TCP/TLS 连接管理"""

import asyncio
import errno
import logging
import socket
import ssl
from typing import Optional, Tuple

from .models import BannerResult, ProbeFailure

logger = logging.getLogger("banner_scanner.transport")

class TransportError(Exception):
    phase = "protocol_exchange"
    detail_code = "protocol_exchange_failed"

    def __init__(self, message: str, *, phase: str | None = None,
                 detail_code: str | None = None, os_error: int | None = None,
                 context: dict | None = None):
        super().__init__(message)
        if phase is not None:
            self.phase = phase
        if detail_code is not None:
            self.detail_code = detail_code
        self.os_error = os_error
        self.context = context or {}


class ConnectionTimeout(TransportError):
    phase = "tcp_connect"
    detail_code = "tcp_connect_timeout"


class ReadTimeout(TransportError):
    phase = "protocol_read"
    detail_code = "protocol_read_timeout"


class DnsResolutionError(TransportError):
    phase = "dns_resolution"
    detail_code = "dns_resolution_failed"


def failure_from_exception(exc: BaseException, *, elapsed_ms: float = 0.0) -> ProbeFailure:
    """Convert a transport exception into stable result diagnostics."""
    if isinstance(exc, TransportError):
        return ProbeFailure(
            phase=exc.phase,
            detail_code=exc.detail_code,
            message=str(exc),
            elapsed_ms=round(elapsed_ms, 1),
            os_error=exc.os_error,
            context=dict(exc.context),
        )
    return ProbeFailure(
        phase="system",
        detail_code="unexpected_error",
        message=f"Unexpected: {exc}",
        elapsed_ms=round(elapsed_ms, 1),
    )


def record_failure(result: BannerResult, exc: BaseException, *, elapsed_ms: float = 0.0) -> None:
    """Preserve an existing text error while adding structured diagnostics."""
    failure = failure_from_exception(exc, elapsed_ms=elapsed_ms)
    result.failure = failure
    result.error = failure.message
    result.response_time_ms = max(result.response_time_ms, failure.elapsed_ms)
    result.retry_elapsed_ms = max(result.retry_elapsed_ms, failure.elapsed_ms)
    attempt = {
        "attempt": 1,
        "phase": failure.phase,
        "detail_code": failure.detail_code,
        "elapsed_ms": failure.elapsed_ms,
    }
    if failure.context:
        attempt["context"] = failure.context
    result.retry_history = [attempt]


def record_result_failure(result: BannerResult, *, phase: str, detail_code: str,
                          message: str, elapsed_ms: float = 0.0) -> None:
    """Record an incomplete exchange that did not raise an exception."""
    result.failure = ProbeFailure(
        phase=phase,
        detail_code=detail_code,
        message=message,
        elapsed_ms=round(elapsed_ms, 1),
    )
    result.error = message
    result.response_time_ms = max(result.response_time_ms, round(elapsed_ms, 1))
    result.retry_elapsed_ms = max(result.retry_elapsed_ms, round(elapsed_ms, 1))
    result.retry_history = [{
        "attempt": 1,
        "phase": phase,
        "detail_code": detail_code,
        "elapsed_ms": round(elapsed_ms, 1),
    }]


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


def _address_family(host: str) -> str:
    """Report the address family without attempting a second resolution."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return "ipv4"
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return "ipv6"
    except OSError:
        return "hostname"


def _connect_context(host: str, port: int, connect_timeout: float) -> dict:
    return {
        "endpoint": {"host": host, "port": port},
        "address_family": _address_family(host),
        "connect_timeout_ms": round(connect_timeout * 1000, 1),
    }


def _resource_errnos() -> set[int]:
    return {
        value for value in (
            getattr(errno, "EMFILE", None),
            getattr(errno, "ENFILE", None),
            getattr(errno, "ENOBUFS", None),
            getattr(errno, "ENOMEM", None),
            getattr(errno, "EADDRNOTAVAIL", None),
        ) if value is not None
    }


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
    except asyncio.TimeoutError as exc:
        raise TransportError(
            f"TLS handshake with {host} timed out after {handshake_timeout:g}s",
            phase="tls_handshake",
            detail_code="tls_handshake_timeout",
        ) from exc
    except (OSError, ssl.SSLError) as exc:
        raise TransportError(
            f"TLS handshake with {host} failed: {exc}",
            phase="tls_handshake",
            detail_code="tls_handshake_failed",
            os_error=getattr(exc, "errno", None),
        ) from exc


async def connect_tcp(
    host: str, port: int, *, connect_timeout: float, use_tls: bool = False,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, dict]:
    """返回 (reader, writer, tcp_info) 其中 tcp_info 含 TCP 层元数据"""
    tcp_info = {}
    context = _connect_context(host, port, connect_timeout)
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
        raise ConnectionTimeout(
            f"connect to {host}:{port} timed out",
            context=context,
        )
    except socket.gaierror as exc:
        raise DnsResolutionError(
            f"DNS resolution for {host} failed: {exc}",
            os_error=exc.errno,
            context=context,
        ) from exc
    except OSError as exc:
        errno_code = exc.errno
        if errno_code == errno.ECONNREFUSED:
            detail_code = "tcp_connection_refused"
        elif errno_code == errno.ENETUNREACH:
            detail_code = "network_unreachable"
        elif errno_code == errno.EHOSTUNREACH:
            detail_code = "host_unreachable"
        elif errno_code in {errno.EACCES, errno.EPERM}:
            detail_code = "local_permission_denied"
        elif errno_code in _resource_errnos():
            detail_code = "local_resource_exhausted"
        else:
            detail_code = "tcp_connect_failed"
        raise TransportError(
            f"connect to {host}:{port} failed: {exc}",
            phase="tcp_connect",
            detail_code=detail_code,
            os_error=errno_code,
            context=context,
        ) from exc


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
