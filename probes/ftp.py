"""FTP 协议 Banner 探测。对应 C++ 版 FtpProtocol::async_probe。"""

import asyncio
import logging
from typing import Optional

from ..core.models import BannerResult, FtpFeatures, ProbeConfig
from ..core.parsers import parse_ftp_features, extract_ftp_features_from_lines
import banner_scanner.core.transport as _transport

logger = logging.getLogger("banner_scanner.probe.ftp")


async def probe_ftp(
    host: str,
    port: int = 21,
    config: Optional[ProbeConfig] = None,
) -> BannerResult:
    if config is None:
        config = ProbeConfig()

    result = BannerResult(protocol="FTP", host=host, port=port)
    start = asyncio.get_event_loop().time()
    writer = None

    try:
        use_tls = (port == 990)
        reader, writer = await _transport.connect_tcp(
            host, port,
            connect_timeout=config.connect_timeout,
            use_tls=use_tls,
        )

        data, truncated = await _transport.read_exact(
            reader,
            max_bytes=config.max_banner_bytes,
            read_timeout=config.read_timeout,
        )

        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        result.response_time_ms = elapsed

        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        banner = lines[0].rstrip("\r") if lines else text
        result.banner = banner
        result.banner_truncated = truncated
        result.accessible = True

        cfg = config.protocol_config.get("ftp")
        send_feat = cfg.send_feat if cfg else True
        if send_feat:
            try:
                writer.write(b"FEAT\r\n")
                await writer.drain()

                feat_data, _ = await _transport.read_exact(
                    reader,
                    max_bytes=config.max_banner_bytes,
                    read_timeout=config.read_timeout,
                )
                feat_text = feat_data.decode("utf-8", errors="replace")
                features = extract_ftp_features_from_lines(
                    feat_text.splitlines()
                )
                if features:
                    result.ftp = parse_ftp_features(features)
            except (_transport.ReadTimeout, _transport.TransportError) as e:
                logger.debug("[FTP] %s:%d FEAT failed: %s", host, port, e)
                result.ftp = FtpFeatures()

    except (_transport.ConnectionTimeout,
            _transport.ReadTimeout,
            _transport.TransportError,
            _transport.TlsError) as e:
        result.error = str(e)
        logger.debug("[FTP] %s:%d %s", host, port, e)
    except Exception as e:
        result.error = f"Unexpected: {e}"
        logger.warning("[FTP] %s:%d unexpected error: %s", host, port, e)
    finally:
        await _transport.safe_close(writer)

    return result
