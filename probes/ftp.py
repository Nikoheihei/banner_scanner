"""FTP 协议 Banner 探测。增强版：主动触发获取 Banner + 多重提取策略。"""

import asyncio
import logging
from typing import Optional

from ..core.models import BannerResult, FtpFeatures, ProbeConfig, get_effective_timeout
from ..core.evidence import captured_response_sha256
from ..core.parsers import (
    parse_ftp_features, extract_ftp_features_from_lines,
    parse_ftp_banner_info, extract_banner_info,
)
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
    ct, rt = get_effective_timeout(config, "ftp")

    try:
        use_tls = (port == 990)
        reader, writer, _tcp = await _transport.connect_tcp(
            host, port,
            connect_timeout=ct,
            use_tls=use_tls,
        )

        # --- 第一阶段：读取服务端欢迎 Banner ---
        data, truncated = await _transport.read_exact(
            reader,
            max_bytes=config.max_banner_bytes,
            read_timeout=rt,
        )
        captured_data = bytearray(data)

        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        result.response_time_ms = elapsed

        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        banner = lines[0].rstrip("\r") if lines else text
        # 保留完整多行响应
        full_text = text
        result.banner = banner
        result.banner_truncated = truncated
        result.accessible = True

        # --- 第二阶段：若 Banner 为空，主动发送命令触发响应 ---
        if not banner.strip():
            banner, full_text, proactive_data = await _proactive_ftp_probe(
                reader, writer, config, host, port, rt
            )
            captured_data.extend(proactive_data)
            if banner:
                result.banner = banner
                # 更新耗时（含主动探测）
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                result.response_time_ms = elapsed

        # --- 第三阶段：提取软件信息 ---
        ftp_info = parse_ftp_banner_info(banner)

        # --- 第四阶段：FEAT 递归多行读取（参照 C++ 原版）---
        cfg = config.protocol_config.get("ftp")
        send_feat = cfg.send_feat if cfg else True
        if send_feat and banner.strip():
            try:
                writer.write(b"FEAT\r\n")
                await writer.drain()
                features, feature_data = await _read_feat_lines(
                    reader, rt * 0.5, config.max_banner_bytes,
                )
                captured_data.extend(feature_data)
                if features:
                    result.ftp = parse_ftp_features(features)
                    result.ftp.software = ftp_info.software
                    result.ftp.version = ftp_info.version
                    result.ftp.full_banner = full_text
                else:
                    result.ftp = ftp_info
            except (_transport.ReadTimeout, _transport.TransportError, OSError) as e:
                logger.debug("[FTP] %s:%d FEAT failed: %s", host, port, e)
                result.ftp = ftp_info
        else:
            result.ftp = ftp_info

        # --- 第五阶段：标记无 Banner 但可达的情况 ---
        if not banner.strip():
            result.banner = ""  # 明确标注无 Banner
            # 在 error 中说明（但仍标记 accessible）
            _transport.record_result_failure(
                result,
                phase="protocol_read",
                detail_code="protocol_no_banner",
                message="TCP connected but no FTP banner received",
                elapsed_ms=(asyncio.get_event_loop().time() - start) * 1000,
            )

        result.response_sha256 = captured_response_sha256(bytes(captured_data))
        # 统一提取有效信息
        result.info = extract_banner_info(result)

    except (_transport.ConnectionTimeout,
            _transport.ReadTimeout,
            _transport.TransportError) as e:
        _transport.record_failure(
            result, e,
            elapsed_ms=(asyncio.get_event_loop().time() - start) * 1000,
        )
        logger.debug("[FTP] %s:%d %s", host, port, e)
    except Exception as e:
        _transport.record_failure(
            result, e,
            elapsed_ms=(asyncio.get_event_loop().time() - start) * 1000,
        )
        logger.warning("[FTP] %s:%d unexpected error: %s", host, port, e)
    finally:
        await _transport.safe_close(writer)

    return result


async def _read_feat_lines(reader, read_timeout: float,
                           max_bytes: int) -> tuple[str, bytes]:
    """递归逐行读取 FEAT 响应，直到遇到 '211 ' 结束标记（参照 C++ 原版）"""
    all_data = b""
    while True:
        try:
            chunk, _ = await _transport.read_exact(
                reader, max_bytes=4096, read_timeout=read_timeout,
            )
            if not chunk: break
            all_data += chunk
            # 检查是否已收到结束标记
            text = all_data.decode("utf-8", errors="replace")
            if "\r\n211 " in text or text.startswith("211 "):
                break
        except _transport.ReadTimeout:
            break

    text = all_data.decode("utf-8", errors="replace")
    features = []
    for line in text.split("\r\n"):
        ol = line  # original line
        line = ol.strip()
        if not line: continue
        if line.startswith("211 "): break      # 结束行
        if line.startswith("211-"): continue    # 首行
        if ol[0] in (" ", "\t"):                # 特性行（空格开头）
            feat = line
            # 用分号截断（如 "AUTH TLS;SSL;" → "AUTH TLS"），
            # 比 C++ 原版用空格截断更准确
            semi = feat.find(";")
            if semi > 0:
                feat = feat[:semi].strip()
            features.append(feat)
    return (", ".join(features) if features else ""), all_data


async def _proactive_ftp_probe(reader, writer, config: ProbeConfig,
                                host: str, port: int,
                                read_timeout: float) -> tuple[str, str, bytes]:
    """主动触发 FTP 响应：尝试 HELP / SYST / 等待更长时间"""
    commands = [b"HELP\r\n", b"SYST\r\n", b""]  # "" = 再等一轮
    for cmd in commands:
        try:
            if cmd:
                writer.write(cmd)
                await writer.drain()

            data, _ = await _transport.read_exact(
                reader,
                max_bytes=config.max_banner_bytes,
                read_timeout=read_timeout * 0.7,
            )
            if data and data.strip():
                text = data.decode("utf-8", errors="replace")
                first_line = text.splitlines()[0].strip() if text.splitlines() else text
                logger.debug("[FTP] %s:%d proactive %s => %s",
                           host, port, cmd.decode() if cmd else "wait", first_line[:80])
                return first_line, text, data
        except (_transport.ReadTimeout, _transport.TransportError):
            continue

    return "", "", b""
