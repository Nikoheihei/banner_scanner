"""Telnet 协议 Banner 探测。增强版：主动交互 + IAC 协商处理。"""

import asyncio
import logging
from typing import Optional

from ..core.models import BannerResult, ProbeConfig, get_effective_timeout
from ..core.evidence import captured_response_sha256
from ..core.parsers import parse_telnet_banner, extract_banner_info
import banner_scanner.core.transport as _transport

logger = logging.getLogger("banner_scanner.probe.telnet")

_TELNET_BANNER_MAX = 512

# Telnet 协议常量
IAC  = 0xFF
WILL = 0xFB; WONT = 0xFC; DO = 0xFD; DONT = 0xFE
SB   = 0xFA; SE   = 0xF0


async def probe_telnet(
    host: str,
    port: int = 23,
    config: Optional[ProbeConfig] = None,
) -> BannerResult:
    if config is None:
        config = ProbeConfig()

    result = BannerResult(protocol="TELNET", host=host, port=port)
    start = asyncio.get_event_loop().time()
    writer = None
    all_raw_data = bytearray()
    ct, rt = get_effective_timeout(config, "telnet")

    try:
        reader, writer, tcp_info = await _transport.connect_tcp(
            host, port, connect_timeout=ct,
        )

        # --- 阶段1: 读初始数据 + IAC 协商 ---
        for rnd in range(3):
            try:
                data, _ = await _transport.read_exact(
                    reader, max_bytes=1024,
                    read_timeout=rt * (0.5 if rnd == 0 else 0.4),
                )
            except _transport.ReadTimeout:
                if rnd == 0:
                    writer.write(b"\r\n"); await writer.drain()
                    continue
                break

            if not data:
                break
            all_raw_data.extend(data)

            # 处理 IAC 协商：对 DO → WONT, WILL → DONT
            reply = _build_reply(data)
            if reply:
                writer.write(reply); await writer.drain()

            if _has_text(bytes(all_raw_data)):
                break

        # --- 二次探测：若只有裸 login: 且无设备特征，输 admin 触发更多信息 ---
        raw = bytes(all_raw_data)
        clean_text0 = _filter_iac(raw)
        text0 = clean_text0[:200].decode("utf-8", errors="replace") if clean_text0 else ""
        if text0.strip() and not _has_device_identifier(text0):
            try:
                writer.write(b"admin\r\n"); await writer.drain()
                extra_data, _ = await _transport.read_exact(
                    reader, max_bytes=1024, read_timeout=rt * 0.3,
                )
                if extra_data:
                    all_raw_data.extend(extra_data)
            except (_transport.ReadTimeout, _transport.TransportError):
                pass

        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        result.response_time_ms = elapsed

        # --- 生成 IAC 标准化签名 + 微特征 ---
        raw = bytes(all_raw_data)
        iac_sig = _build_iac_signature(raw)
        micro = _extract_micro_features(raw)
        
        clean_text = _filter_iac(raw)
        result.banner_truncated = len(raw) >= 1024
        result.banner = clean_text[:min(len(clean_text), _TELNET_BANNER_MAX)].decode("utf-8", errors="replace") if clean_text else ""
        result.accessible = True
        result.telnet = parse_telnet_banner(raw, result.banner)
        result.info = extract_banner_info(result)
        # 保留原始 hex + IAC 签名用于指纹匹配
        result.banner_raw_hex = raw[:128].hex() if raw else ""
        result.response_sha256 = captured_response_sha256(raw)
        result.info["iac_signature"] = iac_sig
        result.info["micro_features"] = micro
        # TCP 层元数据 + 长度填充指纹
        result.info["tcp_info"] = tcp_info
        result.info["raw_length"] = len(raw)
        # 长度簇：256/512/1024 固件页对齐
        if len(raw) >= 240 and len(raw) <= 270: result.info["length_cluster"] = "256"
        elif len(raw) >= 500 and len(raw) <= 530: result.info["length_cluster"] = "512"
        elif len(raw) >= 1000 and len(raw) <= 1050: result.info["length_cluster"] = "1024"
        # 前导填充检测
        padding = _detect_padding(raw)
        if padding: result.info["padding"] = padding

    except (_transport.ConnectionTimeout, _transport.TransportError) as e:
        result.error = str(e)
        logger.debug("[TELNET] %s:%d %s", host, port, e)
    except Exception as e:
        result.error = f"Unexpected: {e}"
        logger.warning("[TELNET] %s:%d unexpected error: %s", host, port, e)
    finally:
        await _transport.safe_close(writer)

    return result


def _build_reply(data: bytes) -> bytes:
    """对 DO → WONT, WILL → DONT"""
    r = bytearray(); i = 0
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            cmd = data[i + 1]
            if cmd == DO:   r.extend(bytes([IAC, WONT, data[i + 2]])); i += 3; continue
            elif cmd == WILL: r.extend(bytes([IAC, DONT, data[i + 2]])); i += 3; continue
            elif cmd == SB:
                j = i + 2
                while j < len(data) - 1 and not (data[j] == IAC and data[j + 1] == SE): j += 1
                i = j + 2; continue
            elif cmd in (WONT, DONT): i += 3; continue
            i += 2; continue
        i += 1
    return bytes(r)


def _filter_iac(data: bytes) -> bytearray:
    clean = bytearray(); i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd == SB:
                j = i + 2
                while j < len(data) - 1 and not (data[j] == IAC and data[j + 1] == SE): j += 1
                i = j + 2; continue
            elif cmd == IAC: clean.append(IAC); i += 2; continue
            i += 2
            if cmd in (WILL, WONT, DO, DONT) and i < len(data): i += 1
            continue
        if data[i] >= 0x20 or data[i] in (0x0A, 0x0D, 0x09): clean.append(data[i])
        i += 1
    return clean


def _has_text(data: bytes) -> bool:
    if not data: return False
    t = _filter_iac(data)
    return sum(1 for b in t if 0x20 <= b <= 0x7E) >= 3


def _has_device_identifier(text: str) -> bool:
    """检查文本是否已包含设备标识（非裸 login:/password:）"""
    low = text.lower()
    identifiers = [
        'ubuntu', 'debian', 'centos', 'red hat', 'fedora', 'suse',
        'freebsd', 'openbsd', 'netbsd', 'windows', 'cisco', 'ios',
        'busybox', 'dd-wrt', 'openwrt', 'mikrotik', 'routeros',
        'huawei', 'zyxel', 'd-link', 'tp-link', 'netgear',
        'broadband router', 'cambium', 'ubiquiti', 'airmax',
        'fortinet', 'fortigate', 'pfsense', 'sonicwall',
        'jetdirect', 'apc', 'axis', 'draytek', 'technicolor',
        'raspbian', 'raspberry', 'cradlepoint', 'arris',
        'ont', 'rdk', 'yocto', 'as400', 'mainframe',
        'telnet password is not set', 'restricted access',
        'verification', 'authorized', 'maximum number',
    ]
    return any(k in low for k in identifiers)


# ==================== IAC 签名 + 微特征 ====================

IAC_CMD_NAMES = {0xFB: 'WILL', 0xFC: 'WONT', 0xFD: 'DO', 0xFE: 'DONT'}
IAC_OPT_NAMES = {
    1: 'ECHO', 3: 'SGA', 5: 'STATUS', 6: 'TIMING',
    24: 'TTYPE', 31: 'NAWS', 32: 'TSPEED', 33: 'RFLOW',
    34: 'LINEMODE', 35: 'XDISPLOC', 36: 'ENVIRON',
    37: 'AUTH', 38: 'ENCRYPT', 39: 'NEWENV',
}


def _build_iac_signature(raw: bytes) -> str:
    """从原始字节生成标准化 IAC 签名: WILL(1),WILL(3),DO(24)"""
    sig = []
    i = 0
    while i < len(raw):
        if raw[i] == IAC and i + 2 < len(raw):
            cmd, opt = raw[i+1], raw[i+2]
            if cmd in IAC_CMD_NAMES:
                sig.append(f"{IAC_CMD_NAMES[cmd]}({opt})")
            i += 3
        else:
            i += 1
    return ",".join(sig) if sig else ""


def _extract_micro_features(raw: bytes) -> dict:
    """提取字节级微特征（即使裸 login: 也能用的特征）"""
    features = {}

    # 过滤后的文本
    clean = _filter_iac(raw)
    text = clean.decode("utf-8", errors="replace") if clean else ""
    features["clean_text"] = text[:200]

    # 换行符模式: CRLF vs LF vs CR
    if b"\r\n" in raw[:100]:
        features["line_ending"] = "CRLF"
    elif b"\n" in raw[:100]:
        features["line_ending"] = "LF"
    elif b"\r" in raw[:100]:
        features["line_ending"] = "CR"
    else:
        features["line_ending"] = "none"

    # prompt 类型检测
    low = text.lower()
    if "username:" in low or "user name" in low:
        features["prompt_type"] = "username"
    elif "password:" in low:
        features["prompt_type"] = "password"
    elif "login:" in low or "login :" in low:
        features["prompt_type"] = "login"
    elif "account:" in low:
        features["prompt_type"] = "account"
    else:
        features["prompt_type"] = "none"

    # 尾部空格检测
    if b"login: \r" in raw or b"login: \n" in raw:
        features["trailing_space"] = True
    if b"Username: \r" in raw or b"Username: \n" in raw:
        features["trailing_space"] = True

    # 前导空行数
    pre = raw[:min(len(raw), 30)]
    features["leading_crlf"] = pre.count(b"\r\n")

    # ANSI 颜色
    features["has_ansi"] = b"\x1b[" in raw

    # NULL 字节
    features["has_null"] = b"\x00" in raw[:200]

    # 总长度
    features["raw_length"] = len(raw)

    # IAC 签名
    features["iac_signature"] = _build_iac_signature(raw)
    # 长度簇标记
    rl = len(raw)
    if 240 <= rl <= 270: features["length_cluster"] = "256"
    elif 500 <= rl <= 530: features["length_cluster"] = "512"
    elif 1000 <= rl <= 1050: features["length_cluster"] = "1024"

    return features


def _detect_padding(raw: bytes) -> str:
    """检测前导填充: \x00 (NULL) 或 \x20 (空格)"""
    if len(raw) < 30: return ""
    # 前 20 字节中 \x00 占比
    nulls = raw[:min(len(raw), 50)].count(b'\x00')
    spaces = raw[:min(len(raw), 50)].count(b'\x20')
    if nulls > 8: return "NULL"
    if spaces > 8: return "SPACE"
    return ""
