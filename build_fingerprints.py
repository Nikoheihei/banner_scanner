#!/usr/bin/env python3
"""
指纹库构建工具：从 fingerprint.db 的 templates 表中提取指纹规则，
生成 vendors.json 供 FingerprintMatcher 使用。

用法:
    python3 build_fingerprints.py [--db fingerprint.db] [--output vendors.json]
"""

import json
import re
import sqlite3
import sys
from collections import OrderedDict
from pathlib import Path


# ==================== 厂商名提取 ====================

# SSH Banner 格式: SSH-2.0-{software}_{version} [{comments}]
SSH_SOFTWARE_PATTERNS = [
    # 知名 SSH 软件
    (r'OpenSSH[_\-for]', 'OpenSSH'),
    (r'AWS_SFTP', 'AWS SFTP'),
    (r'Dropbear', 'Dropbear'),
    (r'Cisco', 'Cisco'),
    (r'FlowSsh|Bitvise|WinSSHD', 'Bitvise'),
    (r'Serv-U', 'Serv-U'),
    (r'CrushFTPSSHD', 'CrushFTP'),
    (r'SFTPGo', 'SFTPGo'),
    (r'GoAnywhere', 'GoAnywhere'),
    (r'CerberusFTPServer', 'Cerberus FTP'),
    (r'WS_FTP-SSH|WS_FTP', 'WS_FTP'),
    (r'GitLab-SSHD', 'GitLab SSHD'),
    (r'Maverick_SSHD', 'Maverick SSHD'),
    (r'mod_sftp', 'mod_sftp'),
    (r'WingFTPServer', 'Wing FTP'),
    (r'WeOnlyDo-wodFTPD', 'WeOnlyDo wodFTPD'),
    (r'xlightftpd', 'xlightftpd'),
    (r'paramiko', 'Paramiko'),
    (r'VShell', 'VShell'),
    (r'Platform\.sh', 'Platform.sh'),
    (r'FILES\.COM', 'FILES.COM'),
    (r'DOMO', 'Domo'),
    (r'SSHD-CORE', 'SSHD-CORE'),
    (r'srtSSHServer', 'srtSSHServer'),
    (r'babeld', 'babeld'),
    (r'AudioCodes', 'AudioCodes'),
    (r'Nielsen', 'Nielsen SFTP'),
    (r'SSHPiper', 'SSHPiper'),
    (r'OnShift', 'OnShift'),
    (r'RSYNCD', 'RSYNCD'),
]

# FTP Banner 格式: 220 {software} {message}
FTP_SOFTWARE_PATTERNS = [
    (r'vsFTPd', 'vsFTPd'),
    (r'FileZilla\s+Pro\s+Enterprise', 'FileZilla Pro Enterprise'),
    (r'FileZilla\s+Server', 'FileZilla Server'),
    (r'Pure-FTPd', 'Pure-FTPd'),
    (r'Microsoft\s+FTP', 'Microsoft FTP'),
    (r'ProFTPD', 'ProFTPD'),
    (r'Serv-U\s+FTP', 'Serv-U FTP'),
    (r'Core\s+FTP\s+Server', 'Core FTP Server'),
    (r'pyftpdlib', 'pyftpdlib'),
    (r'Alpine\s+ftp', 'Alpine FTP'),
    (r'WS_FTP', 'WS_FTP'),
    (r'Cisco', 'Cisco'),
    (r'Adeptia', 'Adeptia Internal FTP'),
    (r'Lumina\s+Datamatics', 'Lumina Datamatics FTP'),
    (r'Phoenix\s+Online', 'Phoenix Online FTP'),
    (r'Hindawi\s+FTP', 'Hindawi FTP'),
    (r'CoursEval\s+FTPS', 'CoursEval FTPS'),
    (r'OnShift\s+FTP', 'OnShift FTP'),
]


def extract_ssh_vendor(template: str) -> str:
    """从 SSH 模板中提取厂商名"""
    if not template.startswith('SSH-'):
        return ""
    for pattern, name in SSH_SOFTWARE_PATTERNS:
        if re.search(pattern, template, re.IGNORECASE):
            return name

    # 提取 SSH-2.0- 后面的软件标识
    rest = template[7:]  # 去掉 "SSH-2.0-"
    # 尝试通过 _ 分割取软件名
    underscore_pos = rest.find("_")
    if underscore_pos > 0:
        candidate = rest[:underscore_pos]
        # 过滤纯数字/太短的
        if not candidate.isdigit() and len(candidate) > 1:
            return candidate

    # 取空格或 _ 前的第一个 token
    match = re.match(r'([A-Za-z][\w.-]+)', rest)
    if match and not match.group(1).isdigit():
        return match.group(1)
    return ""


# 通用/无意义词汇 (不应作为厂商名)
GENERIC_TERMS = {
    'welcome to', 'welcome', 'service ready', 'service ready for new',
    'ftp server', 'ftp server welcome', 'service',
    'for previously approved', 'unauthorized access',
    'image gallery', 'welcome message', 'ftp',
}

def extract_ftp_vendor(template: str) -> str:
    """从 FTP 模板中提取厂商名"""
    for pattern, name in FTP_SOFTWARE_PATTERNS:
        if re.search(pattern, template, re.IGNORECASE):
            return name
    return ""


def extract_telnet_vendor(template: str) -> str:
    """从 Telnet 模板中提取厂商名"""
    # Telnet 通常没有明确 Banner，尝试从文件内容判断
    for pattern, name in SSH_SOFTWARE_PATTERNS + FTP_SOFTWARE_PATTERNS:
        if re.search(pattern, template, re.IGNORECASE):
            return name
    return ""


def extract_vendor(template: str, protocol: str) -> str:
    """根据协议类型提取厂商名"""
    protocol_upper = protocol.upper()
    if protocol_upper == 'SSH':
        return extract_ssh_vendor(template)
    elif protocol_upper == 'FTP':
        return extract_ftp_vendor(template)
    elif protocol_upper == 'TELNET':
        return extract_telnet_vendor(template)
    return ""


# ==================== 正则转换 ====================

def escape_pattern_for_json(pattern: str) -> str:
    """将数据库中的正则模式转换为可用的正则字符串。

    数据库中的模式使用转义格式 (如 \\-)，
    需要保持为有效的正则表达式。
    """
    if not pattern:
        return ""
    # 替换数据库存储的占位符为通用匹配
    pattern = pattern.replace(r'\[DomainName\]', r'.+?')
    pattern = pattern.replace(r'\.+?', r'.+?')
    return pattern


def normalize_regex_pattern(pattern: str) -> str:
    """标准化正则模式。数据库中的模式已是有效正则表达式。
    对知名软件将具体版本替换为通配，以匹配同一厂商不同版本。"""
    if not pattern:
        return ""
    p = pattern
    # SSH 软件版本泛化
    p = re.sub(r'OpenSSH_[^ \\]+', r'OpenSSH.*', p)
    p = re.sub(r'AWS_SFTP_[^ \\]+', r'AWS_SFTP.*', p)
    p = re.sub(r'Dropbear[^ \\]*', r'Dropbear.*', p)
    p = re.sub(r'SFTPGo_[^ \\]+', r'SFTPGo.*', p)
    p = re.sub(r'CerberusFTPServer_[^ \\]+', r'CerberusFTPServer.*', p)
    p = re.sub(r'Serv-U[^ \\]*', r'Serv-U.*', p)
    p = re.sub(r'VShell[_ ][^ \\]+', r'VShell.*', p)
    p = re.sub(r'GoAnywhere[^ \\]*', r'GoAnywhere.*', p)
    p = re.sub(r'paramiko_[^ \\]+', r'paramiko.*', p)
    p = re.sub(r'xlightftpd_[^ \\]+', r'xlightftpd.*', p)
    # FTP 软件版本泛化
    p = re.sub(r'vsFTPd[^ \\)]+', r'vsFTPd.*', p)
    p = re.sub(r'ProFTPD[^ \\]+', r'ProFTPD.*', p)
    p = re.sub(r'FileZilla[^ \\]+', r'FileZilla.*', p)
    p = re.sub(r'Pure-FTPd[^ \\]+', r'Pure-FTPd.*', p)
    return p


# ==================== 主构建逻辑 ====================

def build_fingerprints(db_path: str) -> list[dict]:
    """从 SQLite 数据库构建指纹规则列表。
    
    策略：
    1. 从模板中提取厂商名
    2. 同名厂商合并为一条规则（取最大 count）
    3. 生成宽泛匹配模式 .*VENDOR_NAME.* （不区分大小写）
    4. 未知厂商保留原始精确模式
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, protocol, template, pattern, vendor as db_vendor, count
        FROM templates
        ORDER BY id
    """)

    # 收集规则：{vendor_name: {protocol, vendor_name, count, template_ids}}
    vendor_map: dict[str, dict] = {}

    next_id = 1
    for row in cursor.fetchall():
        tid = row['id']
        protocol = row['protocol']
        template = row['template']
        pattern = row['pattern']
        db_vendor = row['db_vendor']
        count = row['count'] or 0

        # 提取厂商名
        vendor_name = db_vendor.strip() if db_vendor else ""
        if not vendor_name:
            vendor_name = extract_vendor(template, protocol)
        # 过滤纯数字/版本号伪厂商名 (如 "9.8.1.0", "-9.8.1.0")
        if vendor_name and re.match(r'^-?[\d.]+$', vendor_name):
            vendor_name = ""

        # 无法识别的厂商，使用原始精确模式
        if not vendor_name:
            key = f"__unknown__{tid}"
            vendor_map[key] = {
                "id": next_id,
                "name": f"Unknown-{protocol}-{next_id}",
                "protocol": protocol,
                "pattern": pattern if pattern else ".*" + re.escape(template[:80]) + ".*",
                "count": count,
                "template_ids": [tid],
                "is_unknown": True,
            }
            next_id += 1
            continue

        # 已知厂商：合并
        if vendor_name in vendor_map:
            entry = vendor_map[vendor_name]
            entry["count"] = max(entry["count"], count)
            entry["template_ids"].append(tid)
            # 存在多协议时合并
            if protocol not in entry["protocol"]:
                entry["protocol"] = f"{entry['protocol']},{protocol}"
        else:
            vendor_map[vendor_name] = {
                "id": next_id,
                "name": vendor_name,
                "protocol": protocol,
                "pattern": build_broad_pattern(vendor_name),
                "count": count,
                "template_ids": [tid],
                "is_unknown": False,
            }
            next_id += 1

    conn.close()

    # 转换为输出列表
    vendors = []
    for name, entry in sorted(vendor_map.items(), key=lambda x: x[1]['count'], reverse=True):
        vendors.append({
            "id": entry["id"],
            "name": entry["name"],
            "protocol": entry["protocol"],
            "pattern": entry["pattern"],
            "count": entry["count"],
            "template_ids": entry["template_ids"],
        })

    # 补充模板库未覆盖的常见厂商
    for name, pattern in EXTRA_VENDORS:
        vendors.append({
            "id": next_id,
            "name": name,
            "protocol": "SSH,FTP,TELNET",
            "pattern": pattern,
            "count": 0,
            "template_ids": [],
        })
        next_id += 1

    return vendors


def build_broad_pattern(vendor_name: str) -> str:
    """为已知厂商构建宽泛匹配的正则模式。
    将非字母数字分隔符替换为 .* 实现最大兼容性。
    例如: GitLab SSHD -> .*GitLab.*SSHD.*
    """
    parts = re.split(r'[^a-zA-Z0-9]+', vendor_name)
    parts = [p for p in parts if p]
    if not parts:
        return f".*{re.escape(vendor_name)}.*"
    return ".*" + ".*".join(re.escape(p) for p in parts) + ".*"


# 模板库中未覆盖但常见的厂商（手动补充）
EXTRA_VENDORS = [
    # SSH
    ("Dropbear", r".*[Dd]ropbear.*"),
    ("BusyBox", r".*BusyBox.*"),
    ("RouterOS", r".*RouterOS.*"),
    # FTP
    ("DreamHost FTP", r".*DreamHost.*FTP.*"),
    ("www.net.cn FTP", r".*www\.net\.cn.*FTP.*"),
    ("QTCP FTP", r".*QTCP.*"),
    ("Eshcom FTP", r".*Eshcom.*FTP.*"),
    ("OnShift FTP", r".*OnShift.*FTP.*"),
    ("Adeptia Internal FTP", r".*Adeptia.*FTP.*"),
    ("Lumina Datamatics FTP", r".*Lumina.*Datamatics.*FTP.*"),
    ("Phoenix Online FTP", r".*Phoenix.*Online.*FTP.*"),
    ("CoursEval FTPS", r".*CoursEval.*FTPS.*"),
    ("Hindawi FTP", r".*Hindawi.*FTP.*"),
    ("Axis Camera FTP", r".*AXIS.*Network.*Camera.*"),
    ("APC Management Card", r".*AP.*Network.*Management.*Card.*"),
    ("MikroTik", r".*MikroTik.*"),
    # === SSH 冷门厂商 ===
    ("NetScreen", r".*NetScreen.*"),
    ("Adtran", r".*Adtran.*"),
    ("MOVEit", r".*MOVEit.*"),
    ("Crestron", r".*Crestron.*"),
    ("RomSShell", r".*RomSShell.*"),
    # === FTP 高频未命中 ===
    ("Gameservers FTPD", r".*Gameservers.*FTP.*"),
    ("Arvixe FTP", r".*Arvixe.*"),
    ("Firmware Update FTP", r".*[Ff]irmware.*[Uu]pdate.*[Ff][Tt][Pp].*"),
    # === Telnet 纯文本 新增 (309未匹配中发现的) ===
    ("Ubuntu Server", r".*Ubuntu \d+\.\d+.*login:.*"),
    ("login+Password同屏设备", r".*login:.*Password:.*"),
    ("Ruijie Device", r".*[Rr]ui[Jj]ie.*"),
    ("IPCamera Telnet", r".*IP[Cc]amera.*"),
    ("ATP-Cli Device", r".*ATP.Cli.*"),
    ("Aamra Networks", r".*[Aa]amra.*"),
    ("Remote Management Console", r".*Remote Management Console.*"),
    ("HD9084 Device", r".*HD9084.*"),
    # 清洗后新发现
    ("Synchronet BBS", r".*Synchronet BBS.*"),
    ("CP841 Telnet", r".*CP841.*Telnet.*"),
    ("AC7621 Router", r".*AC7621.*"),
    ("YHTC Device", r".*YHTC.*"),
    ("sbs-ipcam", r".*sbs[- ]?ipcam.*"),
    ("ASUS Device", r".*[Aa]su login:.*"),
    ("Huawei Stelnet Warning", r".*[Ss]telnet.*"),
    # 联合聚类新发现的设备
    ("Synology DiskStation", r".*Synology.*"),
    ("ASUS Router (RT-AC)", r".*RT-AC\d+.*"),
    ("DASAN Zhone GPON", r".*DASAN.*Zhone.*"),
    ("TANDBERG Codec", r".*TANDBERG.*"),
    ("DragonWave Horizon", r".*DragonWave.*|.*Horizon_IDU.*"),
    ("UHP Satellite Modem", r".*UHP-10.*"),
    ("buildroot", r".*buildroot.*"),
    ("EdgeOS Router", r".*EdgeOS.*"),
    ("NetComm Router", r".*NetComm.*"),
    ("Debian Linux", r".*Debian GNU/Linux.*"),
    ("RTCS RTOS", r".*RTCS.*Telnet.*"),
    ("VOTER System", r".*VOTER.*System.*"),
    ("Matrix NVR", r".*Matrix[- ]NVR.*"),
    ("Adtec Telnet", r".*Adtec.*Telnet.*"),
    ("UsenetExpress NNTP", r".*UsenetExpress.*"),
    ("FG8102 Router", r".*FG8102.*"),
    ("DSL-500B Router", r".*DSL-500B.*"),
    ("XPON ONT", r".*XPON-\d+.*"),
    ("aigoWiFi", r".*aigoWiFi.*"),
    ("AsyncSSH", r".*AsyncSSH.*"),
    ("WeOnlyDo SSH", r".*WeOnlyDo.*"),
    ("PYNG-HUB", r".*PYNG-HUB.*"),
    # === 兜底族 (Fallback Family)：只匹配最小词，不覆盖设备规则 ===
    ("Embedded/Gateway (login)", r"(?<![A-Za-z])[Ll]ogin:"),
    ("Network Device (user prompt)", r"(?<![A-Za-z])[Uu]ser(?:name)?:"),
    ("Serial Gateway (password)", r"(?<![A-Za-z])[Pp]assword:"),
    ("Embedded (login+password)", r"[Ll]ogin:\s*[Pp]assword:"),
    ("[Status] Connection Refused", r".*[Cc]onnection [Rr]efused.*"),
    ("[Status] Too Many Connections", r".*[Tt]oo many connections.*|.*maximum number.*exceeded.*"),
    ("[Status] System Busy", r".*[Bb]usy.*|.*all ports.*|.*try again.*"),
    ("[Status] Access Denied", r".*[Aa]ccess [Dd]enied.*|.*[Uu]nauthorized.*"),
    ("[Status] Service Disabled", r".*[Dd]isabled.*|.*not available.*|.*[Ss]hutdown.*"),
    # === Telnet IAC 指纹 (WILL=fb, DO=fd, WONT=fc, DONT=fe → ff[fb-fe]) ===
    ("Cisco IOS telnetd", r".*ff[fb-fe]01.*ff[fb-fe]03.*ff[fb-fe]18.*ff[fb-fe]1f.*"),
    ("Linux telnetd", r".*ff[fb-fe]25.*ff[fb-fe]26.*ff[fb-fe]01.*ff[fb-fe]03.*"),
    ("BusyBox telnetd", r".*ff[fb-fe]01.*ff[fb-fe]01.*"),
    ("Windows telnetd", r".*ff[fb-fe]18.*ff[fb-fe]1f.*ff[fb-fe]22.*ff[fb-fe]27.*"),
    ("Embedded telnetd", r".*fffd01.*fffb01.*fffb03.*"),
    ("Router telnetd", r".*ff[b-fd]01.*ff[b-fd]03(?!.*ff[b-fd](?:18|1f|25|26)).*"),
    # === Telnet 文本设备指纹（覆盖面广） ===
    ("Cisco Device", r".*[Uu]ser Access Verification.*|.*[Cc]isco.*"),
    ("Broadband Router", r".*[Bb]roadband [Rr]outer.*"),
    ("Cambium Networks", r".*[Cc]ambium.*"),
    ("DD-WRT", r".*DD-WRT.*"),
    ("MikroTik RouterOS", r".*[Mm]ikro[Tt]ik.*|.*RouterOS.*"),
    ("Huawei Device", r".*[Hh]uawei.*"),
    ("Ubiquiti Device", r".*[Uu]biquiti.*|.*[Aa]ir[Mm]ax.*|.*[Ee]dge[Mm]ax.*"),
    ("OpenWrt", r".*[Oo]pen[Ww]rt.*"),
    ("D-Link Router", r".*[Dd][- ]?[Ll]ink.*"),
    ("Zyxel Device", r".*[Zz]yxel.*"),
    ("DrayTek Router", r".*[Dd]ray[Tt]ek.*|.*[Vv]igor.*"),
    ("TP-Link Router", r".*[Tt][Pp][- ]?[Ll]ink.*"),
    ("Netgear Router", r".*[Nn]et[Gg]ear.*"),
    ("ARRIS Gateway", r".*[Aa][Rr][Rr][Ii][Ss].*"),
    ("Actiontec Router", r".*[Aa]ctiontec.*"),
    ("Raspberry Pi", r".*[Rr]asp[bB]erry.*"),
    ("BusyBox", r".*[Bb]usy[Bb]ox.*"),
    ("Juniper SSG", r".*[Ss][Ss][Gg].*[Ll]ogin.*"),
    ("Fortinet", r".*[Ff]ortinet.*|.*[Ff]orti[Gg]ate.*"),
    ("pfSense", r".*pf[Ss]ense.*"),
    ("SonicWall", r".*[Ss]onic[Ww]all.*"),
    ("Technicolor Gateway", r".*[Tt]echnicolor.*"),
    ("Belkin Router", r".*[Bb]elkin.*"),
    ("Buffalo Router", r".*[Bb]uffalo.*"),
    # === Telnet 特定提示文本指纹 ===
    ("ONT Device", r".*[Oo][Nn][Tt].*[Ll]ogin.*|.*SFU.*1GE.*Micro.*"),
    ("RDK Gateway", r".*RDK.*Yocto.*"),
    ("AS400 Mainframe", r".*Sign On.*System.*"),
    ("HP JetDirect", r".*[Hh][Pp].*[Jj]et[Dd]irect.*"),
    ("APC UPS", r".*[Aa][Pp][Cc].*"),
    ("Axis Camera", r".*[Aa][Xx][Ii][Ss].*[Cc]amera.*"),
    ("Dropbear SSH", r".*[Dd]ropbear.*"),
    # === Telnet 状态/限制提示 ===
    ("Restricted Access Device", r".*[Rr]estricted [Aa]ccess.*"),
    ("Session Limited Device", r".*[Ss]ession.*[Ll]imit.*|.*[Mm]aximum.*[Tt]elnet.*|.*[Nn]o more connections.*"),
    ("Telnet Disabled/Error", r".*[Tt]elnet.*[Dd]isabled.*|.*[Tt]elnet.*[Nn]ot.*[Ss]et.*|.*[Ss]ervice.*disabled.*"),
    ("HTTP on Port 23", r".*HTTP/1\.[01] 200.*"),
    ("Connection Closed", r".*connection closed.*"),
    # === Telnet 裸 login 微特征 (字节级) ===
    # 尾部空格 + CRLF 模式
    ("Linux login (trailing space)", r".*login.*TS=1.*LE=CRLF.*"),
    ("Linux login (no space)", r".*login.*TS=0.*LE=LF.*"),
    # 双空行 + Username (Cisco风格)
    ("Cisco-style prompt", r".*prompt_type=username.*LCRLF=2.*"),
    ("Username prompt", r".*prompt_type=username.*"),
    # ANSI + 大Banner
    ("ANSI Terminal Device", r".*ANSI=1.*"),
    # NULL字节 (RTOS/嵌入式)
    ("NULL-byte Device", r".*has_null.*"),
    # 纯 IAC 签名匹配 (标准化)
    ("Linux netkit-telnetd", r".*WILL\(1\).*WILL\(3\).*"),
    ("BusyBox telnetd (iac)", r".*WILL\(1\).*DO\(3\)(?!.*DO\(24\)).*"),
    ("Full RFC telnetd", r".*DO\(24\).*DO\(31\).*DO\(32\).*"),
    # === 长度填充指纹 (固件页对齐) ===
    ("256B Padded Device", r".*LEN=256.*"),
    ("512B Padded Device", r".*LEN=512.*"),
    ("1024B Padded Device", r".*LEN=1024.*"),
    ("NULL-padded Firmware", r".*PAD=NULL.*"),
    ("SPACE-padded Firmware", r".*PAD=SPACE.*"),
]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="从 fingerprint.db 构建指纹库")
    parser.add_argument("--db", default="fingerprint.db",
                        help="SQLite 数据库路径")
    parser.add_argument("--output", default="vendors.json",
                        help="输出 JSON 文件路径")
    parser.add_argument("--csv", default=None,
                        help="可选：同时从 CSV 导出")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Error: Database not found: {db_path}")
        sys.exit(1)

    print(f"Loading templates from {db_path}...")
    vendors = build_fingerprints(str(db_path))
    print(f"Extracted {len(vendors)} fingerprint rules.")

    # 统计
    protocols = {}
    for v in vendors:
        p = v['protocol']
        protocols[p] = protocols.get(p, 0) + 1
    print("By protocol:", protocols)

    named_count = sum(1 for v in vendors if not v['name'].startswith(('SSH-', 'FTP-', 'TELNET-', 'UNKNOWN-')))
    print(f"Named vendors: {named_count}/{len(vendors)}")

    # 写入 JSON
    output = {"vendors": vendors}
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nFingerprint database written to: {args.output}")
    print(f"File size: {Path(args.output).stat().st_size} bytes")

    # 打印示例
    print("\n=== Sample rules ===")
    for v in vendors[:5]:
        print(f"  ID={v['id']:3d}  {v['protocol']:6s}  {v['name']:25s}  count={v['count']:5d}")


if __name__ == "__main__":
    main()
