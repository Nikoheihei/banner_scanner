"""协议 Banner 解析器。提取软件名、版本号、操作系统等有效信息。"""

import re
from typing import Optional, Tuple

from .models import SshBanner, FtpFeatures, TelnetBanner, BannerResult


# ==================== SSH 解析 ====================

# OS 指纹数据库: (banner regex pattern, os_type, os_version 提取)
OS_PATTERNS = [
    # Debian 系
    (r'Ubuntu-(\d+ubuntu[\d.]+)', 'Ubuntu'),
    (r'Debian-(\d+\+deb\d+u\d+)', 'Debian'),
    (r'Debian-(\d+~bpo\d+\+\d+)', 'Debian'),
    (r'Raspbian-(\d+)', 'Raspbian'),
    (r'kali(\d*)', 'Kali'),
    # RedHat 系
    (r'(?:el|rhel)(\d+)[._]', 'RHEL/CentOS'),
    (r'fc(\d+)', 'Fedora'),
    # BSD 系
    (r'FreeBSD-([\d._]+)', 'FreeBSD'),
    (r'OpenBSD[._-]([\d.]+)', 'OpenBSD'),
    (r'NetBSD[._-]([\d.]+)', 'NetBSD'),
    # Windows
    (r'(?:for_Windows|Win32|Windows)[_ ]([\d.]+)?', 'Windows'),
    # 其他
    (r'(?:SUSE|suse)[._-]?([\d.]+)?', 'SUSE'),
    (r'Gentoo', 'Gentoo'),
    (r'Arch(?:\sLinux)?', 'Arch Linux'),
    (r'Alpine[._-]?([\d.]+)?', 'Alpine'),
    (r'Darwin[._-]?([\d.]+)?', 'macOS'),
    (r'Solaris[._-]?([\d.]+)?', 'Solaris'),
    (r'Cisco', 'Cisco IOS'),
    # 通用版本号模式 (fallback)
    (r'(?:^|\s)([\w]+)-([\d.]+[a-z]?\d*)(?:\s|$)', None),  # generic
]

# SSH 软件名标准化
SSH_SOFTWARE_ALIASES = {
    'openssh': 'OpenSSH',
    'dropbear': 'Dropbear',
    'aws_sftp': 'AWS SFTP',
    'files.com': 'FILES.COM',
    'cerberusftpserver': 'Cerberus FTP',
    'sftpgoplus': 'SFTPGo Plus',
    'sftpgo': 'SFTPGo',
    'crushftpd': 'CrushFTPD',
    'crushftpsshd': 'CrushFTP',
    'proftpd': 'ProFTPD',
    'mod_sftp': 'mod_sftp',
    'gitlab-sshd': 'GitLab SSHD',
    'goanywhere': 'GoAnywhere',
    'maverick_sshd': 'Maverick SSHD',
    'wingftpserver': 'Wing FTP',
    'bitvise': 'Bitvise',
    'winsshd': 'Bitvise',
    'flowssh': 'Bitvise',
    'vshell': 'VShell',
    'weonlydo': 'WeOnlyDo',
    'wodftpd': 'WeOnlyDo',
    'xlightftpd': 'xlightftpd',
    'paramiko': 'Paramiko',
    'domo': 'Domo',
    'platform.sh': 'Platform.sh',
    'sshd-core': 'SSHD-CORE',
    'srtsshserver': 'srtSSHServer',
    'babeld': 'babeld',
    'audiocodes': 'AudioCodes',
    'nielsen': 'Nielsen SFTP',
    'sshpier': 'SSHPiper',
    'go': 'Go SSH',
    'ssh2js': 'ssh2js',
    'mutur': 'mutUr',
    # 扫描发现的冷门厂商
    'netscreen': 'NetScreen',
    'adtran': 'Adtran',
    'rosssh': 'ROSSSH',
    'romsshell': 'RomSShell',
    'cradlepoint': 'Cradlepoint',
    'arris': 'ARRIS',
    'coreftp': 'CoreFTP',
    'ipssh': 'IPSSH',
    'moveit': 'MOVEit',
    'mpssh': 'mpSSH',
    'crestron': 'Crestron',
    'cryptlib': 'cryptlib',
}


def parse_ssh_banner(banner: str) -> SshBanner:
    """解析 SSH Banner，提取软件名、版本号、操作系统。

    格式: SSH-{proto_ver}-{software_id}[ {comments}]
    示例: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
    """
    info = SshBanner(version_string=banner)

    if len(banner) < 6 or not banner.startswith("SSH-"):
        return info

    parts = banner.split("-", 2)
    if len(parts) < 3:
        return info

    info.protocol_version = parts[1]

    rest = parts[2]
    space_pos = rest.find(" ")
    sw_id = rest[:space_pos] if space_pos != -1 else rest
    info.comments = rest[space_pos + 1:] if space_pos != -1 else ""

    if not sw_id:
        return info

    # --- 软件名和版本 ---
    software, version = _parse_ssh_software_version(sw_id)
    info.software = software
    info.version = version

    # --- 操作系统信息 ---
    os_type, os_version = _parse_ssh_os(info.comments)
    info.os_type = os_type
    info.os_version = os_version
    if os_type:
        info.os_distro = f"{os_type}-{os_version}" if os_version else os_type

    return info


def _parse_ssh_software_version(sw_id: str) -> Tuple[str, str]:
    """从 software_id 字段提取软件名和版本号。
    例如: OpenSSH_8.9p1 -> ('OpenSSH', '8.9p1')
          Cisco-1.25    -> ('Cisco', '1.25')
    """
    underscore_pos = sw_id.find("_")
    if underscore_pos != -1:
        raw_soft = sw_id[:underscore_pos]
        raw_ver = sw_id[underscore_pos + 1:]
    else:
        last_dash = sw_id.rfind("-")
        if last_dash > 0:
            raw_soft = sw_id[:last_dash]
            raw_ver = sw_id[last_dash + 1:]
        else:
            raw_soft = sw_id
            raw_ver = ""

    # 标准化软件名
    software = SSH_SOFTWARE_ALIASES.get(raw_soft.lower(), raw_soft)
    return software, raw_ver


def _parse_ssh_os(comments: str) -> Tuple[str, str]:
    """从 SSH comments 中提取操作系统类型和版本。

    返回: (os_type, os_version)
    """
    if not comments:
        return "", ""

    for pattern, os_name in OS_PATTERNS:
        m = re.search(pattern, comments, re.IGNORECASE)
        if m and os_name:
            ver = m.group(1) if m.lastindex else ""
            return os_name, ver

    # 无匹配时尝试提取通用标识
    # 如 "Debian/Ubuntu" -> 可能是 Debian
    if re.search(r'debian|ubuntu', comments, re.IGNORECASE):
        return "Linux", comments[:40]
    if re.search(r'freebsd|openbsd|netbsd', comments, re.IGNORECASE):
        return "BSD", comments[:40]

    return "", ""


# ==================== FTP 解析 ====================

# FTP Banner 软件识别模式: (regex, software_name, version_group)
FTP_SOFTWARE_PATTERNS = [
    # 知名软件
    (r'vsFTPd\s*([\d.]+)', 'vsFTPd', 1),
    (r'FileZilla\s+Server\s*([\d.]+(?:\s*beta)?)', 'FileZilla Server', 1),
    (r'FileZilla\s+Pro\s+Enterprise\s+Server\s*([\d.]+)', 'FileZilla Pro Enterprise', 1),
    (r'Pure-FTPd\s*\[?([^\]]*)\]?', 'Pure-FTPd', 1),
    (r'ProFTPD\s*([\d.a-z]+(?:rc\d+)?)\s+Server', 'ProFTPD', 1),
    (r'Microsoft\s+FTP\s+Service\s*(?:\(Version\s*([\d.]+)\))?', 'Microsoft FTP', 1),
    (r'Serv-U\s+FTP\s+Server\s*([\d.]+)?', 'Serv-U FTP', 1),
    (r'Core\s+FTP\s+Server\s+Version\s*([\d.]+)', 'Core FTP Server', 1),
    (r'pyftpdlib\s*([\d.]+)', 'pyftpdlib', 1),
    (r'Alpine\s+ftp\s+server\s*\(?([^)]*)\)?', 'Alpine FTP', 1),
    (r'WS_FTP\s+Server\s*([\d.]+(?:\(\d+\))?)', 'WS_FTP', 1),
    (r'Wing\s+FTP\s+Server\s*\(?([^)]*)\)?', 'Wing FTP', 1),
    (r'Cerberus\s+FTP\s+Server\s*([\d.]+)?', 'Cerberus FTP', 1),
    (r'CrushFTP\s*([\d.]+)?', 'CrushFTP', 1),
    (r'xlight\s+FTP\s+Server\s*([\d.]+)?', 'xlight FTP', 1),
    (r'MikroTik', 'MikroTik', 0),
    # 从扫描结果发现的新厂商
    (r'DreamHost\s+FTP', 'DreamHost FTP', 0),
    (r'www\.net\.cn\s+FTP', 'www.net.cn FTP', 0),
    (r'QTCP\s+at', 'QTCP FTP', 0),
    (r'Eshcom\s+FTP', 'Eshcom FTP', 0),
    (r'OnShift\s+FTP', 'OnShift FTP', 0),
    (r'Adeptia\s+Internal\s+FTP', 'Adeptia Internal FTP', 0),
    (r'Lumina\s+Datamatics\s+FTP', 'Lumina Datamatics FTP', 0),
    (r'Phoenix\s+Online.*FTP', 'Phoenix Online FTP', 0),
    (r'CoursEval\s+FTPS', 'CoursEval FTPS', 0),
    (r'Hindawi\s+FTP', 'Hindawi FTP', 0),
    (r'AXIS\s+\d+.*Network\s+Camera', 'Axis Camera FTP', 0),
    (r'AP\d+.*Network\s+Management\s+Card', 'APC Management Card', 0),
    # 扫描发现的高频厂商
    (r'DreamHost\s+FTP\s+Server', 'DreamHost FTP', 0),
    (r'Gameservers\s+FTPD?\s*v?([\d.]+)', 'Gameservers FTPD', 1),
    (r'Arvixe', 'Arvixe FTP', 0),
    (r'Ftp\s+firmware\s+update\s+utility', 'Firmware Update FTP', 0),
    # 通用模式：提取 "220 XXX FTP" 中的厂商名
    (r'220[-\s]+(?:Welcome\s+to\s+)?(.+?)\s+(?:FTP|ftp)', None, 1),
]


def parse_ftp_banner_info(banner: str, features: str = "") -> FtpFeatures:
    """从 FTP Banner 提取软件信息和特性。

    返回: FtpFeatures (含 software, version)
    """
    info = FtpFeatures(features=features)
    info.full_banner = banner

    if not banner:
        return info

    # 第一行作为主 Banner
    first_line = banner.split("\n")[0].strip()

    # 提取软件和版本
    software, version = _parse_ftp_software(first_line)
    info.software = software
    info.version = version

    return info


def _parse_ftp_software(banner_line: str) -> Tuple[str, str]:
    """从 FTP Banner 行提取软件名和版本号"""
    if not banner_line:
        return "", ""

    for pattern, name, ver_group in FTP_SOFTWARE_PATTERNS:
        m = re.search(pattern, banner_line, re.IGNORECASE)
        if m:
            if name is None:
                # 通用提取模式
                software = m.group(1) if (m.lastindex or 0) >= 1 else m.group(0)
                return software.strip(), ""
            version = m.group(ver_group) if ver_group and (m.lastindex or 0) >= ver_group else ""
            return name, version.strip() if version else ""

    return "", ""


def parse_ftp_features(features_csv: str) -> FtpFeatures:
    """解析 FTP FEAT 特性列表，对应 C++ 版 parse_ftp_features

    输入: "UTF8, AUTH TLS, SIZE, MDTM, MLSD, TVFS"
    """
    info = FtpFeatures(features=features_csv)

    for feat in features_csv.split(","):
        feat = feat.strip().upper()
        if feat == "UTF8":
            info.utf8 = True
        elif feat == "AUTH TLS":
            info.auth_tls = True
        elif feat == "AUTH SSL":
            info.auth_ssl = True
        elif feat == "SIZE":
            info.size_cmd = True
        elif feat == "MDTM":
            info.mdtm = True
        elif feat in ("MLSD", "MLST"):
            info.mldst = True
        elif feat == "TVFS":
            info.tvfs = True
        elif feat == "XCRC":
            info.xcrc = True
        elif feat == "XCUP":
            info.xcup = True

    return info


def extract_ftp_features_from_lines(lines: list[str]) -> str:
    """从 FEAT 响应行中提取特性名列表（逗号分隔）

    对应 C++ 版 FtpProbeContext 中 features_accum 的构建逻辑。
    """
    features = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if line[0] in (" ", "\t"):
            features.append(stripped)
    return ", ".join(features)


# ==================== Telnet 解析 ====================

TELNET_LOGIN_PATTERNS = [
    r'login:', r'username:', r'user:', r'password:',
    r'Welcome', r'Unauthorized', r'Authorized',
    r'Ubuntu', r'Debian', r'CentOS', r'Red Hat', r'Fedora',
    r'Cisco', r'Router', r'Switch',
    r'BusyBox', r'DD-WRT', r'OpenWrt',
]


def parse_telnet_banner(raw_data: bytes, clean_text: str) -> TelnetBanner:
    """解析 Telnet 原始数据，提取服务信息和登录提示。

    Args:
        raw_data: 原始字节数据
        clean_text: 过滤 IAC 后的文本

    Returns:
        TelnetBanner 解析结果
    """
    info = TelnetBanner(banner=clean_text)

    # 原始 hex (前 64 字节)
    hex_len = min(len(raw_data), 64)
    info.banner_raw_hex = raw_data[:hex_len].hex()

    # 检查 IAC 协商
    info.has_iac_negotiation = b'\xff' in raw_data

    # 提取可读文本
    lines = clean_text.splitlines()
    readable = [l.strip() for l in lines if l.strip()]
    info.extracted_text = "\n".join(readable[:20])  # 最多 20 行

    # 检测登录提示
    for pattern in TELNET_LOGIN_PATTERNS:
        if re.search(pattern, clean_text, re.IGNORECASE):
            info.has_login_prompt = True
            break

    # 检测服务类型
    detected = _detect_telnet_service(clean_text)
    info.detected_service = detected

    return info


def _detect_telnet_service(text: str) -> str:
    """从 Telnet 文本检测服务类型"""
    if not text:
        return ""

    detections = [
        (r'Cisco|IOS|Router|Switch', 'Cisco Device'),
        (r'BusyBox|DD-WRT|OpenWrt|Tomato', 'Embedded Linux'),
        (r'Ubuntu|Debian|CentOS|Red Hat|Fedora|SUSE', 'Linux Server'),
        (r'FreeBSD|OpenBSD|NetBSD', 'BSD Server'),
        (r'Windows|Win32|Microsoft', 'Windows Server'),
        (r'MikroTik|RouterOS', 'MikroTik'),
        (r'HP|JetDirect|Printer', 'Printer/HP JetDirect'),
        (r'Apache|nginx|HTTP', 'HTTP Service'),
        (r'SMTP|Postfix|Sendmail|Exim', 'Mail Server'),
        (r'FTP|vsFTPd|ProFTPD', 'FTP Server'),
    ]

    for pattern, service in detections:
        if re.search(pattern, text, re.IGNORECASE):
            return service

    return ""


# ==================== 统一信息提取 ====================

def extract_banner_info(result: BannerResult) -> dict:
    """从 BannerResult 统一提取有效信息，返回结构化字典。

    Returns:
        {
            "service_name": str,       # 服务名/软件名
            "service_version": str,    # 版本号
            "os": str,                 # 操作系统
            "os_version": str,         # 操作系统版本
            "protocol": str,           # 协议
            "features": list[str],     # 特性列表
            "raw_summary": str,        # Banner 摘要 (前 200 字符)
        }
    """
    info = {
        "service_name": "",
        "service_version": "",
        "os": "",
        "os_version": "",
        "protocol": result.protocol,
        "features": [],
        "raw_summary": result.banner[:200] if result.banner else "",
    }

    if result.protocol == "SSH" and result.ssh:
        s = result.ssh
        info["service_name"] = s.software
        info["service_version"] = s.version
        info["os"] = s.os_type
        info["os_version"] = s.os_version
        info["protocol_version"] = s.protocol_version
        info["comments"] = s.comments[:200] if s.comments else ""

    elif result.protocol == "FTP" and result.ftp:
        f = result.ftp
        info["service_name"] = f.software
        info["service_version"] = f.version
        if f.utf8: info["features"].append("UTF8")
        if f.auth_tls: info["features"].append("AUTH TLS")
        if f.auth_ssl: info["features"].append("AUTH SSL")
        if f.mldst: info["features"].append("MLSD/MLST")
        if f.size_cmd: info["features"].append("SIZE")
        if f.mdtm: info["features"].append("MDTM")

    elif result.protocol == "TELNET" and result.telnet:
        t = result.telnet
        info["service_name"] = t.detected_service
        info["has_login_prompt"] = t.has_login_prompt
        info["has_iac_negotiation"] = t.has_iac_negotiation
        info["extracted_text"] = t.extracted_text[:500] if t.extracted_text else ""

    # 指纹匹配结果也合并进来
    if result.vendor:
        if not info["service_name"]:
            info["service_name"] = result.vendor
        info["fingerprint_vendor"] = result.vendor
        info["fingerprint_vendor_id"] = result.vendor_id

    return info
