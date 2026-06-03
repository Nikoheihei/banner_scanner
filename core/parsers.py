"""协议 Banner 解析器。与 C++ 版 parse_ssh_version / parse_ftp_feat 一一对应。"""

from .models import SshBanner, FtpFeatures


def parse_ssh_banner(banner: str) -> SshBanner:
    """解析 SSH Banner，对应 C++ 版 SshProtocol::parse_capabilities

    格式: SSH-{proto_ver}-{software_id}[ {comments}]
    示例: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
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
    if not sw_id:
        return info

    underscore_pos = sw_id.find("_")
    if underscore_pos != -1:
        info.software = sw_id[:underscore_pos]
        info.version = sw_id[underscore_pos + 1:]
    else:
        last_dash = sw_id.rfind("-")
        if last_dash > 0:
            info.software = sw_id[:last_dash]
            info.version = sw_id[last_dash + 1:]
        else:
            info.software = sw_id

    return info


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
        # RFC 2389: 特性行以空格/制表符开头
        if line[0] in (" ", "\t"):
            features.append(stripped)
    return ", ".join(features)
