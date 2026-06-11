#!/usr/bin/env python3
"""
离线指纹匹配：对 fingerprint.db 中已有的 FTP/Telnet Banner 直接跑提取+匹配，
不发起网络连接，完全本地执行。
"""
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

_parent = str(Path(__file__).parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from banner_scanner.core.parsers import (
    parse_ssh_banner, parse_ftp_banner_info, parse_telnet_banner,
    extract_banner_info, parse_ftp_features
)
from banner_scanner.core.models import BannerResult, SshBanner, FtpFeatures, TelnetBanner
from banner_scanner.core.matcher import FingerprintMatcher


def analyze_protocol(db_path: str, protocol: str, matcher: FingerprintMatcher,
                     limit: int = None):
    """对数据库内某协议的所有 Banner 执行离线分析"""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    query = f"""
        SELECT DISTINCT ip, port, banner, template_id
        FROM banner_mapping
        WHERE protocol = ? AND banner != '' AND banner IS NOT NULL
        ORDER BY RANDOM()
    """
    if limit:
        query += f" LIMIT {limit}"

    rows = conn.execute(query, (protocol.upper(),)).fetchall()
    conn.close()

    total = len(rows)
    svc_counter = Counter()
    fp_counter = Counter()
    ver_counter = Counter()
    matched = 0
    has_svc = 0

    for row in rows:
        banner = row['banner']
        ip, port = row['ip'], row['port']

        # 构造 BannerResult
        br = BannerResult(protocol=protocol.upper(), host=ip, port=port,
                          accessible=True, banner=banner)

        # 解析 Banner
        if protocol.upper() == 'FTP':
            br.ftp = parse_ftp_banner_info(banner)
        elif protocol.upper() == 'TELNET':
            br.telnet = parse_telnet_banner(b'', banner)

        # 指纹匹配
        matcher.match(br)
        br.info = extract_banner_info(br)

        if br.info.get('service_name'):
            has_svc += 1
            svc_counter[br.info['service_name']] += 1
            sv = br.info['service_name']
            ver = br.info.get('service_version', '')
            if sv == 'vsFTPd':
                ver_counter[ver] += 1
            elif sv == 'ProFTPD':
                ver_counter[ver] += 1
            elif sv == 'Pure-FTPd':
                ver_counter[ver] += 1

        if br.vendor:
            matched += 1
            fp_counter[br.vendor] += 1

    print(f"\n{'='*55}")
    print(f"  {protocol} 离线指纹匹配 ({total} 条 Banner)")
    print(f"{'='*55}")
    print(f"  总数:          {total}")
    print(f"  提取到服务商:  {has_svc} ({has_svc/max(total,1)*100:.1f}%)")
    print(f"  指纹命中:      {matched} ({matched/max(total,1)*100:.1f}%)")
    print(f"\n  服务商 Top10:")
    for name, cnt in svc_counter.most_common(10):
        print(f"    {cnt:>6}  {name}")
    if ver_counter:
        print(f"\n  版本分布:")
        for ver, cnt in ver_counter.most_common(8):
            print(f"    {cnt:>6}  {ver}")
    print(f"\n  指纹命中 Top10:")
    for fp, cnt in fp_counter.most_common(10):
        print(f"    {cnt:>6}  {fp}")

    return total, has_svc, matched


def main():
    db_path = Path(__file__).parent / "fingerprint.db"
    fp_path = Path(__file__).parent / "vendors.json"

    if not db_path.exists():
        print(f"Error: {db_path} not found")
        sys.exit(1)

    matcher = FingerprintMatcher.load(fp_path)
    print(f"Loaded {matcher.rule_count} fingerprint rules")

    # FTP + Telnet 各取 5 万分析
    for proto in ['FTP', 'TELNET']:
        analyze_protocol(str(db_path), proto, matcher, limit=50000)


if __name__ == "__main__":
    main()
