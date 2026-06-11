#!/usr/bin/env python3
"""
测试扫描器：从 fingerprint.db 中采样 IP，执行 Banner 探测 + 指纹匹配，
并验证匹配准确率。

用法:
    python3 scanner_test.py [--sample 50] [--timeout 3.0] [--retries 2]
"""

import argparse
import asyncio
import json
import logging
import random
import sqlite3
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

# 添加项目父目录到 path (banner_scanner 是 package)
_parent = str(Path(__file__).parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from banner_scanner.core.models import ProbeConfig, ProtocolConfig
from banner_scanner.core.engine import ProbeEngine
from banner_scanner.core.matcher import FingerprintMatcher

logger = logging.getLogger("banner_scanner.test")


# ==================== 数据库读取 ====================

def load_sample_ips(db_path: str, sample_size: int = 50,
                    protocol: Optional[str] = None) -> list[dict]:
    """从 banner_mapping 表中随机采样 IP 记录。

    Returns:
        [{ip, port, protocol, banner, template_id}]
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    where = ""
    params = []
    if protocol:
        where = "WHERE protocol = ?"
        params.append(protocol.upper())

    # 先获取总记录数
    count_row = conn.execute(
        f"SELECT COUNT(*) as cnt FROM banner_mapping {where}", params
    ).fetchone()
    total = count_row['cnt']
    logger.info("Total banner_mapping records: %d", total)

    # 随机采样 - 使用 ROWID 随机采样 (更快)
    sample = []
    # 按协议分层采样
    protocols = ['SSH', 'FTP', 'TELNET']
    per_proto = max(1, sample_size // len(protocols))

    for proto in protocols:
        proto_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM banner_mapping WHERE protocol=?",
            (proto,)
        ).fetchone()['cnt']

        if proto_count == 0:
            continue

        # 随机选取 ROWID 范围中的记录
        rows = conn.execute("""
            SELECT banner_seq, ip, port, protocol, banner, template_id
            FROM banner_mapping
            WHERE protocol = ?
            ORDER BY RANDOM()
            LIMIT ?
        """, (proto, per_proto)).fetchall()

        for r in rows:
            sample.append({
                'ip': r['ip'],
                'port': r['port'],
                'protocol': r['protocol'],
                'banner': r['banner'],
                'template_id': r['template_id'],
            })

    conn.close()
    random.shuffle(sample)
    logger.info("Sampled %d IPs from banner_mapping", len(sample))
    return sample


def load_template_map(db_path: str) -> dict[int, dict]:
    """加载模板映射 (template_id -> {name, pattern, protocol})"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, protocol, template, pattern, vendor, count FROM templates"
    ).fetchall()
    conn.close()

    return {
        r['id']: {
            'protocol': r['protocol'],
            'template': r['template'],
            'pattern': r['pattern'],
            'vendor': r['vendor'],
            'count': r['count'],
        }
        for r in rows
    }


# ==================== 扫描执行 ====================

async def run_scan(sample: list[dict], config: ProbeConfig,
                   matcher: FingerprintMatcher) -> list[dict]:
    """对采样 IP 执行探测"""
    engine = ProbeEngine(config)
    engine._matcher = matcher  # 直接注入匹配器

    results = []
    total = len(sample)
    logger.info("Starting scan of %d targets...", total)

    for i, record in enumerate(sample):
        host = record['ip']
        proto = record['protocol'].lower()
        port = record['port']

        try:
            host_result = await engine.probe_host(host, protocols=[proto])

            br = host_result.results.get(proto)
            if br:
                result = {
                    'target_ip': host,
                    'target_port': port,
                    'protocol': proto.upper(),
                    'expected_banner': record['banner'],
                    'expected_template_id': record['template_id'],
                    'probe_accessible': br.accessible,
                    'probe_banner': br.banner,
                    'probe_banner_truncated': br.banner_truncated,
                    'probe_error': br.error,
                    'probe_time_ms': br.response_time_ms,
                    'probe_retry_count': br.retry_count,
                    'probe_retry_elapsed_ms': br.retry_elapsed_ms,
                    # 提取的有效信息
                    'extracted_info': br.info,
                    'matched_vendor': br.vendor,
                    'matched_vendor_id': br.vendor_id,
                    'matched_confidence': br.vendor_confidence,
                    'matched_rules': [
                        {'id': m.vendor_id, 'name': m.vendor_name}
                        for m in br.matched_rules
                    ],
                    'host_total_time_ms': host_result.total_time_ms,
                }
            else:
                result = {
                    'target_ip': host,
                    'target_port': port,
                    'protocol': proto.upper(),
                    'expected_banner': record['banner'],
                    'expected_template_id': record['template_id'],
                    'probe_accessible': False,
                    'probe_error': f"No result for protocol {proto}",
                }

            results.append(result)

            # 进度输出
            if (i + 1) % max(1, total // 10) == 0:
                acc = sum(1 for r in results if r.get('probe_accessible'))
                matched = sum(1 for r in results if r.get('matched_vendor_id'))
                logger.info(
                    "Progress: %d/%d (accessible=%d, fingerprint_matched=%d)",
                    i + 1, total, acc, matched,
                )

        except Exception as e:
            logger.error("Scan failed for %s:%d: %s", host, port, e)
            results.append({
                'target_ip': host,
                'target_port': port,
                'protocol': proto.upper(),
                'expected_banner': record['banner'],
                'expected_template_id': record['template_id'],
                'probe_accessible': False,
                'probe_error': str(e),
            })

    return results


# ==================== 报告生成 ====================

def generate_report(results: list[dict], template_map: dict[int, dict],
                    output_path: str) -> dict:
    """生成扫描报告"""
    total = len(results)
    accessible = [r for r in results if r.get('probe_accessible')]
    inaccessible = [r for r in results if not r.get('probe_accessible')]
    matched = [r for r in accessible if r.get('matched_vendor_id')]
    unmatched = [r for r in accessible if not r.get('matched_vendor_id')]

    # 按协议统计
    by_proto = defaultdict(lambda: {'total': 0, 'accessible': 0, 'matched': 0})
    for r in results:
        p = r['protocol']
        by_proto[p]['total'] += 1
        if r.get('probe_accessible'):
            by_proto[p]['accessible'] += 1
        if r.get('matched_vendor_id'):
            by_proto[p]['matched'] += 1

    # 匹配详情
    match_details = []
    for r in matched[:10]:
        tid = r['expected_template_id']
        tpl_info = template_map.get(tid, {})
        match_details.append({
            'ip': r['target_ip'],
            'port': r['target_port'],
            'protocol': r['protocol'],
            'probe_banner': r.get('probe_banner', '')[:120],
            'expected_template_id': tid,
            'expected_template': tpl_info.get('template', '')[:80],
            'extracted_info': r.get('extracted_info', {}),
            'matched_vendor': r['matched_vendor'],
            'matched_id': r['matched_vendor_id'],
            'retry_count': r.get('probe_retry_count', 0),
        })

    # 未匹配样本
    unmatched_samples = []
    for r in unmatched[:10]:
        unmatched_samples.append({
            'ip': r['target_ip'],
            'port': r['target_port'],
            'protocol': r['protocol'],
            'probe_banner': r.get('probe_banner', '')[:120],
            'extracted_info': r.get('extracted_info', {}),
            'error': r.get('probe_error', ''),
        })

    # 重试统计
    retry_used = [r for r in accessible if r.get('probe_retry_count', 0) > 0]

    report = {
        'scan_summary': {
            'total_targets': total,
            'accessible': len(accessible),
            'accessible_pct': round(len(accessible) / max(total, 1) * 100, 1),
            'inaccessible': len(inaccessible),
            'fingerprint_matched': len(matched),
            'match_rate_pct': round(len(matched) / max(len(accessible), 1) * 100, 1),
            'unmatched': len(unmatched),
            'retry_used_count': len(retry_used),
        },
        'by_protocol': {
            p: {
                'total': s['total'],
                'accessible': s['accessible'],
                'accessible_pct': round(s['accessible'] / max(s['total'], 1) * 100, 1),
                'matched': s['matched'],
                'match_rate_pct': round(s['matched'] / max(s['accessible'], 1) * 100, 1),
            }
            for p, s in sorted(by_proto.items())
        },
        'match_samples': match_details,
        'unmatched_samples': unmatched_samples,
        'retry_stats': {
            'targets_with_retry': len(retry_used),
            'avg_retries': round(
                sum(r.get('probe_retry_count', 0) for r in retry_used) / max(len(retry_used), 1), 1
            ) if retry_used else 0,
        },
    }

    # 写入文件
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return report


def print_report(report: dict):
    """打印报告摘要"""
    s = report['scan_summary']
    bp = report['by_protocol']
    rs = report['retry_stats']

    print("\n" + "=" * 60)
    print("  📊  Banner Scanner - 测试扫描报告")
    print("=" * 60)
    print(f"  总目标数:       {s['total_targets']}")
    print(f"  可达:           {s['accessible']} ({s['accessible_pct']}%)")
    print(f"  不可达:         {s['inaccessible']}")
    print(f"  指纹匹配成功:   {s['fingerprint_matched']} ({s['match_rate_pct']}%)")
    print(f"  未匹配:         {s['unmatched']}")
    print(f"  使用重试:       {rs['targets_with_retry']} (平均 {rs['avg_retries']} 次)")
    print("-" * 60)
    print("  按协议:")
    for proto, stats in bp.items():
        print(f"    {proto:8s}: {stats['total']:4d} 目标, "
              f"{stats['accessible']:4d} 可达({stats['accessible_pct']:5.1f}%), "
              f"{stats['matched']:4d} 匹配({stats['match_rate_pct']:5.1f}%)")
    print("=" * 60)

    if report['match_samples']:
        print("\n  ✅ 匹配样例:")
        for m in report['match_samples'][:5]:
            info = m.get('extracted_info', {})
            print(f"    {m['ip']}:{m['port']} [{m['protocol']}]")
            print(f"      Banner: {m['probe_banner'][:100]}")
            print(f"      服务商:  {info.get('service_name', '-')}")
            print(f"      版本号:  {info.get('service_version', '-')}")
            print(f"      操作系统: {info.get('os', '-')} {info.get('os_version', '-')}")
            print(f"      指纹匹配: {m['matched_vendor']} (ID={m['matched_id']})")
            if m['retry_count']:
                print(f"      Retries: {m['retry_count']}")

    if report['unmatched_samples']:
        print("\n  ❌ 未匹配样例:")
        for m in report['unmatched_samples'][:5]:
            info = m.get('extracted_info', {})
            print(f"    {m['ip']}:{m['port']} [{m['protocol']}]")
            print(f"      Banner: {m['probe_banner'][:100]}")
            if info.get('service_name'):
                print(f"      服务商:  {info.get('service_name')}")
            if info.get('os'):
                print(f"      操作系统: {info.get('os')} {info.get('os_version', '')}")
            if m.get('error'):
                print(f"      Error: {m['error'][:80]}")


# ==================== 主入口 ====================

async def main():
    parser = argparse.ArgumentParser(
        description="Banner Scanner 测试扫描 - 从 fingerprint.db 采样 IP 进行探测验证"
    )
    parser.add_argument("--db", default="fingerprint.db",
                        help="SQLite 数据库路径")
    parser.add_argument("--fingerprints", default="vendors.json",
                        help="vendors.json 指纹库路径")
    parser.add_argument("--sample", type=int, default=50,
                        help="采样 IP 数量 (默认 50)")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="连接超时 (秒)")
    parser.add_argument("--retries", type=int, default=2,
                        help="最大重试次数 (默认 2)")
    parser.add_argument("--output", default="scan_report.json",
                        help="报告输出路径")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="详细日志")
    args = parser.parse_args()

    # 日志设置
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # 检查文件
    db_path = Path(args.db)
    fp_path = Path(args.fingerprints)
    if not db_path.exists():
        print(f"Error: Database not found: {db_path}")
        sys.exit(1)
    if not fp_path.exists():
        print(f"Error: Fingerprint file not found: {fp_path}")
        sys.exit(1)

    # 1. 加载采样 IP
    print(f"📡 Loading sample IPs from {db_path}...")
    sample = load_sample_ips(str(db_path), sample_size=args.sample)

    if not sample:
        print("No IPs sampled. Exiting.")
        return

    print(f"   Sampled {len(sample)} IPs across {len(set(r['protocol'] for r in sample))} protocols")

    # 2. 加载模板映射（用于对比）
    template_map = load_template_map(str(db_path))

    # 3. 加载指纹库
    print(f"🔍 Loading fingerprint database: {fp_path}...")
    matcher = FingerprintMatcher.load(fp_path)
    print(f"   Loaded {matcher.rule_count} fingerprint rules")

    # 4. 配置探测引擎（含重试）
    config = ProbeConfig(
        connect_timeout=args.timeout,
        read_timeout=args.timeout * 1.5,
        max_retries=args.retries,
        retry_base_delay=1.0,
        fingerprint_path=str(fp_path),
    )

    # 5. 执行扫描
    print(f"\n🚀 Starting scan with {args.retries} retries, timeout={args.timeout}s...")
    start_time = time.time()
    scan_results = await run_scan(sample, config, matcher)
    elapsed = time.time() - start_time
    print(f"   Scan completed in {elapsed:.1f}s")

    # 6. 生成报告
    report = generate_report(scan_results, template_map, args.output)
    print_report(report)
    print(f"\n📄 Detailed report saved to: {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
