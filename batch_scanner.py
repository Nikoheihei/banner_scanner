#!/usr/bin/env python3
"""
批量扫描器：对 fingerprint.db 中 banner_mapping 表的所有 IP 进行大规模并发探测。
结果写入 scan_output.txt (逐行 JSON)，支持断点续传。

用法:
    python3 batch_scanner.py --concurrency 300 --timeout 2.0 --output scan_output.txt

    # 断点续传 (自动跳过已扫描)
    python3 batch_scanner.py -c 300 --resume

    # 限制数量
    python3 batch_scanner.py -c 100 --limit 5000

    # 仅某协议
    python3 batch_scanner.py -c 200 --protocol FTP
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

_parent = str(Path(__file__).parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from banner_scanner.core.models import ProbeConfig
from banner_scanner.core.engine import ProbeEngine
from banner_scanner.core.matcher import FingerprintMatcher

logger = logging.getLogger("batch_scanner")

# ==================== 目标加载 ====================

def load_targets(db_path: str, protocol: str = None,
                 limit: int = None, random_sample: bool = False) -> list[dict]:
    """加载去重后的 (ip, port, protocol) 目标列表"""
    import sqlite3
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    where, params = "", []
    if protocol:
        where = "WHERE protocol = ?"
        params.append(protocol.upper())
    order = "ORDER BY RANDOM()" if random_sample else ""
    query = f"""
        SELECT ip, port, protocol
        FROM banner_mapping {where}
        GROUP BY ip, port, protocol
        {order}
    """
    if limit:
        query += f" LIMIT {limit}"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    targets = [{'ip': r['ip'], 'port': r['port'], 'protocol': r['protocol']} for r in rows]
    logger.info("Loaded %d unique targets", len(targets))
    return targets


def load_scanned_set(output_path: str) -> set:
    """从已有输出文件读取已扫描的 (ip, port, protocol)"""
    scanned = set()
    if not os.path.exists(output_path):
        return scanned
    with open(output_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                scanned.add((obj['ip'], obj['port'], obj['protocol']))
            except json.JSONDecodeError:
                continue
    logger.info("Loaded %d already-scanned entries from %s", len(scanned), output_path)
    return scanned


# ==================== 并发扫描 ====================

async def scan_batch(targets: list[dict], engine: ProbeEngine,
                     semaphore: asyncio.Semaphore,
                     output_file: str, chunk_size: int = 5000,
                     progress_interval: int = 1000):
    """分块高并发扫描，增量写入结果，避免一次性创建数百万协程撑爆内存"""
    scanned_count = 0
    accessible_count = 0
    start_time = time.time()
    lock = asyncio.Lock()
    progress_file = output_file + ".progress"

    async def probe_one(target: dict) -> dict:
        nonlocal scanned_count, accessible_count
        ip, port, proto = target['ip'], target['port'], target['protocol']

        async with semaphore:
            try:
                br = await engine.probe_single(ip, port, proto.lower())
            except Exception as e:
                br = None
                error = str(e)

        if br and br.accessible:
            info = br.info if br.info else {}
            result = {
                'ip': ip, 'port': port, 'protocol': proto.upper(),
                'accessible': 1,
                'banner': br.banner[:500],
                'banner_truncated': br.banner_truncated,
                'response_time_ms': round(br.response_time_ms, 1),
                'service_name': info.get('service_name', ''),
                'service_version': info.get('service_version', ''),
                'os': info.get('os', ''),
                'os_version': info.get('os_version', ''),
                'fingerprint_vendor': info.get('fingerprint_vendor', ''),
                'fingerprint_vendor_id': info.get('fingerprint_vendor_id', 0),
                'fingerprint_rule_ids': info.get('fingerprint', {}).get('matched_rule_ids', []),
                'deployment_mode': info.get('deployment_mode', ''),
                'auth_method': info.get('auth_method', ''),
                'auth_plugin': info.get('auth_plugin', ''),
                'sqlstate': info.get('sqlstate', ''),
                'retry_count': br.retry_count,
            }
            accessible_count += 1
        else:
            result = {
                'ip': ip, 'port': port, 'protocol': proto.upper(),
                'accessible': 0,
                'banner': '',
                'error': br.error if br else error,
            }

        async with lock:
            scanned_count += 1
            with open(output_file, 'a') as f:
                f.write(json.dumps(result, ensure_ascii=False) + '\n')

            if scanned_count % progress_interval == 0:
                elapsed = time.time() - start_time
                rate = scanned_count / elapsed if elapsed > 0 else 0
                eta = (len(targets) - scanned_count) / rate if rate > 0 else 0
                logger.info(
                    "Progress: %d/%d (%.1f%%) | accessible=%d | %.0f/s | ETA %.0fmin",
                    scanned_count, len(targets),
                    scanned_count / max(len(targets), 1) * 100,
                    accessible_count, rate, eta / 60,
                )
                with open(progress_file, 'w') as pf:
                    pf.write(f"{scanned_count}\n")

        return result

    # 分块处理，每块最多 chunk_size 个目标
    total = len(targets)
    for chunk_start in range(0, total, chunk_size):
        chunk = targets[chunk_start:chunk_start + chunk_size]
        tasks = [probe_one(t) for t in chunk]
        await asyncio.gather(*tasks)
        logger.debug("Chunk %d-%d complete", chunk_start, min(chunk_start + chunk_size, total))

    elapsed = time.time() - start_time
    logger.info("=" * 50)
    logger.info(
        "Scan complete: %d targets in %.0fmin | accessible=%d (%.1f%%) | %.0f/s",
        scanned_count, elapsed / 60, accessible_count,
        accessible_count / max(scanned_count, 1) * 100,
        scanned_count / max(elapsed, 1),
    )
    logger.info("Output: %s", os.path.abspath(output_file))
    return scanned_count, accessible_count


# ==================== 主入口 ====================

async def main():
    parser = argparse.ArgumentParser(description="批量扫描 banner_mapping 中所有 IP")
    parser.add_argument("--db", default="fingerprint.db", help="输入数据库")
    parser.add_argument("--fingerprints", default="vendors.json", help="指纹库")
    parser.add_argument("--output", default="scan_output.txt", help="输出文件")
    parser.add_argument("-c", "--concurrency", type=int, default=300,
                        help="并发数 (默认 300)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                        help="连接超时 (秒)")
    parser.add_argument("--retries", type=int, default=1, help="重试次数")
    parser.add_argument("--limit", type=int, default=None, help="限制目标数")
    parser.add_argument("--random", action="store_true", help="随机采样")
    parser.add_argument("--protocol", default=None, help="仅扫描某协议")
    parser.add_argument("--resume", action="store_true", help="断点续传")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细日志")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # 1. 加载目标
    db_path = os.path.abspath(args.db)
    fp_path = os.path.abspath(args.fingerprints)
    output_path = os.path.abspath(args.output)

    logger.info("Loading targets from %s ...", db_path)
    targets = load_targets(db_path, args.protocol, args.limit, args.random)

    # 2. 断点续传
    if args.resume:
        scanned = load_scanned_set(output_path)
        before = len(targets)
        targets = [t for t in targets if (t['ip'], t['port'], t['protocol']) not in scanned]
        logger.info("Resume: skipped %d already scanned, %d remaining", before - len(targets), len(targets))
    elif os.path.exists(output_path):
        # 不清空，追加模式
        logger.info("Output file exists, appending (use --resume to skip scanned)")

    if not targets:
        logger.info("No targets to scan!")
        return

    # 3. 估算时间
    est_seconds = len(targets) / (args.concurrency / max(args.timeout, 0.5))
    logger.info(
        "Targets: %d | Concurrency: %d | Timeout: %.1fs | Retries: %d | Est: %.0f min",
        len(targets), args.concurrency, args.timeout, args.retries,
        est_seconds / 60,
    )

    # 4. 初始化引擎
    if not os.path.exists(fp_path):
        logger.warning("Fingerprint file not found: %s, skipping fingerprint matching", fp_path)
        matcher = FingerprintMatcher([])
    else:
        matcher = FingerprintMatcher.load(fp_path)
        logger.info("Loaded %d fingerprint rules", matcher.rule_count)

    config = ProbeConfig(
        connect_timeout=args.timeout,
        read_timeout=args.timeout * 1.5,
        max_retries=args.retries,
        retry_base_delay=0.5,
    )
    engine = ProbeEngine(config)
    engine._matcher = matcher

    # 5. 执行扫描
    semaphore = asyncio.Semaphore(args.concurrency)
    logger.info("Starting scan with %d concurrent probes...", args.concurrency)
    start = time.time()

    scanned, accessible = await scan_batch(targets, engine, semaphore, output_path)

    elapsed = time.time() - start
    logger.info("=" * 50)
    logger.info("Scan complete!")
    logger.info("  Total:     %d", scanned)
    logger.info("  Accessible: %d (%.1f%%)", accessible,
                accessible / max(scanned, 1) * 100)
    logger.info("  Time:      %.0f sec (%.0f min)", elapsed, elapsed / 60)
    logger.info("  Rate:      %.0f targets/sec", scanned / max(elapsed, 1))
    logger.info("  Output:    %s", output_path)


if __name__ == "__main__":
    asyncio.run(main())
