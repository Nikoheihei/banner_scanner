#!/usr/bin/env python3
"""Banner Scanner CLI"""

import argparse
import asyncio
import json
import sys
from typing import Any

from .core.engine import ProbeEngine
from .core.models import ProbeConfig
from .core.log import setup_logging


def _result_to_dict(result: Any) -> dict:
    """BannerResult 或 HostResult 转可序列化字典"""
    from .core.models import BannerResult, HostResult
    if isinstance(result, HostResult):
        return {
            "host": result.host,
            "total_time_ms": round(result.total_time_ms, 1),
            "protocols": {
                p: _result_to_dict(r) for p, r in result.results.items()
            },
        }
    if isinstance(result, BannerResult):
        d: dict = {
            "protocol": result.protocol,
            "host": result.host,
            "port": result.port,
            "accessible": result.accessible,
            "banner": result.banner,
            "banner_truncated": result.banner_truncated,
            "response_time_ms": round(result.response_time_ms, 1),
            "error": result.error,
        }
        if result.ssh:
            d["ssh"] = {
                "version_string": result.ssh.version_string,
                "protocol_version": result.ssh.protocol_version,
                "software": result.ssh.software,
                "version": result.ssh.version,
            }
        if result.ftp:
            d["ftp"] = {
                "features": result.ftp.features,
                "utf8": result.ftp.utf8,
                "auth_tls": result.ftp.auth_tls,
                "auth_ssl": result.ftp.auth_ssl,
                "size_cmd": result.ftp.size_cmd,
                "mdtm": result.ftp.mdtm,
                "mldst": result.ftp.mldst,
                "tvfs": result.ftp.tvfs,
            }
        # 指纹信息
        if result.vendor:
            d["vendor"] = result.vendor
            d["vendor_id"] = result.vendor_id
            d["vendor_confidence"] = result.vendor_confidence
        if result.matched_rules:
            d["matched_rules"] = [
                {
                    "vendor_id": r.vendor_id,
                    "vendor_name": r.vendor_name,
                    "pattern": r.pattern,
                    "confidence": r.confidence,
                    "source": r.source,
                }
                for r in result.matched_rules
            ]
        return d
    return {}


def _format_text(results: list) -> str:
    """格式化为可读文本"""
    lines = []
    for host_result in results:
        if isinstance(host_result, dict):
            host_result = _result_to_dict(host_result)
        host = host_result.get("host", "?")
        lines.append(f"\n{'#'*54}")
        lines.append(f"#  {'目标: ' + host:<48}#")
        lines.append(f"{'#'*54}")

        for proto, result in host_result.get("protocols", {}).items():
            lines.append(f"\n{'='*50}")
            lines.append(f"  {result.get('protocol', proto.upper())} ({host}:{result.get('port', '?')})")
            lines.append(f"{'='*50}")

            if result.get("error"):
                lines.append(f"  ❌ {result['error']}")
                continue
            if not result.get("accessible"):
                lines.append(f"  ❌ 不可访问")
                continue

            lines.append(f"  ✅ 可访问")
            lines.append(f"  ⏱  响应时间: {result.get('response_time_ms', 0):.1f}ms")

            banner = result.get("banner", "")
            if banner:
                lines.append(f"  📋 Banner:")
                for line in banner.split("\n"):
                    lines.append(f"      {line}")
            if result.get("banner_truncated"):
                lines.append(f"  ⚠️  Banner 被截断")

            ssh = result.get("ssh")
            if ssh and ssh.get("software"):
                lines.append(f"  🔑 SSH 详细信息:")
                lines.append(f"      软件: {ssh['software']}")
                if ssh.get("version"):
                    lines.append(f"      版本: {ssh['version']}")
                lines.append(f"      协议版本: {ssh['protocol_version']}")

            ftp = result.get("ftp")
            if ftp and ftp.get("features"):
                lines.append(f"  📁 FTP 特性: {ftp['features']}")

            # 指纹信息
            vendor = result.get("vendor")
            if vendor:
                lines.append(f"  🏷️  指纹匹配: {vendor}")
                if result.get("vendor_confidence", 0) > 0:
                    lines.append(f"      置信度: {result['vendor_confidence']:.0%}")
            matched = result.get("matched_rules")
            if matched and len(matched) > 1:
                lines.append(f"      更多匹配:")
                for r in matched[1:]:
                    lines.append(f"        - {r['vendor_name']} (来源: {r.get('source', 'banner')})")

    return "\n".join(lines)


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Banner Scanner - 网络协议 Banner 探测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s 192.168.1.1
  %(prog)s 192.168.1.1 --protocols ssh,ftp
  %(prog)s 192.168.1.1 10.0.0.1 --timeout 5 --json
  %(prog)s 192.168.1.1 --protocols telnet --no-feat
  %(prog)s --health                         # 探测引擎健康状态
  %(prog)s 192.168.1.1 --fingerprint vendors.json  # 加载指纹库
        """,
    )
    parser.add_argument("hosts", nargs="*", help="目标 IP 地址")
    parser.add_argument("-p", "--protocols", default="ssh,ftp,telnet",
                        help="协议列表，逗号分隔 (默认: ssh,ftp,telnet)")
    parser.add_argument("-t", "--timeout", type=float, default=3.0,
                        help="连接超时秒数 (默认: 3.0)")
    parser.add_argument("--read-timeout", type=float, default=4.0,
                        help="读取超时秒数 (默认: 4.0)")
    parser.add_argument("--max-banner", type=int, default=65536,
                        help="Banner 最大字节数 (默认: 65536)")
    parser.add_argument("--concurrent", type=int, default=50,
                        help="最大并发主机数 (默认: 50)")
    parser.add_argument("--json", action="store_true", help="JSON 格式输出")
    parser.add_argument("--json-log", action="store_true", help="JSON 格式日志")
    parser.add_argument("--log-file", help="日志文件路径")
    parser.add_argument("--no-feat", action="store_true", help="FTP 不发送 FEAT")
    parser.add_argument("--health", action="store_true", help="查看引擎健康状态")
    parser.add_argument("--fingerprint", help="指纹库文件路径（JSON）")
    parser.add_argument("--verbose", "-v", action="store_true", help="DEBUG 日志")

    args = parser.parse_args(argv)

    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(level=log_level, json_format=args.json_log, log_file=args.log_file)

    config = ProbeConfig(
        connect_timeout=args.timeout,
        read_timeout=args.read_timeout,
        max_banner_bytes=args.max_banner,
        max_concurrent_hosts=args.concurrent,
        fingerprint_path=args.fingerprint,
    )
    if args.no_feat:
        config.protocol_config["ftp"].send_feat = False

    engine = ProbeEngine(config=config)

    if args.health:
        health = await engine.health_check()
        if args.json:
            json.dump(health, sys.stdout, indent=2, ensure_ascii=False)
            print()
        else:
            print(f"  ✅ 健康: {health['healthy']}")
            print(f"  ⏱  运行时间: {health['uptime_s']:.0f}s")
            print(f"  📊 总探测: {health['total_probes']}")
            print(f"  ❌ 总错误: {health['total_errors']}")
            print(f"  📈 错误率: {health['error_rate_pct']}%")
            print(f"  🔒 熔断主机: {health['circuit_breaker_open_hosts']}")
            if health.get("fingerprint"):
                fp = health["fingerprint"]
                print(f"  🏷️  指纹规则: {fp['total_rules']} 条, {len(fp['vendors'])} 个厂商")
            else:
                print(f"  🏷️  指纹库: 未加载")
        return 0

    if not args.hosts:
        parser.print_help()
        return 1

    protocols = [p.strip().lower() for p in args.protocols.split(",")]
    results = await engine.probe_hosts(args.hosts, protocols=protocols)

    if args.json:
        output = {r.host: _result_to_dict(r) for r in results}
        json.dump(output, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print(_format_text([_result_to_dict(r) for r in results]))

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
