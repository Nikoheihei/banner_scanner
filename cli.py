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
        if result.redis:
            d["redis"] = {
                "implementation": result.redis.implementation,
                "version": result.redis.version,
                "mode": result.redis.mode,
                "os": result.redis.os,
                "fields": result.redis.fields,
            }
        if result.mysql:
            d["mysql"] = {
                "protocol_version": result.mysql.protocol_version,
                "version": result.mysql.version,
                "implementation": result.mysql.implementation,
                "connection_id": result.mysql.connection_id,
                "capability_flags": result.mysql.capability_flags,
                "character_set": result.mysql.character_set,
                "status_flags": result.mysql.status_flags,
                "auth_plugin": result.mysql.auth_plugin,
            }
        if result.pgsql:
            d["pgsql"] = {
                "protocol_version": result.pgsql.protocol_version,
                "ssl_response": result.pgsql.ssl_response,
                "implementation": result.pgsql.implementation,
                "auth_code": result.pgsql.auth_code,
                "auth_method": result.pgsql.auth_method,
                "fields": result.pgsql.fields,
                "parameters": result.pgsql.parameters,
                "message_types": result.pgsql.message_types,
            }
        if result.vendor:
            d["vendor"] = result.vendor
            d["vendor_id"] = result.vendor_id
            d["vendor_confidence"] = result.vendor_confidence
        if result.matched_rules:
            d["matched_rules"] = [
                {"vendor_id": r.vendor_id, "vendor_name": r.vendor_name,
                 "pattern": r.pattern, "source": r.source,
                 "category": r.category, "labels": r.labels,
                 "extracted": r.extracted}
                for r in result.matched_rules
            ]
        if result.fingerprint_details:
            d["fingerprint_details"] = result.fingerprint_details
        return d
    return {}


def _format_text(results: list) -> str:
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
            lines.append(f"  ⏱  {result.get('response_time_ms', 0):.1f}ms")
            banner = result.get("banner", "")
            if banner:
                lines.append(f"  📋 {banner}")

            ssh = result.get("ssh")
            if ssh and ssh.get("software"):
                lines.append(f"  🔑 {ssh['software']} {ssh.get('version', '')}")

            ftp = result.get("ftp")
            if ftp and ftp.get("features"):
                lines.append(f"  📁 {ftp['features']}")

            redis = result.get("redis")
            if redis:
                lines.append(
                    f"  Redis: {redis.get('implementation', '')} "
                    f"{redis.get('version', '')} {redis.get('mode', '')}".rstrip()
                )

            mysql = result.get("mysql")
            if mysql:
                lines.append(
                    f"  MySQL: {mysql.get('implementation', '')} "
                    f"{mysql.get('version', '')}".rstrip()
                )

            pgsql = result.get("pgsql")
            if pgsql:
                lines.append(
                    f"  PGSQL: SSL={pgsql.get('ssl_response', '')} "
                    f"AUTH={pgsql.get('auth_method', '')} "
                    f"SQLSTATE={pgsql.get('fields', {}).get('sqlstate', '')}".rstrip()
                )

            vendor = result.get("vendor")
            if vendor:
                lines.append(f"  🏷️  {vendor}")

    return "\n".join(lines)


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Banner Scanner - 网络协议 Banner 探测工具",
    )
    parser.add_argument("hosts", nargs="*", help="目标 IP 地址")
    parser.add_argument(
        "-p", "--protocols",
        default="ssh,ftp,telnet,redis,mysql,pgsql",
        help="逗号分隔协议：ssh,ftp,telnet,redis,mysql,pgsql",
    )
    parser.add_argument("-t", "--timeout", type=float, default=3.0)
    parser.add_argument("--read-timeout", type=float, default=4.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-feat", action="store_true")
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--fingerprint", help="指纹库文件路径")
    parser.add_argument(
        "--database-fingerprints",
        help="Redis/MySQL/PGSQL 结构化指纹库目录（默认使用内置目录）",
    )
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args(argv)

    setup_logging(level="DEBUG" if args.verbose else "INFO")

    config = ProbeConfig(
        connect_timeout=args.timeout,
        read_timeout=args.read_timeout,
        max_retries=args.retries,
        fingerprint_path=args.fingerprint,
        database_fingerprint_path=args.database_fingerprints,
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
            print(f"  总探测: {health['total_probes']}")
            print(f"  总错误: {health['total_errors']}")
            print(f"  错误率: {health['error_rate_pct']}%")
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
