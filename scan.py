#!/usr/bin/env python3
"""快速扫描脚本 — 修改 HOSTS 列表后直接运行"""
import asyncio
import sys
from pathlib import Path

_project_root = str(Path(__file__).parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from banner_scanner.core.engine import ProbeEngine
from banner_scanner.core.models import ProbeConfig

# ====== 在这里修改目标 ======
HOSTS = [
    "192.168.1.1",
    # "10.0.0.1",
    # "example.com",
]
PROTOCOLS = ["ssh", "ftp", "telnet", "redis", "mysql", "pgsql"]
# ============================

async def main():
    engine = ProbeEngine(ProbeConfig(connect_timeout=2.0, read_timeout=3.0))

    results = await engine.probe_hosts(HOSTS, protocols=PROTOCOLS)

    for hr in results:
        print(f"\n{'='*50}")
        print(f"  目标: {hr.host}")
        print(f"{'='*50}")
        for proto, br in hr.results.items():
            status = "✅" if br.accessible else "❌"
            print(f"  [{proto}] {br.host}:{br.port} {status}")
            if br.banner:
                print(f"    Banner: {br.banner}")
            if br.vendor:
                print(f"    厂商:   {br.vendor} (置信度: {br.vendor_confidence})")
            if br.error:
                print(f"    错误:   {br.error}")
            if br.ssh and br.ssh.software:
                print(f"    SSH:    {br.ssh.software} {br.ssh.version}")
            if br.ftp and br.ftp.features:
                print(f"    FTP:    {br.ftp.features}")
            if br.telnet and br.telnet.detected_service:
                print(f"    Telnet: {br.telnet.detected_service}")
            if br.redis:
                print(f"    Redis:  {br.redis.implementation} {br.redis.version} {br.redis.mode}")
            if br.mysql:
                print(f"    MySQL:  {br.mysql.implementation} {br.mysql.version}")
            if br.pgsql:
                print(
                    f"    PGSQL:  SSL={br.pgsql.ssl_response} "
                    f"AUTH={br.pgsql.auth_method} "
                    f"SQLSTATE={br.pgsql.fields.get('sqlstate', '')}"
                )

if __name__ == "__main__":
    asyncio.run(main())
