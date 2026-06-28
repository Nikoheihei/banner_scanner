"""集成测试：Mock 传输层，验证完整探测流程。"""

import asyncio
import struct
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from banner_scanner.core.engine import ProbeEngine
from banner_scanner.core.models import ProbeConfig
import banner_scanner.core.transport as _transport


class _MockTransport:
    def __init__(self):
        self._closed = False
    def is_closing(self): return self._closed
    def close(self): self._closed = True
    def get_extra_info(self, name, default=None): return None
    def write(self, data): pass
    def writelines(self, data): pass
    def write_eof(self): pass
    def can_write_eof(self): return False
    def abort(self): self._closed = True
    def set_write_buffer_limits(self, high=None, low=None): pass
    def get_write_buffer_size(self): return 0
    def pause_reading(self): pass
    def resume_reading(self): pass
    def get_protocol(self): return None


async def test_probe_ssh():
    original = _transport.connect_tcp

    async def mock_connect(host, port, **kw):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        reader.feed_data(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\n")
        reader.feed_eof()
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(_MockTransport(), protocol, reader, loop)
        return reader, writer, {}

    _transport.connect_tcp = mock_connect
    try:
        config = ProbeConfig(connect_timeout=1.0, read_timeout=1.0)
        engine = ProbeEngine(config=config)
        result = await engine.probe_host("192.168.1.1", protocols=["ssh"])
        br = result.results.get("ssh")
        assert br is not None
        assert br.accessible == True
        assert br.ssh.software == "OpenSSH"
    finally:
        _transport.connect_tcp = original


async def test_probe_ftp():
    original = _transport.connect_tcp

    async def mock_connect(host, port, **kw):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        reader.feed_data(b"220 vsftpd 3.0.5 ready.\r\n")
        # 异步注入 FEAT 响应（模拟服务端交互）
        async def inject():
            await asyncio.sleep(0.01)
            reader.feed_data(
                b"211-Extensions supported:\r\n"
                b" UTF8\r\n AUTH TLS\r\n SIZE\r\n211 End\r\n"
            )
            reader.feed_eof()
        asyncio.create_task(inject())
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(_MockTransport(), protocol, reader, loop)
        return reader, writer, {}

    _transport.connect_tcp = mock_connect
    try:
        config = ProbeConfig(connect_timeout=1.0, read_timeout=3.0)
        engine = ProbeEngine(config=config)
        result = await engine.probe_host("192.168.1.1", protocols=["ftp"])
        br = result.results.get("ftp")
        assert br is not None
        assert br.accessible == True, f"accessible={br.accessible}, error={br.error}"
        assert br.ftp is not None, f"ftp is None, error={br.error}"
        assert br.ftp.utf8 == True
        assert br.ftp.auth_tls == True
    finally:
        _transport.connect_tcp = original


async def test_probe_telnet():
    original = _transport.connect_tcp

    async def mock_connect(host, port, **kw):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        reader.feed_data(b"Ubuntu 22.04 LTS\nlogin: ")
        reader.feed_eof()
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(_MockTransport(), protocol, reader, loop)
        return reader, writer, {}

    _transport.connect_tcp = mock_connect
    try:
        config = ProbeConfig(connect_timeout=1.0, read_timeout=1.0)
        engine = ProbeEngine(config=config)
        result = await engine.probe_host("192.168.1.1", protocols=["telnet"])
        br = result.results.get("telnet")
        assert br is not None
        assert br.accessible == True
        assert "Ubuntu" in br.banner
    finally:
        _transport.connect_tcp = original


async def test_connection_timeout():
    original = _transport.connect_tcp

    async def mock_timeout(host, port, **kw):
        raise _transport.ConnectionTimeout(
            f"connect to {host}:{port} timed out"
        )

    _transport.connect_tcp = mock_timeout
    try:
        config = ProbeConfig(connect_timeout=0.1, read_timeout=0.1)
        engine = ProbeEngine(config=config)
        result = await engine.probe_host("10.0.0.1", protocols=["ssh"])
        br = result.results.get("ssh")
        assert br is not None
        assert br.accessible == False
        assert "timed out" in br.error
    finally:
        _transport.connect_tcp = original


async def test_health_check():
    original = _transport.connect_tcp

    async def mock_connect(host, port, **kw):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        reader.feed_data(b"SSH-2.0-OpenSSH_8.9p1\n")
        reader.feed_eof()
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(_MockTransport(), protocol, reader, loop)
        return reader, writer, {}

    _transport.connect_tcp = mock_connect
    try:
        config = ProbeConfig(connect_timeout=1.0, read_timeout=1.0)
        engine = ProbeEngine(config=config)
        await engine.probe_host("10.0.0.1", protocols=["ssh"])
        health = await engine.health_check()
        assert health["healthy"] == True
        assert health["total_probes"] > 0
    finally:
        _transport.connect_tcp = original


async def test_probe_redis():
    original = _transport.connect_tcp

    async def mock_connect(host, port, **kw):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        payload = b"# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n"
        reader.feed_data(b"+PONG\r\n" + f"${len(payload)}\r\n".encode() + payload + b"\r\n")
        reader.feed_eof()
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(_MockTransport(), protocol, reader, loop)
        return reader, writer, {}

    _transport.connect_tcp = mock_connect
    try:
        engine = ProbeEngine(ProbeConfig(max_retries=0))
        br = await engine.probe_single("192.0.2.10", 6379, "redis")
        assert br.accessible is True
        assert br.redis.version == "7.2.4"
        assert br.redis.mode == "standalone"
        assert br.vendor == "Redis"
        assert br.fingerprint_details["protocol_match"] is True
    finally:
        _transport.connect_tcp = original


async def test_probe_mysql():
    original = _transport.connect_tcp

    async def mock_connect(host, port, **kw):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        version = b"10.11.6-MariaDB-0+deb12u1\x00"
        caps = 0x00088201
        payload = (
            b"\x0a" + version + struct.pack("<I", 42) + b"12345678" + b"\x00" +
            struct.pack("<H", caps & 0xFFFF) + b"\x2d" + struct.pack("<H", 2) +
            struct.pack("<H", caps >> 16) + b"\x15" + (b"\x00" * 10) +
            b"abcdefghijklm" + b"mysql_native_password\x00"
        )
        reader.feed_data(len(payload).to_bytes(3, "little") + b"\x00" + payload)
        reader.feed_eof()
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(_MockTransport(), protocol, reader, loop)
        return reader, writer, {}

    _transport.connect_tcp = mock_connect
    try:
        engine = ProbeEngine(ProbeConfig(max_retries=0))
        br = await engine.probe_single("192.0.2.11", 3306, "mysql")
        assert br.accessible is True
        assert br.mysql.protocol_version == 10
        assert br.mysql.implementation == "MariaDB"
        assert br.vendor == "MariaDB"
        assert br.info["service_version"].startswith("10.11.6")
    finally:
        _transport.connect_tcp = original


async def test_probe_pgsql():
    original = _transport.connect_tcp

    async def mock_connect(host, port, **kw):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        payload = b"SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00"
        reader.feed_data(b"N" + b"E" + struct.pack("!I", len(payload) + 4) + payload)
        reader.feed_eof()
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(_MockTransport(), protocol, reader, loop)
        return reader, writer, {}

    _transport.connect_tcp = mock_connect
    try:
        engine = ProbeEngine(ProbeConfig(max_retries=0))
        br = await engine.probe_single("192.0.2.12", 5432, "pgsql")
        assert br.accessible is True
        assert br.pgsql.ssl_response == "N"
        assert br.pgsql.fields["sqlstate"] == "28P01"
        assert br.info["sqlstate"] == "28P01"
        assert br.fingerprint_details["protocol_match"] is True
    finally:
        _transport.connect_tcp = original


async def test_probe_pgsql_direct_error():
    original = _transport.connect_tcp

    async def mock_connect(host, port, **kw):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        payload = b"SFATAL\x00C08P01\x00Munsupported frontend protocol\x00\x00"
        reader.feed_data(b"E" + struct.pack("!I", len(payload) + 4) + payload)
        reader.feed_eof()
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(_MockTransport(), protocol, reader, loop)
        return reader, writer, {}

    _transport.connect_tcp = mock_connect
    try:
        engine = ProbeEngine(ProbeConfig(max_retries=0))
        br = await engine.probe_single("192.0.2.13", 5432, "pgsql")
        assert br.accessible is True
        assert br.pgsql.ssl_response == "E"
        assert br.pgsql.fields["sqlstate"] == "08P01"
        assert br.fingerprint_details["protocol_match"] is True
    finally:
        _transport.connect_tcp = original


if __name__ == "__main__":
    tests = [(k, v) for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            asyncio.run(fn())
            print(f"  ✅ {name}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ❌ {name}: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    print(f"\n{'='*40}")
    print(f"  Total: {passed + failed}  |  ✅ Passed: {passed}  |  ❌ Failed: {failed}")
    sys.exit(0 if failed == 0 else 1)
