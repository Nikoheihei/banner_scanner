"""单元测试：Banner 解析器，与 C++ 版 tests/unit/ssh_ftp_parser_test.cpp 保持用例一致。"""

import struct
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from banner_scanner.core.parsers import (
    extract_ftp_features_from_lines, parse_ftp_banner_info, parse_ftp_features,
    parse_mysql_handshake, parse_pgsql_messages, parse_redis_response,
    parse_ssh_banner,
)


# ===================== SSH =====================

def test_ssh_openssh_with_comments():
    info = parse_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15")
    assert info.software == "OpenSSH"
    assert info.version == "8.9p1"
    assert info.protocol_version == "2.0"
    assert info.version_string == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15"


def test_ssh_dropbear():
    info = parse_ssh_banner("SSH-2.0-dropbear_2022.82")
    assert info.software == "Dropbear"
    assert info.version == "2022.82"
    assert info.protocol_version == "2.0"


def test_ssh_cisco_dash_version():
    info = parse_ssh_banner("SSH-1.99-Cisco-1.25")
    assert info.software == "Cisco"
    assert info.version == "1.25"
    assert info.protocol_version == "1.99"


def test_ssh_libssh():
    info = parse_ssh_banner("SSH-2.0-libssh_0.9.6")
    assert info.software == "libssh"
    assert info.version == "0.9.6"


def test_ssh_invalid():
    assert parse_ssh_banner("").software == ""
    assert parse_ssh_banner("HTTP/1.1 200 OK").software == ""
    assert parse_ssh_banner("SSH-2.0").software == ""


def test_ssh_extra_dashes():
    info = parse_ssh_banner("SSH-2.0-RouterOS_7.12")
    assert info.software == "RouterOS"
    assert info.version == "7.12"


def test_ssh_paramiko_without_separator():
    info = parse_ssh_banner("SSH-2.0-paramiko2.12.0")
    assert info.software == "Paramiko"
    assert info.version == "2.12.0"


def test_ssh_mod_sftp_slash_version():
    info = parse_ssh_banner("SSH-2.0-mod_sftp/0.9.9")
    assert info.software == "mod_sftp"
    assert info.version == "0.9.9"


# ===================== FTP =====================

def test_ftp_vsftpd():
    info = parse_ftp_features("AUTH TLS, AUTH SSL, SIZE, MDTM, UTF8")
    assert info.auth_tls == True
    assert info.auth_ssl == True
    assert info.size_cmd == True
    assert info.mdtm == True
    assert info.utf8 == True
    assert info.tvfs == False


def test_ftp_proftpd():
    info = parse_ftp_features("UTF8, AUTH TLS, SIZE, MDTM, MLSD, TVFS")
    assert info.utf8 == True
    assert info.auth_tls == True
    assert info.size_cmd == True
    assert info.mdtm == True
    assert info.mldst == True
    assert info.tvfs == True


def test_ftp_empty():
    info = parse_ftp_features("")
    assert info.utf8 == False
    assert info.auth_tls == False
    assert info.xcrc == False


def test_ftp_single():
    info = parse_ftp_features("UTF8")
    assert info.utf8 == True
    assert info.auth_tls == False


def test_ftp_case_insensitive():
    info = parse_ftp_features("utf8, auth tls")
    assert info.utf8 == True
    assert info.auth_tls == True


def test_ftp_extract_lines():
    """extract_ftp_features_from_lines: 模拟 vsftpd FEAT 响应"""
    lines = [
        "211-Extensions supported:",
        " UTF8",
        " AUTH TLS",
        " SIZE",
        " MDTM",
        "211 End",
    ]
    result = extract_ftp_features_from_lines(lines)
    assert "UTF8" in result
    assert "AUTH TLS" in result  # 多词特性名不会被截断
    assert "SIZE" in result


def test_ftp_pcman_banner():
    info = parse_ftp_banner_info("220 PCMan's FTP Server 2.0 Ready.")
    assert info.software == "PCMan FTP Server"
    assert info.version == "2.0"


# ===================== Databases =====================

def test_redis_info_response():
    payload = (
        "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n"
        "os:Linux 6.1 x86_64\r\n"
    )
    response = f"${len(payload.encode())}\r\n{payload}\r\n"
    info = parse_redis_response("+PONG\r\n", response)
    assert info.implementation == "Redis"
    assert info.version == "7.2.4"
    assert info.mode == "standalone"
    assert info.fields["os"].startswith("Linux")


def test_mysql_handshake():
    version = b"8.0.36-0ubuntu0.22.04.1\x00"
    capability_flags = 0x00088201
    payload = (
        b"\x0a" + version + struct.pack("<I", 1234) + b"12345678" + b"\x00" +
        struct.pack("<H", capability_flags & 0xFFFF) + b"\x2d" +
        struct.pack("<H", 2) + struct.pack("<H", capability_flags >> 16) +
        b"\x15" + (b"\x00" * 10) + b"abcdefghijklm" +
        b"caching_sha2_password\x00"
    )
    packet = len(payload).to_bytes(3, "little") + b"\x00" + payload
    info = parse_mysql_handshake(packet)
    assert info.protocol_version == 10
    assert info.version.startswith("8.0.36")
    assert info.connection_id == 1234
    assert info.capability_flags == capability_flags
    assert info.auth_plugin == "caching_sha2_password"
    assert info.implementation == "MySQL_or_compatible"


def test_pgsql_error_response():
    payload = b"SERROR\x00C28P01\x00Mpassword authentication failed\x00\x00"
    packet = b"E" + struct.pack("!I", len(payload) + 4) + payload
    info = parse_pgsql_messages(packet, ssl_response="N")
    assert info.fields["severity"] == "ERROR"
    assert info.fields["sqlstate"] == "28P01"
    assert info.fields["message"] == "password authentication failed"


def test_pgsql_auth_response():
    payload = struct.pack("!I", 10)
    packet = b"R" + struct.pack("!I", len(payload) + 4) + payload
    info = parse_pgsql_messages(packet, ssl_response="N")
    assert info.auth_code == 10
    assert info.auth_method == "sasl"


# ===================== Runner =====================

if __name__ == "__main__":
    tests = [(k, v) for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✅ {name}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ❌ {name}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{'='*40}")
    print(f"  Total: {passed + failed}  |  ✅ Passed: {passed}  |  ❌ Failed: {failed}")
    sys.exit(0 if failed == 0 else 1)
