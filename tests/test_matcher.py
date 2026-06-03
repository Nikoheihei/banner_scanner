"""测试：指纹加载、匹配、Banner 标准化。"""

import json
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from banner_scanner.core.matcher import (
    FingerprintLoader, FingerprintMatcher, FingerprintRule,
    normalize_banner, extract_banner_key, match_banner,
)
from banner_scanner.core.models import BannerResult, FingerprintMatch


# ==================== 指纹加载 ====================

SAMPLE_FINGERPRINTS = {
    "vendors": [
        {"id": 401, "name": "OpenSSH", "pattern": ".*OpenSSH.*"},
        {"id": 402, "name": "Dropbear", "pattern": ".*[Dd]ropbear.*"},
        {"id": 301, "name": "vsftpd", "pattern": ".*vsftpd.*"},
        {"id": 302, "name": "Pure-FTPd", "pattern": ".*Pure-FTPd.*"},
        {"id": 501, "name": "Cisco Telnet", "pattern": ".*Cisco IOS.*"},
        {"id": 502, "name": "MikroTik", "pattern": ".*MikroTik.*"},
        {"id": 601, "name": "ProFTPD", "pattern": ".*ProFTPD.*"},
    ]
}


def test_loader_json():
    """从 JSON 字符串加载指纹"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(SAMPLE_FINGERPRINTS, f)
        fname = f.name

    try:
        rules = FingerprintLoader.load(fname)
        assert len(rules) == 7
        assert rules[0].vendor_id == 401
        assert rules[0].name == "OpenSSH"
        assert rules[0].pattern == ".*OpenSSH.*"
    finally:
        os.unlink(fname)


def test_loader_file_not_found():
    try:
        FingerprintLoader.load("/nonexistent/fingerprint.json")
        assert False, "Should raise FileNotFoundError"
    except FileNotFoundError:
        pass


def test_loader_unsupported_format():
    try:
        FingerprintLoader.load("/tmp/test.xyz")
        assert False, "Should raise ValueError"
    except ValueError as e:
        assert "Unsupported" in str(e)


# ==================== 正则匹配 ====================

def test_rule_match():
    rule = FingerprintRule(401, "OpenSSH", ".*OpenSSH.*")
    assert rule.match("SSH-2.0-OpenSSH_8.9p1") == True
    assert rule.match("SSH-2.0-dropbear_2022.82") == False


def test_rule_case_sensitive():
    rule = FingerprintRule(402, "Dropbear", ".*[Dd]ropbear.*")
    assert rule.match("dropbear_2022.82") == True
    assert rule.match("Dropbear_2022.82") == True


# ==================== 指纹匹配器 ====================

def test_matcher_match_ssh():
    matcher = FingerprintMatcher.load_from_dict(SAMPLE_FINGERPRINTS)

    result = BannerResult(
        protocol="SSH", host="10.0.0.1", port=22,
        accessible=True, banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
    )
    result = matcher.match(result)

    assert result.vendor == "OpenSSH"
    assert result.vendor_id == 401
    assert result.vendor_confidence == 1.0
    assert len(result.matched_rules) >= 1


def test_matcher_match_ftp():
    matcher = FingerprintMatcher.load_from_dict(SAMPLE_FINGERPRINTS)

    result = BannerResult(
        protocol="FTP", host="10.0.0.1", port=21,
        accessible=True, banner="220 vsftpd 3.0.5 ready.",
    )
    result = matcher.match(result)

    assert result.vendor == "vsftpd"
    assert result.vendor_id == 301


def test_matcher_match_telnet():
    matcher = FingerprintMatcher.load_from_dict(SAMPLE_FINGERPRINTS)

    result = BannerResult(
        protocol="TELNET", host="10.0.0.1", port=23,
        accessible=True,
        banner="Cisco IOS Software, C1900 Software\nUser Access Verification",
    )
    result = matcher.match(result)

    assert result.vendor == "Cisco Telnet"


def test_matcher_no_match():
    matcher = FingerprintMatcher.load_from_dict(SAMPLE_FINGERPRINTS)

    result = BannerResult(
        protocol="SSH", host="10.0.0.1", port=22,
        accessible=True, banner="SSH-2.0-UnknownServer_1.0",
    )
    result = matcher.match(result)

    assert result.vendor == ""
    assert result.vendor_id == 0
    assert len(result.matched_rules) == 0


def test_matcher_not_accessible():
    """不可访问的结果不执行匹配"""
    matcher = FingerprintMatcher.load_from_dict(SAMPLE_FINGERPRINTS)

    result = BannerResult(
        protocol="SSH", host="10.0.0.1", port=22,
        accessible=False, error="Connection refused",
        banner="SSH-2.0-OpenSSH_8.9p1",  # 有 banner 但不应该匹配
    )
    result = matcher.match(result)

    assert result.vendor == ""
    assert len(result.matched_rules) == 0


def test_matcher_multiple_matches():
    """多个规则匹配时去重"""
    fingerprints = {
        "vendors": [
            {"id": 401, "name": "OpenSSH", "pattern": ".*OpenSSH.*"},
            {"id": 401, "name": "OpenSSH", "pattern": ".*ssh.*"},  # 同 ID 重复
            {"id": 402, "name": "Dropbear", "pattern": ".*dropbear.*"},
        ]
    }
    matcher = FingerprintMatcher.load_from_dict(fingerprints)

    result = BannerResult(
        protocol="SSH", host="10.0.0.1", port=22,
        accessible=True, banner="SSH-2.0-OpenSSH_8.9p1",
    )
    result = matcher.match(result)

    assert result.vendor == "OpenSSH"
    assert len(result.matched_rules) == 1  # 去重后只有一条


# ==================== Banner 标准化 ====================

def test_normalize_banner_trims():
    assert normalize_banner("  Hello World  ") == "Hello World"


def test_normalize_banner_removes_timestamp():
    result = normalize_banner("220 mail.example.com ESMTP [1234567890]")
    assert "[" not in result
    assert "220 mail.example.com ESMTP" in result


def test_normalize_banner_removes_ip():
    result = normalize_banner("220 [192.168.1.1] ESMTP Postfix")
    assert "192.168.1.1" not in result
    assert "220 ESMTP Postfix" in result


def test_normalize_banner_unicode():
    result = normalize_banner("  220 vsftpd ready.   ")
    assert result == "220 vsftpd ready."


def test_extract_banner_key_single_line():
    banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\nExtra info"
    key = extract_banner_key(banner)
    assert "\n" not in key
    assert key.startswith("SSH-2.0-OpenSSH_8.9p1")


def test_extract_banner_key_truncated():
    long = "A" * 200
    key = extract_banner_key(long)
    assert len(key) == 120


# ==================== 便捷函数 ====================

def test_match_banner_direct():
    rules = [
        FingerprintRule(401, "OpenSSH", ".*OpenSSH.*"),
        FingerprintRule(301, "vsftpd", ".*vsftpd.*"),
    ]
    matches = match_banner("SSH-2.0-OpenSSH_8.9p1", rules)
    assert len(matches) == 1
    assert matches[0].vendor_name == "OpenSSH"


# ==================== Runner ====================

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
            import traceback
            traceback.print_exc()
            failed += 1
    print(f"\n{'='*40}")
    print(f"  Total: {passed + failed}  |  ✅ Passed: {passed}  |  ❌ Failed: {failed}")
    sys.exit(0 if failed == 0 else 1)
