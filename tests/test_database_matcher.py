"""Structured database fingerprint library tests."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from banner_scanner.core.database_matcher import DatabaseFingerprintMatcher
from banner_scanner.core.models import BannerResult, MysqlInfo, PgsqlInfo, RedisInfo


def test_default_libraries_loaded():
    matcher = DatabaseFingerprintMatcher.load_default()
    assert matcher.rule_count == 59


def test_redis_valkey_match():
    matcher = DatabaseFingerprintMatcher.load_default()
    banner = "$55\r\n# Server\r\nserver_name:valkey\r\nvalkey_version:8.0.1\r\n\r\n"
    result = BannerResult(
        protocol="REDIS", host="192.0.2.1", port=6379,
        accessible=True, banner=banner,
        redis=RedisInfo(version="8.0.1", implementation="Valkey"),
    )
    matcher.match(result)
    assert result.vendor == "Valkey"
    assert result.fingerprint_details["protocol_match"] is True
    assert "redis.impl.valkey" in result.fingerprint_details["matched_rule_ids"]


def test_mysql_provider_and_implementation_match():
    matcher = DatabaseFingerprintMatcher.load_default()
    result = BannerResult(
        protocol="MYSQL", host="192.0.2.2", port=3306,
        accessible=True, banner="8.0.35-azure",
        mysql=MysqlInfo(
            protocol_version=10,
            version="8.0.35-azure",
            implementation="MySQL_or_compatible",
        ),
    )
    matcher.match(result)
    assert result.vendor == "MySQL_or_compatible"
    assert "mysql.dist.azure" in result.fingerprint_details["matched_rule_ids"]


def test_pgsql_auth_match():
    matcher = DatabaseFingerprintMatcher.load_default()
    result = BannerResult(
        protocol="PGSQL", host="192.0.2.3", port=5432,
        accessible=True, banner="Authentication:sasl",
        pgsql=PgsqlInfo(ssl_response="N", auth_code=10, auth_method="sasl"),
    )
    matcher.match(result)
    assert result.fingerprint_details["protocol_match"] is True
    assert "pgsql.auth.method.sasl" in result.fingerprint_details["matched_rule_ids"]


def test_pgsql_implementation_hint():
    matcher = DatabaseFingerprintMatcher.load_default()
    result = BannerResult(
        protocol="PGSQL", host="192.0.2.4", port=5432,
        accessible=True, banner="FATAL check cluster configuration port",
        pgsql=PgsqlInfo(
            ssl_response="N",
            fields={"message": "check cluster configuration port"},
        ),
    )
    matcher.match(result)
    assert result.vendor == "Amazon Redshift"
    assert "pgsql.impl.redshift" in result.fingerprint_details["matched_rule_ids"]


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in globals().items() if name.startswith("test_")]
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS {name}")
            passed += 1
        except Exception as exc:
            print(f"  FAIL {name}: {type(exc).__name__}: {exc}")
            failed += 1
    print(f"\nTotal: {passed + failed} | Passed: {passed} | Failed: {failed}")
    sys.exit(0 if failed == 0 else 1)
