"""Matcher for the structured Redis/MySQL/PostgreSQL fingerprint libraries."""

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from .models import BannerResult, FingerprintMatch

logger = logging.getLogger("banner_scanner.database_matcher")

DEFAULT_LIBRARY_DIR = Path(__file__).parent.parent / "fingerprints" / "databases"


def _get_path(record: dict[str, Any], dotted: str) -> Any:
    current: Any = record
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return ""
        current = current[part]
    return current


def _regex_match(value: Any, pattern: str) -> bool:
    return re.search(pattern, str(value), re.IGNORECASE | re.MULTILINE | re.DOTALL) is not None


def _result_record(result: BannerResult) -> dict[str, Any]:
    record: dict[str, Any] = {
        "protocol": result.protocol,
        "port": result.port,
        "accessible": result.accessible,
        "banner": result.banner,
        "vendor": result.vendor,
    }
    if result.mysql:
        record["mysql"] = {
            "protocol_version": result.mysql.protocol_version,
            "version": result.mysql.version,
            "capability_flags": result.mysql.capability_flags,
            "auth_plugin": result.mysql.auth_plugin,
        }
    if result.pgsql:
        record["pgsql"] = {
            "protocol_version": result.pgsql.protocol_version,
            "version": result.pgsql.parameters.get("server_version", ""),
            "ssl_response": result.pgsql.ssl_response,
            "implementation": result.pgsql.implementation,
        }
        record["pgsql_auth"] = {
            "code": result.pgsql.auth_code,
            "method": result.pgsql.auth_method,
        }
        record["pgsql_fields"] = result.pgsql.fields
        record["pgsql_parameters"] = result.pgsql.parameters
    return record


def _condition_matches(match: dict[str, Any], result: BannerResult,
                       record: dict[str, Any]) -> bool:
    context = {"scanner_protocol": result.protocol}
    for key, expected in match.get("requires_context", {}).items():
        if context.get(key) != expected:
            return False

    banner = result.banner
    for pattern in match.get("all", []):
        if not _regex_match(banner, pattern):
            return False
    any_patterns = match.get("any", [])
    if any_patterns and not any(_regex_match(banner, pattern) for pattern in any_patterns):
        return False
    for pattern in match.get("none", []):
        if _regex_match(banner, pattern):
            return False

    for field, expected in match.get("field_equals", {}).items():
        if _get_path(record, field) != expected:
            return False
    for field, pattern in match.get("field_regex", {}).items():
        if not _regex_match(_get_path(record, field), pattern):
            return False
    for field in match.get("field_present", []):
        if _get_path(record, field) in ("", None):
            return False
    any_fields = match.get("any_field_regex", [])
    if any_fields and not any(
        _regex_match(_get_path(record, item["field"]), item["regex"])
        for item in any_fields
    ):
        return False
    for item in match.get("none_field_regex", []):
        if _regex_match(_get_path(record, item["field"]), item["regex"]):
            return False
    return True


def _extract_values(rule: dict[str, Any], result: BannerResult,
                    record: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for extractor in rule.get("extract", []):
        source = extractor.get("source")
        raw = _get_path(record, source) if source else result.banner
        pattern = extractor.get("regex")
        if not pattern:
            if raw not in ("", None):
                values[extractor["field"]] = str(raw)
            continue
        match = re.search(pattern, str(raw), re.IGNORECASE | re.MULTILINE | re.DOTALL)
        if not match:
            continue
        group = extractor.get("group")
        if group:
            value = match.group(group)
        elif match.groups():
            value = match.group(1)
        else:
            value = match.group(0)
        values[extractor["field"]] = value.strip()
    return values


class DatabaseFingerprintMatcher:
    """Load and apply the validated database fingerprint rule schema."""

    def __init__(self, libraries: Optional[list[dict[str, Any]]] = None):
        self._libraries = libraries or []

    @classmethod
    def load_directory(cls, path: str | Path) -> "DatabaseFingerprintMatcher":
        directory = Path(path)
        libraries = []
        if directory.exists():
            for library_path in sorted(directory.glob("*_fingerprints.json")):
                with library_path.open("r", encoding="utf-8") as handle:
                    libraries.append(json.load(handle))
        matcher = cls(libraries)
        logger.info("Loaded %d database fingerprint rules from %s",
                    matcher.rule_count, directory)
        return matcher

    @classmethod
    def load_default(cls) -> "DatabaseFingerprintMatcher":
        return cls.load_directory(DEFAULT_LIBRARY_DIR)

    @property
    def rule_count(self) -> int:
        return sum(len(library.get("rules", [])) for library in self._libraries)

    def match(self, result: BannerResult) -> BannerResult:
        if not result.accessible:
            return result

        record = _result_record(result)
        matches: list[tuple[float, dict[str, Any], dict[str, str]]] = []
        for library in self._libraries:
            canonical = library.get("protocol", {}).get("canonical", "")
            if canonical and canonical != result.protocol:
                continue
            for rule in library.get("rules", []):
                if _condition_matches(rule.get("match", {}), result, record):
                    matches.append((
                        float(rule.get("confidence", 0.5)),
                        rule,
                        _extract_values(rule, result, record),
                    ))

        matches.sort(key=lambda item: item[0], reverse=True)
        implementations: list[tuple[float, str, str]] = []
        extracted: dict[str, str] = {}
        labels_by_category: dict[str, list[dict[str, Any]]] = {}
        rule_ids: list[str] = []

        existing_ids = {match.vendor_id for match in result.matched_rules}
        for confidence, rule, values in matches:
            rule_id = rule["id"]
            if rule_id in existing_ids:
                continue
            labels = rule.get("labels", {})
            category = rule.get("category", "")
            rule_ids.append(rule_id)
            extracted.update(values)
            labels_by_category.setdefault(category, []).append(labels)
            result.matched_rules.append(FingerprintMatch(
                vendor_id=rule_id,
                vendor_name=rule.get("name", rule_id),
                pattern=rule_id,
                confidence=confidence,
                source="database_fingerprint_library",
                category=category,
                labels=labels,
                extracted=values,
            ))
            implementation = labels.get("implementation") or labels.get("implementation_hint", "")
            if category in {"implementation", "implementation_hint"} and implementation:
                implementations.append((confidence, implementation, rule_id))

        if implementations:
            confidence, implementation, rule_id = max(implementations)
            result.vendor = implementation
            result.vendor_id = rule_id
            result.vendor_confidence = confidence
            if result.redis:
                result.redis.implementation = implementation
            elif result.mysql:
                result.mysql.implementation = implementation
            elif result.pgsql:
                result.pgsql.implementation = implementation

        version = (
            extracted.get("redis_version") or extracted.get("version") or
            extracted.get("server_version") or ""
        )
        if result.redis and version:
            result.redis.version = version
        if result.redis:
            modes = [
                labels.get("mode", "")
                for labels in labels_by_category.get("deployment_mode", [])
            ]
            if any(modes):
                result.redis.mode = next(mode for mode in modes if mode)

        result.fingerprint_details = {
            "library_schema": "structured-fingerprint-rule-v1",
            "protocol_match": any(
                rule.get("category") in {"protocol_identity", "protocol_identity_weak"}
                for _, rule, _ in matches
            ),
            "matched_rule_ids": rule_ids,
            "extracted": extracted,
            "labels": labels_by_category,
        }
        return result
