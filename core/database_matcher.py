"""Matcher for the structured Redis/MySQL/PostgreSQL fingerprint libraries."""

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from .identification import (
    EVIDENCE_STRENGTH_RANK,
    LEGACY_CONFIDENCE,
    MATCH_LEVEL_RANK,
    finalize_identification,
)
from .models import (
    BannerResult,
    EVIDENCE_STRENGTHS,
    FingerprintMatch,
    RESULT_TYPES,
)

logger = logging.getLogger("banner_scanner.database_matcher")

DEFAULT_LIBRARY_DIR = Path(__file__).parent.parent / "fingerprints" / "databases"

CONDITION_KEYS = {
    "requires_context",
    "all",
    "any",
    "none",
    "field_equals",
    "field_regex",
    "field_present",
    "any_field_regex",
    "none_field_regex",
}


def _evidence_strength(rule: dict[str, Any]) -> str:
    explicit = str(rule.get("evidence_strength") or "")
    if explicit:
        return explicit
    legacy = float(rule.get("confidence", 0.5))
    if legacy >= 0.98:
        return "conclusive"
    if legacy >= 0.85:
        return "strong"
    if legacy >= 0.65:
        return "moderate"
    return "weak"


def _rule_semantics(rule: dict[str, Any]) -> tuple[str, str, bool]:
    result_type = str(rule.get("result_type") or "")
    match_level = str(rule.get("match_level") or "")
    primary_eligible = rule.get("primary_eligible")
    if result_type and match_level and primary_eligible is not None:
        return result_type, match_level, bool(primary_eligible)

    category = str(rule.get("category") or "")
    mapping = {
        "implementation": ("software", "software_name", True),
        "implementation_hint": ("software", "implementation_hint", True),
        "version_extraction": ("software", "software_version", False),
        "protocol_identity": ("protocol_identity", "protocol_only", False),
        "protocol_identity_weak": ("protocol_identity", "protocol_only", False),
        "provider_hint": ("provider", "generic_device_hint", False),
        "provider_metadata": ("provider", "generic_device_hint", False),
        "distribution_hint": ("deployment", "generic_device_hint", False),
        "deployment_distribution": ("deployment", "generic_device_hint", False),
        "deployment_hint": ("deployment", "generic_device_hint", False),
        "deployment_mode": ("deployment", "generic_device_hint", False),
        "runtime_hint": ("deployment", "generic_device_hint", False),
        "runtime_environment": ("deployment", "generic_device_hint", False),
        "auth_metadata": ("authentication", "status_fact", False),
        "auth_fingerprint": ("authentication", "status_fact", False),
        "auth_state": ("authentication", "status_fact", False),
        "security_requirement": ("authentication", "status_fact", False),
        "capability_metadata": ("capability", "status_fact", False),
        "probe_depth": ("capability", "status_fact", False),
        "error_classification": ("service_status", "status_fact", False),
        "availability_state": ("service_status", "status_fact", False),
        "field_extraction": ("service_status", "status_fact", False),
    }
    return mapping.get(category, ("capability", "status_fact", False))


def _database_rule_rank(rule: dict[str, Any]) -> tuple[int, int, int, str]:
    _result_type, match_level, _primary_eligible = _rule_semantics(rule)
    return (
        MATCH_LEVEL_RANK.get(match_level, 0),
        EVIDENCE_STRENGTH_RANK.get(_evidence_strength(rule), 0),
        int(rule.get("tie_breaker", 0)),
        str(rule.get("id", "")),
    )


def _validate_regex(pattern: str, rule_id: str) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex in rule {rule_id}: {exc}") from exc


def _validate_condition_tree(condition: Any, rule_id: str) -> None:
    if isinstance(condition, str):
        _validate_regex(condition, rule_id)
        return
    if not isinstance(condition, dict):
        raise ValueError(f"Invalid condition node in rule {rule_id}")
    unknown = set(condition) - CONDITION_KEYS
    if unknown:
        raise ValueError(f"Unknown condition keys in rule {rule_id}: {sorted(unknown)}")
    for operator in ("all", "any", "none"):
        if operator in condition:
            for child in _condition_items(condition[operator]):
                _validate_condition_tree(child, rule_id)
    for pattern in condition.get("field_regex", {}).values():
        _validate_regex(str(pattern), rule_id)
    for operator in ("any_field_regex", "none_field_regex"):
        for item in condition.get(operator, []):
            _validate_regex(str(item["regex"]), rule_id)


def _validate_libraries(libraries: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    for library in libraries:
        for rule in library.get("rules", []):
            rule_id = str(rule.get("id") or "")
            if not rule_id:
                raise ValueError("Database fingerprint rule is missing id")
            if rule_id in seen:
                raise ValueError(f"Duplicate database fingerprint rule id: {rule_id}")
            seen.add(rule_id)
            result_type, _match_level, _primary_eligible = _rule_semantics(rule)
            if result_type not in RESULT_TYPES:
                raise ValueError(f"Invalid result_type in rule {rule_id}: {result_type}")
            strength = _evidence_strength(rule)
            if strength not in EVIDENCE_STRENGTHS:
                raise ValueError(
                    f"Invalid evidence_strength in rule {rule_id}: {strength}"
                )
            _validate_condition_tree(rule.get("match", {}), rule_id)
            for extractor in rule.get("extract", []):
                if extractor.get("regex"):
                    _validate_regex(str(extractor["regex"]), rule_id)


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


def _condition_items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _condition_matches(match: Any, result: BannerResult,
                       record: dict[str, Any]) -> bool:
    """Evaluate a recursive condition tree without deriving evidence strength."""
    if isinstance(match, str):
        return _regex_match(result.banner, match)
    if not isinstance(match, dict):
        return False

    context = {"scanner_protocol": result.protocol}
    for key, expected in match.get("requires_context", {}).items():
        if context.get(key) != expected:
            return False

    banner = result.banner
    for child in _condition_items(match.get("all", [])):
        if not _condition_matches(child, result, record):
            return False
    any_conditions = _condition_items(match.get("any", []))
    if any_conditions and not any(
        _condition_matches(child, result, record) for child in any_conditions
    ):
        return False
    for child in _condition_items(match.get("none", [])):
        if _condition_matches(child, result, record):
            return False

    for field, expected in match.get("field_equals", {}).items():
        if _get_path(record, field) != expected:
            return False
    for field, pattern in match.get("field_regex", {}).items():
        if not _regex_match(_get_path(record, field), pattern):
            return False
    for field in _condition_items(match.get("field_present", [])):
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
        _validate_libraries(self._libraries)

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

    def stats(self) -> dict[str, int]:
        return {
            str(library.get("protocol", {}).get("canonical") or "").upper(): len(
                library.get("rules", [])
            )
            for library in self._libraries
            if library.get("protocol", {}).get("canonical")
        }

    def match(self, result: BannerResult) -> BannerResult:
        if not result.accessible:
            return result

        record = _result_record(result)
        matches: list[tuple[dict[str, Any], dict[str, str]]] = []
        for library in self._libraries:
            canonical = library.get("protocol", {}).get("canonical", "")
            if canonical and canonical != result.protocol:
                continue
            for rule in library.get("rules", []):
                if _condition_matches(rule.get("match", {}), result, record):
                    matches.append((rule, _extract_values(rule, result, record)))

        matches.sort(key=lambda item: _database_rule_rank(item[0]), reverse=True)
        extracted: dict[str, str] = {}
        labels_by_category: dict[str, list[dict[str, Any]]] = {}
        rule_ids: list[str] = []

        existing_ids = {match.vendor_id for match in result.matched_rules}
        for rule, values in matches:
            rule_id = rule["id"]
            if rule_id in existing_ids:
                continue
            labels = rule.get("labels", {})
            category = rule.get("category", "")
            rule_ids.append(rule_id)
            extracted.update(values)
            labels_by_category.setdefault(category, []).append(labels)
            result_type, match_level, primary_eligible = _rule_semantics(rule)
            strength = _evidence_strength(rule)
            semantic_name = str(
                labels.get("implementation")
                or labels.get("implementation_hint")
                or rule.get("name", rule_id)
            )
            result.matched_rules.append(FingerprintMatch(
                vendor_id=rule_id,
                vendor_name=semantic_name,
                pattern=rule_id,
                confidence=LEGACY_CONFIDENCE.get(strength, 0.0),
                source="database_fingerprint_library",
                category=category,
                labels=labels,
                extracted=values,
                result_type=result_type,
                match_level=match_level,
                evidence_strength=strength,
                primary_eligible=primary_eligible,
                tie_breaker=int(rule.get("tie_breaker", 0)),
                explanation=str(rule.get("description") or ""),
            ))

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
                for rule, _ in matches
            ),
            "matched_rule_ids": rule_ids,
            "extracted": extracted,
            "labels": labels_by_category,
        }
        finalize_identification(result)
        if result.primary_identification:
            implementation = result.primary_identification.name
            if result.redis:
                result.redis.implementation = implementation
            elif result.mysql:
                result.mysql.implementation = implementation
            elif result.pgsql:
                result.pgsql.implementation = implementation
        return result
