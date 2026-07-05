"""Semantic fingerprint result selection shared by all protocol matchers."""

from __future__ import annotations

from typing import Any

from .models import BannerResult, FingerprintMatch, Identification, RESULT_TYPES


EVIDENCE_STRENGTH_RANK = {
    "weak": 10,
    "moderate": 20,
    "strong": 30,
    "conclusive": 40,
}

MATCH_LEVEL_RANK = {
    "protocol_only": 10,
    "software_family": 10,
    "provider_name": 20,
    "status_fact": 10,
    "generic_device_hint": 10,
    "device_family": 20,
    "implementation_hint": 20,
    "software_name": 30,
    "exact_model": 30,
    "software_version": 40,
    "vendor_build": 50,
}

LEGACY_CONFIDENCE = {
    "weak": 0.40,
    "moderate": 0.65,
    "strong": 0.85,
    "conclusive": 1.0,
}


def legacy_rule_metadata(category: str, priority: int = 0) -> dict[str, Any]:
    """Map v1 text-rule metadata into the v2 semantic fields."""
    if category == "fallback":
        return {
            "result_type": "protocol_identity",
            "match_level": "protocol_only",
            "evidence_strength": "weak",
            "primary_eligible": False,
        }
    if category == "family":
        return {
            "result_type": "device_family",
            "match_level": "device_family",
            "evidence_strength": "moderate",
            "primary_eligible": False,
        }
    if category == "status":
        return {
            "result_type": "service_status",
            "match_level": "status_fact",
            "evidence_strength": "moderate",
            "primary_eligible": False,
        }
    strength = "conclusive" if priority >= 140 else "strong"
    level = "implementation_hint" if priority and priority < 100 else "software_name"
    return {
        "result_type": "software",
        "match_level": level,
        "evidence_strength": strength,
        "primary_eligible": True,
    }


def match_rank(match: FingerprintMatch) -> tuple[int, int, int, int, int, str]:
    """Return a deterministic rank used only inside one result type."""
    return (
        MATCH_LEVEL_RANK.get(match.match_level, 0),
        EVIDENCE_STRENGTH_RANK.get(match.evidence_strength, 0),
        match.tie_breaker,
        match.specificity,
        match.match_length,
        str(match.vendor_id),
    )


def _version_for(result: BannerResult, match: FingerprintMatch) -> str:
    extracted = match.extracted
    version = (
        extracted.get("version")
        or extracted.get("redis_version")
        or extracted.get("server_version")
        or ""
    )
    if version:
        return version
    name = match.vendor_name.casefold()
    if result.ssh and result.ssh.software and result.ssh.software.casefold() in name:
        return result.ssh.version
    if result.ftp and result.ftp.software and result.ftp.software.casefold() in name:
        return result.ftp.version
    if result.redis and result.redis.implementation and result.redis.implementation.casefold() in name:
        return result.redis.version
    if result.mysql and result.mysql.implementation and result.mysql.implementation.casefold() in name:
        return result.mysql.version
    if result.pgsql and result.pgsql.implementation and result.pgsql.implementation.casefold() in name:
        return result.pgsql.parameters.get("server_version", "")
    return ""


def _identification(result: BannerResult, match: FingerprintMatch) -> Identification:
    explanation = match.explanation or (
        f"Matched {match.match_level.replace('_', ' ')} evidence for "
        f"{match.vendor_name}."
    )
    return Identification(
        result_type=match.result_type,
        name=match.vendor_name,
        version=_version_for(result, match),
        evidence_strength=match.evidence_strength,
        explanation=explanation,
    )


def finalize_identification(result: BannerResult) -> BannerResult:
    """Build semantic findings and choose a primary software identification.

    Different result types are retained in parallel.  Ranking is applied only
    between candidates of the same result type.  Equal top software evidence
    for different names is reported as a conflict instead of being hidden by
    regex length or file order.
    """
    findings: dict[str, list[dict[str, Any]]] = {key: [] for key in RESULT_TYPES}
    seen_findings: set[tuple[str, str, str]] = set()
    for match in result.matched_rules:
        result_type = match.result_type if match.result_type in findings else "capability"
        semantic = _identification(result, match)
        key = (result_type, semantic.name.casefold(), semantic.version)
        if key in seen_findings:
            continue
        seen_findings.add(key)
        item: dict[str, Any] = {
            "name": semantic.name,
            "evidence_strength": semantic.evidence_strength,
            "explanation": semantic.explanation,
        }
        if semantic.version:
            item["version"] = semantic.version
        if match.labels:
            item["labels"] = match.labels
        if match.extracted:
            item["extracted"] = match.extracted
        findings[result_type].append(item)
    result.findings = {key: value for key, value in findings.items() if value}

    best_by_name: dict[str, FingerprintMatch] = {}
    for match in result.matched_rules:
        if (
            match.result_type != "software"
            or not match.primary_eligible
            or not match.vendor_name
            or match.vendor_name.casefold().startswith("unknown-")
        ):
            continue
        name_key = match.vendor_name.casefold()
        existing = best_by_name.get(name_key)
        if existing is None or match_rank(match) > match_rank(existing):
            best_by_name[name_key] = match

    candidates = sorted(best_by_name.values(), key=match_rank, reverse=True)
    result.primary_identification = None
    result.identification_candidates = []
    result.identification_status = "unidentified"
    if not candidates:
        result.vendor = ""
        result.vendor_id = 0
        result.vendor_confidence = 0.0
        return result

    top = candidates[0]
    top_semantic_rank = match_rank(top)[:3]
    conflicting = [candidate for candidate in candidates if match_rank(candidate)[:3] == top_semantic_rank]
    conflicting_names = {candidate.vendor_name.casefold() for candidate in conflicting}
    if len(conflicting_names) > 1:
        result.identification_status = "conflict"
        result.identification_candidates = [_identification(result, candidate) for candidate in conflicting]
        result.vendor = ""
        result.vendor_id = 0
        result.vendor_confidence = 0.0
        return result

    primary = _identification(result, top)
    result.identification_status = "identified"
    result.primary_identification = primary
    result.identification_candidates = [primary]
    result.vendor = primary.name
    result.vendor_id = top.vendor_id
    result.vendor_confidence = LEGACY_CONFIDENCE.get(primary.evidence_strength, 0.0)
    return result
