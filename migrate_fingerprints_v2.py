#!/usr/bin/env python3
"""Migrate the six isolated fingerprint libraries to the explicit v2 envelope."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from banner_scanner.build_fingerprints import stable_text_rule_id, v2_text_metadata
from banner_scanner.core.database_matcher import _evidence_strength, _rule_semantics


ROOT = Path(__file__).resolve().parent


def migrate_text_libraries() -> None:
    for path in sorted((ROOT / "fingerprints" / "protocols").glob("*_fingerprints.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        used_ids: set[str] = set()
        for rule in data.get("vendors", []):
            legacy_id = rule.get("legacy_id", rule["id"])
            category = str(rule.get("category") or "implementation")
            priority = int(rule.get("priority", 100))
            metadata = v2_text_metadata(category, priority)
            for key, value in metadata.items():
                rule.setdefault(key, value)
            stable_id = stable_text_rule_id(
                str(rule.get("protocol") or data.get("protocol") or ""),
                str(rule["result_type"]),
                str(rule["name"]),
            )
            if stable_id in used_ids:
                digest = hashlib.sha1(rule["pattern"].encode("utf-8")).hexdigest()[:8]
                stable_id = f"{stable_id}.{digest}"
            used_ids.add(stable_id)
            rule["legacy_id"] = legacy_id
            rule["id"] = stable_id
            rule.pop("priority", None)
            rule.pop("category", None)
        data["schema"] = "banner-scanner.protocol-fingerprints.v2"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def migrate_database_libraries() -> None:
    for path in sorted((ROOT / "fingerprints" / "databases").glob("*_fingerprints.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for rule in data.get("rules", []):
            result_type, match_level, primary_eligible = _rule_semantics(rule)
            rule.setdefault("result_type", result_type)
            rule.setdefault("match_level", match_level)
            rule.setdefault("evidence_strength", _evidence_strength(rule))
            rule.setdefault("primary_eligible", primary_eligible)
            rule.pop("confidence", None)
        data["schema"] = "banner-scanner.database-fingerprints.v2"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    migrate_text_libraries()
    migrate_database_libraries()


if __name__ == "__main__":
    main()
