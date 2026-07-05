#!/usr/bin/env python3
"""Offline rule-regression audit over the six original Banner corpora.

This validates rule construction and conflict behavior only.  It does not
replace the authorized active performance and MCP flow tests.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from ..core.identify import OfflineIdentifier
from ..core.parsers import parse_ftp_banner_info, parse_redis_response, parse_ssh_banner
from .active_fingerprint_eval import iter_concatenated_json, normalize_label, truth_label


def prediction(protocol: str, result) -> str:
    if result.primary_identification is None:
        return ""
    return normalize_label(protocol, result.primary_identification.name)


def database_rows(path: Path) -> Iterable[tuple[str, str, int, str, dict[str, Any]]]:
    uri = f"file:{path}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        for host, port, protocol, banner in connection.execute(
            "SELECT ip, port, protocol, banner FROM banner_mapping "
            "WHERE protocol IN ('SSH','FTP','TELNET')"
        ):
            yield str(host), str(protocol), int(port), str(banner or ""), {}
    finally:
        connection.close()


def json_rows(path: Path) -> Iterable[tuple[str, str, int, str, dict[str, Any]]]:
    for item in iter_concatenated_json(path):
        default_host = str(item.get("ip") or item.get("domain") or "")
        for record in item.get("protocols", []):
            if not record.get("accessible"):
                continue
            yield (
                str(record.get("host") or default_host),
                str(record.get("protocol") or "").upper(),
                int(record.get("port") or 0),
                str(record.get("banner") or ""),
                record,
            )


def structured_fields(protocol: str, banner: str, record: dict[str, Any]) -> dict[str, Any]:
    if protocol == "SSH":
        return vars(parse_ssh_banner(banner))
    if protocol == "FTP":
        return vars(parse_ftp_banner_info(banner))
    if protocol == "REDIS":
        return vars(parse_redis_response("", banner))
    if protocol == "MYSQL":
        return dict(record.get("mysql") or {})
    if protocol == "PGSQL":
        values = dict(record.get("pgsql") or {})
        version = str(values.pop("version", "") or "")
        if version:
            values["parameters"] = {"server_version": version}
        return values
    return {}


def audit_rows(rows, identifier: OfflineIdentifier, per_class: int,
               seen: dict[tuple[str, str], set[str]], counters: Counter,
               confusion: Counter, exceptions: list[dict[str, Any]]) -> None:
    for host, protocol, _port, banner, record in rows:
        label = truth_label(protocol, banner, record)
        if not label or not host:
            continue
        key = (protocol, label)
        if host in seen[key] or len(seen[key]) >= per_class:
            continue
        seen[key].add(host)
        result = identifier.identify(
            protocol,
            raw_banner=banner,
            structured_fields=structured_fields(protocol, banner, record),
        )
        predicted = prediction(protocol, result)
        counters["samples"] += 1
        counters[f"status:{result.identification_status}"] += 1
        counters["correct"] += int(predicted == label)
        confusion[(protocol, label, predicted, result.identification_status)] += 1
        if result.identification_status != "identified" and len(exceptions) < 100:
            exceptions.append({
                "protocol": protocol,
                "expected": label,
                "host": host,
                "banner_preview": banner[:500],
                "identification_status": result.identification_status,
                "candidates": [
                    candidate.name for candidate in result.identification_candidates
                ],
            })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fingerprint-db", required=True)
    parser.add_argument("--redis", required=True)
    parser.add_argument("--mysql", required=True)
    parser.add_argument("--pgsql", required=True)
    parser.add_argument("--per-class", type=int, default=384)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    identifier = OfflineIdentifier.load_default()
    seen: dict[tuple[str, str], set[str]] = defaultdict(set)
    counters: Counter = Counter()
    confusion: Counter = Counter()
    exceptions: list[dict[str, Any]] = []
    audit_rows(
        database_rows(Path(args.fingerprint_db)), identifier, args.per_class,
        seen, counters, confusion, exceptions,
    )
    for path in (args.redis, args.mysql, args.pgsql):
        audit_rows(
            json_rows(Path(path)), identifier, args.per_class,
            seen, counters, confusion, exceptions,
        )

    payload = {
        "samples": counters["samples"],
        "correct": counters["correct"],
        "accuracy": counters["correct"] / max(counters["samples"], 1),
        "identification_status": {
            key.split(":", 1)[1]: value
            for key, value in counters.items() if str(key).startswith("status:")
        },
        "per_class": [
            {
                "protocol": protocol,
                "expected": expected,
                "predicted": predicted,
                "identification_status": status,
                "count": count,
            }
            for (protocol, expected, predicted, status), count in sorted(confusion.items())
        ],
        "exceptions": exceptions,
    }
    Path(args.output).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({key: value for key, value in payload.items() if key != "per_class"},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
