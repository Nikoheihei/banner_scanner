"""Build a reproducible per-software target manifest for Cherry Studio SSE tests."""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
from collections import defaultdict
from pathlib import Path


PROTOCOL_NAMES = {
    "FTP": "ftp",
    "MYSQL": "mysql",
    "PGSQL": "pgsql",
    "REDIS": "redis",
    "SSH": "ssh",
    "TELNET": "telnet",
}


def slug(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--per-class", type=int, default=100)
    parser.add_argument("--seed", type=int, default=2026070601)
    args = parser.parse_args()

    source = Path(args.source)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = json.loads(source.read_text(encoding="utf-8"))

    grouped: dict[tuple[str, str], dict[tuple[str, int], dict]] = defaultdict(dict)
    for row in rows:
        protocol = str(row["protocol"]).upper()
        software = str(row["software_true"])
        host = str(row["host"])
        port = int(row["port"])
        address = ipaddress.ip_address(host)
        if not address.is_global:
            continue
        grouped[(protocol, software)][(host, port)] = row

    rng = random.Random(args.seed)
    manifest = []
    for index, ((protocol, software), unique_rows) in enumerate(sorted(grouped.items()), start=1):
        candidates = list(unique_rows.values())
        rng.shuffle(candidates)
        selected = candidates[: args.per_class]
        class_id = f"{index:02d}-{PROTOCOL_NAMES[protocol]}-{slug(software)}"
        manifest.append({
            "class_id": class_id,
            "protocol": PROTOCOL_NAMES[protocol],
            "protocol_label": protocol,
            "software": software,
            "requested": args.per_class,
            "available_unique_public": len(candidates),
            "selected": len(selected),
            "shortage": max(0, args.per_class - len(selected)),
            "hosts": [row["host"] for row in selected],
            "endpoints": [
                {"host": row["host"], "port": int(row["port"])}
                for row in selected
            ],
        })

    (output_dir / "target_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    summary = {
        "seed": args.seed,
        "requested_per_class": args.per_class,
        "classes": len(manifest),
        "selected_targets": sum(item["selected"] for item in manifest),
        "full_100_classes": sum(item["selected"] == args.per_class for item in manifest),
        "shortage_classes": [
            {
                "class_id": item["class_id"],
                "protocol": item["protocol"],
                "software": item["software"],
                "available": item["selected"],
                "shortage": item["shortage"],
            }
            for item in manifest if item["shortage"]
        ],
    }
    (output_dir / "selection_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
