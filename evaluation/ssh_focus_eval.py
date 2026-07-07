"""Focused active evaluation for SSH software classes with explicit banner prefixes."""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from ..core.matcher import DEFAULT_PROTOCOL_LIBRARY_DIR

from .active_fingerprint_eval import (
    DeterministicSampler,
    TargetSample,
    compute_metrics,
    filter_unreachable_classes,
    make_engine,
    run_engine_samples,
    run_mcp_samples,
    select_flow_samples,
    write_json,
    write_jsonl,
)


FOCUS_PREFIXES = {
    "ssh-2.0-paramiko": "Paramiko",
    "ssh-2.0-mod_sftp": "mod_sftp",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fingerprint-db", required=True)
    parser.add_argument("--output-dir", required=True)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--vendors", default=str(DEFAULT_PROTOCOL_LIBRARY_DIR))
    parser.add_argument("--database-fingerprints", default=str(root / "fingerprints" / "databases"))
    parser.add_argument("--performance-per-class", type=int, default=384)
    parser.add_argument("--flow-per-class", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20260628)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--mcp-chunk-size", type=int, default=20)
    parser.add_argument("--connect-timeout", type=float, default=2.5)
    parser.add_argument("--read-timeout", type=float, default=2.5)
    parser.add_argument("--confirm-authorized", action="store_true")
    return parser.parse_args()


def first_line(text: str) -> str:
    return text.splitlines()[0].strip() if text else ""


def focused_label(banner: str) -> str:
    lowered = first_line(banner).lower()
    for prefix, label in FOCUS_PREFIXES.items():
        if lowered.startswith(prefix):
            return label
    return ""


def build_samples(args: argparse.Namespace) -> tuple[dict, list[TargetSample], list[TargetSample]]:
    cap = args.performance_per_class + args.flow_per_class
    sampler = DeterministicSampler(cap, args.seed)
    uri = f"file:{Path(args.fingerprint_db)}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        cursor = connection.execute(
            "SELECT ip, port, protocol, banner FROM banner_mapping WHERE protocol='SSH'"
        )
        for host, port, protocol, banner in cursor:
            label = focused_label(banner or "")
            if not label:
                continue
            sampler.add(TargetSample(
                protocol=protocol.upper(),
                software_true=label,
                host=host,
                port=int(port),
                source=Path(args.fingerprint_db).name,
                historical_banner=(banner or "")[:1000],
            ))
    finally:
        connection.close()

    selected = sampler.samples()
    performance: list[TargetSample] = []
    flow: list[TargetSample] = []
    classes = []
    for key, samples in sorted(selected.items()):
        protocol, software = key
        if len(samples) > args.flow_per_class:
            flow_count = args.flow_per_class
            performance_count = min(args.performance_per_class, len(samples) - flow_count)
            performance_group = samples[:performance_count]
            flow_group = samples[-flow_count:]
        else:
            performance_count = min(args.performance_per_class, len(samples))
            flow_count = len(samples)
            performance_group = samples[:performance_count]
            flow_group = samples[:flow_count]
        performance.extend(performance_group)
        flow.extend(flow_group)
        classes.append({
            "protocol": protocol,
            "software": software,
            "candidate_rows": sampler.candidate_rows[key],
            "selected_unique_ips": len(samples),
            "performance_targets": performance_count,
            "flow_targets": flow_count,
            "flow_has_100": flow_count == args.flow_per_class,
            "performance_flow_overlap": len(
                {sample.host for sample in performance_group}
                & {sample.host for sample in flow_group}
            ),
        })
    inventory = {
        "seed": args.seed,
        "performance_per_class": args.performance_per_class,
        "flow_per_class": args.flow_per_class,
        "classes": classes,
        "performance_targets": len(performance),
        "flow_targets": len(flow),
    }
    return inventory, performance, flow


def main() -> int:
    args = parse_args()
    if not args.confirm_authorized:
        raise SystemExit("Active probing requires --confirm-authorized")

    output_dir = Path(args.output_dir)
    inventory, performance_samples, flow_samples = build_samples(args)
    write_json(output_dir / "inventory.json", inventory)
    write_json(output_dir / "performance_manifest.json", [asdict(sample) for sample in performance_samples])

    engine = make_engine(args)
    performance_records = asyncio.run(
        run_engine_samples(performance_samples, engine, args.concurrency)
    )
    performance_records, skipped_performance_classes = filter_unreachable_classes(
        performance_records
    )
    write_jsonl(output_dir / "performance_active_results.jsonl", performance_records)
    performance_metrics = compute_metrics(performance_records)
    write_json(output_dir / "performance_metrics.json", performance_metrics)

    flow_samples, skipped_flow_seed_classes = select_flow_samples(
        flow_samples,
        performance_samples,
        performance_records,
        args.flow_per_class,
    )
    write_json(output_dir / "flow_manifest.json", [asdict(sample) for sample in flow_samples])
    flow_records, mcp_health = run_mcp_samples(
        flow_samples, args.concurrency, args.mcp_chunk_size,
    )
    flow_records, skipped_flow_classes = filter_unreachable_classes(flow_records)
    write_jsonl(output_dir / "flow_mcp_results.jsonl", flow_records)
    flow_metrics = compute_metrics(flow_records)
    write_json(output_dir / "flow_metrics.json", flow_metrics)
    write_json(output_dir / "mcp_health.json", mcp_health)
    skipped = {
        "performance": skipped_performance_classes,
        "flow": skipped_flow_seed_classes + skipped_flow_classes,
    }
    write_json(output_dir / "skipped_classes.json", skipped)
    summary = {
        "inventory": inventory,
        "performance": performance_metrics,
        "flow": flow_metrics,
        "mcp_health": mcp_health,
        "skipped_classes": skipped,
    }
    write_json(output_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
