"""Run resumable per-software active evaluations through the MCP SSE transport."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def _tool_payload(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    for content in getattr(result, "content", []):
        text = getattr(content, "text", "")
        if text:
            value = json.loads(text)
            if isinstance(value, dict):
                return value
    raise RuntimeError("MCP tool returned no JSON object")


def _result_shape(item: dict[str, Any]) -> tuple[Any, ...]:
    """Describe a UI-distinct result while ignoring literal target/software values."""
    endpoint = item.get("endpoint") or {}
    primary = item.get("primary_identification") or {}
    observations = item.get("observations") or {}
    findings = item.get("findings") or {}
    error = item.get("error") or {}
    observation_shape = tuple(
        sorted(
            (name, tuple(sorted(value.keys())) if isinstance(value, dict) else type(value).__name__)
            for name, value in observations.items()
        )
    )
    finding_shape = tuple(sorted(findings.keys()))
    return (
        str(endpoint.get("protocol") or "").lower(),
        item.get("network_status", ""),
        item.get("protocol_status", ""),
        item.get("identification_status", ""),
        primary.get("result_type", ""),
        primary.get("match_level", ""),
        primary.get("evidence_strength", ""),
        observation_shape,
        finding_shape,
        error.get("code", ""),
    )


async def _call_tool(url: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        from mcp import ClientSession
        from mcp.client.sse import sse_client
    except ImportError as exc:
        raise RuntimeError('Install the locked dependency: pip install "mcp[cli]==1.28.1"') from exc

    async with sse_client(url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            return _tool_payload(await session.call_tool(tool, arguments=arguments))


async def _run_class(
    url: str,
    entry: dict[str, Any],
    retries: int,
    concurrency: int,
    detail_level: str,
) -> dict[str, Any]:
    payload = await _call_tool(url, "scan_batch", {
        "hosts": entry["hosts"],
        "protocol": entry["protocol"],
        "retries": retries,
        "concurrency": concurrency,
        "detail_level": detail_level,
    })
    by_host = {
        str((item.get("endpoint") or {}).get("host") or ""): item
        for item in payload.get("results", [])
    }
    ordered_results = []
    for endpoint in entry["endpoints"]:
        host = endpoint["host"]
        item = by_host.get(host)
        if item is None:
            item = {
                "network_status": "unreachable",
                "protocol_status": "not_observed",
                "identification_status": "unidentified",
                "endpoint": {
                    "host": host,
                    "port": endpoint["port"],
                    "protocol": entry["protocol"].upper(),
                },
                "primary_identification": None,
                "error": {"code": "missing_result", "message": "MCP result missing"},
            }
        ordered_results.append({
            "expected_software": entry["software"],
            "result_shape": list(_result_shape(item)),
            "mcp_result": item,
        })
    return {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "transport": "sse",
        "sse_url": url,
        "class": entry,
        "mcp_envelope": {key: value for key, value in payload.items() if key != "results"},
        "results": ordered_results,
    }


def _write_aggregate(output_dir: Path, class_results: list[dict[str, Any]]) -> None:
    all_rows: list[dict[str, Any]] = []
    for result in class_results:
        entry = result["class"]
        for row in result["results"]:
            all_rows.append({
                "class_id": entry["class_id"],
                "protocol": entry["protocol"],
                "software_true": entry["software"],
                **row,
            })

    shape_groups: dict[str, dict[str, Any]] = {}
    for row in all_rows:
        signature = json.dumps(row["result_shape"], ensure_ascii=False, sort_keys=True)
        group = shape_groups.setdefault(signature, {
            "shape_id": f"shape-{len(shape_groups) + 1:02d}",
            "signature": row["result_shape"],
            "classes": set(),
            "representative": {
                "class_id": row["class_id"],
                "protocol": row["protocol"],
                "software": row["software_true"],
                "host": (row["mcp_result"].get("endpoint") or {}).get("host", ""),
            },
        })
        group["classes"].add(row["class_id"])
    serializable_shapes = []
    for group in shape_groups.values():
        serializable_shapes.append({
            **group,
            "classes": sorted(group["classes"]),
            "class_count": len(group["classes"]),
        })

    class_index = [
        {
            "class_id": result["class"]["class_id"],
            "protocol": result["class"]["protocol"],
            "software": result["class"]["software"],
            "targets": len(result["results"]),
        }
        for result in class_results
    ]
    (output_dir / "completed_classes.json").write_text(
        json.dumps(class_index, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with (output_dir / "sse_results.jsonl").open("w", encoding="utf-8") as handle:
        for row in all_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    (output_dir / "unique_result_shapes.json").write_text(
        json.dumps(serializable_shapes, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    aggregate = {
        "transport": "sse",
        "classes_completed": len(class_results),
        "targets": len(all_rows),
        "unique_result_shapes": len(serializable_shapes),
    }
    (output_dir / "aggregate_summary.json").write_text(
        json.dumps(aggregate, ensure_ascii=False, indent=2), encoding="utf-8"
    )


async def main_async(args: argparse.Namespace) -> None:
    manifest_path = Path(args.manifest)
    output_dir = Path(args.output_dir or manifest_path.parent)
    class_dir = output_dir / "classes"
    class_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    health_path = output_dir / "sse_health.json"
    if not health_path.exists() or args.force:
        health = await _call_tool(args.url, "health_check", {})
        health_path.write_text(json.dumps(health, ensure_ascii=False, indent=2), encoding="utf-8")

    completed = []
    for index, entry in enumerate(manifest, start=1):
        path = class_dir / f"{entry['class_id']}.json"
        if path.exists() and not args.force:
            result = json.loads(path.read_text(encoding="utf-8"))
            print(f"[{index:02d}/{len(manifest)}] resume {entry['protocol']}/{entry['software']}", flush=True)
        else:
            print(
                f"[{index:02d}/{len(manifest)}] scan {entry['protocol']}/{entry['software']} "
                f"targets={entry['selected']}",
                flush=True,
            )
            result = await _run_class(
                args.url, entry, args.retries, args.concurrency, args.detail_level,
            )
            temporary = path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(path)
            print(f"  received={len(result['results'])}", flush=True)
        completed.append(result)
        _write_aggregate(output_dir, completed)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir")
    parser.add_argument("--url", default="http://127.0.0.1:8877/sse")
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--detail-level", choices=("summary", "evidence"), default="summary")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
