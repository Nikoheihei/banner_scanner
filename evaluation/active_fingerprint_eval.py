"""Build labeled target samples and actively evaluate banner fingerprints.

Historical files are used only to establish explicit protocol/software labels
and choose targets.  Every metric produced by ``run`` comes from a fresh
network connection, either through ``ProbeEngine`` (performance test) or the
HTTP MCP ``probe_banner`` tool (flow test).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import heapq
import json
import math
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from ..core.engine import ProbeEngine
from ..core.matcher import DEFAULT_PROTOCOL_LIBRARY_DIR, FingerprintMatcher
from ..core.models import BannerResult, ProbeConfig


@dataclass(frozen=True)
class TargetSample:
    protocol: str
    software_true: str
    host: str
    port: int
    source: str
    historical_banner: str


TRUTH_PATTERNS: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "SSH": [
        (re.compile(r"OpenSSH", re.I), "OpenSSH"),
        (re.compile(r"Dropbear", re.I), "Dropbear"),
        (re.compile(r"FlowSsh|WinSSHD|Bitvise", re.I), "Bitvise"),
        (re.compile(r"AWS_SFTP", re.I), "AWS SFTP"),
        (re.compile(r"FILES\.COM", re.I), "FILES.COM"),
        (re.compile(r"Nielsen", re.I), "Nielsen SFTP"),
        (re.compile(r"mod_sftp", re.I), "mod_sftp"),
        (re.compile(r"paramiko", re.I), "Paramiko"),
        (re.compile(r"GitLab[-_ ]SSHD", re.I), "GitLab SSHD"),
        (re.compile(r"Maverick", re.I), "Maverick SSHD"),
        (re.compile(r"SFTPGo", re.I), "SFTPGo"),
        (re.compile(r"SFTPPlus", re.I), "SFTPPlus"),
        (re.compile(r"GoAnywhere", re.I), "GoAnywhere"),
        (re.compile(r"ProFTPD", re.I), "ProFTPD"),
        (re.compile(r"CrushFTP", re.I), "CrushFTP"),
        (re.compile(r"WingFTP", re.I), "Wing FTP"),
        (re.compile(r"VShell", re.I), "VShell"),
        (re.compile(r"WeOnlyDo|wodFTPD", re.I), "WeOnlyDo SSH"),
        (re.compile(r"Cisco", re.I), "Cisco"),
        (re.compile(r"SSHPiper", re.I), "SSHPiper"),
        (re.compile(r"AsyncSSH", re.I), "AsyncSSH"),
    ],
    "FTP": [
        (re.compile(r"vsFTPd", re.I), "vsFTPd"),
        (re.compile(r"Pure-FTPd", re.I), "Pure-FTPd"),
        (re.compile(r"ProFTPD", re.I), "ProFTPD"),
        (re.compile(r"FileZilla", re.I), "FileZilla Server"),
        (re.compile(r"Microsoft FTP", re.I), "Microsoft FTP"),
        (re.compile(r"Serv-U", re.I), "Serv-U FTP"),
        (re.compile(r"Core FTP", re.I), "Core FTP Server"),
        (re.compile(r"pyftpdlib", re.I), "pyftpdlib"),
        (re.compile(r"Cerberus", re.I), "Cerberus FTP"),
        (re.compile(r"CrushFTP", re.I), "CrushFTP"),
        (re.compile(r"Wing FTP", re.I), "Wing FTP"),
        (re.compile(r"WS_FTP", re.I), "WS_FTP"),
        (re.compile(r"SFTPGo", re.I), "SFTPGo"),
        (re.compile(r"CoursEval", re.I), "CoursEval FTPS"),
        (re.compile(r"DreamHost", re.I), "DreamHost FTP"),
        (re.compile(r"Gameservers", re.I), "Gameservers FTPD"),
        (re.compile(r"xlight", re.I), "xlightftpd"),
    ],
    "TELNET": [
        (re.compile(r"BusyBox", re.I), "BusyBox telnetd"),
        (re.compile(r"Cisco|IOS", re.I), "Cisco IOS telnetd"),
        (re.compile(r"RouterOS|MikroTik", re.I), "RouterOS"),
        (re.compile(r"Windows|Microsoft", re.I), "Windows telnetd"),
        (re.compile(r"JetDirect", re.I), "HP JetDirect"),
        (re.compile(r"FileZilla", re.I), "FileZilla Server"),
    ],
    "PGSQL": [
        (re.compile(r"redshift", re.I), "Amazon Redshift"),
        (re.compile(r"crate|PgDecoder", re.I), "CrateDB"),
        (re.compile(r"cockroach", re.I), "CockroachDB"),
        (re.compile(r"yugabyte", re.I), "YugabyteDB"),
    ],
}


def iter_concatenated_json(path: str | Path, chunk_size: int = 1 << 20) -> Iterator[dict]:
    """Yield pretty-printed JSON objects concatenated without separators."""
    decoder = json.JSONDecoder()
    buffer = ""
    with Path(path).open("r", encoding="utf-8") as handle:
        while True:
            chunk = handle.read(chunk_size)
            eof = not chunk
            buffer += chunk
            position = 0
            while True:
                while position < len(buffer) and buffer[position].isspace():
                    position += 1
                if position >= len(buffer):
                    buffer = ""
                    break
                try:
                    value, end = decoder.raw_decode(buffer, position)
                except json.JSONDecodeError:
                    buffer = buffer[position:]
                    break
                if not isinstance(value, dict):
                    raise ValueError(
                        f"Expected JSON object in {path}, got {type(value).__name__}"
                    )
                yield value
                position = end
            if eof:
                if buffer.strip():
                    raise ValueError(f"Incomplete JSON object at end of {path}")
                return


def truth_label(protocol: str, banner: str, record: Optional[dict[str, Any]] = None) -> str:
    protocol = protocol.upper()
    record = record or {}
    text = banner or ""
    if protocol == "REDIS":
        for key, label in (
            ("valkey_version", "Valkey"),
            ("dragonfly_version", "Dragonfly"),
            ("memurai_version", "Memurai"),
            ("keydb_version", "KeyDB"),
            ("redis_version", "Redis"),
        ):
            if re.search(rf"(?mi)^{key}:", text):
                return label
        return ""
    if protocol == "MYSQL":
        version = str(record.get("mysql", {}).get("version") or text)
        for pattern, label in (
            (r"mariadb", "MariaDB"),
            (r"percona", "Percona Server"),
            (r"tidb", "TiDB"),
            (r"oceanbase", "OceanBase"),
        ):
            if re.search(pattern, version, re.I):
                return label
        if re.match(r"^(?:MySQL\s*)?\d", version, re.I):
            return "MySQL_or_compatible"
        return ""
    for pattern, label in TRUTH_PATTERNS.get(protocol, []):
        if pattern.search(text):
            return label
    return ""


def normalize_label(protocol: str, label: str) -> str:
    if not label:
        return ""
    protocol = protocol.upper()
    text = label.strip()
    lowered = text.lower()
    aliases = {
        "dropbear ssh": "Dropbear",
        "serv-u": "Serv-U FTP",
        "mysql-compatible": "MySQL_or_compatible",
        "mysql or compatible": "MySQL_or_compatible",
        "tenant-aware-proxy": "tenant-aware-proxy",
    }
    if lowered in aliases:
        return aliases[lowered]
    if protocol == "MYSQL":
        for token, canonical in (
            ("mariadb", "MariaDB"), ("percona", "Percona Server"),
            ("tidb", "TiDB"), ("oceanbase", "OceanBase"),
            ("mysql", "MySQL_or_compatible"),
        ):
            if token in lowered:
                return canonical
    if protocol == "REDIS":
        for token, canonical in (
            ("valkey", "Valkey"), ("dragonfly", "Dragonfly"),
            ("memurai", "Memurai"), ("keydb", "KeyDB"), ("redis", "Redis"),
        ):
            if token in lowered:
                return canonical
    for pattern, canonical in TRUTH_PATTERNS.get(protocol, []):
        if pattern.search(text):
            return canonical
    return text


class DeterministicSampler:
    def __init__(self, per_class: int, seed: int):
        self.per_class = per_class
        self.seed = seed
        self.heaps: dict[tuple[str, str], list[tuple[int, str, TargetSample]]] = defaultdict(list)
        self.selected_hosts: dict[tuple[str, str], set[str]] = defaultdict(set)
        self.candidate_rows: Counter[tuple[str, str]] = Counter()

    def add(self, sample: TargetSample) -> None:
        key = (sample.protocol, sample.software_true)
        self.candidate_rows[key] += 1
        if sample.host in self.selected_hosts[key]:
            return
        digest = hashlib.sha256(
            f"{self.seed}|{sample.protocol}|{sample.software_true}|{sample.host}".encode()
        ).digest()
        score = int.from_bytes(digest[:8], "big")
        heap = self.heaps[key]
        entry = (-score, sample.host, sample)
        if len(heap) < self.per_class:
            heapq.heappush(heap, entry)
            self.selected_hosts[key].add(sample.host)
            return
        largest_score = -heap[0][0]
        if score >= largest_score:
            return
        _, removed_host, _ = heapq.heapreplace(heap, entry)
        self.selected_hosts[key].remove(removed_host)
        self.selected_hosts[key].add(sample.host)

    def samples(self) -> dict[tuple[str, str], list[TargetSample]]:
        result = {}
        for key, heap in self.heaps.items():
            result[key] = [entry[2] for entry in sorted(heap, key=lambda item: (-item[0], item[1]))]
        return result


def collect_from_fingerprint_db(path: str | Path, sampler: DeterministicSampler) -> None:
    uri = f"file:{Path(path)}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        cursor = connection.execute(
            "SELECT ip, port, protocol, banner FROM banner_mapping "
            "WHERE protocol IN ('SSH','FTP','TELNET')"
        )
        for host, port, protocol, banner in cursor:
            label = truth_label(protocol, banner or "")
            if not label:
                continue
            sampler.add(TargetSample(
                protocol=protocol.upper(), software_true=label, host=host,
                port=int(port), source="fingerprint.db",
                historical_banner=(banner or "")[:1000],
            ))
    finally:
        connection.close()


def collect_from_json(path: str | Path, sampler: DeterministicSampler) -> None:
    for item in iter_concatenated_json(path):
        default_host = str(item.get("ip") or item.get("domain") or "")
        for record in item.get("protocols", []):
            if not record.get("accessible"):
                continue
            protocol = str(record.get("protocol", "")).upper()
            banner = str(record.get("banner") or "")
            label = truth_label(protocol, banner, record)
            host = str(record.get("host") or default_host)
            if not label or not host:
                continue
            sampler.add(TargetSample(
                protocol=protocol, software_true=label, host=host,
                port=int(record.get("port") or default_port(protocol)),
                source=Path(path).name, historical_banner=banner[:1000],
            ))


def default_port(protocol: str) -> int:
    return {"SSH": 22, "FTP": 21, "TELNET": 23, "REDIS": 6379,
            "MYSQL": 3306, "PGSQL": 5432}.get(protocol.upper(), 0)


def final_prediction_from_banner_result(result: BannerResult) -> tuple[str, str, str]:
    fingerprint = normalize_label(result.protocol, result.vendor)
    parsed = ""
    if result.ssh:
        parsed = result.ssh.software
    elif result.ftp:
        parsed = result.ftp.software
    elif result.telnet:
        parsed = result.telnet.detected_service
    elif result.redis:
        parsed = result.redis.implementation
    elif result.mysql:
        parsed = result.mysql.implementation
    elif result.pgsql:
        parsed = result.pgsql.implementation
    parsed = normalize_label(result.protocol, parsed)
    return fingerprint or parsed, fingerprint, parsed


def final_prediction_from_mcp(result: dict[str, Any]) -> tuple[str, str, str]:
    protocol = str(result.get("protocol", ""))
    fingerprint = normalize_label(protocol, str(result.get("fingerprint") or ""))
    parsed = ""
    for field, key in (("ssh", "software"), ("ftp", "software"),
                       ("telnet", "detected_service"),
                       ("redis", "implementation"), ("mysql", "implementation"),
                       ("pgsql", "implementation")):
        if result.get(field):
            parsed = str(result[field].get(key) or "")
            break
    parsed = normalize_label(protocol, parsed)
    return fingerprint or parsed, fingerprint, parsed


def active_record(sample: TargetSample, result: BannerResult, channel: str) -> dict[str, Any]:
    predicted, fingerprint, parsed = final_prediction_from_banner_result(result)
    return {
        "channel": channel,
        "protocol": sample.protocol,
        "software_true": sample.software_true,
        "software_pred": predicted,
        "fingerprint_pred": fingerprint,
        "parsed_pred": parsed,
        "correct": predicted == sample.software_true,
        "fingerprint_correct": fingerprint == sample.software_true,
        "host": sample.host,
        "port": result.port,
        "accessible": result.accessible,
        "banner": result.banner,
        "error": result.error,
        "response_time_ms": round(result.response_time_ms, 3),
        "matched_rule_ids": [match.vendor_id for match in result.matched_rules],
        "fingerprint_details": result.fingerprint_details,
        "source": sample.source,
    }


def mcp_record(sample: TargetSample, result: dict[str, Any]) -> dict[str, Any]:
    predicted, fingerprint, parsed = final_prediction_from_mcp(result)
    details = result.get("fingerprint_details") or {}
    return {
        "channel": "mcp_http",
        "protocol": sample.protocol,
        "software_true": sample.software_true,
        "software_pred": predicted,
        "fingerprint_pred": fingerprint,
        "parsed_pred": parsed,
        "correct": predicted == sample.software_true,
        "fingerprint_correct": fingerprint == sample.software_true,
        "host": sample.host,
        "port": result.get("port", sample.port),
        "accessible": bool(result.get("accessible")),
        "banner": result.get("banner", ""),
        "error": result.get("error", ""),
        "response_time_ms": result.get("response_time_ms", 0),
        "matched_rule_ids": details.get("matched_rule_ids", []),
        "fingerprint_details": details,
        "source": sample.source,
    }


async def run_engine_samples(samples: list[TargetSample], engine: ProbeEngine,
                             concurrency: int) -> list[dict[str, Any]]:
    grouped: dict[str, list[TargetSample]] = defaultdict(list)
    for sample in samples:
        grouped[sample.protocol].append(sample)
    records: list[dict[str, Any]] = []
    for protocol, group in sorted(grouped.items()):
        host_results = await engine.probe_hosts(
            [sample.host for sample in group], protocols=[protocol.lower()],
            concurrency=concurrency,
        )
        for sample, host_result in zip(group, host_results):
            result = host_result.results.get(protocol.lower())
            if result is None:
                result = BannerResult(protocol=protocol, host=sample.host,
                                      port=sample.port, error="missing result")
            records.append(active_record(sample, result, "probe_engine"))
    return records


def free_local_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def json_rpc(url: str, method: str, params: dict[str, Any], request_id: int,
             timeout: float) -> dict[str, Any]:
    payload = json.dumps({"jsonrpc": "2.0", "id": request_id,
                          "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.loads(response.read().decode())
    if "error" in value:
        raise RuntimeError(value["error"].get("message", str(value["error"])))
    return value["result"]


def wait_for_server(url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url.rsplit("/", 1)[0] + "/", timeout=1):
                return
        except (urllib.error.URLError, TimeoutError):
            time.sleep(0.2)
    raise TimeoutError("MCP HTTP server did not start")


def run_mcp_samples(samples: list[TargetSample], concurrency: int,
                    chunk_size: int, port: int = 0) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    port = port or free_local_port()
    package_parent = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["MCP_PORT"] = str(port)
    env["PYTHONPATH"] = str(package_parent) + os.pathsep + env.get("PYTHONPATH", "")
    process = subprocess.Popen(
        [sys.executable, "-m", "banner_scanner.server.mcp_http_server"],
        cwd=package_parent, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    url = f"http://127.0.0.1:{port}/message"
    records: list[dict[str, Any]] = []
    request_id = 1
    health: dict[str, Any] = {}
    try:
        wait_for_server(url)
        health_result = json_rpc(
            url, "tools/call", {"name": "health_check", "arguments": {}},
            request_id, 30,
        )
        request_id += 1
        health = json.loads(health_result["content"][0]["text"])

        grouped: dict[tuple[str, str], list[TargetSample]] = defaultdict(list)
        for sample in samples:
            grouped[(sample.protocol, sample.software_true)].append(sample)
        for (protocol, _software), group in sorted(grouped.items()):
            for start in range(0, len(group), chunk_size):
                chunk = group[start:start + chunk_size]
                result = json_rpc(
                    url, "tools/call",
                    {"name": "probe_banner", "arguments": {
                        "hosts": [sample.host for sample in chunk],
                        "protocols": [protocol.lower()], "retries": 0,
                        "concurrency": concurrency,
                    }},
                    request_id, max(60.0, len(chunk) * 10.0),
                )
                request_id += 1
                payload = json.loads(result["content"][0]["text"])
                by_host = {str(item.get("host")): item for item in payload.get("results", [])}
                for sample in chunk:
                    item = by_host.get(sample.host, {
                        "protocol": protocol, "host": sample.host,
                        "accessible": False, "error": "missing MCP result",
                    })
                    records.append(mcp_record(sample, item))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return records, health


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def identification_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Split active results into reachability, abstention, and wrong matches."""
    total = len(records)
    reachable_records = [record for record in records if record["accessible"]]
    reachable = len(reachable_records)
    correct = sum(bool(record["correct"]) for record in reachable_records)
    fingerprint_covered = sum(
        bool(record.get("fingerprint_pred")) for record in reachable_records
    )
    abstained = sum(
        not record.get("software_pred") for record in reachable_records
    )
    misidentified = sum(
        bool(record.get("software_pred")) and not record["correct"]
        for record in reachable_records
    )
    return {
        "reachable": reachable,
        "reachability_rate": round(safe_div(reachable, total), 6),
        "post_reach_accuracy": round(safe_div(correct, reachable), 6),
        "fingerprint_covered": fingerprint_covered,
        "fingerprint_coverage_rate": round(
            safe_div(fingerprint_covered, reachable), 6,
        ),
        "abstained": abstained,
        "abstention_rate": round(safe_div(abstained, reachable), 6),
        "misidentified": misidentified,
        "misidentification_rate": round(
            safe_div(misidentified, reachable), 6,
        ),
    }


def compute_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_protocol: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_protocol[record["protocol"]].append(record)
    protocol_output: dict[str, Any] = {}
    for protocol, protocol_records in sorted(by_protocol.items()):
        labels = sorted({record["software_true"] for record in protocol_records})
        software_output = {}
        for label in labels:
            tp = sum(r["software_true"] == label and r["software_pred"] == label
                     for r in protocol_records)
            fp = sum(r["software_true"] != label and r["software_pred"] == label
                     for r in protocol_records)
            fn = sum(r["software_true"] == label and r["software_pred"] != label
                     for r in protocol_records)
            tn = len(protocol_records) - tp - fp - fn
            own = [r for r in protocol_records if r["software_true"] == label]
            accessible = [r for r in own if r["accessible"]]
            fingerprint_correct = sum(r.get("fingerprint_correct", False) for r in own)
            precision = safe_div(tp, tp + fp)
            recall = safe_div(tp, tp + fn)
            software_output[label] = {
                "samples": len(own), "correct": tp,
                "accuracy_e2e": round(safe_div(tp, len(own)), 6),
                "accuracy_valid": round(safe_div(
                    sum(r["correct"] for r in accessible), len(accessible)), 6),
                "fingerprint_only_accuracy": round(safe_div(fingerprint_correct, len(own)), 6),
                "accessible_rate": round(safe_div(len(accessible), len(own)), 6),
                "precision": round(precision, 6), "recall": round(recall, 6),
                "f1": round(safe_div(2 * precision * recall, precision + recall), 6),
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                **identification_metrics(own),
            }
        times = [float(r.get("response_time_ms") or 0) for r in protocol_records]
        correct = sum(r["correct"] for r in protocol_records)
        accessible = sum(r["accessible"] for r in protocol_records)
        protocol_output[protocol] = {
            "samples": len(protocol_records), "correct": correct,
            "accuracy": round(safe_div(correct, len(protocol_records)), 6),
            "accessible_rate": round(safe_div(accessible, len(protocol_records)), 6),
            **identification_metrics(protocol_records),
            "mean_response_time_ms": round(safe_div(sum(times), len(times)), 3),
            "p50_response_time_ms": round(percentile(times, 0.50), 3),
            "p95_response_time_ms": round(percentile(times, 0.95), 3),
            "software": software_output,
            "failure_reasons": dict(Counter(
                "correct" if r["correct"] else
                "unreachable" if not r["accessible"] else
                "no_match" if not r["software_pred"] else "wrong_software"
                for r in protocol_records
            )),
        }
    total = len(records)
    return {
        "metric_definitions": {
            "accuracy": "correct / samples",
            "reachability_rate": "reachable / samples",
            "post_reach_accuracy": "correct / reachable",
            "fingerprint_coverage_rate": (
                "reachable records with non-empty fingerprint_pred / reachable"
            ),
            "abstention_rate": (
                "reachable records with empty software_pred / reachable"
            ),
            "misidentification_rate": (
                "reachable records with non-empty incorrect software_pred / reachable"
            ),
        },
        "samples": total,
        "correct": sum(record["correct"] for record in records),
        "accuracy": round(safe_div(sum(record["correct"] for record in records), total), 6),
        **identification_metrics(records),
        "protocols": protocol_output,
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def build_samples(args: argparse.Namespace) -> tuple[dict, list[TargetSample], list[TargetSample]]:
    cap = args.performance_per_class + args.flow_per_class
    sampler = DeterministicSampler(cap, args.seed)
    collect_from_fingerprint_db(args.fingerprint_db, sampler)
    for path in (args.redis_results, args.mysql_results, args.pgsql_results):
        collect_from_json(path, sampler)

    selected = sampler.samples()
    performance: list[TargetSample] = []
    flow: list[TargetSample] = []
    inventory_classes = []
    for key, samples in sorted(selected.items()):
        protocol, software = key
        if len(samples) > args.flow_per_class:
            flow_count = args.flow_per_class
            performance_count = min(
                args.performance_per_class, len(samples) - flow_count,
            )
            performance_group = samples[:performance_count]
            flow_group = samples[-flow_count:]
        else:
            performance_count = min(args.performance_per_class, len(samples))
            flow_count = len(samples)
            performance_group = samples[:performance_count]
            flow_group = samples[:flow_count]
        performance.extend(performance_group)
        flow.extend(flow_group)
        overlap = len({sample.host for sample in performance_group} &
                      {sample.host for sample in flow_group})
        inventory_classes.append({
            "protocol": protocol, "software": software,
            "candidate_rows": sampler.candidate_rows[key],
            "selected_unique_ips": len(samples),
            "performance_targets": performance_count,
            "flow_targets": flow_count,
            "flow_has_100": flow_count == args.flow_per_class,
            "performance_flow_overlap": overlap,
        })
    inventory = {
        "seed": args.seed,
        "performance_per_class": args.performance_per_class,
        "flow_per_class": args.flow_per_class,
        "classes": inventory_classes,
        "performance_targets": len(performance),
        "flow_targets": len(flow),
    }
    return inventory, performance, flow


def group_target_samples(samples: list[TargetSample]) -> dict[tuple[str, str], list[TargetSample]]:
    grouped: dict[tuple[str, str], list[TargetSample]] = defaultdict(list)
    for sample in samples:
        grouped[(sample.protocol, sample.software_true)].append(sample)
    return grouped


def filter_unreachable_classes(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[(record["protocol"], record["software_true"])].append(record)
    kept: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for (protocol, software), group in sorted(grouped.items()):
        reachable = sum(bool(record["accessible"]) for record in group)
        if reachable:
            kept.extend(group)
            continue
        skipped.append({
            "protocol": protocol,
            "software": software,
            "samples": len(group),
            "reason": "no reachable targets in active probe sample",
        })
    return kept, skipped


def select_flow_samples(
    flow_candidates: list[TargetSample],
    performance_samples: list[TargetSample],
    performance_records: list[dict[str, Any]],
    flow_per_class: int,
) -> tuple[list[TargetSample], list[dict[str, Any]]]:
    perf_sample_map = {
        (sample.protocol, sample.software_true, sample.host): sample
        for sample in performance_samples
    }
    reachable_perf_by_class: dict[tuple[str, str], list[TargetSample]] = defaultdict(list)
    for record in performance_records:
        if not record["accessible"]:
            continue
        key = (record["protocol"], record["software_true"], record["host"])
        sample = perf_sample_map.get(key)
        if sample is None:
            continue
        reachable_perf_by_class[(sample.protocol, sample.software_true)].append(sample)

    selected: list[TargetSample] = []
    skipped: list[dict[str, Any]] = []
    for key, candidates in sorted(group_target_samples(flow_candidates).items()):
        protocol, software = key
        target_count = min(flow_per_class, len(candidates))
        chosen: list[TargetSample] = []
        seen_hosts: set[str] = set()

        for sample in sorted(
            reachable_perf_by_class.get(key, []),
            key=lambda item: (item.host, item.port),
        ):
            if sample.host in seen_hosts:
                continue
            chosen.append(sample)
            seen_hosts.add(sample.host)
            if len(chosen) >= target_count:
                break

        if not chosen:
            skipped.append({
                "protocol": protocol,
                "software": software,
                "samples": target_count,
                "reason": "no reachable targets available from active performance probe",
            })
            continue

        for sample in candidates:
            if sample.host in seen_hosts:
                continue
            chosen.append(sample)
            seen_hosts.add(sample.host)
            if len(chosen) >= target_count:
                break

        selected.extend(chosen[:target_count])
    return selected, skipped


def make_engine(args: argparse.Namespace) -> ProbeEngine:
    config = ProbeConfig(
        connect_timeout=args.connect_timeout, read_timeout=args.read_timeout,
        max_retries=0, fingerprint_path=str(Path(args.vendors).resolve()),
        database_fingerprint_path=str(Path(args.database_fingerprints).resolve()),
    )
    for protocol_config in config.protocol_config.values():
        protocol_config.connect_timeout = args.connect_timeout
        protocol_config.read_timeout = args.read_timeout
    engine = ProbeEngine(config)
    engine._matcher = FingerprintMatcher.load(args.vendors)
    return engine


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fingerprint-db", required=True)
    parser.add_argument("--redis-results", required=True)
    parser.add_argument("--mysql-results", required=True)
    parser.add_argument("--pgsql-results", required=True)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--vendors", default=str(DEFAULT_PROTOCOL_LIBRARY_DIR))
    parser.add_argument("--database-fingerprints", default=str(root / "fingerprints" / "databases"))
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--performance-per-class", type=int, default=384)
    parser.add_argument("--flow-per-class", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20260628)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--mcp-chunk-size", type=int, default=20)
    parser.add_argument("--connect-timeout", type=float, default=2.5)
    parser.add_argument("--read-timeout", type=float, default=2.5)
    parser.add_argument("--inventory-only", action="store_true")
    parser.add_argument("--flow-only", action="store_true",
                        help="Reuse and filter existing active performance results")
    parser.add_argument("--confirm-authorized", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir)
    inventory, performance_samples, flow_samples = build_samples(args)
    write_json(output_dir / "inventory.json", inventory)
    write_json(output_dir / "performance_manifest.json",
               [asdict(sample) for sample in performance_samples])
    if args.inventory_only:
        print(json.dumps(inventory, indent=2, ensure_ascii=False))
        return 0
    if not args.confirm_authorized:
        raise SystemExit("Active probing requires --confirm-authorized")

    performance_path = output_dir / "performance_active_results.jsonl"
    if args.flow_only:
        existing = read_jsonl(performance_path)
        selected_keys = {
            (sample.protocol, sample.software_true, sample.host)
            for sample in performance_samples
        }
        performance_records = [
            record for record in existing
            if (record["protocol"], record["software_true"], record["host"])
            in selected_keys
        ]
    else:
        engine = make_engine(args)
        performance_records = asyncio.run(run_engine_samples(
            performance_samples, engine, args.concurrency,
        ))
    performance_records, skipped_performance_classes = filter_unreachable_classes(
        performance_records
    )
    write_jsonl(performance_path, performance_records)
    performance_metrics = compute_metrics(performance_records)
    write_json(output_dir / "performance_metrics.json", performance_metrics)

    flow_samples, skipped_flow_classes = select_flow_samples(
        flow_samples, performance_samples, performance_records, args.flow_per_class,
    )
    write_json(output_dir / "flow_manifest.json", [asdict(sample) for sample in flow_samples])
    flow_records, mcp_health = run_mcp_samples(
        flow_samples, args.concurrency, args.mcp_chunk_size,
    )
    flow_records, additional_skipped_flow_classes = filter_unreachable_classes(
        flow_records
    )
    write_jsonl(output_dir / "flow_mcp_results.jsonl", flow_records)
    flow_metrics = compute_metrics(flow_records)
    write_json(output_dir / "flow_metrics.json", flow_metrics)
    write_json(output_dir / "mcp_health.json", mcp_health)
    skipped_classes = {
        "performance": skipped_performance_classes,
        "flow": skipped_flow_classes + additional_skipped_flow_classes,
    }
    write_json(output_dir / "skipped_classes.json", skipped_classes)
    summary = {
        "inventory": inventory,
        "performance": performance_metrics,
        "flow": flow_metrics,
        "mcp_health": mcp_health,
        "skipped_classes": skipped_classes,
    }
    write_json(output_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
