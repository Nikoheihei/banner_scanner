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
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from ..core.engine import ProbeEngine
from ..core.matcher import DEFAULT_PROTOCOL_LIBRARY_DIR, FingerprintMatcher
from ..core.models import BannerResult, ProbeConfig
from ..core.protocol_detection import FTP_MARKER


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
        (re.compile(r"FlowSsh|WinSSHD|Bitvise", re.I), "Bitvise SSH Server"),
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
        (re.compile(r"wodFTPD", re.I), "wodFTPD"),
        (re.compile(r"WeOnlyDo", re.I), "WeOnlyDo SSH"),
        (re.compile(r"Cisco", re.I), "Cisco"),
        (re.compile(r"SSHPiper", re.I), "SSHPiper"),
        (re.compile(r"AsyncSSH", re.I), "AsyncSSH"),
    ],
    "FTP": [
        (re.compile(r"vsFTPd", re.I), "vsFTPd"),
        (re.compile(r"Pure-FTPd", re.I), "Pure-FTPd"),
        (re.compile(r"ProFTPD", re.I), "ProFTPD"),
        (re.compile(r"FileZilla\s+Pro\s+Enterprise", re.I), "FileZilla Pro Enterprise"),
        (re.compile(r"FileZilla\s+Server", re.I), "FileZilla Server"),
        (re.compile(r"Microsoft FTP", re.I), "Microsoft FTP"),
        (re.compile(r"Serv-U", re.I), "Serv-U FTP"),
        (re.compile(r"Core\s+FTP\s+Server\s+Version", re.I), "Core FTP Server"),
        (re.compile(r"pyftpdlib", re.I), "pyftpdlib"),
        (re.compile(r"Cerberus", re.I), "Cerberus FTP"),
        (re.compile(r"CrushFTP", re.I), "CrushFTP"),
        (re.compile(r"\bWing\s+FTP\s+Server\b", re.I), "Wing FTP"),
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
        (re.compile(r"Windows(?:\s+CE)?\s+Telnet\s+Service", re.I), "Windows telnetd"),
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
    if protocol == "SSH" and not re.match(r"^SSH-[12]\.[0-9]+-", text):
        return ""
    if protocol == "FTP" and (
        re.match(r"^SSH-[12]\.[0-9]+-", text)
        or not re.match(r"^(?:120|220)[- ]", text)
    ):
        return ""
    if protocol == "TELNET" and (
        re.match(r"^SSH-[12]\.[0-9]+-", text) or FTP_MARKER.search(text)
    ):
        return ""
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
        "bitvise": "Bitvise SSH Server",
        "weonlydo wodftpd": "wodFTPD",
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
    endpoint = result.get("endpoint") or {}
    protocol = str(endpoint.get("protocol") or "")
    primary = result.get("primary_identification") or {}
    fingerprint = normalize_label(protocol, str(primary.get("name") or ""))
    parsed = ""
    observations = result.get("observations") or {}
    for field, key in (("ssh", "software"), ("ftp", "software"),
                       ("telnet", "detected_service"),
                       ("redis", "implementation"), ("mysql", "implementation"),
                       ("pgsql", "implementation")):
        if observations.get(field):
            parsed = str(observations[field].get(key) or "")
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
    endpoint = result.get("endpoint") or {}
    observations = result.get("observations") or {}
    error = result.get("error") or {}
    connected = result.get("network_status") == "connected"
    protocol_matches = result.get("protocol_status") != "mismatch"
    if not protocol_matches:
        predicted = fingerprint = parsed = ""
    return {
        "channel": "mcp_streamable_http",
        "protocol": sample.protocol,
        "software_true": sample.software_true,
        "software_pred": predicted,
        "fingerprint_pred": fingerprint,
        "parsed_pred": parsed,
        "correct": predicted == sample.software_true,
        "fingerprint_correct": fingerprint == sample.software_true,
        "host": sample.host,
        "port": endpoint.get("port", sample.port),
        "accessible": connected,
        "protocol_status": result.get("protocol_status", "not_observed"),
        "banner": observations.get("banner", ""),
        "error": error.get("message", ""),
        "response_time_ms": result.get("response_time_ms", 0),
        "identification_status": result.get("identification_status", "unidentified"),
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


async def _call_mcp_samples(url: str, samples: list[TargetSample],
                            concurrency: int, chunk_size: int
                            ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:
        raise RuntimeError(
            'Active MCP flow tests require: pip install "mcp[cli]==1.28.1"'
        ) from exc

    records: list[dict[str, Any]] = []
    async with streamable_http_client(url) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            health = _tool_payload(await session.call_tool("health_check", arguments={}))

            grouped: dict[tuple[str, str], list[TargetSample]] = defaultdict(list)
            for sample in samples:
                grouped[(sample.protocol, sample.software_true)].append(sample)
            for (protocol, _software), group in sorted(grouped.items()):
                for start in range(0, len(group), chunk_size):
                    chunk = group[start:start + chunk_size]
                    response = await asyncio.wait_for(
                        session.call_tool("scan_batch", arguments={
                            "hosts": [sample.host for sample in chunk],
                            "protocol": protocol.lower(),
                            "retries": 0,
                            "concurrency": min(concurrency, 50),
                            "detail_level": "evidence",
                            "authorization_confirmed": True,
                        }),
                        timeout=max(60.0, len(chunk) * 10.0),
                    )
                    payload = _tool_payload(response)
                    by_host = {
                        str((item.get("endpoint") or {}).get("host")): item
                        for item in payload.get("results", [])
                    }
                    for sample in chunk:
                        item = by_host.get(sample.host, {
                            "endpoint": {
                                "host": sample.host,
                                "port": sample.port,
                                "protocol": protocol,
                            },
                            "network_status": "unreachable",
                            "protocol_status": "not_observed",
                            "error": {"message": "missing MCP result"},
                        })
                        records.append(mcp_record(sample, item))
    return records, health


def wait_for_server(process: subprocess.Popen, host: str, port: int,
                    timeout: float = 15.0) -> None:
    async def wait() -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if process.poll() is not None:
                stderr = process.stderr.read() if process.stderr else ""
                raise RuntimeError(f"MCP HTTP server exited before startup: {stderr.strip()}")
            try:
                reader, writer = await asyncio.open_connection(host, port)
                writer.close()
                await writer.wait_closed()
                return
            except OSError:
                await asyncio.sleep(0.2)
        raise TimeoutError("MCP HTTP server did not start")

    asyncio.run(wait())


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
    url = f"http://127.0.0.1:{port}/mcp"
    try:
        wait_for_server(process, "127.0.0.1", port)
        records, health = asyncio.run(
            _call_mcp_samples(url, samples, concurrency, chunk_size)
        )
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
        "connection_rate": round(safe_div(reachable, total), 6),
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
        reachable_protocol_records = [
            record for record in protocol_records if record["accessible"]
        ]
        software_output = {}
        for label in labels:
            tp = sum(r["software_true"] == label and r["software_pred"] == label
                     for r in reachable_protocol_records)
            fp = sum(r["software_true"] != label and r["software_pred"] == label
                     for r in reachable_protocol_records)
            fn = sum(r["software_true"] == label and r["software_pred"] != label
                     for r in reachable_protocol_records)
            tn = len(reachable_protocol_records) - tp - fp - fn
            own = [r for r in protocol_records if r["software_true"] == label]
            accessible = [r for r in own if r["accessible"]]
            precision = safe_div(tp, tp + fp)
            recall = safe_div(tp, tp + fn)
            software_output[label] = {
                "samples": len(own), "correct": tp,
                "reachable_samples": len(accessible),
                "connection_rate": round(safe_div(len(accessible), len(own)), 6),
                "precision": round(precision, 6), "recall": round(recall, 6),
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                **identification_metrics(own),
            }
        times = [float(r.get("response_time_ms") or 0) for r in protocol_records]
        correct = sum(r["correct"] for r in protocol_records)
        protocol_output[protocol] = {
            "samples": len(protocol_records), "correct": correct,
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
            "connection_rate": "reachable / samples",
            "precision": "TP / (TP + FP), calculated over reachable samples",
            "recall": "TP / (TP + FN), calculated over reachable samples",
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
    """Compatibility wrapper that reports, but never removes, zero-connection classes."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[(record["protocol"], record["software_true"])].append(record)
    diagnostics: list[dict[str, Any]] = []
    for (protocol, software), group in sorted(grouped.items()):
        reachable = sum(bool(record["accessible"]) for record in group)
        if not reachable:
            diagnostics.append({
            "protocol": protocol,
            "software": software,
            "samples": len(group),
            "reason": "zero connections in active probe sample; records retained",
            })
    return list(records), diagnostics


def zero_connection_classes(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Report zero-connection classes without deleting them from metrics."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[(record["protocol"], record["software_true"])].append(record)
    return [
        {
            "protocol": protocol,
            "software": software,
            "samples": len(group),
            "connection_rate": 0.0,
        }
        for (protocol, software), group in sorted(grouped.items())
        if not any(record["accessible"] for record in group)
    ]


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
    parser.add_argument("--performance-only", action="store_true",
                        help="Run active ProbeEngine performance evaluation without MCP flow")
    parser.add_argument("--flow-only", action="store_true",
                        help="Reuse existing active performance results")
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
    write_jsonl(performance_path, performance_records)
    performance_metrics = compute_metrics(performance_records)
    write_json(output_dir / "performance_metrics.json", performance_metrics)
    if args.performance_only:
        summary = {
            "inventory": inventory,
            "performance": performance_metrics,
            "zero_connection_classes": {
                "performance": zero_connection_classes(performance_records),
            },
        }
        write_json(output_dir / "summary.json", summary)
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    flow_samples, _selection_diagnostics = select_flow_samples(
        flow_samples, performance_samples, performance_records, args.flow_per_class,
    )
    write_json(output_dir / "flow_manifest.json", [asdict(sample) for sample in flow_samples])
    flow_records, mcp_health = run_mcp_samples(
        flow_samples, args.concurrency, args.mcp_chunk_size,
    )
    write_jsonl(output_dir / "flow_mcp_results.jsonl", flow_records)
    flow_metrics = compute_metrics(flow_records)
    write_json(output_dir / "flow_metrics.json", flow_metrics)
    write_json(output_dir / "mcp_health.json", mcp_health)
    zero_connection = {
        "performance": zero_connection_classes(performance_records),
        "flow": zero_connection_classes(flow_records),
    }
    write_json(output_dir / "zero_connection_classes.json", zero_connection)
    summary = {
        "inventory": inventory,
        "performance": performance_metrics,
        "flow": flow_metrics,
        "mcp_health": mcp_health,
        "zero_connection_classes": zero_connection,
    }
    write_json(output_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
