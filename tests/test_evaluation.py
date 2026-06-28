"""Tests for active evaluation data preparation and metrics."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from banner_scanner.evaluation.active_fingerprint_eval import (
    compute_metrics,
    iter_concatenated_json,
    normalize_label,
    truth_label,
)


def test_iter_concatenated_json():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "objects.jsonl"
        path.write_text(
            json.dumps({"ip": "192.0.2.1"}, indent=2)
            + "\n"
            + json.dumps({"ip": "192.0.2.2"}, indent=2),
            encoding="utf-8",
        )
        assert [item["ip"] for item in iter_concatenated_json(path, chunk_size=7)] == [
            "192.0.2.1", "192.0.2.2",
        ]


def test_truth_labels_are_protocol_evidence_based():
    assert truth_label("SSH", "SSH-2.0-OpenSSH_9.6p1") == "OpenSSH"
    assert truth_label("FTP", "220 (vsFTPd 3.0.5)") == "vsFTPd"
    assert truth_label("REDIS", "# Server\r\nvalkey_version:8.0.0\r\n") == "Valkey"
    assert truth_label("MYSQL", "5.5.68-MariaDB", {
        "mysql": {"version": "5.5.68-MariaDB"},
    }) == "MariaDB"
    assert truth_label("PGSQL", "FPgDecoder.java crate.protocols") == "CrateDB"


def test_normalize_prediction_aliases():
    assert normalize_label("SSH", "Dropbear SSH") == "Dropbear"
    assert normalize_label("MYSQL", "MySQL 8.0.46") == "MySQL_or_compatible"
    assert normalize_label("REDIS", "Redis 7.2.4") == "Redis"


def test_compute_metrics_counts_unreachable_as_e2e_failure():
    records = [
        {"protocol": "MYSQL", "software_true": "MariaDB",
         "software_pred": "MariaDB", "correct": True,
         "fingerprint_correct": True, "accessible": True,
         "response_time_ms": 10},
        {"protocol": "MYSQL", "software_true": "MariaDB",
         "software_pred": "", "correct": False,
         "fingerprint_correct": False, "accessible": False,
         "response_time_ms": 20},
        {"protocol": "MYSQL", "software_true": "MySQL_or_compatible",
         "software_pred": "MariaDB", "correct": False,
         "fingerprint_correct": False, "accessible": True,
         "response_time_ms": 30},
    ]
    metrics = compute_metrics(records)
    mariadb = metrics["protocols"]["MYSQL"]["software"]["MariaDB"]
    assert mariadb["accuracy_e2e"] == 0.5
    assert mariadb["accuracy_valid"] == 1.0
    assert mariadb["precision"] == 0.5
    assert mariadb["recall"] == 0.5
