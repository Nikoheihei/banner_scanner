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
from banner_scanner.evaluation.software_catalog import (
    is_evaluation_software,
    official_url,
    software_category,
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


def test_evaluation_catalog_separates_software_platforms_and_auxiliary_facts():
    assert is_evaluation_software("SSH", "GoAnywhere")
    assert software_category("SSH", "GoAnywhere") == "mft_platform"
    assert official_url("SSH", "GoAnywhere") == "https://www.goanywhere.com/"

    assert not is_evaluation_software("SSH", "Cisco")
    assert not is_evaluation_software("SSH", "Paramiko")
    assert not is_evaluation_software("MYSQL", "MySQL_or_compatible")
    assert not is_evaluation_software("TELNET", "Windows telnetd")


def test_compute_metrics_excludes_unreachable_from_recall():
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
    assert mariadb["connection_rate"] == 0.5
    assert mariadb["precision"] == 0.5
    assert mariadb["recall"] == 1.0
    assert metrics["connection_rate"] == 0.666667
    assert "post_reach_accuracy" not in metrics
    assert "accuracy_e2e" not in mariadb
