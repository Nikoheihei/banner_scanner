"""Dependency-free runner for the repository's plain assert-based tests."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

MODULES = (
    "banner_scanner.tests.test_parsers",
    "banner_scanner.tests.test_matcher",
    "banner_scanner.tests.test_protocol_fingerprint_split",
    "banner_scanner.tests.test_database_matcher",
    "banner_scanner.tests.test_probes",
    "banner_scanner.tests.test_evaluation",
    "banner_scanner.tests.test_identify",
    "banner_scanner.tests.test_policy",
    "banner_scanner.tests.test_mcp_serialization",
    "banner_scanner.tests.test_mcp_service",
    "banner_scanner.tests.test_mcp_app",
    "banner_scanner.tests.test_http_middleware",
    "banner_scanner.tests.test_audit",
    "banner_scanner.tests.test_rule_regressions",
)


def main() -> int:
    passed = 0
    for module_name in MODULES:
        module = importlib.import_module(module_name)
        for name, function in inspect.getmembers(module, inspect.isfunction):
            if not name.startswith("test_"):
                continue
            if inspect.signature(function).parameters:
                raise RuntimeError(f"Unsupported fixture parameters: {module_name}.{name}")
            if inspect.iscoroutinefunction(function):
                asyncio.run(function())
            else:
                function()
            passed += 1
    print(f"{passed} tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
