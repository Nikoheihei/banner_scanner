# Legacy Tools

This directory keeps early development scripts that are no longer part of the
current MCP service path.

- `vendors.json` is the old shared text fingerprint library. The current
  service uses isolated libraries under `fingerprints/protocols/` and
  `fingerprints/databases/`.
- `batch_scanner.py` and `scanner_test.py` were early `fingerprint.db`-based
  probing scripts that used `vendors.json`.
- `scan.py` is a local quick-probe helper with hard-coded hosts.

Keep these files only for historical comparison or manual debugging. The
deliverable MCP service entrypoints are defined in `pyproject.toml`.
