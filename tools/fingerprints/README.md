# Fingerprint Tools

These scripts are not required when running the MCP service. They are retained
to make the fingerprint libraries reproducible from source data.

- `build_fingerprints.py` rebuilds the SSH, FTP, and Telnet text fingerprint
  libraries from the original SQLite template database.
- `migrate_fingerprints_v2.py` migrates existing protocol and database
  fingerprint libraries to the current explicit rule schema.

The service loads the generated JSON libraries under `fingerprints/`.
