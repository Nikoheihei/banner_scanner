# Active fingerprint evaluation

`active_fingerprint_eval.py` uses historical scan files only to obtain labeled,
authorized targets. Every scored result comes from a new network connection.

The evaluation has two independent paths:

- Performance: up to 384 targets per protocol/software class are actively
  probed through `ProbeEngine`.
- Flow: up to 100 targets per class are actively probed through the local HTTP
  MCP server and its `probe_banner` tool.

For classes with enough unique targets, the performance and flow target sets
do not overlap. Smaller classes use all available targets and report their
actual sample count.

Run from the package parent directory:

```bash
python3 -m banner_scanner.evaluation.active_fingerprint_eval \
  --fingerprint-db /path/to/fingerprint.db \
  --redis-results /path/to/scan_results.jsonl \
  --mysql-results /path/to/mysql_results.jsonl \
  --pgsql-results /path/to/pgsql_results.jsonl \
  --output-dir /path/to/results \
  --performance-per-class 384 \
  --flow-per-class 100 \
  --concurrency 16 \
  --confirm-authorized
```

`--confirm-authorized` is mandatory. The output directory contains manifests,
per-target active results, aggregate metrics, MCP health data, and a combined
summary. Do not commit it: it may contain public IP addresses and live banners.
