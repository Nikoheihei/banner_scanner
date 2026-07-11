# MCP Tools

This directory contains helper scripts for manually checking a running MCP
service.

- `verify_mcp.py` connects to a Streamable HTTP or SSE MCP endpoint, checks that
  the three public tools are exposed, and calls `health_check`.

These scripts are not part of the runtime service path.
