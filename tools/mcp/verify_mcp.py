#!/usr/bin/env python3
"""Verify the MCP tool surface through an official SDK client."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any


def tool_payload(result: Any) -> dict[str, Any]:
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


async def verify_session(session, args: argparse.Namespace) -> None:
    await session.initialize()
    listed = await session.list_tools()
    names = {tool.name for tool in listed.tools}
    expected = {"probe_banner", "scan_batch", "health_check"}
    if names != expected:
        raise RuntimeError(f"Unexpected MCP tools: {sorted(names)}")

    health = tool_payload(await session.call_tool("health_check", arguments={}))
    if health.get("service") != "ok":
        raise RuntimeError(f"MCP health check failed: {health}")
    print(json.dumps({"tools": sorted(names), "health": health}, indent=2))

    if args.probe_host:
        result = tool_payload(await session.call_tool("probe_banner", arguments={
            "hosts": [args.probe_host],
            "protocols": args.protocol,
        }))
        print(json.dumps(result, indent=2, ensure_ascii=False))


async def main_async(args: argparse.Namespace) -> None:
    try:
        from mcp import ClientSession
        from mcp.client.sse import sse_client
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:
        raise RuntimeError('Install with: pip install "mcp[cli]==1.28.1"') from exc

    if args.transport == "sse":
        async with sse_client(args.url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await verify_session(session, args)
        return

    async with streamable_http_client(args.url) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await verify_session(session, args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--transport",
        choices=("streamable-http", "sse"),
        default="streamable-http",
    )
    parser.add_argument("--url")
    parser.add_argument("--probe-host")
    parser.add_argument("--protocol", action="append")
    args = parser.parse_args()
    if not args.url:
        args.url = (
            "http://127.0.0.1:8877/sse"
            if args.transport == "sse"
            else "http://127.0.0.1:8877/mcp"
        )
    return args


def main() -> None:
    asyncio.run(main_async(parse_args()))


if __name__ == "__main__":
    main()
