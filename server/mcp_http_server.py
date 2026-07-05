"""Official MCP SDK HTTP launcher.

Streamable HTTP is the primary HTTP transport.  SSE is retained only for
legacy compatibility and teaching acceptance; both use the same tool layer.
"""

from __future__ import annotations

import argparse
import os

from .http_middleware import MCPHttpGuard
from .mcp_app import create_mcp
from .policy import RuntimeLimits, TargetPolicy
from .serialization import banner_result_to_dict as _banner_to_dict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Banner Scanner MCP HTTP server")
    parser.add_argument(
        "--transport",
        choices=("streamable-http", "sse"),
        default=os.environ.get("MCP_TRANSPORT", "streamable-http"),
        help="HTTP transport; SSE is legacy compatibility only",
    )
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT", "8877")))
    return parser


def main() -> None:
    args = build_parser().parse_args()
    remote_bind = args.host not in {"127.0.0.1", "::1", "localhost"}
    auth_token = os.environ.get("BANNER_SCANNER_AUTH_TOKEN", "")
    if remote_bind:
        if os.environ.get("BANNER_SCANNER_ALLOW_REMOTE_BIND") != "1":
            raise SystemExit(
                "Non-loopback MCP binding requires BANNER_SCANNER_ALLOW_REMOTE_BIND=1, "
                "authentication, target allowlists, and rate limiting."
            )
        if not auth_token:
            raise SystemExit("Non-loopback MCP binding requires BANNER_SCANNER_AUTH_TOKEN")
        if not TargetPolicy.from_env().allowlist_enabled:
            raise SystemExit("Non-loopback MCP binding requires a target allowlist")
    transport_name = "sse" if args.transport == "sse" else "streamable_http"
    mcp = create_mcp(
        transport_name=transport_name,
        host=args.host,
        port=args.port,
    )
    if args.transport == "sse":
        inner_app = mcp.sse_app()
    else:
        inner_app = mcp.streamable_http_app()

    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit('Install the locked dependency with: pip install "mcp[cli]==1.28.1"') from exc

    allowed_origins = tuple(
        item.strip()
        for item in os.environ.get("BANNER_SCANNER_CORS_ORIGINS", "").split(",")
        if item.strip()
    )
    guarded_app = MCPHttpGuard(
        inner_app,
        max_body_bytes=RuntimeLimits().max_request_body_bytes,
        allowed_origins=allowed_origins,
        bearer_token=auth_token,
    )
    uvicorn.run(guarded_app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
