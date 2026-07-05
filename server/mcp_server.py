"""Official MCP SDK stdio launcher."""

from __future__ import annotations

from .mcp_app import create_mcp
from .serialization import banner_result_to_dict as _banner_to_dict


def main() -> None:
    create_mcp(transport_name="stdio").run(transport="stdio")


if __name__ == "__main__":
    main()
