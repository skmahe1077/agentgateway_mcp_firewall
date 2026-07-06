#!/bin/sh
# Start both the firewall proxy and the MCP server
python -m src.firewall_mcp_server --port 8889 &
exec python -m src.firewall "$@"
