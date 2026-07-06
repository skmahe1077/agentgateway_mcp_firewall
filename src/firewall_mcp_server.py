"""
Firewall MCP Server

Exposes the MCP Tool Firewall scanning engine as MCP tools via JSON-RPC
over HTTP (streamable-http transport). AI agents (including kagent agents)
can use these tools to programmatically scan MCP servers for poisoning.

Tools exposed:
  1. scan_tool_description - Scan a single tool description
  2. scan_mcp_server - Scan all tools on a remote MCP server
  3. get_firewall_stats - Get accumulated firewall statistics
  4. generate_security_report - Generate a full markdown security report
  5. check_tool_response - Scan a tool response for secrets/PII/data leaks
  6. toggle_kill_switch - Enable/disable emergency kill switch
"""

import argparse
import json

from aiohttp import web, ClientSession

from .scanner import ToolScanner
from .reporter import AuditReporter
from .response_scanner import ResponseScanner
from .semantic_detector import SemanticDetector

scanner = ToolScanner()
try:
    reporter = AuditReporter(log_dir="logs", verbose=False)
except PermissionError:
    reporter = AuditReporter(log_dir="/tmp/firewall-logs", verbose=False)
response_scanner = ResponseScanner()
semantic_detector = SemanticDetector()

# Kill switch state (shared with proxy if co-located)
_kill_switch_enabled = False

SERVER_INFO = {
    "name": "mcp-tool-firewall-server",
    "version": "2.0.0",
}

TOOLS = [
    {
        "name": "scan_tool_description",
        "description": "Scan a single MCP tool description for poisoning attacks. Returns risk score, risk level, and detected attack patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Name of the tool to scan"},
                "tool_description": {"type": "string", "description": "Description text of the tool to scan for poisoning"},
            },
            "required": ["tool_name", "tool_description"],
        },
    },
    {
        "name": "scan_mcp_server",
        "description": "Connect to a remote MCP server and scan all its tools for poisoning attacks. Returns a full scan report with per-tool results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_host": {"type": "string", "description": "Hostname or IP of the MCP server"},
                "server_port": {"type": "integer", "description": "Port number of the MCP server"},
            },
            "required": ["server_host", "server_port"],
        },
    },
    {
        "name": "get_firewall_stats",
        "description": "Get accumulated statistics from the firewall including total scans, tools scanned, tools blocked, detections by pattern, and response scan findings.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "generate_security_report",
        "description": "Scan an MCP server and generate a detailed markdown security report with executive summary, per-tool analysis, and remediation recommendations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_host": {"type": "string", "description": "Hostname or IP of the MCP server"},
                "server_port": {"type": "integer", "description": "Port number of the MCP server"},
            },
            "required": ["server_host", "server_port"],
        },
    },
    {
        "name": "check_tool_response",
        "description": "Scan a tool call response for sensitive data leakage including API keys, tokens, private keys, PII (emails, SSNs, credit cards), and data exfiltration patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "response_content": {"type": "string", "description": "The tool response content to scan for sensitive data"},
            },
            "required": ["response_content"],
        },
    },
    {
        "name": "toggle_kill_switch",
        "description": "Enable or disable the emergency kill switch. When enabled, the firewall blocks ALL tools from ALL servers immediately.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "description": "Set to true to enable kill switch (block all), false to disable"},
            },
            "required": ["enabled"],
        },
    },
    {
        "name": "semantic_analyze_description",
        "description": "Use LLM-based semantic analysis to detect malicious intent in a tool description. Catches attacks that bypass regex patterns: paraphrased injections, multi-language attacks, social engineering, and novel attack patterns. Requires ANTHROPIC_API_KEY.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Name of the tool"},
                "tool_description": {"type": "string", "description": "Description text to analyze semantically"},
            },
            "required": ["tool_name", "tool_description"],
        },
    },
]


async def _fetch_tools_from_server(host: str, port: int) -> list:
    url = f"http://{host}:{port}/mcp"
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {},
    }
    async with ClientSession() as session:
        async with session.post(url, json=payload) as resp:
            data = await resp.json()
            return data.get("result", {}).get("tools", [])


async def handle_scan_tool_description(params: dict) -> dict:
    tool_name = params["tool_name"]
    tool_description = params["tool_description"]
    result = scanner.scan_tool(tool_name, tool_description)
    return result.to_dict()


async def handle_scan_mcp_server(params: dict) -> dict:
    host = params["server_host"]
    port = params["server_port"]
    tools = await _fetch_tools_from_server(host, port)
    server_name = f"{host}:{port}"
    report = scanner.scan_tools_list(server_name, tools)
    reporter.log_scan(report)
    return report.to_dict()


async def handle_get_firewall_stats(_params: dict) -> dict:
    stats = reporter.get_stats()
    stats["response_scanner"] = response_scanner.get_stats()
    stats["kill_switch_enabled"] = _kill_switch_enabled
    return stats


async def handle_generate_security_report(params: dict) -> dict:
    host = params["server_host"]
    port = params["server_port"]
    tools = await _fetch_tools_from_server(host, port)
    server_name = f"{host}:{port}"
    report = scanner.scan_tools_list(server_name, tools)
    reporter.log_scan(report)
    markdown = reporter.generate_markdown_report(report)
    return {"report": markdown}


async def handle_check_tool_response(params: dict) -> dict:
    content = params["response_content"]
    result = response_scanner.scan_response(content)
    return result.to_dict()


async def handle_toggle_kill_switch(params: dict) -> dict:
    global _kill_switch_enabled
    _kill_switch_enabled = bool(params["enabled"])
    return {
        "kill_switch": _kill_switch_enabled,
        "message": f"Kill switch {'ENABLED — all tools will be blocked' if _kill_switch_enabled else 'DISABLED — normal operation resumed'}",
    }


async def handle_semantic_analyze(params: dict) -> dict:
    tool_name = params["tool_name"]
    tool_description = params["tool_description"]

    if not semantic_detector.is_available:
        return {
            "error": "Semantic detector unavailable — set ANTHROPIC_API_KEY to enable",
            "available": False,
        }

    analysis = semantic_detector.analyze(tool_name, tool_description)
    if analysis is None:
        return {"error": "Semantic analysis failed", "available": True}

    # Also run regex scan for comparison
    regex_result = scanner.scan_tool(tool_name, tool_description)

    return {
        "semantic_analysis": analysis.to_dict(),
        "regex_scan": {
            "risk_score": regex_result.risk_score,
            "risk_level": regex_result.risk_level,
            "blocked": regex_result.blocked,
            "detections": [d.to_dict() for d in regex_result.detections if d.matched],
        },
        "combined_verdict": {
            "malicious": analysis.malicious or regex_result.blocked,
            "reason": (
                f"Semantic: {analysis.reasoning}"
                if analysis.malicious and not regex_result.blocked
                else f"Regex: score={regex_result.risk_score}"
                if regex_result.blocked and not analysis.malicious
                else f"Both: semantic + regex (score={regex_result.risk_score})"
                if analysis.malicious and regex_result.blocked
                else "Clean by both regex and semantic analysis"
            ),
        },
    }


TOOL_HANDLERS = {
    "scan_tool_description": handle_scan_tool_description,
    "scan_mcp_server": handle_scan_mcp_server,
    "get_firewall_stats": handle_get_firewall_stats,
    "generate_security_report": handle_generate_security_report,
    "check_tool_response": handle_check_tool_response,
    "toggle_kill_switch": handle_toggle_kill_switch,
    "semantic_analyze_description": handle_semantic_analyze,
}


async def handle_jsonrpc(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
            status=400,
        )

    req_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params", {})

    if method == "initialize":
        return web.json_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        })

    if method == "tools/list":
        return web.json_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS},
        })

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return web.json_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
            })

        try:
            result = await handler(arguments)
            return web.json_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                },
            })
        except Exception as e:
            return web.json_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"Tool execution error: {str(e)}"},
            })

    return web.json_response({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    })


async def stdio_loop():
    """Run as stdio transport — read JSON-RPC from stdin, write to stdout."""
    import sys
    import asyncio

    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)

    while True:
        line = await reader.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            body = json.loads(line)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue

        req_id = body.get("id")
        method = body.get("method", "")
        params = body.get("params", {})

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                },
            }
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            handler = TOOL_HANDLERS.get(tool_name)
            if handler:
                try:
                    result = await handler(arguments)
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
                    }
                except Exception as e:
                    resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": str(e)}}
            else:
                resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}
        else:
            resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


def main():
    import asyncio

    parser = argparse.ArgumentParser(description="MCP Tool Firewall Server")
    parser.add_argument("--port", type=int, default=8889, help="Server port")
    parser.add_argument("--stdio", action="store_true", help="Run in stdio transport mode")
    args = parser.parse_args()

    if args.stdio:
        asyncio.run(stdio_loop())
    else:
        app = web.Application()
        app.router.add_post("/mcp", handle_jsonrpc)

        print(f"MCP Tool Firewall Server starting on port {args.port}")
        print(f"Tools available: {', '.join(t['name'] for t in TOOLS)}")

        web.run_app(app, port=args.port)


if __name__ == "__main__":
    main()
