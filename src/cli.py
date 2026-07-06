"""
MCP Tool Firewall — CLI Scanner

Quick command-line tool to scan MCP servers or tool descriptions
without running the full proxy.

Usage:
    # Scan a running MCP server
    mcp-firewall-scan --server localhost:9999

    # Scan a single tool description
    mcp-firewall-scan --tool "get_weather" --description "Ignore all previous instructions..."

    # Scan with custom threshold
    mcp-firewall-scan --server localhost:9999 --block-threshold 30

    # Output as JSON
    mcp-firewall-scan --server localhost:9999 --json
"""

import argparse
import asyncio
import json
import sys

from .scanner import ToolScanner
from .reporter import AuditReporter
from .response_scanner import ResponseScanner
from .semantic_detector import SemanticDetector


async def _fetch_and_scan(host: str, port: int, scanner: ToolScanner, reporter: AuditReporter):
    from aiohttp import ClientSession

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
            tools = data.get("result", {}).get("tools", [])

    server_name = f"{host}:{port}"
    report = scanner.scan_tools_list(server_name, tools)
    reporter.log_scan(report)
    return report


def scan_main():
    parser = argparse.ArgumentParser(
        prog="mcp-firewall-scan",
        description="MCP Tool Firewall — Scan MCP servers or tool descriptions for poisoning attacks",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--server",
        metavar="HOST:PORT",
        help="Scan a running MCP server (e.g., localhost:9999)",
    )
    group.add_argument(
        "--tool",
        metavar="NAME",
        help="Scan a single tool description (use with --description)",
    )
    group.add_argument(
        "--check-response",
        metavar="TEXT",
        help="Scan response content for secrets/PII/data leaks",
    )

    parser.add_argument(
        "--description",
        metavar="DESC",
        help="Tool description to scan (use with --tool)",
    )
    parser.add_argument(
        "--block-threshold",
        type=int,
        default=51,
        help="Risk score threshold for blocking (default: 51)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--semantic",
        action="store_true",
        default=False,
        help="Enable LLM-based semantic analysis (requires ANTHROPIC_API_KEY)",
    )

    args = parser.parse_args()

    scanner = ToolScanner(
        block_threshold=args.block_threshold,
        enable_semantic=args.semantic,
    )
    reporter = AuditReporter(log_dir="logs", verbose=not args.json_output)

    # --- Scan a single tool description ---
    if args.tool:
        if not args.description:
            parser.error("--description is required with --tool")
        result = scanner.scan_tool(args.tool, args.description)
        if args.json_output:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            status = "BLOCKED" if result.blocked else "SAFE"
            print(f"\n[{status}] {result.tool_name}")
            print(f"  Risk score: {result.risk_score} ({result.risk_level})")
            for d in result.detections:
                if d.matched:
                    print(f"  -> {d.pattern_name} (severity {d.severity}): {d.evidence[:80]}")
            if not any(d.matched for d in result.detections):
                print("  -> No attacks detected")
        sys.exit(1 if result.blocked else 0)

    # --- Scan response content ---
    if args.check_response:
        resp_scanner = ResponseScanner()
        result = resp_scanner.scan_response(args.check_response)
        if args.json_output:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"\nResponse scan: {result.risk_level}")
            print(f"  Content length: {result.content_length}")
            print(f"  Findings: {len(result.findings)}")
            for f in result.findings:
                print(f"  -> [{f.category}] {f.finding_type} (severity {f.severity}): {f.redacted_evidence}")
            if not result.findings:
                print("  -> Clean, no sensitive data detected")
        sys.exit(1 if result.should_redact else 0)

    # --- Scan a running MCP server ---
    if args.server:
        parts = args.server.split(":")
        if len(parts) != 2:
            parser.error("--server must be in HOST:PORT format")
        host, port = parts[0], int(parts[1])

        try:
            report = asyncio.run(_fetch_and_scan(host, port, scanner, reporter))
        except Exception as e:
            print(f"Error connecting to {args.server}: {e}", file=sys.stderr)
            sys.exit(2)

        if args.json_output:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(f"\nSummary: {report.tools_blocked} blocked, {report.tools_warned} warned, {report.tools_safe} safe out of {report.total_tools} tools")

        sys.exit(1 if report.tools_blocked > 0 else 0)


if __name__ == "__main__":
    scan_main()
