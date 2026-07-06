"""
Audit Reporter

Logs scan results to JSONL files, tracks statistics, and generates
markdown security reports.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from .scanner import ScanReport, ToolScanResult


class AuditReporter:
    def __init__(self, log_dir: str = "logs", verbose: bool = True):
        self.log_dir = log_dir
        self.verbose = verbose
        self.stats: Dict[str, Any] = {
            "total_scans": 0,
            "total_tools_scanned": 0,
            "total_tools_blocked": 0,
            "detections_by_pattern": {},
        }
        os.makedirs(log_dir, exist_ok=True)

    def _get_log_file(self) -> str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"audit-{date_str}.jsonl")

    def log_scan(self, report: ScanReport, gateway_identity: dict = None) -> None:
        self.stats["total_scans"] += 1
        self.stats["total_tools_scanned"] += report.total_tools
        self.stats["total_tools_blocked"] += report.tools_blocked

        for result in report.results:
            for detection in result.detections:
                if detection.matched:
                    pattern = detection.pattern_name
                    self.stats["detections_by_pattern"][pattern] = (
                        self.stats["detections_by_pattern"].get(pattern, 0) + 1
                    )

        log_entry = {
            "timestamp": report.timestamp,
            "server_name": report.server_name,
            "total_tools": report.total_tools,
            "tools_blocked": report.tools_blocked,
            "tools_warned": report.tools_warned,
            "tools_safe": report.tools_safe,
            "max_risk_score": report.max_risk_score,
            "results": [r.to_dict() for r in report.results],
        }

        # Include agentgateway identity in audit trail for compliance
        if gateway_identity:
            log_entry["gateway_identity"] = gateway_identity

        try:
            with open(self._get_log_file(), "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            if self.verbose:
                print(f"  [!] Failed to write audit log: {e}")

        if self.verbose:
            self._print_report(report)

    def _print_report(self, report: ScanReport) -> None:
        print(f"\n{'='*60}")
        print(f"  MCP Tool Firewall - Scan Report")
        print(f"  Server: {report.server_name}")
        print(f"  Time: {report.timestamp}")
        print(f"{'='*60}")
        print(f"  Total tools:   {report.total_tools}")
        print(f"  Blocked:       {report.tools_blocked}")
        print(f"  Warned:        {report.tools_warned}")
        print(f"  Safe:          {report.tools_safe}")
        print(f"  Max risk:      {report.max_risk_score}")
        print(f"{'='*60}")

        for result in report.results:
            if result.blocked:
                status = "[BLOCKED]"
            elif result.risk_score >= 26:
                status = "[WARNING]"
            else:
                status = "[  OK  ]"

            print(f"  {status} {result.tool_name} (score: {result.risk_score}, level: {result.risk_level})")
            for d in result.detections:
                if d.matched:
                    print(f"           -> {d.pattern_name}: {d.evidence[:80]}")

        print(f"{'='*60}\n")

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)

    def generate_markdown_report(self, report: ScanReport) -> str:
        lines = []
        lines.append("# MCP Tool Firewall - Security Audit Report\n")
        lines.append(f"**Server:** {report.server_name}  ")
        lines.append(f"**Scan Time:** {report.timestamp}  ")
        lines.append(f"**Max Risk Score:** {report.max_risk_score}\n")

        lines.append("## Executive Summary\n")
        lines.append(f"| Metric | Count |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total Tools Scanned | {report.total_tools} |")
        lines.append(f"| Tools Blocked | {report.tools_blocked} |")
        lines.append(f"| Tools Warned | {report.tools_warned} |")
        lines.append(f"| Tools Safe | {report.tools_safe} |")
        lines.append("")

        if report.tools_blocked > 0:
            lines.append("**ALERT:** Dangerous tools were detected and blocked.\n")

        lines.append("## Per-Tool Analysis\n")
        lines.append("| Tool | Risk Score | Level | Status | Detections |")
        lines.append("|------|-----------|-------|--------|------------|")

        for result in report.results:
            status = "BLOCKED" if result.blocked else ("WARNING" if result.risk_score >= 26 else "SAFE")
            detections = ", ".join(
                d.pattern_name for d in result.detections if d.matched
            )
            if not detections:
                detections = "None"
            lines.append(
                f"| {result.tool_name} | {result.risk_score} | {result.risk_level} | {status} | {detections} |"
            )

        lines.append("")
        lines.append("## Detailed Findings\n")

        for result in report.results:
            matched = [d for d in result.detections if d.matched]
            if not matched:
                continue

            lines.append(f"### {result.tool_name} (Score: {result.risk_score})\n")
            for d in matched:
                lines.append(f"- **{d.pattern_name}** (severity {d.severity}): {d.evidence}")
            lines.append("")

        lines.append("## Remediation Recommendations\n")

        if report.tools_blocked > 0:
            lines.append("1. **Immediately review** all blocked tools with their MCP server maintainers")
            lines.append("2. **Remove or sanitize** tool descriptions that contain injection patterns")
            lines.append("3. **Audit the MCP server source code** for intentional or accidental poisoning")
            lines.append("4. **Consider blocklisting** the server until issues are resolved")
        else:
            lines.append("No critical issues found. Continue regular monitoring.")

        lines.append("\n---\n*Generated by MCP Tool Poisoning Firewall*")

        return "\n".join(lines)
