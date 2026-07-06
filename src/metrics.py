"""
Prometheus Metrics Collector

Collects and exposes metrics in Prometheus text format.
No external dependencies — generates plain text exposition format.
"""

import time
from typing import Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class MetricSample:
    name: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """Collects metrics and exposes them in Prometheus exposition format."""

    def __init__(self):
        # Counters
        self.semantic_scans_total: int = 0
        self.semantic_detections_total: int = 0
        self.semantic_cache_hits: int = 0
        self.scans_total: int = 0
        self.tools_scanned_total: int = 0
        self.tools_blocked_total: int = 0
        self.tools_warned_total: int = 0
        self.tools_safe_total: int = 0
        self.detections_by_pattern: Dict[str, int] = {}
        self.response_findings_by_type: Dict[str, int] = {}
        self.kill_switch_activations: int = 0
        self.policy_overrides_total: int = 0

        # Histograms (bucket counts)
        self.risk_score_buckets: Dict[str, int] = {
            "0_25": 0,
            "26_50": 0,
            "51_75": 0,
            "76_100": 0,
        }

        # Timing
        self.scan_durations: List[float] = []

        # Gauges
        self.kill_switch_enabled: bool = False
        self._start_time = time.time()

    def record_scan(self, total_tools: int, blocked: int, warned: int, safe: int):
        self.scans_total += 1
        self.tools_scanned_total += total_tools
        self.tools_blocked_total += blocked
        self.tools_warned_total += warned
        self.tools_safe_total += safe

    def record_risk_score(self, score: int):
        if score <= 25:
            self.risk_score_buckets["0_25"] += 1
        elif score <= 50:
            self.risk_score_buckets["26_50"] += 1
        elif score <= 75:
            self.risk_score_buckets["51_75"] += 1
        else:
            self.risk_score_buckets["76_100"] += 1

    def record_detection(self, pattern_name: str):
        self.detections_by_pattern[pattern_name] = (
            self.detections_by_pattern.get(pattern_name, 0) + 1
        )

    def record_response_finding(self, finding_type: str):
        self.response_findings_by_type[finding_type] = (
            self.response_findings_by_type.get(finding_type, 0) + 1
        )

    def record_scan_duration(self, duration_seconds: float):
        self.scan_durations.append(duration_seconds)
        # Keep last 1000 samples
        if len(self.scan_durations) > 1000:
            self.scan_durations = self.scan_durations[-1000:]

    def record_kill_switch(self, enabled: bool):
        self.kill_switch_enabled = enabled
        if enabled:
            self.kill_switch_activations += 1

    def record_policy_override(self):
        self.policy_overrides_total += 1

    def record_semantic_scan(self, detected: bool, cached: bool):
        self.semantic_scans_total += 1
        if detected:
            self.semantic_detections_total += 1
        if cached:
            self.semantic_cache_hits += 1

    def generate_metrics(self) -> str:
        """Generate Prometheus exposition format text."""
        lines = []

        # Uptime
        uptime = time.time() - self._start_time
        lines.append("# HELP mcp_firewall_uptime_seconds Time since firewall started")
        lines.append("# TYPE mcp_firewall_uptime_seconds gauge")
        lines.append(f"mcp_firewall_uptime_seconds {uptime:.2f}")
        lines.append("")

        # Scan counters
        lines.append("# HELP mcp_firewall_scans_total Total number of tool list scans performed")
        lines.append("# TYPE mcp_firewall_scans_total counter")
        lines.append(f"mcp_firewall_scans_total {self.scans_total}")
        lines.append("")

        lines.append("# HELP mcp_firewall_tools_scanned_total Total number of tools scanned")
        lines.append("# TYPE mcp_firewall_tools_scanned_total counter")
        lines.append(f"mcp_firewall_tools_scanned_total {self.tools_scanned_total}")
        lines.append("")

        lines.append("# HELP mcp_firewall_tools_blocked_total Total number of tools blocked")
        lines.append("# TYPE mcp_firewall_tools_blocked_total counter")
        lines.append(f"mcp_firewall_tools_blocked_total {self.tools_blocked_total}")
        lines.append("")

        lines.append("# HELP mcp_firewall_tools_warned_total Total number of tools warned")
        lines.append("# TYPE mcp_firewall_tools_warned_total counter")
        lines.append(f"mcp_firewall_tools_warned_total {self.tools_warned_total}")
        lines.append("")

        lines.append("# HELP mcp_firewall_tools_safe_total Total number of safe tools passed")
        lines.append("# TYPE mcp_firewall_tools_safe_total counter")
        lines.append(f"mcp_firewall_tools_safe_total {self.tools_safe_total}")
        lines.append("")

        # Detection counters by pattern
        lines.append("# HELP mcp_firewall_detections_total Detections by attack pattern")
        lines.append("# TYPE mcp_firewall_detections_total counter")
        for pattern, count in sorted(self.detections_by_pattern.items()):
            safe_label = pattern.replace('"', '\\"')
            lines.append(f'mcp_firewall_detections_total{{pattern="{safe_label}"}} {count}')
        lines.append("")

        # Response findings
        lines.append("# HELP mcp_firewall_response_findings_total Response scan findings by type")
        lines.append("# TYPE mcp_firewall_response_findings_total counter")
        for ftype, count in sorted(self.response_findings_by_type.items()):
            safe_label = ftype.replace('"', '\\"')
            lines.append(f'mcp_firewall_response_findings_total{{type="{safe_label}"}} {count}')
        lines.append("")

        # Risk score histogram
        lines.append("# HELP mcp_firewall_risk_score_bucket Risk score distribution")
        lines.append("# TYPE mcp_firewall_risk_score_bucket gauge")
        cumulative = 0
        for bucket, count in [("25", self.risk_score_buckets["0_25"]),
                               ("50", self.risk_score_buckets["26_50"]),
                               ("75", self.risk_score_buckets["51_75"]),
                               ("100", self.risk_score_buckets["76_100"])]:
            cumulative += count
            lines.append(f'mcp_firewall_risk_score_bucket{{le="{bucket}"}} {cumulative}')
        lines.append(f'mcp_firewall_risk_score_bucket{{le="+Inf"}} {cumulative}')
        lines.append("")

        # Scan duration
        if self.scan_durations:
            avg_duration = sum(self.scan_durations) / len(self.scan_durations)
            max_duration = max(self.scan_durations)
            lines.append("# HELP mcp_firewall_scan_duration_seconds Scan duration statistics")
            lines.append("# TYPE mcp_firewall_scan_duration_seconds gauge")
            lines.append(f"mcp_firewall_scan_duration_seconds_avg {avg_duration:.6f}")
            lines.append(f"mcp_firewall_scan_duration_seconds_max {max_duration:.6f}")
            lines.append(f"mcp_firewall_scan_duration_seconds_count {len(self.scan_durations)}")
        lines.append("")

        # Kill switch
        lines.append("# HELP mcp_firewall_kill_switch_enabled Whether kill switch is active")
        lines.append("# TYPE mcp_firewall_kill_switch_enabled gauge")
        lines.append(f"mcp_firewall_kill_switch_enabled {1 if self.kill_switch_enabled else 0}")
        lines.append("")

        lines.append("# HELP mcp_firewall_kill_switch_activations_total Kill switch activation count")
        lines.append("# TYPE mcp_firewall_kill_switch_activations_total counter")
        lines.append(f"mcp_firewall_kill_switch_activations_total {self.kill_switch_activations}")
        lines.append("")

        # Policy overrides
        lines.append("# HELP mcp_firewall_policy_overrides_total Policy engine override count")
        lines.append("# TYPE mcp_firewall_policy_overrides_total counter")
        lines.append(f"mcp_firewall_policy_overrides_total {self.policy_overrides_total}")
        lines.append("")

        # Semantic analysis
        lines.append("# HELP mcp_firewall_semantic_scans_total LLM semantic analysis scans")
        lines.append("# TYPE mcp_firewall_semantic_scans_total counter")
        lines.append(f"mcp_firewall_semantic_scans_total {self.semantic_scans_total}")
        lines.append("")

        lines.append("# HELP mcp_firewall_semantic_detections_total Malicious detections by semantic analysis")
        lines.append("# TYPE mcp_firewall_semantic_detections_total counter")
        lines.append(f"mcp_firewall_semantic_detections_total {self.semantic_detections_total}")
        lines.append("")

        lines.append("# HELP mcp_firewall_semantic_cache_hits_total Semantic analysis cache hits")
        lines.append("# TYPE mcp_firewall_semantic_cache_hits_total counter")
        lines.append(f"mcp_firewall_semantic_cache_hits_total {self.semantic_cache_hits}")
        lines.append("")

        return "\n".join(lines) + "\n"
