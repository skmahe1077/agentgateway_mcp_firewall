"""
MCP Tool Description Scanner

Scans tool descriptions for poisoning attacks using pattern detectors
and optional LLM-based semantic analysis. Calculates risk scores,
determines risk levels, and filters dangerous tools.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any

from .patterns import ALL_DETECTORS, DetectionResult
from .semantic_detector import SemanticDetector


@dataclass
class ToolScanResult:
    tool_name: str
    risk_score: int
    risk_level: str
    blocked: bool
    detections: List[DetectionResult]
    scan_time_ms: float
    original_description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "blocked": self.blocked,
            "detections": [d.to_dict() for d in self.detections if d.matched],
            "scan_time_ms": round(self.scan_time_ms, 2),
            "original_description": self.original_description,
        }


@dataclass
class ScanReport:
    server_name: str
    timestamp: str
    total_tools: int
    tools_blocked: int
    tools_warned: int
    tools_safe: int
    max_risk_score: int
    results: List[ToolScanResult]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_name": self.server_name,
            "timestamp": self.timestamp,
            "total_tools": self.total_tools,
            "tools_blocked": self.tools_blocked,
            "tools_warned": self.tools_warned,
            "tools_safe": self.tools_safe,
            "max_risk_score": self.max_risk_score,
            "results": [r.to_dict() for r in self.results],
        }


class ToolScanner:
    def __init__(
        self,
        block_threshold: int = 51,
        warn_threshold: int = 26,
        enabled_patterns: Optional[List[str]] = None,
        enable_semantic: bool = True,
        semantic_api_key: Optional[str] = None,
        semantic_model: str = "claude-haiku-4-5-20251001",
    ):
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold

        if enabled_patterns:
            self.detectors = [
                d for d in ALL_DETECTORS if d.name in enabled_patterns
            ]
        else:
            self.detectors = ALL_DETECTORS

        # Initialize semantic detector (LLM-based analysis)
        self.semantic_detector: Optional[SemanticDetector] = None
        if enable_semantic:
            self.semantic_detector = SemanticDetector(
                api_key=semantic_api_key,
                model=semantic_model,
            )

    def _calculate_risk_score(self, detections: List[DetectionResult]) -> int:
        matched = [d for d in detections if d.matched]
        if not matched:
            return 0

        sorted_detections = sorted(matched, key=lambda d: d.severity, reverse=True)
        base_score = sorted_detections[0].severity

        for i, detection in enumerate(sorted_detections[1:], start=1):
            base_score += detection.severity * (0.3 / i)

        return min(int(base_score), 100)

    def _get_risk_level(self, score: int) -> str:
        if score >= 76:
            return "dangerous"
        elif score >= 51:
            return "risky"
        elif score >= 26:
            return "suspicious"
        else:
            return "safe"

    def scan_tool(self, name: str, description: str) -> ToolScanResult:
        start = time.time()

        detections = []
        for detector in self.detectors:
            result = detector.detect(name, description)
            detections.append(result)

        # Run LLM-based semantic analysis if available
        if self.semantic_detector and self.semantic_detector.is_available:
            analysis = self.semantic_detector.analyze(name, description)
            semantic_result = self.semantic_detector.to_detection_result(analysis)
            detections.append(semantic_result)

        risk_score = self._calculate_risk_score(detections)
        risk_level = self._get_risk_level(risk_score)
        blocked = risk_score >= self.block_threshold
        scan_time_ms = (time.time() - start) * 1000

        return ToolScanResult(
            tool_name=name,
            risk_score=risk_score,
            risk_level=risk_level,
            blocked=blocked,
            detections=detections,
            scan_time_ms=scan_time_ms,
            original_description=description,
        )

    def scan_tools_list(
        self, server_name: str, tools: List[Dict[str, Any]]
    ) -> ScanReport:
        from datetime import datetime, timezone

        results = []
        for tool in tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")
            result = self.scan_tool(name, desc)
            results.append(result)

        blocked = sum(1 for r in results if r.blocked)
        warned = sum(
            1
            for r in results
            if not r.blocked and r.risk_score >= self.warn_threshold
        )
        safe = sum(
            1 for r in results if r.risk_score < self.warn_threshold
        )
        max_score = max((r.risk_score for r in results), default=0)

        return ScanReport(
            server_name=server_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_tools=len(tools),
            tools_blocked=blocked,
            tools_warned=warned,
            tools_safe=safe,
            max_risk_score=max_score,
            results=results,
        )

    def filter_tools_list(
        self, server_name: str, tools: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], ScanReport]:
        report = self.scan_tools_list(server_name, tools)

        blocked_names = {r.tool_name for r in report.results if r.blocked}
        filtered = [t for t in tools if t.get("name") not in blocked_names]

        return filtered, report
