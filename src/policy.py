"""
YAML Policy Engine

Rule-based policy evaluation for MCP tool access control.
Supports allowlists, blocklists, server trust levels, and
description length limits.
"""

import re
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

import yaml


@dataclass
class PolicyDecision:
    action: str  # "allow", "block", "default" (fall through to scanner)
    reason: str
    rule_name: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "rule_name": self.rule_name,
        }


class PolicyEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.allowlist: List[Dict[str, str]] = []
        self.blocklist: List[Dict[str, str]] = []
        self.max_description_length: int = 0
        self.server_trust: Dict[str, Dict[str, Any]] = {}
        self.required_patterns: List[str] = []

        if config:
            self._load_config(config)

    def _load_config(self, config: Dict[str, Any]):
        policies = config.get("policies", {})

        self.allowlist = policies.get("allowlist", [])
        self.blocklist = policies.get("blocklist", [])
        self.max_description_length = policies.get("max_description_length", 0)
        self.required_patterns = policies.get("required_patterns", [])

        trust_list = policies.get("server_trust", [])
        for entry in trust_list:
            server = entry.get("server", "")
            self.server_trust[server] = {
                "trust_level": entry.get("trust_level", "normal"),
                "block_threshold": entry.get("block_threshold", 51),
                "warn_threshold": entry.get("warn_threshold", 26),
            }

    @classmethod
    def from_yaml_file(cls, path: str) -> "PolicyEngine":
        with open(path, "r") as f:
            config = yaml.safe_load(f)
        return cls(config)

    def _matches_pattern(self, tool_name: str, pattern: str) -> bool:
        """Check if tool name matches a pattern (supports * glob)."""
        if pattern == "*":
            return True
        regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        return bool(re.match(regex, tool_name, re.IGNORECASE))

    def evaluate(
        self,
        tool_name: str,
        server_name: str,
        description: str = "",
        risk_score: int = 0,
    ) -> PolicyDecision:
        """Evaluate policies for a tool. Returns a decision."""

        # Check blocklist first (highest priority)
        for rule in self.blocklist:
            name_pattern = rule.get("tool_name", "")
            server_pattern = rule.get("server", "*")

            if self._matches_pattern(tool_name, name_pattern) and self._matches_pattern(server_name, server_pattern):
                return PolicyDecision(
                    action="block",
                    reason=f"Tool '{tool_name}' matches blocklist rule",
                    rule_name="blocklist",
                )

        # Check allowlist (override scanner)
        for rule in self.allowlist:
            name_pattern = rule.get("tool_name", "")
            server_pattern = rule.get("server", "*")

            if self._matches_pattern(tool_name, name_pattern) and self._matches_pattern(server_name, server_pattern):
                return PolicyDecision(
                    action="allow",
                    reason=f"Tool '{tool_name}' matches allowlist rule",
                    rule_name="allowlist",
                )

        # Check description length limit
        if self.max_description_length > 0 and len(description) > self.max_description_length:
            return PolicyDecision(
                action="block",
                reason=f"Description length ({len(description)}) exceeds max ({self.max_description_length})",
                rule_name="max_description_length",
            )

        # Check server trust levels (adjust threshold)
        if server_name in self.server_trust:
            trust = self.server_trust[server_name]
            threshold = trust.get("block_threshold", 51)
            if risk_score >= threshold:
                return PolicyDecision(
                    action="block",
                    reason=f"Risk score {risk_score} exceeds server trust threshold {threshold}",
                    rule_name="server_trust",
                )
            elif risk_score > 0:
                return PolicyDecision(
                    action="allow",
                    reason=f"Risk score {risk_score} below server trust threshold {threshold}",
                    rule_name="server_trust",
                )

        # Default: let the scanner decide
        return PolicyDecision(
            action="default",
            reason="No policy match, using scanner threshold",
            rule_name="none",
        )

    def get_server_thresholds(self, server_name: str) -> Dict[str, int]:
        """Get adjusted thresholds for a server based on trust level."""
        if server_name in self.server_trust:
            trust = self.server_trust[server_name]
            return {
                "block_threshold": trust.get("block_threshold", 51),
                "warn_threshold": trust.get("warn_threshold", 26),
            }
        return {"block_threshold": 51, "warn_threshold": 26}

    def get_required_patterns(self) -> List[str]:
        return list(self.required_patterns)
