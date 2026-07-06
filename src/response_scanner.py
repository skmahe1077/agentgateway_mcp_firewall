"""
Outbound Response Scanner

Scans MCP tool call responses for sensitive data leakage:
1. Secret Detection — API keys, tokens, private keys, passwords
2. PII Detection — emails, phone numbers, SSNs, credit cards
3. Data Leak Detection — large base64 blobs, JSON dumps, embedded URLs
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class ResponseFinding:
    category: str  # "secret", "pii", "data_leak"
    finding_type: str  # e.g., "aws_key", "email", "base64_blob"
    severity: int
    evidence: str
    redacted_evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "evidence": self.redacted_evidence,
        }


@dataclass
class ResponseScanResult:
    content_length: int
    findings: List[ResponseFinding]
    risk_level: str  # "clean", "warning", "critical"
    should_redact: bool
    scan_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content_length": self.content_length,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "risk_level": self.risk_level,
            "should_redact": self.should_redact,
        }


# --- Secret Detection Patterns ---

SECRET_PATTERNS = [
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", 95),
    ("aws_secret_key", r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access)?[_\-\s]*key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", 95),
    ("openai_api_key", r"\bsk-[A-Za-z0-9]{20,}\b", 90),
    ("github_token", r"\bghp_[A-Za-z0-9]{36}\b", 90),
    ("github_oauth", r"\bgho_[A-Za-z0-9]{36}\b", 90),
    ("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", 90),
    ("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9\-]{20,}\b", 90),
    ("stripe_key", r"\b[sr]k_(live|test)_[A-Za-z0-9]{20,}\b", 90),
    ("private_key", r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----", 95),
    ("generic_api_key", r"(?i)(?:api[_\-\s]*key|apikey|api_secret|access_token|auth_token|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})", 75),
    ("password_in_text", r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})", 80),
    ("bearer_token", r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}", 85),
    ("jwt_token", r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b", 85),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", 90),
    ("connection_string", r"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s]{10,}", 85),
]

# --- PII Detection Patterns ---

PII_PATTERNS = [
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 60),
    ("phone_us", r"\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b", 50),
    ("phone_intl", r"\b\+[0-9]{1,3}[-.\s]?[0-9]{6,14}\b", 50),
    ("ssn", r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", 90),
    ("credit_card", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", 90),
    ("ip_address", r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", 40),
    ("iban", r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,18})?\b", 70),
]

# --- Data Leak Patterns ---

DATA_LEAK_PATTERNS = [
    ("large_base64", r"[A-Za-z0-9+/]{100,}={0,2}", 60),
    ("embedded_url", r"https?://(?!(?:example\.com|localhost))[^\s\"'<>]{15,}", 40),
]


def _redact(text: str, keep_chars: int = 4) -> str:
    """Redact sensitive text, keeping first few chars visible."""
    if len(text) <= keep_chars + 4:
        return "*" * len(text)
    return text[:keep_chars] + "*" * (len(text) - keep_chars)


def _luhn_check(number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


class ResponseScanner:
    def __init__(self, enable_secrets: bool = True, enable_pii: bool = True, enable_data_leak: bool = True):
        self.enable_secrets = enable_secrets
        self.enable_pii = enable_pii
        self.enable_data_leak = enable_data_leak
        self.stats = {
            "total_scans": 0,
            "total_findings": 0,
            "findings_by_type": {},
        }

    def scan_response(self, content: str) -> ResponseScanResult:
        """Scan a tool call response for sensitive data."""
        import time
        start = time.time()

        findings: List[ResponseFinding] = []

        if self.enable_secrets:
            findings.extend(self._detect_secrets(content))

        if self.enable_pii:
            findings.extend(self._detect_pii(content))

        if self.enable_data_leak:
            findings.extend(self._detect_data_leaks(content))

        # Determine risk level
        max_severity = max((f.severity for f in findings), default=0)
        if max_severity >= 80:
            risk_level = "critical"
        elif max_severity >= 50:
            risk_level = "warning"
        else:
            risk_level = "clean"

        should_redact = max_severity >= 80

        scan_time_ms = (time.time() - start) * 1000

        # Update stats
        self.stats["total_scans"] += 1
        self.stats["total_findings"] += len(findings)
        for f in findings:
            self.stats["findings_by_type"][f.finding_type] = (
                self.stats["findings_by_type"].get(f.finding_type, 0) + 1
            )

        return ResponseScanResult(
            content_length=len(content),
            findings=findings,
            risk_level=risk_level,
            should_redact=should_redact,
            scan_time_ms=scan_time_ms,
        )

    def _detect_secrets(self, content: str) -> List[ResponseFinding]:
        findings = []
        for name, pattern, severity in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                findings.append(ResponseFinding(
                    category="secret",
                    finding_type=name,
                    severity=severity,
                    evidence=match,
                    redacted_evidence=_redact(str(match)),
                ))
        return findings

    def _detect_pii(self, content: str) -> List[ResponseFinding]:
        findings = []
        for name, pattern, severity in PII_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                # Validate credit cards with Luhn
                if name == "credit_card" and not _luhn_check(match):
                    continue
                findings.append(ResponseFinding(
                    category="pii",
                    finding_type=name,
                    severity=severity,
                    evidence=match,
                    redacted_evidence=_redact(str(match)),
                ))
        return findings

    def _detect_data_leaks(self, content: str) -> List[ResponseFinding]:
        findings = []

        # Large base64 blobs
        for name, pattern, severity in DATA_LEAK_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                findings.append(ResponseFinding(
                    category="data_leak",
                    finding_type=name,
                    severity=severity,
                    evidence=match[:50] + "..." if len(match) > 50 else match,
                    redacted_evidence=f"[{name}: {len(match)} chars]",
                ))

        # Large JSON dumps
        if len(content) > 5000:
            try:
                import json
                json.loads(content)
                findings.append(ResponseFinding(
                    category="data_leak",
                    finding_type="large_json_dump",
                    severity=55,
                    evidence=f"JSON response of {len(content)} chars",
                    redacted_evidence=f"[large_json_dump: {len(content)} chars]",
                ))
            except (json.JSONDecodeError, ValueError):
                pass

        return findings

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)
