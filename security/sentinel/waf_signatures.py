"""
waf_signatures.py - Passive attack-pattern detection for live traffic.

Unlike dast_engine.py (which actively SENDS attack payloads to a target to test
it), this module only LOOKS AT incoming request data - path, query string, POST
body, headers - and flags it if it matches a known attack signature. It never
sends a request anywhere. This is the detection core shared by the real-time
monitor (server-side middleware installed on a protected site) and, later, any
other live-traffic connector.
"""

import re
from typing import Any, Dict, List

SQLI_PATTERNS = [
    re.compile(r"(\bunion\b\s+\bselect\b)", re.I),
    re.compile(r"(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)", re.I),
    re.compile(r"(\bsleep\s*\(\s*\d+\s*\))", re.I),
    re.compile(r"(\bselect\b.{1,40}\bfrom\b)", re.I),
    re.compile(r"(--|#|/\*)\s*$"),
    re.compile(r"(\bdrop\b\s+\btable\b)", re.I),
    re.compile(r"(\bxp_cmdshell\b)", re.I),
    re.compile(r"(';)"),
]

XSS_PATTERNS = [
    re.compile(r"<script[\s>]", re.I),
    re.compile(r"onerror\s*=", re.I),
    re.compile(r"onload\s*=", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"<img[^>]+src\s*=\s*['\"]?x['\"]?[^>]*onerror", re.I),
    re.compile(r"document\.cookie", re.I),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e%2f", re.I),
    re.compile(r"/etc/passwd", re.I),
    re.compile(r"win(dows|\.ini)|boot\.ini", re.I),
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(;|\||&&)\s*(cat|ls|whoami|id|wget|curl|nc|bash|sh)\b", re.I),
    re.compile(r"\$\(.+\)"),
    re.compile(r"`.+`"),
]

SSRF_PATTERNS = [
    re.compile(r"169\.254\.169\.254"),
    re.compile(r"\b(127\.0\.0\.1|localhost)\b.*://", re.I),
    re.compile(r"file://", re.I),
    re.compile(r"gopher://", re.I),
]

SIGNATURE_GROUPS = {
    "sqli": (SQLI_PATTERNS, "HIGH"),
    "xss": (XSS_PATTERNS, "MEDIUM"),
    "path_traversal": (PATH_TRAVERSAL_PATTERNS, "HIGH"),
    "command_injection": (COMMAND_INJECTION_PATTERNS, "CRITICAL"),
    "ssrf": (SSRF_PATTERNS, "HIGH"),
}

# Known malicious/scanner user-agents (low confidence alone, raises score when combined)
SUSPICIOUS_UA_PATTERNS = [
    re.compile(r"sqlmap", re.I),
    re.compile(r"nikto", re.I),
    re.compile(r"acunetix", re.I),
    re.compile(r"nessus", re.I),
    re.compile(r"\bnmap\b", re.I),
]


def _scan_text(text: str, domain: str = "") -> List[Dict[str, Any]]:
    hits = []
    if not text:
        return hits
    for category, (patterns, severity) in SIGNATURE_GROUPS.items():
        for pat in patterns:
            if pat.search(text):
                hits.append({"category": category, "severity": severity, "pattern": pat.pattern})
                break  # one hit per category is enough signal

    # Self-learning layer: signatures Sentinel picked up itself, from a real
    # incident anywhere it's deployed, or taught by a human after a bypass.
    # Anti-poisoning: a 'provisional' signature (single-domain origin, not yet
    # independently corroborated) only applies to the domain that produced it -
    # it can't unilaterally start blocking unrelated protected sites.
    try:
        from .learned_signatures import get_active_learned_patterns
        for sig in get_active_learned_patterns():
            if sig.get("scope") == "provisional" and sig.get("source_domain") != domain:
                continue
            if sig["_compiled"].search(text):
                hits.append({"category": sig["category"], "severity": sig["severity"],
                             "pattern": f"learned#{sig['id']}"})
    except Exception:
        pass
    return hits


def inspect_request(method: str, path: str, query_string: str = "",
                     body: str = "", headers: Dict[str, str] = None, domain: str = "") -> List[Dict[str, Any]]:
    """
    Passively inspects one incoming HTTP request for known attack signatures.
    Returns a list of findings (empty if nothing suspicious was seen).
    Never makes any outbound network call - pure local pattern matching.
    `domain` scopes which learned signatures are trusted (see _scan_text).
    """
    headers = headers or {}
    findings: List[Dict[str, Any]] = []

    for src_name, src_val in (("path", path), ("query", query_string), ("body", body)):
        for hit in _scan_text(src_val or "", domain=domain):
            findings.append({**hit, "source": src_name})

    user_agent = headers.get("User-Agent") or headers.get("user-agent") or ""
    for pat in SUSPICIOUS_UA_PATTERNS:
        if pat.search(user_agent):
            findings.append({"category": "scanner_tool_ua", "severity": "LOW",
                              "pattern": pat.pattern, "source": "headers"})
            break

    # Deduplicate identical (category, source) pairs
    seen = set()
    deduped = []
    for f in findings:
        key = (f["category"], f["source"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def highest_severity(findings: List[Dict[str, Any]]) -> str:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if not findings:
        return "NONE"
    return max(findings, key=lambda f: order.get(f["severity"], 0))["severity"]
