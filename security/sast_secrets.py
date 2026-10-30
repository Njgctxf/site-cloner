"""
sast_secrets.py - Static Application Security Testing (SAST) for Hardcoded Secrets
Scans source code, HTML, JavaScript bundles, and config files for leaked private keys,
API tokens, cloud credentials, and high-entropy secret strings.
"""

import math
import re
from typing import List, Dict, Any, Tuple

# High-confidence exact regex signatures for real-world API tokens & secrets
SECRET_SIGNATURES = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "CRITICAL", "Cloud Infrastructure"),
    ("AWS Secret Key Assignment", re.compile(r"""(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]""", re.I), "CRITICAL", "Cloud Infrastructure"),
    ("Stripe Secret Key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,34})\b"), "CRITICAL", "Payment Gateway"),
    ("Stripe Restricted Key", re.compile(r"\b(rk_live_[0-9a-zA-Z]{24,34})\b"), "CRITICAL", "Payment Gateway"),
    ("OpenAI API Key", re.compile(r"\b(sk-[a-zA-Z0-9]{48})\b"), "CRITICAL", "AI & Machine Learning"),
    ("GitHub Personal Access Token", re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36})\b"), "CRITICAL", "Source Code Management"),
    ("Private Key Block", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"), "CRITICAL", "Cryptographic Material"),
    ("Slack Bot/User Token", re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"), "HIGH", "Collaboration & Webhooks"),
    ("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}"), "HIGH", "Collaboration & Webhooks"),
    ("Database Connection URI", re.compile(r"""\b((?:postgres|mysql|mongodb|redis)://[a-zA-Z0-9_\-\.]+:[^@\s"']+@[a-zA-Z0-9_\-\.]+:\d+/[a-zA-Z0-9_\-\.]+)\b""", re.I), "CRITICAL", "Database Storage"),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "MEDIUM", "Cloud Services"),
    ("Generic Hardcoded Secret Assignment", re.compile(r"""(?:api_secret|client_secret|jwt_secret|app_secret|private_token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]""", re.I), "HIGH", "Credentials"),
]

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string (measures randomness)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def mask_secret(secret: str) -> str:
    """Safely masks a secret string for reporting (e.g. sk_live_a1b2... -> sk_live_****b2)."""
    if not secret or len(secret) < 8:
        return "****"
    prefix = secret[:min(8, len(secret) // 3)]
    suffix = secret[-min(4, len(secret) // 4):]
    return f"{prefix}****{suffix}"

def _finding(id_: str, title: str, severity: str, category: str, description: str,
             proof: str, impact: str, remediation: str) -> Dict[str, Any]:
    return {
        "id": id_,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "proof": proof,
        "impact": impact,
        "remediation": remediation
    }

def scan_code_for_secrets(content: str, source_name: str = "Source Code") -> List[Dict[str, Any]]:
    """
    Scans text/code content for known secret signatures and high-entropy strings.
    """
    findings = []
    seen = set()

    # 1. Exact Signature Matches
    for label, pattern, severity, category in SECRET_SIGNATURES:
        for match in pattern.finditer(content or ""):
            secret_val = match.group(1) if match.groups() else match.group(0)
            if secret_val in seen:
                continue
            seen.add(secret_val)

            masked = mask_secret(secret_val)
            findings.append(_finding(
                f"LEAKED_SECRET_{label.upper().replace(' ', '_')}",
                f"Secret sensible ou clé d'API exposé en clair ({label})",
                severity,
                f"A02:2021-Cryptographic Failures / {category}",
                f"Une valeur ressemblant à une clé d'API active ({label}) a été détectée en clair dans {source_name}.",
                f"Signature détectée : '{label}'. Valeur masquée : {masked} (Longueur: {len(secret_val)} caractères).",
                "Un tiers analysant le code public ou le fichier compilé peut s'emparer de cette clé pour accéder aux services tiers, facturer des ressources ou compromettre l'infrastructure de l'entreprise.",
                "Révoquez immédiatement cette clé sur la plateforme émettrice. Ne stockez jamais de secrets dans le code source ; utilisez des variables d'environnement sécurisées (ex: Secret Manager, HashiCorp Vault, fichiers .env non publiés)."
            ))

    # 2. High-Entropy Tokens inside string assignments
    assignment_pattern = re.compile(r"""(?:token|key|secret|password|auth)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.+=/]{28,80})['"]""", re.I)
    for m in assignment_pattern.finditer(content or ""):
        candidate = m.group(1)
        if candidate in seen:
            continue
        # Shannon entropy > 4.3 indicates pseudo-random cryptographic tokens
        if shannon_entropy(candidate) >= 4.3:
            seen.add(candidate)
            findings.append(_finding(
                "HIGH_ENTROPY_TOKEN_EXPOSED",
                "Jeton aléatoire de haute entropie exposé dans le code",
                "HIGH",
                "A02:2021-Cryptographic Failures",
                f"Une chaîne de haute entropie ({shannon_entropy(candidate):.2f} bits) ressemblant à un jeton d'accès a été détectée dans {source_name}.",
                f"Attribution détectée : valeur masquée {mask_secret(candidate)}.",
                "Risque d'usurpation d'identité ou de session si ce jeton correspond à une clé d'authentification valide.",
                "Déplacez ce secret vers un gestionnaire de configuration sécurisé côté serveur."
            ))

    return findings
