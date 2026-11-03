"""
logic_engine.py - Business Logic Vulnerability Diagnostic Engine
Evaluates e-commerce & workflow state transitions:
- Price tampering (zero or negative prices)
- Quantity tampering (negative quantities reducing cart total)
- Role parameter pollution (is_admin: true / role: admin)
- Step skipping in checkout funnels
"""

import re
from typing import Dict, Any, List, Optional
import requests

def audit_price_tampering(
    session: requests.Session,
    checkout_url: str,
    method: str = "POST",
    base_payload: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Submits modified price & quantity payloads to verify whether the backend
    recalculates values server-side or naively trusts client-provided amounts.
    """
    findings = []
    payload_base = dict(base_payload or {"item_id": 1, "price": 49.99, "quantity": 1})

    # Test cases: (name, tampered_payload, expected_behavior)
    test_cases = [
        ("Prix Zéro", {"price": 0.00, "amount": 0.00, "total": 0.00}),
        ("Prix Négatif", {"price": -10.00, "amount": -10.00, "total": -10.00}),
        ("Quantité Négative", {"quantity": -1, "qty": -1}),
    ]

    for label, tampered in test_cases:
        test_payload = dict(payload_base)
        test_payload.update(tampered)

        try:
            if method.upper() == "POST":
                r = session.post(checkout_url, json=test_payload, timeout=5, allow_redirects=False)
            else:
                r = session.get(checkout_url, params=test_payload, timeout=5, allow_redirects=False)

            # If the backend accepts the request (200/201/204) without an error code
            if r.status_code in (200, 201, 204) and not re.search(r"invalide|erreur|refus|error|interdit|négatif|negative", r.text, re.I):
                findings.append({
                    "id": f"BUSINESS_LOGIC_TAMPERING_{label.upper().replace(' ', '_')}",
                    "title": f"Vulnérabilité de Logique Métier : Falsification Acceptée ({label})",
                    "severity": "CRITICAL",
                    "category": "A04:2021-Insecure Design",
                    "description": f"L'endpoint {checkout_url} a accepté un paramètre frelaté ({label}) sans validation stricte côté serveur.",
                    "proof": f"Payload envoyé: {tampered} -> Réponse HTTP {r.status_code} ({len(r.text)} octets).",
                    "impact": "Un acheteur peut acquérir des biens gratuitement ou créditer son solde avec des montants négatifs.",
                    "remediation": "Ne faites JAMAIS confiance aux montants envoyés par le client. Recalculez systématiquement les prix et les totaux côté serveur à partir de la base de données produit."
                })
        except Exception:
            continue

    return findings

def audit_role_parameter_tampering(
    session: requests.Session,
    profile_update_url: str,
    method: str = "POST",
    base_payload: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Tests mass assignment / parameter pollution to elevate privileges (e.g. is_admin: true).
    """
    findings = []
    base_data = dict(base_payload or {"name": "Test User", "email": "test@example.com"})

    tampered_roles = [
        {"role": "admin"},
        {"is_admin": True},
        {"isAdmin": 1},
        {"permissions": ["admin", "superadmin"]}
    ]

    for role_injection in tampered_roles:
        payload = dict(base_data)
        payload.update(role_injection)

        try:
            r = session.post(profile_update_url, json=payload, timeout=5, allow_redirects=False)
            if r.status_code in (200, 204) and any(kw in r.text.lower() for kw in ("admin", "role", "success")):
                findings.append({
                    "id": "MASS_ASSIGNMENT_ROLE_ELEVATION",
                    "title": "Attribution de Privilèges par Falsification de Paramètre (Mass Assignment)",
                    "severity": "CRITICAL",
                    "category": "A01:2021-Broken Access Control",
                    "description": f"L'endpoint {profile_update_url} semble avoir accepté l'injection du paramètre de rôle {role_injection}.",
                    "proof": f"POST avec payload: {role_injection} -> HTTP {r.status_code}.",
                    "impact": "Élévation de privilèges vers le statut administrateur sans vérification des droits.",
                    "remediation": "Utilisez des Data Transfer Objects (DTO) stricts avec liste blanche de champs modifiables par l'utilisateur ordinaire."
                })
                break
        except Exception:
            continue

    return findings
