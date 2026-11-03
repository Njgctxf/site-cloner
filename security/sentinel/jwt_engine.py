"""
jwt_engine.py - Non-Destructive JWT Security Diagnostic Engine
Audits JSON Web Tokens for:
- 'none' algorithm acceptance
- Weak HMAC secrets (offline dictionary check)
- Missing expiration & audience claims
- Sensitive data disclosure in payloads
"""

import hmac
import hashlib
import base64
import json
import time
from typing import Dict, Any, List, Optional
import requests

COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "jwt_secret", "app_secret",
    "secret_key", "supersecret", "token", "default", "key", "auth_secret",
    "private", "master", "development", "test", "production"
]

def _b64_decode(data: str) -> bytes:
    data = data.replace("-", "+").replace("_", "/")
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    return base64.b64decode(data)

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def parse_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Decodes JWT components without validating signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64_decode(parts[1]).decode("utf-8"))
        return {
            "header": header,
            "payload": payload,
            "signature_raw": parts[2],
            "raw_parts": parts
        }
    except Exception:
        return None

def forge_alg_none_token(parsed_jwt: Dict[str, Any]) -> str:
    """Creates a forged token with alg='none' and an empty signature."""
    new_header = dict(parsed_jwt["header"])
    new_header["alg"] = "none"
    h_b64 = _b64_encode(json.dumps(new_header, separators=(',', ':')).encode("utf-8"))
    p_b64 = parsed_jwt["raw_parts"][1]
    return f"{h_b64}.{p_b64}."

def audit_jwt(token: str, verify_endpoint_url: Optional[str] = None, session: Optional[requests.Session] = None) -> List[Dict[str, Any]]:
    """
    Performs comprehensive, strictly non-destructive analysis of a JWT token.
    """
    findings = []
    parsed = parse_jwt(token)
    if not parsed:
        return [{
            "id": "JWT_INVALID_FORMAT",
            "title": "Format de Jeton JWT Invalide",
            "severity": "LOW",
            "category": "A02:2021-Cryptographic Failures",
            "description": "La chaîne fournie ne correspond pas à la structure standard d'un JSON Web Token (en-tête.payload.signature).",
            "proof": f"Token: {token[:30]}...",
            "impact": "Incapacité à traiter ou authentifier le token.",
            "remediation": "Vérifiez la conformité avec la RFC 7519."
        }]

    header = parsed["header"]
    payload = parsed["payload"]

    # 1. Header Algorithm Checks
    alg = header.get("alg", "").lower()
    if alg == "none":
        findings.append({
            "id": "JWT_ALG_NONE_DECLARED",
            "title": "Algorithme 'none' Déclaré dans le Jeton JWT",
            "severity": "CRITICAL",
            "category": "A02:2021-Cryptographic Failures",
            "description": "Le jeton déclare explicitement l'algorithme 'none', désactivant toute vérification d'intégrité ou de signature cryptographique.",
            "proof": f"Header: {json.dumps(header)}",
            "impact": "Un attaquant peut modifier arbitrairement n'importe quelle revendication (ex: changer le user_id ou le rôle admin) sans que le serveur ne rejette le jeton.",
            "remediation": "Rejetez catégoriquement tout jeton avec alg='none' dans votre bibliothèque JWT côté serveur."
        })

    # 2. Offline Weak Secret Brute-Force Check
    if alg in ("hs256", "hs384", "hs512"):
        signing_input = f"{parsed['raw_parts'][0]}.{parsed['raw_parts'][1]}".encode("utf-8")
        raw_sig = _b64_decode(parsed['raw_parts'][2])

        for secret in COMMON_JWT_SECRETS:
            expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(expected, raw_sig):
                findings.append({
                    "id": "JWT_WEAK_SECRET_KEY",
                    "title": f"Clé Secrète JWT Prévisible / Faible ('{secret}')",
                    "severity": "CRITICAL",
                    "category": "A02:2021-Cryptographic Failures",
                    "description": f"La signature du token a été reproduite hors-ligne avec le secret de dictionnaire '{secret}'.",
                    "proof": f"Algorithme: {alg.upper()}, Secret trouvé: '{secret}'",
                    "impact": "Permet la falsification complète de tokens administrateur et l'usurpation totale de comptes utilisateurs.",
                    "remediation": "Utilisez une clé secrète générée cryptographiquement d'au moins 256 bits (ex: openssl rand -base64 32)."
                })
                break

    # 3. Expiration Claim (exp) Verification
    if "exp" not in payload:
        findings.append({
            "id": "JWT_NO_EXPIRATION",
            "title": "Absence de Revendication d'Expiration ('exp') dans le JWT",
            "severity": "HIGH",
            "category": "A07:2021-Identification and Authentication Failures",
            "description": "Le jeton n'a pas de date d'expiration définie. Il reste valide indéfiniment en cas d'interception.",
            "proof": f"Payload: {json.dumps(payload)}",
            "impact": "Une session volée ne peut pas expirer automatiquement et reste exploitable indéfiniment.",
            "remediation": "Incluez systématiquement une revendication 'exp' avec une durée de vie courte (ex: 15 à 60 minutes) combinée à un mécanisme de refresh token."
        })
    else:
        exp_time = payload["exp"]
        if isinstance(exp_time, (int, float)) and exp_time < time.time():
            findings.append({
                "id": "JWT_EXPIRED_TOKEN",
                "title": "Jeton JWT Expiré",
                "severity": "LOW",
                "category": "A07:2021-Identification and Authentication Failures",
                "description": f"Le token a expiré à {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp_time))} UTC.",
                "proof": f"exp: {exp_time}, temps actuel: {int(time.time())}",
                "impact": "Le token doit être renouvelé.",
                "remediation": "Utilisez le point d'accès de rafraîchissement (refresh token)."
            })

    # 4. Sensitive Information in Payload
    sensitive_keys = [k for k in payload.keys() if any(s in k.lower() for s in ("password", "passwd", "secret", "private", "ssn", "credit_card"))]
    if sensitive_keys:
        findings.append({
            "id": "JWT_SENSITIVE_DATA_LEAK",
            "title": f"Données Confidentielles Exposées dans le Payload JWT ({', '.join(sensitive_keys)})",
            "severity": "HIGH",
            "category": "A04:2021-Insecure Design",
            "description": "Le payload d'un JWT est simplement encodé en Base64, non chiffré. N'importe quel porteur peut lire ces champs.",
            "proof": f"Champs sensibles trouvés: {sensitive_keys}",
            "impact": "Fuite de secrets ou de mots de passe vers les clients ou dans les logs réseau.",
            "remediation": "Ne stockez jamais de données confidentielles en clair dans le payload d'un JWT. Utilisez JWE (JWT chiffré) si nécessaire."
        })

    # 5. Active probe: test if the backend accepts an alg=none forged token
    if verify_endpoint_url and session:
        try:
            forged_token = forge_alg_none_token(parsed)
            headers = {"Authorization": f"Bearer {forged_token}"}
            resp = session.get(verify_endpoint_url, headers=headers, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                findings.append({
                    "id": "JWT_ALG_NONE_ACCEPTED_BY_SERVER",
                    "title": "Vulnérabilité Critique : Le Serveur Accepte les Jetons avec alg='none'",
                    "severity": "CRITICAL",
                    "category": "A02:2021-Cryptographic Failures",
                    "description": f"Le point d'accès {verify_endpoint_url} a répondu HTTP 200 OK lors de l'envoi d'un jeton altéré sans signature (alg='none').",
                    "proof": f"GET {verify_endpoint_url} avec token forgé sans signature -> Réponse HTTP 200 OK.",
                    "impact": "Bypass d'authentification absolu. N'importe quel attaquant peut forger une identité utilisateur quelconque.",
                    "remediation": "Configurez le middleware de validation JWT pour forcer expressément l'algorithme attendu (ex: algorithms=['HS256'])."
                })
        except Exception:
            pass

    return findings
