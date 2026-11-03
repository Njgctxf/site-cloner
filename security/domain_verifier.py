"""
domain_verifier.py - Domain Ownership Challenge & Verification
Proves that the requester has administrative control of the target domain
via DNS TXT record or HTTP challenge file before allowing any security assessment.
"""

import os
import re
import secrets
import subprocess
import urllib.parse
from typing import Dict, Any, Tuple
import requests

from .network_guard import validate_target_url
from .safe_session import build_safe_session

TOKEN_PREFIX = "sc-audit-"

def generate_challenge_token() -> str:
    """Generates a cryptographically strong challenge token."""
    return f"{TOKEN_PREFIX}{secrets.token_hex(16)}"

def normalize_domain(domain_or_url: str) -> str:
    """Normalizes an input string to a clean domain name (e.g., 'sub.example.com')."""
    raw = (domain_or_url or "").strip().lower()
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        raw = parsed.hostname or ""
    else:
        # Strip path or port if provided
        raw = raw.split("/")[0].split(":")[0]
    # Remove leading dots or www if top-level normalization
    return raw.strip(". ")

def query_doh_txt(hostname: str) -> list:
    """
    Queries TXT records using DNS-over-HTTPS (Cloudflare & Google DoH).
    Resistant to local resolver manipulation and works on all OS without dnspython.
    """
    records = []
    headers = {"Accept": "application/dns-json"}

    # 1. Cloudflare DoH
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={hostname}&type=TXT"
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            for ans in data.get("Answer", []):
                if ans.get("type") == 16:  # TXT record type
                    val = ans.get("data", "").strip('"')
                    if val:
                        records.append(val)
    except Exception:
        pass

    if records:
        return records

    # 2. Google DoH
    try:
        url = f"https://dns.google/resolve?name={hostname}&type=TXT"
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            for ans in data.get("Answer", []):
                if ans.get("type") == 16:
                    val = ans.get("data", "").strip('"')
                    if val:
                        records.append(val)
    except Exception:
        pass

    if records:
        return records

    # 3. System nslookup fallback
    try:
        cmd = ["nslookup", "-type=TXT", hostname]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in proc.stdout.splitlines():
            if "text =" in line.lower() or '"' in line:
                m = re.search(r'"([^"]+)"', line)
                if m:
                    records.append(m.group(1))
    except Exception:
        pass

    return records

def verify_dns_txt(domain: str, expected_token: str) -> Tuple[bool, str]:
    """
    Checks if expected_token is present in DNS TXT records for:
    - _sc-audit.{domain}
    - {domain}
    """
    clean_domain = normalize_domain(domain)
    if not clean_domain:
        return False, "Nom de domaine invalide."

    candidates = [f"_sc-audit.{clean_domain}", clean_domain]
    all_found = []

    for host in candidates:
        records = query_doh_txt(host)
        all_found.extend(records)
        for rec in records:
            if expected_token in rec:
                return True, f"Enregistrement DNS TXT vérifié avec succès sur {host}."

    return False, f"Jeton '{expected_token}' introuvable dans les enregistrements DNS TXT vérifiés ({', '.join(candidates)})."

def verify_http_challenge(domain: str, expected_token: str) -> Tuple[bool, str]:
    """
    Checks if expected_token is published at:
    https://{domain}/.well-known/security-audit-challenge.txt
    Protected against SSRF before making the request.
    """
    clean_domain = normalize_domain(domain)
    if not clean_domain:
        return False, "Nom de domaine invalide."

    test_urls = [
        f"https://{clean_domain}/.well-known/security-audit-challenge.txt",
        f"http://{clean_domain}/.well-known/security-audit-challenge.txt"
    ]

    for target_url in test_urls:
        # Step 1: Strict Anti-SSRF check
        is_safe, norm_url, pinned_ip, err = validate_target_url(target_url, allow_local_lab=False)
        if not is_safe:
            continue

        # Step 2: Fetch challenge file (session re-validates the IP again at connect time,
        # closing the DNS-rebinding window between the Step 1 check and this request)
        try:
            headers = {"User-Agent": "SiteCloner-Security-Verification/1.0"}
            session = build_safe_session(allow_local_lab=False)
            res = session.get(target_url, headers=headers, timeout=6, allow_redirects=False)
            if res.status_code == 200:
                body = res.text.strip()
                if expected_token in body:
                    return True, f"Fichier de vérification validé sur {target_url}."
        except Exception:
            continue

    return False, f"Le fichier /.well-known/security-audit-challenge.txt contenant '{expected_token}' n'a pas pu être validé."

def verify_domain_ownership(domain: str, expected_token: str, method: str = "auto") -> Dict[str, Any]:
    """
    Verifies domain ownership using the requested method ('dns_txt', 'http_file', or 'auto').
    """
    clean = normalize_domain(domain)
    if not clean:
        return {"success": False, "method": method, "error": "Domaine invalide"}

    if method in ("dns_txt", "auto"):
        ok, msg = verify_dns_txt(clean, expected_token)
        if ok:
            return {"success": True, "method": "dns_txt", "message": msg}
        if method == "dns_txt":
            return {"success": False, "method": "dns_txt", "error": msg}

    if method in ("http_file", "auto"):
        ok, msg = verify_http_challenge(clean, expected_token)
        if ok:
            return {"success": True, "method": "http_file", "message": msg}
        if method == "http_file":
            return {"success": False, "method": "http_file", "error": msg}

    return {
        "success": False,
        "method": method,
        "error": "Aucune méthode de vérification n'a abouti (DNS TXT ou fichier HTTP introuvable)."
    }
