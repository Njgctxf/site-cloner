"""
cve_feed.py - Live CVE & Open Source Vulnerability (OSV / NIST NVD 2.0) Feed Connector
Synchronizes real-time vulnerability advisories from official security databases:
1. Google Open Source Vulnerabilities (OSV.dev)
2. National Institute of Standards and Technology (NIST NVD API v2.0)
with persistent local SQLite caching, graceful offline degradation, and server/CMS version analysis.
"""

import re
import json
from typing import List, Dict, Any, Optional
import requests

from .database import get_cached_cves, store_cached_cves

OSV_API_URL = "https://api.osv.dev/v1/query"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Known cutoff thresholds for obsolete infrastructure components prone to RCE/DoS CVEs
KNOWN_OBSOLETE_STACKS = [
    {
        "name": "Nginx",
        "pattern": re.compile(r"""nginx/([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", re.I),
        "min_secure_version": "1.22.0",
        "fallback_cves": ["CVE-2021-23017", "CVE-2019-9511", "CVE-2018-16843"],
        "remediation": "Mettez à jour Nginx vers la dernière version stable (1.24+) et masquez l'en-tête avec 'server_tokens off;'."
    },
    {
        "name": "Apache",
        "pattern": re.compile(r"""Apache/([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", re.I),
        "min_secure_version": "2.4.53",
        "fallback_cves": ["CVE-2021-41773", "CVE-2021-42013", "CVE-2022-22720"],
        "remediation": "Mettez à jour Apache HTTP Server vers 2.4.54+ et désactivez la signature avec 'ServerTokens Prod'."
    },
    {
        "name": "PHP",
        "pattern": re.compile(r"""PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", re.I),
        "min_secure_version": "8.1.0",
        "fallback_cves": ["CVE-2023-3824", "CVE-2022-31629", "CVE-2019-11043"],
        "remediation": "PHP < 8.1 a atteint sa fin de vie (EOL). Migrez vers PHP 8.2 ou 8.3 et masquez 'expose_php = Off'."
    },
    {
        "name": "WordPress",
        "pattern": re.compile(r"""(?:WordPress\s+|<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+)([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", re.I),
        "min_secure_version": "6.4.0",
        "fallback_cves": ["CVE-2023-38000", "CVE-2022-21661"],
        "remediation": "Mettez à jour le coeur WordPress vers la dernière version 6.x et supprimez la balise meta generator."
    }
]


def _parse_semver(v_str: str) -> List[int]:
    parts = []
    for s in (v_str or "").split("."):
        clean = "".join(filter(str.isdigit, s))
        parts.append(int(clean) if clean else 0)
    while len(parts) < 3:
        parts.append(0)
    return parts[:3]


def _is_version_lower(v_current: str, v_threshold: str) -> bool:
    return _parse_semver(v_current) < _parse_semver(v_threshold)


def query_live_cve_feed(package_name: str, version: str, ecosystem: str = "npm") -> List[Dict[str, Any]]:
    """
    Queries the official Open Source Vulnerabilities (OSV) / NVD database for known CVEs.
    Uses SQLite cache to avoid repeated queries and respect rate limits.
    """
    clean_pkg = (package_name or "").strip().lower()
    clean_ver = (version or "").strip()
    clean_eco = (ecosystem or "npm").strip()

    if not clean_pkg or not clean_ver:
        return []

    # 1. Check local cache
    cached = get_cached_cves(clean_pkg, clean_ver, clean_eco)
    if cached is not None:
        return cached

    # 2. Query official OSV API
    payload = {
        "package": {
            "name": clean_pkg,
            "ecosystem": clean_eco
        },
        "version": clean_ver
    }

    cves_found = []

    try:
        res = requests.post(OSV_API_URL, json=payload, timeout=3.5)
        if res.status_code == 200:
            data = res.json()
            raw_vulns = data.get("vulns", [])

            for v in raw_vulns:
                vuln_id = v.get("id", "")
                aliases = v.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                summary = v.get("summary") or v.get("details", "") or "Vulnérabilité de sécurité documentée"

                # Extract CVSS severity if available
                cvss_score = None
                for s in v.get("severity", []):
                    if s.get("type") in ("CVSS_V3", "CVSS_V2"):
                        cvss_score = s.get("score")

                # Determine severity level
                severity = "HIGH"
                if "critical" in summary.lower() or (cvss_score and "CVSS:3" in str(cvss_score) and "/AV:N/" in str(cvss_score)):
                    severity = "CRITICAL"
                elif "low" in summary.lower():
                    severity = "LOW"
                elif "medium" in summary.lower():
                    severity = "MEDIUM"

                cves_found.append({
                    "cve_id": cve_id,
                    "osv_id": vuln_id,
                    "severity": severity,
                    "summary": summary[:180],
                    "package": clean_pkg,
                    "version": clean_ver
                })

        # Store in local SQLite cache
        store_cached_cves(clean_pkg, clean_ver, cves_found, clean_eco)

    except Exception:
        # Graceful fallback: return empty list on network timeout so the scan continues uninterrupted
        return []

    return cves_found


def query_nvd_feed(keyword: str, cpe_name: Optional[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
    """
    Queries official NIST National Vulnerability Database (NVD API v2.0)
    for CVE advisories matching a software package or infrastructure component.
    Results are cached locally in cyberlab.db.
    """
    clean_keyword = (keyword or "").strip()
    if not clean_keyword and not cpe_name:
        return []

    cache_key = f"nvd:{clean_keyword.lower()}"
    cache_ver = cpe_name or "latest"

    # 1. Check local cache
    cached = get_cached_cves(cache_key, cache_ver, "nvd")
    if cached is not None:
        return cached

    cves_found = []

    params: Dict[str, Any] = {"resultsPerPage": min(limit, 10)}
    if cpe_name:
        params["cpeName"] = cpe_name
    elif clean_keyword:
        params["keywordSearch"] = clean_keyword

    headers = {
        "User-Agent": "CyberLab-Security-Scanner/2.4 (Security Research Engine)"
    }

    try:
        res = requests.get(NVD_API_URL, params=params, headers=headers, timeout=4.0)
        if res.status_code == 200:
            data = res.json()
            vulnerabilities = data.get("vulnerabilities", [])

            for item in vulnerabilities:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id", "")
                if not cve_id:
                    continue

                # English description
                descriptions = cve_obj.get("descriptions", [])
                summary = "Vulnérabilité référencée dans la base NIST NVD"
                for d in descriptions:
                    if d.get("lang") == "en":
                        summary = d.get("value", "")
                        break

                # Extract CVSS score
                metrics = cve_obj.get("metrics", {})
                cvss_data = None
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData")
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_data = metrics["cvssMetricV30"][0].get("cvssData")
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_data = metrics["cvssMetricV2"][0].get("cvssData")

                score = 7.5
                severity = "HIGH"
                if cvss_data:
                    score = cvss_data.get("baseScore", 7.5)
                    sev_raw = cvss_data.get("baseSeverity", "").upper()
                    if sev_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        severity = sev_raw
                    elif score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                cves_found.append({
                    "cve_id": cve_id,
                    "osv_id": cve_id,
                    "severity": severity,
                    "score": score,
                    "summary": summary[:220],
                    "package": clean_keyword,
                    "version": cache_ver
                })

        store_cached_cves(cache_key, cache_ver, cves_found, "nvd")

    except Exception:
        # Fallback cleanly on timeout or rate limiting
        return []

    return cves_found


def detect_server_and_cms_cves(server_header: Optional[str] = None,
                               powered_by_header: Optional[str] = None,
                               html_content: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Detects server stack (Nginx, Apache, PHP, CMS) versions and correlates them with
    live NIST NVD / OSV CVE advisories.
    """
    findings = []
    combined_banner = f"{server_header or ''} {powered_by_header or ''}\n{html_content or ''}"

    for stack in KNOWN_OBSOLETE_STACKS:
        name = stack["name"]
        match = stack["pattern"].search(combined_banner)
        if not match:
            continue

        version = match.group(1)
        if _is_version_lower(version, stack["min_secure_version"]):
            # Query NVD for real CVEs
            nvd_cves = query_nvd_feed(f"{name} {version}", limit=3)
            cve_ids = [c["cve_id"] for c in nvd_cves] if nvd_cves else stack["fallback_cves"]
            cve_str = ", ".join(cve_ids[:4])

            # Determine severity based on NVD results or critical default
            has_critical = any(c.get("severity") == "CRITICAL" for c in nvd_cves) or "PHP" in name
            sev = "CRITICAL" if has_critical else "HIGH"

            findings.append({
                "id": f"VULNERABLE_STACK_{name.upper()}_{version.replace('.', '_')}",
                "title": f"Composant d'infrastructure obsolète & vulnérable : {name} {version}",
                "severity": sev,
                "category": "A06:2021-Vulnerable and Outdated Components (OWASP Top 10)",
                "description": f"La version détectée de {name} ({version}) est inférieure au seuil de sécurité recommandé ({stack['min_secure_version']}). Elle est répertoriée dans la base NIST NVD comme affectée par des failles majeures (ex: déni de service, contournement de contrôle d'accès ou exécution de code).",
                "proof": f"Signature identifiée : {name} {version}. Vulnérabilités NIST NVD / CVE associées : {cve_str}.",
                "impact": "Exploitation à distance sans authentification pouvant mener au déni de service du serveur, à la fuite de mémoire ou à la prise de contrôle selon les modules actifs.",
                "remediation": stack["remediation"]
            })

    return findings

