"""
asset_registry.py - Universal Enterprise Asset & Authorization Engine for Sentinel AI
Manages authorized digital assets (Domains, Subdomains, IPs, CIDRs, APIs, Linux/Windows Servers,
Databases, Cloud Resources) and formalized Letters of Authorization (RoE / Rules of Engagement)
with temporal validity and granular test permission scopes.
"""

import json
import uuid
import re
import ipaddress
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from ..database import get_connection, is_domain_authorized, is_admin_private_domain_authorized, log_event
from ..network_guard import LAB_HOSTS

VALID_ASSET_TYPES = {
    "domain",
    "subdomain",
    "ip",
    "network_cidr",
    "web_app",
    "api",
    "linux_server",
    "windows_server",
    "database",
    "cloud_resource"
}

VALID_TEST_TYPES = {
    "all",
    "dast",
    "jwt",
    "upload",
    "race_condition",
    "business_logic",
    "config_audit",
    "system_check",
    "passive_recon",
    "kali_audit",
    "pentagi_audit",
    "external_scan"
}


def init_asset_tables():
    """Creates tables for projects, multi-type assets, and scope authorization mandates."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_projects (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        company_name TEXT NOT NULL,
        description TEXT,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_assets (
        id TEXT PRIMARY KEY,
        project_id TEXT,
        name TEXT NOT NULL,
        asset_type TEXT NOT NULL,
        target TEXT NOT NULL,
        environment TEXT DEFAULT 'production',
        metadata_json TEXT DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY (project_id) REFERENCES sentinel_projects(id) ON DELETE SET NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_authorizations (
        id TEXT PRIMARY KEY,
        asset_id TEXT NOT NULL,
        authorized_by TEXT NOT NULL,
        mandate_ref TEXT,
        allowed_test_types TEXT NOT NULL DEFAULT '["dast"]',
        valid_from TEXT NOT NULL,
        valid_until TEXT NOT NULL,
        max_rate_limit INTEGER DEFAULT 120,
        is_revoked INTEGER DEFAULT 0,
        revocation_reason TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (asset_id) REFERENCES sentinel_assets(id) ON DELETE CASCADE
    )
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Project Management
# --------------------------------------------------------------------------

def create_project(name: str, company_name: str, description: str = "") -> Dict[str, Any]:
    init_asset_tables()
    proj_id = f"proj_{uuid.uuid4().hex[:10]}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_projects (id, name, company_name, description, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (proj_id, name.strip(), company_name.strip(), description.strip(), now))
    conn.commit()
    conn.close()

    log_event("SENTINEL_PROJECT_CREATED", "INFO", "ASSET_REGISTRY", f"Nouveau projet créé: {name} ({company_name})")
    return {"id": proj_id, "name": name, "company_name": company_name, "created_at": now}


def list_projects() -> List[Dict[str, Any]]:
    init_asset_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sentinel_projects ORDER BY created_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# --------------------------------------------------------------------------
# Asset Management
# --------------------------------------------------------------------------

def register_asset(
    name: str,
    asset_type: str,
    target: str,
    project_id: Optional[str] = None,
    environment: str = "production",
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Registers a new infrastructure asset.
    """
    init_asset_tables()
    clean_type = (asset_type or "domain").lower().strip()
    if clean_type not in VALID_ASSET_TYPES:
        raise ValueError(f"Type d'actif non valide: '{clean_type}'. Types autorisés: {sorted(list(VALID_ASSET_TYPES))}")

    clean_target = target.strip()
    if not clean_target:
        raise ValueError("La cible de l'actif ne peut pas être vide.")

    asset_id = f"ast_{uuid.uuid4().hex[:10]}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta_json = json.dumps(metadata or {})

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_assets (id, project_id, name, asset_type, target, environment, metadata_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (asset_id, project_id, name.strip(), clean_type, clean_target, environment, meta_json, now))
    conn.commit()
    conn.close()

    log_event("SENTINEL_ASSET_REGISTERED", "INFO", "ASSET_REGISTRY", f"Actif enregistré: {name} [{clean_type}] -> {clean_target}")
    return {
        "id": asset_id,
        "project_id": project_id,
        "name": name,
        "asset_type": clean_type,
        "target": clean_target,
        "environment": environment,
        "created_at": now
    }


def list_assets(project_id: Optional[str] = None, asset_type: Optional[str] = None) -> List[Dict[str, Any]]:
    init_asset_tables()
    conn = get_connection()
    c = conn.cursor()

    query = """
    SELECT a.*, 
           auth.id as active_auth_id,
           auth.authorized_by,
           auth.mandate_ref,
           auth.allowed_test_types,
           auth.valid_until,
           auth.is_revoked
    FROM sentinel_assets a
    LEFT JOIN sentinel_authorizations auth ON a.id = auth.asset_id AND auth.is_revoked = 0
    WHERE 1=1
    """
    params = []
    if project_id:
        query += " AND a.project_id = ?"
        params.append(project_id)
    if asset_type:
        query += " AND a.asset_type = ?"
        params.append(asset_type.lower())

    query += " ORDER BY a.created_at DESC"
    c.execute(query, params)
    rows = []
    for r in c.fetchall():
        d = dict(r)
        d["metadata"] = json.loads(d.get("metadata_json") or "{}")
        d["allowed_tests"] = json.loads(d.get("allowed_test_types") or "[]")
        rows.append(d)
    conn.close()
    return rows


def get_asset(asset_id: str) -> Optional[Dict[str, Any]]:
    init_asset_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sentinel_assets WHERE id = ?", (asset_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["metadata"] = json.loads(d.get("metadata_json") or "{}")
    return d


# --------------------------------------------------------------------------
# Formal Authorization (Letter of Authorization / RoE Mandate)
# --------------------------------------------------------------------------

def grant_authorization(
    asset_id: str,
    authorized_by: str,
    valid_from: str,
    valid_until: str,
    mandate_ref: str = "",
    allowed_test_types: Optional[List[str]] = None,
    max_rate_limit: int = 120
) -> Dict[str, Any]:
    """
    Issues a formalized authorization scope / RoE mandate for an asset.
    """
    init_asset_tables()
    asset = get_asset(asset_id)
    if not asset:
        raise ValueError(f"Actif introuvable avec l'ID: {asset_id}")

    test_types = allowed_test_types or ["dast"]
    auth_id = f"auth_{uuid.uuid4().hex[:10]}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_authorizations (
        id, asset_id, authorized_by, mandate_ref, allowed_test_types,
        valid_from, valid_until, max_rate_limit, is_revoked, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
    """, (
        auth_id, asset_id, authorized_by.strip(), mandate_ref.strip(),
        json.dumps(test_types), valid_from.strip(), valid_until.strip(),
        max_rate_limit, now
    ))
    conn.commit()
    conn.close()

    log_event("SENTINEL_AUTH_GRANTED", "INFO", "GUARDIAN", f"Autorisation accordée sur actif {asset['name']} ({asset['target']}) par {authorized_by}")
    return {
        "id": auth_id,
        "asset_id": asset_id,
        "asset_name": asset["name"],
        "target": asset["target"],
        "authorized_by": authorized_by,
        "valid_until": valid_until,
        "allowed_test_types": test_types,
        "created_at": now
    }


def revoke_authorization(authorization_id: str, reason: str = "Révocation manuelle par l'administrateur") -> bool:
    init_asset_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    UPDATE sentinel_authorizations
    SET is_revoked = 1, revocation_reason = ?
    WHERE id = ?
    """, (reason, authorization_id))
    affected = c.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_event("SENTINEL_AUTH_REVOKED", "WARNING", "GUARDIAN", f"Autorisation révoquée {authorization_id}: {reason}")
    return affected > 0


# --------------------------------------------------------------------------
# Scope Resolution & Universal Verification
# --------------------------------------------------------------------------

def _extract_target_identifiers(raw_target: str) -> List[str]:
    """
    Extracts all candidate hostnames, IPs, and domains from a target string or URL.
    """
    clean = raw_target.strip().lower()
    candidates = [clean]

    # If it's a URL, extract hostname
    if "://" in clean or clean.startswith("//"):
        try:
            parsed = urllib.parse.urlparse(clean if "://" in clean else f"http:{clean}")
            if parsed.hostname:
                candidates.append(parsed.hostname.lower())
        except Exception:
            pass

    # Strip port if present
    if ":" in clean:
        parts = clean.split(":")
        candidates.append(parts[0].lower())

    # Return unique identifiers
    seen = set()
    return [x for x in candidates if x and not (x in seen or seen.add(x))]


def is_target_in_universal_scope(target_str: str, test_type: Optional[str] = None) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Universal verification against both the new Enterprise Asset Mandates
    AND the legacy CyberLab domain verification (100% backward compatible).
    """
    init_asset_tables()
    identifiers = _extract_target_identifiers(target_str)

    # 1. Check local sandbox / lab
    for ident in identifiers:
        if ident in LAB_HOSTS or ident in ("localhost", "127.0.0.1", "0.0.0.0", "innotech-lab.local", "cyberlab.local"):
            return True, "Cible autorisée (Laboratoire sandboxed local InnoTech)", {"scope": "local_lab", "target": ident}

    # 2. Check universal asset registry with active authorization
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    SELECT a.*, auth.id as auth_id, auth.authorized_by, auth.mandate_ref,
           auth.allowed_test_types, auth.valid_from, auth.valid_until,
           auth.is_revoked, auth.max_rate_limit
    FROM sentinel_assets a
    JOIN sentinel_authorizations auth ON a.id = auth.asset_id
    WHERE auth.is_revoked = 0
    """)
    active_auths = [dict(r) for r in c.fetchall()]
    conn.close()

    now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for record in active_auths:
        # Check temporal validity
        if not (record["valid_from"] <= now_iso <= record["valid_until"]):
            continue

        # Check allowed test type if specified
        allowed_tests = json.loads(record.get("allowed_test_types") or "[]")
        if test_type and "all" not in allowed_tests and test_type not in allowed_tests:
            continue

        asset_target_clean = record["target"].lower().strip()

        # Direct string or identifier match
        if any(ident == asset_target_clean or asset_target_clean in ident or ident in asset_target_clean for ident in identifiers):
            return True, f"Cible autorisée par mandat entreprise '{record.get('mandate_ref') or record['auth_id']}' ({record['authorized_by']})", {
                "scope": "enterprise_mandate",
                "asset_id": record["id"],
                "asset_name": record["name"],
                "asset_type": record["asset_type"],
                "authorized_by": record["authorized_by"],
                "rate_limit": record["max_rate_limit"]
            }

        # IP in CIDR check
        if record["asset_type"] == "network_cidr":
            try:
                network = ipaddress.ip_network(asset_target_clean, strict=False)
                for ident in identifiers:
                    try:
                        ip = ipaddress.ip_address(ident)
                        if ip in network:
                            return True, f"Adresse IP {ident} incluse dans le sous-réseau autorisé {asset_target_clean}", {
                                "scope": "enterprise_cidr",
                                "network": asset_target_clean,
                                "authorized_by": record["authorized_by"]
                            }
                    except ValueError:
                        pass
            except ValueError:
                pass

    # 3. Transparent backward compatibility: check legacy verified domains
    for ident in identifiers:
        if is_domain_authorized(ident) or is_admin_private_domain_authorized(ident):
            return True, f"Domaine vérifié dans le CyberLab ({ident})", {"scope": "verified_domain", "domain": ident}

    return False, f"Cible non autorisée ({target_str}). Aucun mandat d'audit ni vérification de propriété actif.", None
