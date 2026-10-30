"""
database.py - CyberLab Database Engine
Manages both CyberLab audit metrics and the isolated, self-contained mock lab sandbox.
"""

import sqlite3
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

# SiteCloner's data/ folder (git-ignored), next to the shop and admin databases
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cyberlab.db"

def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()

    # 1. CyberLab SOC Platform Tables
    c.execute("""
    CREATE TABLE IF NOT EXISTS verified_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        verification_token TEXT NOT NULL,
        verification_method TEXT DEFAULT 'dns_txt',
        is_verified INTEGER DEFAULT 0,
        verified_at TEXT,
        created_at TEXT NOT NULL,
        status TEXT DEFAULT 'pending'
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_url TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        grade TEXT NOT NULL,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        findings_json TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scheduled_audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        target_url TEXT NOT NULL,
        frequency TEXT DEFAULT 'weekly',
        next_run TEXT NOT NULL,
        last_run TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS cve_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT NOT NULL,
        version TEXT NOT NULL,
        ecosystem TEXT DEFAULT 'npm',
        cves_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(package_name, version, ecosystem)
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS security_api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_name TEXT NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        is_active INTEGER DEFAULT 1
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS admin_private_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        verification_token TEXT NOT NULL,
        verification_method TEXT NOT NULL DEFAULT 'dns_txt',
        is_verified INTEGER NOT NULL DEFAULT 0,
        custom_headers_json TEXT DEFAULT '{}',
        notes TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        verified_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        source TEXT NOT NULL,
        message TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS simulations_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        vuln_type TEXT NOT NULL,
        scenario_title TEXT NOT NULL,
        payload TEXT NOT NULL,
        outcome TEXT NOT NULL,
        is_mitigated INTEGER DEFAULT 0,
        details_json TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS learning_progress (
        module_id TEXT PRIMARY KEY,
        completed INTEGER DEFAULT 0,
        score INTEGER DEFAULT 0,
        last_attempt TEXT
    )
    """)

    # 2. Mock Vulnerable Sandbox Tables (InnoTech Portal)
    c.execute("""
    CREATE TABLE IF NOT EXISTS lab_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        salary TEXT,
        token TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS lab_products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        price REAL NOT NULL,
        description TEXT NOT NULL,
        internal_code TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS lab_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS lab_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        title TEXT NOT NULL,
        confidentiality TEXT NOT NULL,
        content TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

    # Seed initial sandbox data
    seed_lab_data()
    seed_audit_logs()

def seed_lab_data():
    conn = get_connection()
    c = conn.cursor()

    c.execute("DELETE FROM lab_users")
    c.execute("DELETE FROM lab_products")
    c.execute("DELETE FROM lab_comments")
    c.execute("DELETE FROM lab_documents")
    try:
        c.execute("DELETE FROM sqlite_sequence WHERE name IN ('lab_users', 'lab_products', 'lab_comments', 'lab_documents')")
    except Exception:
        pass

    # Lab Users
    users = [
        ("admin", "Admin2026!Secured", "admin@innotech-lab.local", "Administrator", "95,000 EUR", "adm_sec_99a8b7c6"),
        ("jdupont", "password123", "jean.dupont@innotech-lab.local", "DevOps Engineer", "58,000 EUR", "usr_dev_44d1e2f3"),
        ("smartin", "azerty123", "sophie.martin@innotech-lab.local", "HR Manager", "52,000 EUR", "usr_hr_88c7b6a5"),
        ("guest", "guest", "guest@innotech-lab.local", "Auditeur Stagiaire", "12,000 EUR", "usr_gst_11a2b3c4")
    ]
    c.executemany("INSERT INTO lab_users (username, password, email, role, salary, token) VALUES (?, ?, ?, ?, ?, ?)", users)

    # Lab Products
    products = [
        ("Firewall Pro NextGen", "Security Appliance", 4999.99, "Hardware firewall avec inspection dynamique des paquets.", "CONFIDENTIAL_FW_SRC_2026"),
        ("Endpoint Sensor EDR", "Software", 120.00, "Agent de détection des menaces sur terminaux Windows/Linux.", "LIC_EDR_KEY_77492"),
        ("VPN Gateway 10G", "Networking", 2490.50, "Concentrateur VPN IPsec / Wireguard pour entreprise.", "VPN_TUNNEL_SHARED_SECRET"),
        ("Audit Token USB FIDO2", "Authentication", 45.00, "Clé de sécurité physique pour double facteur d'authentification.", "HW_KEY_BATCH_99")
    ]
    c.executemany("INSERT INTO lab_products (name, category, price, description, internal_code) VALUES (?, ?, ?, ?, ?)", products)

    # Lab Comments
    comments = [
        ("Alice", "Test initial de la plateforme de validation.", datetime.now().strftime("%Y-%m-%d %H:%M")),
        ("Bob", "Vérification des règles du pare-feu applicatif (WAF).", datetime.now().strftime("%Y-%m-%d %H:%M"))
    ]
    c.executemany("INSERT INTO lab_comments (author, content, created_at) VALUES (?, ?, ?)", comments)

    # Lab Sensitive Docs
    docs = [
        ("network_architecture.txt", "Schéma d'Architecture DMZ", "CONFIDENTIEL", "Passerelle 192.168.10.1, Serveur SQL 192.168.20.14 (Port interne 5432)."),
        ("employee_handbook.pdf", "Guide Collaborateur", "PUBLIC", "Politique de sécurité des mots de passe: 12 caractères min."),
        ("payroll_q3.csv", "Grille des Rémunérations Q3", "TOP_SECRET", "Direction: 120k, Cadres: 65k, Agents: 35k. Clé de chiffrement bancaire: AES-KEY-998877.")
    ]
    c.executemany("INSERT INTO lab_documents (filename, title, confidentiality, content) VALUES (?, ?, ?, ?)", docs)

    conn.commit()
    conn.close()

def seed_audit_logs():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as cnt FROM audit_logs")
    if c.fetchone()["cnt"] == 0:
        logs = [
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "SYSTEM_INIT", "INFO", "SOC_CORE", "Plateforme CyberLab initialisée avec succès."),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "SANDBOX_READY", "INFO", "LAB_ENV", "Environnement de laboratoire InnoTech isolé démarré."),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "DEFENSE_RULES", "WARN", "POLICY_MGR", "Règles strictes de cloisonnement réseau appliquées (Cibles externes non autorisées).")
        ]
        c.executemany("INSERT INTO audit_logs (timestamp, event_type, severity, source, message) VALUES (?, ?, ?, ?, ?)", logs)
        conn.commit()
    conn.close()

def log_event(event_type, severity, source, message):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_logs (timestamp, event_type, severity, source, message) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_type, severity, source, message)
    )
    conn.commit()
    conn.close()

# ----------------- Verified Domains Management -----------------

def add_pending_domain(domain: str, token: str, method: str = "dns_txt"):
    clean = domain.strip().lower()
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO verified_domains (domain, verification_token, verification_method, is_verified, created_at, status)
        VALUES (?, ?, ?, 0, ?, 'pending')
        ON CONFLICT(domain) DO UPDATE SET
            verification_token = excluded.verification_token,
            verification_method = excluded.verification_method,
            is_verified = 0,
            status = 'pending'
    """, (clean, token, method, now))
    conn.commit()
    c.execute("SELECT * FROM verified_domains WHERE domain = ?", (clean,))
    row = dict(c.fetchone())
    conn.close()
    return row

def get_domain_record(domain: str):
    clean = domain.strip().lower()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM verified_domains WHERE domain = ?", (clean,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def list_domains():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM verified_domains ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def mark_domain_as_verified(domain: str, method_used: str):
    clean = domain.strip().lower()
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO verified_domains (domain, verification_token, verification_method, is_verified, verified_at, created_at, status)
        VALUES (?, 'sc-verified', ?, 1, ?, ?, 'verified')
        ON CONFLICT(domain) DO UPDATE SET
            is_verified = 1, status = 'verified', verified_at = excluded.verified_at, verification_method = excluded.verification_method
    """, (clean, method_used, now, now))
    conn.commit()
    conn.close()

def delete_domain_record(domain_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM verified_domains WHERE id = ?", (domain_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def is_domain_authorized(hostname: str) -> bool:
    """
    Checks if hostname (or its parent root domain) has been verified by the user.
    Also allows local educational lab hosts.
    """
    clean = (hostname or "").strip().lower()
    from .network_guard import LAB_HOSTS
    if clean in LAB_HOSTS:
        return True

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT domain FROM verified_domains WHERE is_verified = 1")
    rows = c.fetchall()
    conn.close()

    for r in rows:
        verified_domain = r["domain"].lower()
        if clean == verified_domain or clean.endswith("." + verified_domain):
            return True

    return False

# ----------------- Scheduled Audits Management -----------------

def add_scheduled_audit(domain: str, target_url: str, frequency: str = "weekly"):
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Compute next run
    next_run = now  # Immediate or next cycle
    c.execute("""
        INSERT INTO scheduled_audits (domain, target_url, frequency, next_run, is_active, created_at)
        VALUES (?, ?, ?, ?, 1, ?)
    """, (domain.strip().lower(), target_url.strip(), frequency, next_run, now))
    audit_id = c.lastrowid
    conn.commit()
    conn.close()
    return audit_id

def list_scheduled_audits():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM scheduled_audits ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def toggle_scheduled_audit(audit_id: int, is_active: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE scheduled_audits SET is_active = ? WHERE id = ?", (1 if is_active else 0, audit_id))
    conn.commit()
    conn.close()

def delete_scheduled_audit(audit_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scheduled_audits WHERE id = ?", (audit_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

# ----------------- CI/CD API Keys Management -----------------

def create_security_api_key(name: str) -> Dict[str, Any]:
    import secrets
    raw_key = f"sc_sec_{secrets.token_hex(24)}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO security_api_keys (key_name, api_key, created_at, is_active)
        VALUES (?, ?, ?, 1)
    """, (name.strip(), raw_key, now))
    key_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"id": key_id, "key_name": name, "api_key": raw_key, "created_at": now}

def list_security_api_keys() -> List[Dict[str, Any]]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, key_name, api_key, created_at, last_used_at, is_active FROM security_api_keys ORDER BY id DESC")
    rows = []
    for r in c.fetchall():
        d = dict(r)
        # Mask key in list view for security (show only sc_sec_****1234)
        k = d["api_key"]
        d["masked_key"] = f"{k[:10]}****{k[-4:]}"
        rows.append(d)
    conn.close()
    return rows

def validate_security_api_key(key_str: str) -> bool:
    if not key_str:
        return False
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("SELECT id FROM security_api_keys WHERE api_key = ? AND is_active = 1", (key_str.strip(),))
    row = c.fetchone()
    if row:
        c.execute("UPDATE security_api_keys SET last_used_at = ? WHERE id = ?", (now, row["id"]))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

def revoke_security_api_key(key_id: int) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM security_api_keys WHERE id = ?", (key_id,))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

# ----------------- CVE Feed Cache Management -----------------

def get_cached_cves(package_name: str, version: str, ecosystem: str = "npm") -> Optional[List[Dict[str, Any]]]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT cves_json FROM cve_cache
        WHERE package_name = ? AND version = ? AND ecosystem = ?
    """, (package_name.lower().strip(), version.strip(), ecosystem.lower().strip()))
    row = c.fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row["cves_json"])
        except Exception:
            return None
    return None

def store_cached_cves(package_name: str, version: str, cves: List[Dict[str, Any]], ecosystem: str = "npm"):
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO cve_cache (package_name, version, ecosystem, cves_json, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(package_name, version, ecosystem) DO UPDATE SET
            cves_json = excluded.cves_json,
            updated_at = excluded.updated_at
    """, (package_name.lower().strip(), version.strip(), ecosystem.lower().strip(), json.dumps(cves), now))
    conn.commit()
    conn.close()


# ----------------- Admin Private Domains Management -----------------

def add_admin_private_domain(domain: str, verification_token: str, method: str = "dns_txt", notes: str = "") -> Dict[str, Any]:
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO admin_private_domains (domain, verification_token, verification_method, is_verified, custom_headers_json, notes, created_at)
        VALUES (?, ?, ?, 0, '{}', ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            verification_token = excluded.verification_token,
            verification_method = excluded.verification_method,
            notes = excluded.notes
    """, (domain.lower().strip(), verification_token.strip(), method, notes.strip(), now))
    conn.commit()
    c.execute("SELECT * FROM admin_private_domains WHERE domain = ?", (domain.lower().strip(),))
    row = dict(c.fetchone())
    conn.close()
    return row

def list_admin_private_domains() -> List[Dict[str, Any]]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM admin_private_domains ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_admin_private_domain(domain_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM admin_private_domains WHERE id = ?", (domain_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def verify_admin_private_domain(domain_id: int) -> bool:
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        UPDATE admin_private_domains
        SET is_verified = 1, verified_at = ?
        WHERE id = ?
    """, (now, domain_id))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def update_admin_private_domain_config(domain_id: int, custom_headers_json: str, notes: str) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        UPDATE admin_private_domains
        SET custom_headers_json = ?, notes = ?
        WHERE id = ?
    """, (custom_headers_json, notes, domain_id))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def delete_admin_private_domain(domain_id: int) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM admin_private_domains WHERE id = ?", (domain_id,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def is_admin_private_domain_authorized(domain: str) -> bool:
    clean = (domain or "").lower().strip()
    if clean in ("localhost", "127.0.0.1", "0.0.0.0", "innotech-lab.local", "cyberlab.local"):
        return True
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM admin_private_domains WHERE domain = ? AND is_verified = 1", (clean,))
    row = c.fetchone()
    conn.close()
    return bool(row)

def save_scan(scan_dict: Dict[str, Any]) -> int:
    conn = get_connection()
    c = conn.cursor()
    target_url = scan_dict.get("target_url", "")
    timestamp = scan_dict.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_score = scan_dict.get("risk_score", 100)
    grade = scan_dict.get("grade", "A")
    counts = scan_dict.get("counts", {})
    crit = counts.get("critical", 0)
    hi = counts.get("high", 0)
    med = counts.get("medium", 0)
    lo = counts.get("low", 0)
    findings = scan_dict.get("findings", [])
    findings_json = json.dumps(findings)

    c.execute("""
        INSERT INTO scans (target_url, timestamp, risk_score, grade, critical_count, high_count, medium_count, low_count, findings_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (target_url, timestamp, risk_score, grade, crit, hi, med, lo, findings_json))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["findings"] = json.loads(d.get("findings_json") or "[]")
    except Exception:
        d["findings"] = []
    return d

def compare_scans(scan_a_id: int, scan_b_id: int) -> Optional[Dict[str, Any]]:
    """
    Compares two audit runs (Scan A: Baseline vs Scan B: Current)
    to compute posture progression, resolved findings, and newly introduced regressions.
    """
    scan_a = get_scan_by_id(scan_a_id)
    scan_b = get_scan_by_id(scan_b_id)
    if not scan_a or not scan_b:
        return None

    findings_a = scan_a.get("findings", [])
    findings_b = scan_b.get("findings", [])

    # Map by finding ID
    map_a = {f["id"]: f for f in findings_a if "id" in f}
    map_b = {f["id"]: f for f in findings_b if "id" in f}

    ids_a = set(map_a.keys())
    ids_b = set(map_b.keys())

    resolved_ids = ids_a - ids_b
    new_ids = ids_b - ids_a
    persistent_ids = ids_a & ids_b

    resolved = [map_a[fid] for fid in resolved_ids]
    new_regressions = [map_b[fid] for fid in new_ids]
    persistent = [map_b[fid] for fid in persistent_ids]

    score_a = scan_a.get("risk_score", 0)
    score_b = scan_b.get("risk_score", 0)
    score_delta = score_b - score_a

    return {
        "scan_a": {
            "id": scan_a["id"],
            "target_url": scan_a["target_url"],
            "timestamp": scan_a["timestamp"],
            "risk_score": score_a,
            "grade": scan_a.get("grade", "N/A"),
            "findings_count": len(findings_a)
        },
        "scan_b": {
            "id": scan_b["id"],
            "target_url": scan_b["target_url"],
            "timestamp": scan_b["timestamp"],
            "risk_score": score_b,
            "grade": scan_b.get("grade", "N/A"),
            "findings_count": len(findings_b)
        },
        "score_delta": score_delta,
        "is_improved": score_delta > 0,
        "resolved_findings": resolved,
        "new_regressions": new_regressions,
        "persistent_findings": persistent,
        "summary": {
            "resolved_count": len(resolved),
            "new_count": len(new_regressions),
            "persistent_count": len(persistent)
        }
    }


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at:", DB_PATH)
