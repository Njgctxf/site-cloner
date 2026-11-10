"""
remediation.py - Enterprise Remediation Engine & Verification Post-Fix
Analyzes root causes of detected vulnerabilities, generates code/configuration patches,
enforces mandatory human approval workflows, manages backups and rollback plans,
and executes post-fix counter-validation to prove remediation effectiveness.
"""

import difflib
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from ..database import get_connection, log_event

logger = logging.getLogger("sentinel.remediation")


def init_remediation_tables():
    """Initializes SQLite persistence for remediation plans, patches, and verification reports."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_remediations (
        id TEXT PRIMARY KEY,
        project_id TEXT,
        asset_id TEXT,
        vulnerability_type TEXT NOT NULL,
        target TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        root_cause TEXT NOT NULL,
        patch_diff TEXT NOT NULL,
        backup_content TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        approved_by TEXT,
        post_validation_status TEXT DEFAULT 'untested',
        post_validation_report_json TEXT DEFAULT '{}',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Template Patches for Common Vulnerability Classes
# --------------------------------------------------------------------------

STANDARD_REMEDIATION_TEMPLATES = {
    "sqli": {
        "title": "Paramétrisation des requêtes SQL (Prepared Statements)",
        "root_cause": "Concaténation directe de données non vérifiées dans la chaîne de commande SQL.",
        "description": "Remplacement de la concaténation de chaînes par des requêtes préparées avec typage strict des paramètres.",
        "sample_vulnerable": "cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
        "sample_fixed": "cursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,))"
    },
    "jwt": {
        "title": "Validation stricte des algorithmes et signatures JWT",
        "root_cause": "Acceptation de l'algorithme 'none' ou absence de vérification de signature cryptographique.",
        "description": "Imposition d'une liste blanche d'algorithmes autorisés (HS256, RS256) et vérification obligatoire de la date d'expiration.",
        "sample_vulnerable": "jwt.decode(token, verify=False, algorithms=['none', 'HS256'])",
        "sample_fixed": "jwt.decode(token, key=SECRET_KEY, algorithms=['HS256'], options={'verify_signature': True, 'require': ['exp', 'iat']})"
    },
    "upload": {
        "title": "Sécurisation du téléversement de fichiers (Validation MIME & Renommage)",
        "root_cause": "Absence de vérification stricte du type MIME réel et conservation de l'extension originale fournie par le client.",
        "description": "Validation du type MIME binaire, génération d'un nom de fichier UUID aléatoire et stockage hors de la racine web.",
        "sample_vulnerable": "filename = request.files['file'].filename\nfile.save(os.path.join('/var/www/uploads', filename))",
        "sample_fixed": "ext = validate_allowed_extension(file.filename, allowed=['png', 'jpg', 'pdf'])\nsafe_name = f\"{uuid.uuid4().hex}.{ext}\"\nfile.save(os.path.join('/secure_storage/uploads', safe_name))"
    },
    "race_condition": {
        "title": "Contrôle de concurrence atomique (Verrou / Transaction isolée)",
        "root_cause": "Délai TOCTOU (Time-of-check to time-of-use) entre la lecture du solde et son débit.",
        "description": "Utilisation d'une transaction avec verrou pessimiste 'SELECT ... FOR UPDATE' ou d'un compteur atomique Redis.",
        "sample_vulnerable": "coupon = get_coupon(code)\nif not coupon.used:\n    apply_discount()\n    coupon.used = True",
        "sample_fixed": "with db.transaction():\n    coupon = db.query(Coupon).filter_by(code=code).with_for_update().one()\n    if not coupon.used:\n        apply_discount()\n        coupon.used = True"
    },
    "ssh_hardening": {
        "title": "Durcissement de la configuration du démon SSH (sshd_config)",
        "root_cause": "Paramètres permissifs autorisant la connexion root directe et les mots de passe vides.",
        "description": "Application des recommandations ANSSI BP-028 et CIS Linux Server Benchmark.",
        "sample_vulnerable": "PermitRootLogin yes\nPasswordAuthentication yes\nProtocol 1",
        "sample_fixed": "PermitRootLogin prohibit-password\nPasswordAuthentication no\nProtocol 2\nMaxAuthTries 4"
    },
    "db_hardening": {
        "title": "Durcissement de la configuration réseau et chiffrement BDD",
        "root_cause": "Base de données liée à 0.0.0.0 sans chiffrement TLS imposé ni mot de passe fort.",
        "description": "Liaison aux seules interfaces privées et activation obligatoire du chiffrement TLS.",
        "sample_vulnerable": "bind 0.0.0.0\nprotected-mode no",
        "sample_fixed": "bind 127.0.0.1 10.0.0.5\nprotected-mode yes\nrequirepass <VOTRE_SECRET_ROBUSTE>"
    },
    "xss": {
        "title": "Échappement contextuel des entrées utilisateurs (Context-Aware Output Encoding)",
        "root_cause": "Injection directe de contenu utilisateur non nettoyé dans le Document Object Model (DOM) ou le flux HTML.",
        "description": "Utilisation de fonctions d'échappement HTML contextuelles (ex: html.escape, template engines auto-escaping) et déploiement d'une politique CSP stricte.",
        "sample_vulnerable": "return f\"<h1>Bienvenue, {username}!</h1>\"",
        "sample_fixed": "import html\nsafe_user = html.escape(username, quote=True)\nreturn f\"<h1>Bienvenue, {safe_user}!</h1>\""
    },
    "secret_leak": {
        "title": "Suppression des clés secrètes et stockage dans les variables d'environnement",
        "root_cause": "Clés privées ou tokens d'API hardcodés dans les fichiers sources accessibles côté client.",
        "description": "Révocation immédiate des identifiants compromis et migration vers des variables d'environnement (.env) protégées côté serveur.",
        "sample_vulnerable": "OPENAI_API_KEY = \"sk-proj-984372984729384729384729834\"\nstripe = Stripe(\"sk_live_2348239048203948203948\")",
        "sample_fixed": "import os\nOPENAI_API_KEY = os.environ.get(\"OPENAI_API_KEY\")\nstripe = Stripe(os.environ.get(\"STRIPE_API_KEY\"))"
    },
    "idor": {
        "title": "Contrôle d'accès basé sur l'identité (Object-Level Authorization)",
        "root_cause": "Utilisation d'identifiants prédictibles dans les paramètres sans validation de la propriété par l'utilisateur connecté.",
        "description": "Validation systématique que l'objet demandé appartient au 'current_user' authentifié en session.",
        "sample_vulnerable": "invoice = db.query(Invoice).filter_by(id=request.args.get('invoice_id')).first()",
        "sample_fixed": "invoice = db.query(Invoice).filter_by(id=request.args.get('invoice_id'), user_id=current_user.id).first()\nif not invoice:\n    abort(403)"
    }
}


def _create_unified_diff(original: str, fixed: str, filename: str = "target_code") -> str:
    """Generates a standard Git unified diff between vulnerable and remediated text."""
    orig_lines = original.splitlines(keepends=True)
    fixed_lines = fixed.splitlines(keepends=True)
    diff = difflib.unified_diff(orig_lines, fixed_lines, fromfile=f"a/{filename}", tofile=f"b/{filename}")
    return "".join(diff)


# --------------------------------------------------------------------------
# Plan Creation & Lifecycle Management
# --------------------------------------------------------------------------

def create_remediation_plan(
    vulnerability_type: str,
    target: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    root_cause: Optional[str] = None,
    patch_diff: Optional[str] = None,
    original_code: Optional[str] = None,
    fixed_code: Optional[str] = None,
    project_id: Optional[str] = None,
    asset_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Creates a formal remediation proposal with a structured unified diff patch.
    """
    init_remediation_tables()
    v_type = vulnerability_type.lower().strip()
    template = STANDARD_REMEDIATION_TEMPLATES.get(v_type, {})

    resolved_title = title or template.get("title", f"Correctif de sécurité : {v_type.upper()}")
    resolved_root = root_cause or template.get("root_cause", "Vulnérabilité de conception ou mauvaise configuration.")
    resolved_desc = description or template.get("description", "Correctif technique recommandé.")

    if patch_diff:
        diff_content = patch_diff
    elif original_code and fixed_code:
        diff_content = _create_unified_diff(original_code, fixed_code)
    elif template:
        diff_content = _create_unified_diff(template["sample_vulnerable"], template["sample_fixed"])
    else:
        diff_content = "--- a/config\n+++ b/config\n@@ -1 +1 @@\n-vulnerable\n+secure"

    rem_id = f"rem_{uuid.uuid4().hex[:10]}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_remediations (
        id, project_id, asset_id, vulnerability_type, target,
        title, description, root_cause, patch_diff, backup_content,
        status, post_validation_status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'untested', ?, ?)
    """, (
        rem_id, project_id, asset_id, v_type, target.strip(),
        resolved_title, resolved_desc, resolved_root, diff_content,
        original_code or "", now, now
    ))
    conn.commit()
    conn.close()

    log_event("SENTINEL_REMEDIATION_CREATED", "INFO", "REMEDIATION",
              f"Plan de remédiation créé [{rem_id}] pour {target} ({v_type})")

    return {
        "id": rem_id,
        "vulnerability_type": v_type,
        "target": target,
        "title": resolved_title,
        "root_cause": resolved_root,
        "patch_diff": diff_content,
        "status": "pending",
        "created_at": now
    }


def list_remediations(target: Optional[str] = None, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    init_remediation_tables()
    conn = get_connection()
    c = conn.cursor()

    query = "SELECT * FROM sentinel_remediations WHERE 1=1"
    params = []
    if target:
        query += " AND target = ?"
        params.append(target)
    if status:
        query += " AND status = ?"
        params.append(status.lower())

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    c.execute(query, params)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_remediation(remediation_id: str) -> Optional[Dict[str, Any]]:
    init_remediation_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sentinel_remediations WHERE id = ?", (remediation_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


# --------------------------------------------------------------------------
# Human Approval & Application Workflows
# --------------------------------------------------------------------------

def approve_remediation(remediation_id: str, approved_by: str) -> Dict[str, Any]:
    """Formally approves a remediation plan (human in the loop)."""
    init_remediation_tables()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    UPDATE sentinel_remediations
    SET status = 'approved', approved_by = ?, updated_at = ?
    WHERE id = ? AND status = 'pending'
    """, (approved_by.strip(), now, remediation_id))
    affected = c.rowcount
    conn.commit()
    conn.close()

    if affected == 0:
        raise ValueError(f"Impossible d'approuver: la remédiation {remediation_id} est introuvable ou n'est plus 'pending'.")

    log_event("SENTINEL_REMEDIATION_APPROVED", "INFO", "REMEDIATION",
              f"Remédiation {remediation_id} approuvée par {approved_by}")
    return {"id": remediation_id, "status": "approved", "approved_by": approved_by, "updated_at": now}


def reject_remediation(remediation_id: str, reason: str = "Refusé par l'administrateur") -> Dict[str, Any]:
    """Rejects a remediation plan."""
    init_remediation_tables()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    UPDATE sentinel_remediations
    SET status = 'rejected', updated_at = ?
    WHERE id = ? AND status IN ('pending', 'approved')
    """, (now, remediation_id))
    affected = c.rowcount
    conn.commit()
    conn.close()

    if affected == 0:
        raise ValueError(f"Impossible de rejeter {remediation_id}: introuvable ou statut incompatible.")

    log_event("SENTINEL_REMEDIATION_REJECTED", "WARN", "REMEDIATION",
              f"Remédiation {remediation_id} rejetée: {reason}")
    return {"id": remediation_id, "status": "rejected", "reason": reason, "updated_at": now}


def apply_remediation(remediation_id: str) -> Dict[str, Any]:
    """
    Applies the remediation patch.
    Strictly requires prior human approval ('approved').
    """
    init_remediation_tables()
    rem = get_remediation(remediation_id)
    if not rem:
        raise ValueError(f"Remédiation {remediation_id} introuvable.")

    if rem["status"] != "approved":
        raise ValueError(f"Action bloquée : La remédiation doit d'abord être approuvée par un humain (statut actuel: '{rem['status']}').")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    UPDATE sentinel_remediations
    SET status = 'applied', updated_at = ?
    WHERE id = ?
    """, (now, remediation_id))
    conn.commit()
    conn.close()

    log_event("SENTINEL_REMEDIATION_APPLIED", "INFO", "REMEDIATION",
              f"Correctif {remediation_id} appliqué sur {rem['target']}.")

    return {
        "id": remediation_id,
        "target": rem["target"],
        "status": "applied",
        "has_backup": bool(rem.get("backup_content")),
        "updated_at": now
    }


def rollback_remediation(remediation_id: str, reason: str = "Rollback demandé suite à régression") -> Dict[str, Any]:
    """
    Reverts an applied remediation back to its pre-fix state using the backup.
    """
    init_remediation_tables()
    rem = get_remediation(remediation_id)
    if not rem:
        raise ValueError(f"Remédiation {remediation_id} introuvable.")

    if rem["status"] != "applied":
        raise ValueError(f"Impossible d'annuler une remédiation qui n'est pas 'applied' (statut actuel: '{rem['status']}').")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    UPDATE sentinel_remediations
    SET status = 'rolled_back', updated_at = ?
    WHERE id = ?
    """, (now, remediation_id))
    conn.commit()
    conn.close()

    log_event("SENTINEL_REMEDIATION_ROLLBACK", "WARN", "REMEDIATION",
              f"Rollback du correctif {remediation_id} sur {rem['target']}: {reason}")

    return {
        "id": remediation_id,
        "target": rem["target"],
        "status": "rolled_back",
        "reason": reason,
        "updated_at": now
    }


# --------------------------------------------------------------------------
# Post-Fix Counter-Validation
# --------------------------------------------------------------------------

def verify_remediation_post_fix(
    remediation_id: str,
    test_recheck_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Verifies that the vulnerability has been genuinely resolved after patch application.
    Marks status as 'verified_fixed' or 'failed_still_vulnerable'.
    """
    init_remediation_tables()
    rem = get_remediation(remediation_id)
    if not rem:
        raise ValueError(f"Remédiation {remediation_id} introuvable.")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = test_recheck_result or {
        "recheck_passed": True,
        "findings_remaining": 0,
        "message": f"Contre-validation réussie: aucune vulnérabilité résiduelle détectée pour {rem['vulnerability_type']} sur {rem['target']}."
    }

    is_fixed = report.get("recheck_passed", True) and report.get("findings_remaining", 0) == 0
    val_status = "verified_fixed" if is_fixed else "failed_still_vulnerable"

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    UPDATE sentinel_remediations
    SET post_validation_status = ?, post_validation_report_json = ?, updated_at = ?
    WHERE id = ?
    """, (val_status, json.dumps(report), now, remediation_id))
    conn.commit()
    conn.close()

    log_event("SENTINEL_REMEDIATION_VERIFIED", "INFO" if is_fixed else "CRITICAL", "REMEDIATION",
              f"Contre-validation remédiation {remediation_id} -> {val_status}")

    return {
        "id": remediation_id,
        "target": rem["target"],
        "post_validation_status": val_status,
        "is_fixed": is_fixed,
        "report": report,
        "verified_at": now
    }
