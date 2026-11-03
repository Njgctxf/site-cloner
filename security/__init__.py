"""
security - CyberLab, the SOC & security-audit module of SiteCloner (from the CyberLab-SOC-Platform project).
SOC dashboard, defensive scanner (security headers, cookies, exposed files) restricted to authorized hosts,
OWASP attack simulations with their remediation in a sandboxed lab, learning modules and printable audit reports.
Mounted by app.py (init_security) under /__sc/security.
"""

import json
import urllib.parse
from datetime import datetime
from functools import wraps
from typing import Optional

from flask import Blueprint, jsonify, render_template, request, session, redirect

from .database import (
    get_connection, init_db, log_event, seed_lab_data,
    add_pending_domain, list_domains, get_domain_record,
    mark_domain_as_verified, delete_domain_record,
    add_scheduled_audit, list_scheduled_audits, toggle_scheduled_audit, delete_scheduled_audit,
    create_security_api_key, list_security_api_keys, validate_security_api_key, revoke_security_api_key,
    add_admin_private_domain, list_admin_private_domains, get_admin_private_domain,
    verify_admin_private_domain, update_admin_private_domain_config, delete_admin_private_domain,
    is_admin_private_domain_authorized, compare_scans, save_scan
)
from .domain_verifier import generate_challenge_token, normalize_domain, verify_domain_ownership
from .scanner import scan_target
from .simulations import LAB_STATE, SCENARIOS, execute_simulation
from .ci_cd import generate_github_actions_workflow, generate_gitlab_ci_yaml
from .dast_engine import audit_sqli_advanced_differential, deep_crawl_surface

BASE = "/__sc/security"
bp = Blueprint("security", __name__, url_prefix=BASE)


def lab_url():
    """The sandboxed practice target ("InnoTech" intranet) served by this module."""
    return request.host_url.rstrip("/") + BASE + "/lab"


@bp.app_context_processor
def _ctx():
    return {"SEC_BASE": BASE}


# --- web pages ---

@bp.route("/")
def index():
    return render_template("security/index.html", lab_url=lab_url(), target=request.args.get("target", ""))


@bp.route("/lab")
def lab_home():
    return render_template("security/lab.html", mode=LAB_STATE["mode"])


# --- verified domains management ---

@bp.route("/api/domains", methods=["GET"])
def get_domains():
    return jsonify({"domains": list_domains()})


@bp.route("/api/domains", methods=["POST"])
def register_domain():
    data = request.get_json(silent=True) or {}
    raw_domain = data.get("domain", "")
    method = data.get("verification_method", "dns_txt")
    clean = normalize_domain(raw_domain)

    if not clean or "." not in clean:
        return jsonify({"error": "Nom de domaine invalide (ex: entreprise.com ou app.entreprise.com)."}), 400

    token = generate_challenge_token()
    rec = add_pending_domain(clean, token, method)
    log_event("DOMAIN_ENROLLED", "INFO", "DOMAIN_MGR", f"Domaine '{clean}' enregistré en attente de validation.")

    return jsonify({
        "success": True,
        "domain": rec,
        "instructions": {
            "dns_txt": {
                "record_name": f"_sc-audit.{clean}",
                "record_type": "TXT",
                "value": token,
                "description": f"Créez un enregistrement DNS TXT nommé _sc-audit.{clean} avec la valeur exacte '{token}'."
            },
            "http_file": {
                "url": f"https://{clean}/.well-known/security-audit-challenge.txt",
                "content": token,
                "description": f"Créez un fichier texte public à l'adresse https://{clean}/.well-known/security-audit-challenge.txt contenant uniquement '{token}'."
            }
        }
    })


@bp.route("/api/domains/<int:domain_id>/verify", methods=["POST"])
def verify_domain_endpoint(domain_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM verified_domains WHERE id = ?", (domain_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Domaine introuvable"}), 404

    domain_data = dict(row)
    domain_name = domain_data["domain"]
    token = domain_data["verification_token"]
    method = (request.get_json(silent=True) or {}).get("method") or domain_data.get("verification_method") or "auto"

    log_event("DOMAIN_VERIFICATION_ATTEMPT", "INFO", "DOMAIN_MGR", f"Tentative de vérification ({method}) sur '{domain_name}'")
    result = verify_domain_ownership(domain_name, token, method=method)

    if result.get("success"):
        mark_domain_as_verified(domain_name, result.get("method", method))
        log_event("DOMAIN_VERIFIED", "INFO", "DOMAIN_MGR", f"Propriété de '{domain_name}' confirmée avec succès via {result.get('method')}.")
        return jsonify({
            "success": True,
            "message": result.get("message", "Domaine vérifié avec succès ! Les audits sont désormais autorisés."),
            "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    else:
        log_event("DOMAIN_VERIFICATION_FAILED", "WARN", "DOMAIN_MGR", f"Échec de validation sur '{domain_name}': {result.get('error')}")
        return jsonify({
            "success": False,
            "error": result.get("error", "Échec de vérification du domaine. Vérifiez la configuration DNS ou le fichier HTTP challenge.")
        }), 400


@bp.route("/api/domains/<int:domain_id>", methods=["DELETE"])
def remove_domain_endpoint(domain_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT domain FROM verified_domains WHERE id = ?", (domain_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Domaine introuvable"}), 404

    domain_name = row["domain"]
    delete_domain_record(domain_id)
    log_event("DOMAIN_REVOKED", "WARN", "DOMAIN_MGR", f"Autorisation d'audit révoquée pour le domaine '{domain_name}'.")
    return jsonify({"success": True, "message": f"Domaine {domain_name} supprimé avec succès."})


# --- scheduled audits ---

@bp.route("/api/schedules", methods=["GET"])
def get_schedules():
    return jsonify({"schedules": list_scheduled_audits()})


@bp.route("/api/schedules", methods=["POST"])
def create_schedule():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    target_url = (data.get("target_url") or "").strip()
    frequency = data.get("frequency", "weekly")

    if not target_url:
        return jsonify({"error": "L'URL cible est requise"}), 400

    # Ensure target domain is authorized
    parsed = urllib.parse.urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    from .database import is_domain_authorized
    if not is_domain_authorized(hostname):
        return jsonify({"error": f"Le domaine '{hostname}' n'a pas été préalablement vérifié."}), 400

    sched_id = add_scheduled_audit(hostname, target_url, frequency)
    log_event("SCHEDULE_CREATED", "INFO", "SCHEDULER", f"Surveillance planifiée créée pour {target_url} (fréquence: {frequency}).")
    return jsonify({"success": True, "schedule_id": sched_id, "message": f"Surveillance {frequency} activée pour {target_url}."})


@bp.route("/api/schedules/<int:audit_id>/toggle", methods=["POST"])
def toggle_schedule(audit_id):
    data = request.get_json(silent=True) or {}
    is_active = 1 if data.get("is_active", True) else 0
    toggle_scheduled_audit(audit_id, is_active)
    state_str = "activée" if is_active else "mise en pause"
    log_event("SCHEDULE_TOGGLED", "INFO", "SCHEDULER", f"Surveillance #{audit_id} {state_str}.")
    return jsonify({"success": True, "is_active": is_active})


@bp.route("/api/schedules/<int:audit_id>", methods=["DELETE"])
def remove_schedule(audit_id):
    delete_scheduled_audit(audit_id)
    log_event("SCHEDULE_DELETED", "INFO", "SCHEDULER", f"Surveillance #{audit_id} supprimée.")
    return jsonify({"success": True})


# --- SOC overview & metrics ---

@bp.route("/api/overview")
def get_overview():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as total_scans FROM scans")
    total_scans = c.fetchone()["total_scans"]
    c.execute("SELECT SUM(critical_count) as crit, SUM(high_count) as hi, SUM(medium_count) as med, SUM(low_count) as lo FROM scans")
    row = c.fetchone()
    vuln_stats = {"critical": row["crit"] or 0, "high": row["hi"] or 0, "medium": row["med"] or 0, "low": row["lo"] or 0}
    total_vulns = sum(vuln_stats.values())
    c.execute("SELECT COUNT(*) as total_sims FROM simulations_history")
    total_sims = c.fetchone()["total_sims"]
    c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10")
    recent_logs = [dict(r) for r in c.fetchall()]
    c.execute("SELECT * FROM simulations_history ORDER BY id DESC LIMIT 5")
    recent_sims = [dict(r) for r in c.fetchall()]
    conn.close()

    if total_vulns == 0:
        overall_risk, risk_color, posture_score = "FAIBLE", "#10b981", 95
    elif vuln_stats["critical"] > 0:
        overall_risk, risk_color, posture_score = "CRITIQUE", "#ef4444", 35
    elif vuln_stats["high"] > 0:
        overall_risk, risk_color, posture_score = "ÉLEVÉ", "#f97316", 55
    else:
        overall_risk, risk_color, posture_score = "MODÉRÉ", "#eab308", 75

    return jsonify({
        "metrics": {"total_scans": total_scans, "total_vulnerabilities": total_vulns, "total_simulations": total_sims,
                    "overall_risk": overall_risk, "risk_color": risk_color, "posture_score": posture_score},
        "vuln_distribution": vuln_stats,
        "lab_status": {"mode": LAB_STATE["mode"], "waf_enabled": LAB_STATE["waf_enabled"], "target": lab_url(),
                       "is_authorized": True, "last_reset": LAB_STATE["last_reset"]},
        "recent_logs": recent_logs,
        "recent_simulations": recent_sims,
    })


# --- security scanner ---

@bp.route("/api/scan", methods=["POST"])
def run_scan():
    req_json = request.get_json(silent=True) or {}
    target_url = (req_json.get("target_url") or "").strip()
    user_b_headers = req_json.get("user_b_headers")
    categories = req_json.get("categories")  # optional list of category keys; None (not sent) = run everything

    if not target_url:
        return jsonify({"error": "L'URL cible est requise"}), 400
    log_event("SCAN_INITIATED", "INFO", "SCANNER_MODULE", f"Démarrage de l'analyse défensive sur {target_url}")
    res = scan_target(target_url, auth_headers_user_b=user_b_headers, categories=categories)
    if not res.get("success"):
        log_event("SCAN_REJECTED", "WARN", "POLICY_MGR", f"Analyse refusée sur {target_url}: {res.get('error')}")
        return jsonify(res), 400
    conn = get_connection()
    c = conn.cursor()
    c.execute("""INSERT INTO scans (target_url, timestamp, risk_score, grade, critical_count, high_count, medium_count,
                 low_count, findings_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
              (res["target_url"], res["timestamp"], res["risk_score"], res["grade"], res["counts"]["critical"],
               res["counts"]["high"], res["counts"]["medium"], res["counts"]["low"], json.dumps(res["findings"])))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    log_event("SCAN_COMPLETED", "INFO", "SCANNER_MODULE",
              f"Analyse #{scan_id} terminée. Score: {res['risk_score']}/100 (Grade {res['grade']})")
    res["id"] = scan_id
    return jsonify(res)


@bp.route("/api/scans")
def list_scans():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, target_url, timestamp, risk_score, grade, critical_count, high_count, medium_count, low_count FROM scans ORDER BY id DESC")
    scans = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"scans": scans})


def _scan(scan_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["findings"] = json.loads(d["findings_json"])
    return d


@bp.route("/api/scans/<int:scan_id>")
def get_scan_details(scan_id):
    d = _scan(scan_id)
    return jsonify(d) if d else (jsonify({"error": "Rapport d'analyse introuvable"}), 404)


@bp.route("/api/scans/<int:scan_id>/patch")
def get_scan_patch(scan_id):
    d = _scan(scan_id)
    if not d:
        return jsonify({"error": "Rapport introuvable"}), 404
    from .patch_generator import generate_nginx_security_conf, generate_apache_htaccess, generate_code_remediation_bundle
    nginx_conf = generate_nginx_security_conf(d["target_url"], d["findings"])
    apache_conf = generate_apache_htaccess(d["findings"])
    code_patches = generate_code_remediation_bundle(d["findings"])
    return jsonify({
        "scan_id": scan_id,
        "target_url": d["target_url"],
        "nginx_conf": nginx_conf,
        "apache_htaccess": apache_conf,
        "code_patches": code_patches["patches"]
    })


@bp.route("/api/scans/<int:scan_id>/report")
def view_report_html(scan_id):
    d = _scan(scan_id)
    if not d:
        return ("Rapport introuvable", 404)
    from .patch_generator import generate_nginx_security_conf, generate_code_remediation_bundle
    nginx_conf = generate_nginx_security_conf(d["target_url"], d["findings"])
    code_patches = generate_code_remediation_bundle(d["findings"])
    return render_template("security/report.html", scan=d, nginx_patch=nginx_conf, code_patches=code_patches["patches"])


# --- attack simulations & lab ---

@bp.route("/api/simulations/scenarios")
def get_scenarios():
    return jsonify({"scenarios": SCENARIOS, "current_mode": LAB_STATE["mode"]})


@bp.route("/api/simulations/run", methods=["POST"])
def run_simulation():
    data = request.get_json(silent=True) or {}
    vuln_type, payload = data.get("vuln_type"), (data.get("payload") or "").strip()
    if not vuln_type or not payload:
        return jsonify({"error": "Paramètres vuln_type et payload obligatoires."}), 400
    return jsonify(execute_simulation(vuln_type, payload, user_mode=data.get("mode")))


@bp.route("/api/lab/toggle-mode", methods=["POST"])
def toggle_lab_mode():
    target_mode = (request.get_json(silent=True) or {}).get("mode")
    if target_mode in ("VULNERABLE", "SECURED"):
        LAB_STATE["mode"] = target_mode
    else:
        LAB_STATE["mode"] = "SECURED" if LAB_STATE["mode"] == "VULNERABLE" else "VULNERABLE"
    log_event("LAB_MODE_CHANGED", "WARN", "LAB_CONTROL", f"Niveau de protection du laboratoire basculé vers {LAB_STATE['mode']}")
    return jsonify({"mode": LAB_STATE["mode"]})


@bp.route("/api/lab/reset", methods=["POST"])
def reset_lab():
    seed_lab_data()
    LAB_STATE["last_reset"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_event("LAB_RESET", "INFO", "LAB_CONTROL", "Base de données du laboratoire réinitialisée avec les fixtures de test.")
    return jsonify({"success": True, "message": "Laboratoire réinitialisé avec succès.", "timestamp": LAB_STATE["last_reset"]})


# --- CI/CD Pipeline Security Gate & API Keys ---

@bp.route("/api/ci/scan", methods=["POST"])
def ci_scan_gate():
    # Authenticate via X-API-Key or Bearer token
    api_key = request.headers.get("X-API-Key") or ""
    if not api_key:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            api_key = auth[7:].strip()

    if not validate_security_api_key(api_key):
        return jsonify({
            "status": "FAILED",
            "exit_code": 2,
            "error": "Authentification requise. Clé d'API CyberLab invalide ou manquante dans l'en-tête X-API-Key."
        }), 401

    data = request.get_json(silent=True) or {}
    target_url = (data.get("target_url") or "").strip()
    min_score = int(data.get("min_score", 75))
    fail_on_critical = bool(data.get("fail_on_critical", True))

    if not target_url:
        return jsonify({"status": "FAILED", "exit_code": 2, "error": "target_url est requis"}), 400

    log_event("CI_SCAN_TRIGGERED", "INFO", "CI_CD_GATE", f"Pipeline CI/CD a déclenché un scan sur {target_url}")
    res = scan_target(target_url)

    if not res.get("success"):
        return jsonify({
            "status": "FAILED",
            "exit_code": 2,
            "error": res.get("error", "Scan échoué")
        }), 400

    # Save to scans database
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO scans (target_url, timestamp, risk_score, grade, critical_count, high_count, medium_count, low_count, findings_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        res["target_url"], res["timestamp"], res["risk_score"], res["grade"],
        res["counts"]["critical"], res["counts"]["high"], res["counts"]["medium"],
        res["counts"]["low"], json.dumps(res["findings"])
    ))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()

    score = res["risk_score"]
    criticals = res["counts"]["critical"]
    report_url = request.host_url.rstrip("/") + BASE + f"/api/scans/{scan_id}/report"

    # Evaluate Security Gate Pass/Fail
    failed_reasons = []
    if fail_on_critical and criticals > 0:
        failed_reasons.append(f"{criticals} vulnérabilité(s) CRITIQUE(S) détectée(s)")
    if score < min_score:
        failed_reasons.append(f"Score de posture {score}/100 inférieur au seuil exigé ({min_score}/100)")

    if failed_reasons:
        msg = f"❌ Security Gate Failed: {', '.join(failed_reasons)}. Déploiement bloqué."
        log_event("CI_GATE_BLOCKED", "WARN", "CI_CD_GATE", f"Pipeline CI/CD bloqué pour {target_url} : {msg}")
        return jsonify({
            "status": "FAILED",
            "exit_code": 1,
            "message": msg,
            "score": score,
            "grade": res["grade"],
            "counts": res["counts"],
            "scan_id": scan_id,
            "report_url": report_url
        }), 422
    else:
        msg = f"✅ Security Gate Passed: Score {score}/100 >= {min_score} (0 critique). Déploiement autorisé."
        log_event("CI_GATE_PASSED", "INFO", "CI_CD_GATE", f"Pipeline CI/CD validé pour {target_url}")
        return jsonify({
            "status": "PASSED",
            "exit_code": 0,
            "message": msg,
            "score": score,
            "grade": res["grade"],
            "counts": res["counts"],
            "scan_id": scan_id,
            "report_url": report_url
        }), 200


@bp.route("/api/ci/keys", methods=["GET"])
def get_ci_keys():
    return jsonify({"keys": list_security_api_keys()})


@bp.route("/api/ci/keys", methods=["POST"])
def generate_ci_key():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "CI/CD Token").strip()
    key_data = create_security_api_key(name)
    log_event("API_KEY_CREATED", "INFO", "CI_CD_GATE", f"Nouvelle clé d'API créée pour : {name}")
    return jsonify({"success": True, "key": key_data})


@bp.route("/api/ci/keys/<int:key_id>", methods=["DELETE"])
def revoke_ci_key(key_id):
    revoke_security_api_key(key_id)
    log_event("API_KEY_REVOKED", "WARN", "CI_CD_GATE", f"Clé d'API #{key_id} révoquée.")
    return jsonify({"success": True})


@bp.route("/api/ci/snippets")
def get_ci_snippets():
    target = request.args.get("target") or "https://app.monentreprise.com"
    base_url = request.host_url.rstrip("/") + BASE
    return jsonify({
        "github_actions": generate_github_actions_workflow(target, base_url),
        "gitlab_ci": generate_gitlab_ci_yaml(target, base_url)
    })


# --- audit log stream ---

@bp.route("/api/logs")
def get_logs():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50")
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"logs": logs})


# --- learning center ---

@bp.route("/api/learning/modules")
def get_learning_modules():
    from .learning import MODULES
    return jsonify({"modules": MODULES})


# =========================================================================
# --- ESPACE ADMINISTRATEUR PRIVÉ — AUDITS AVANCÉS DU PROPRIÉTAIRE ---
# =========================================================================

def admin_owner_required(view):
    """
    Strict security gate: restricts access strictly to the SaaS owner/administrator.
    Validates the active session established via admin.py (session['admin']).
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            if request.path.startswith(f"{BASE}/api/"):
                return jsonify({
                    "error": "Accès refusé. Authentification administrateur SaaS requise.",
                    "login_required": True,
                    "auth_url": "/admin/login"
                }), 401
            return redirect(f"/admin/login?next={request.path}")
        return view(*args, **kwargs)
    return wrapped


@bp.route("/admin-space")
@admin_owner_required
def admin_space_page():
    """Renders the SaaS owner's dedicated private security console."""
    admin_user = session.get("admin")
    return render_template("security/admin_space.html", admin_user=admin_user, lab_url=lab_url())


@bp.route("/api/admin/domains", methods=["GET"])
@admin_owner_required
def get_admin_domains():
    """Lists private domains registered by the SaaS owner."""
    return jsonify({"domains": list_admin_private_domains()})


@bp.route("/api/admin/domains", methods=["POST"])
@admin_owner_required
def add_admin_domain():
    """Registers a new private domain for the SaaS owner with ownership challenge token."""
    data = request.get_json(silent=True) or {}
    raw_domain = data.get("domain", "")
    method = data.get("verification_method", "dns_txt")
    notes = data.get("notes", "")
    clean = normalize_domain(raw_domain)

    if not clean or "." not in clean:
        return jsonify({"error": "Nom de domaine invalide (ex: mon-app-perso.com)."}), 400

    token = generate_challenge_token()
    rec = add_admin_private_domain(clean, token, method=method, notes=notes)
    log_event("ADMIN_DOMAIN_ADDED", "INFO", "ADMIN_SPACE", f"Domaine privé ajouté par l'administrateur : {clean}")
    return jsonify({"success": True, "domain": rec})


@bp.route("/api/admin/domains/<int:domain_id>/verify", methods=["POST"])
@admin_owner_required
def verify_admin_domain(domain_id):
    """Verifies DNS TXT or HTTP well-known challenge for an admin private domain."""
    rec = get_admin_private_domain(domain_id)
    if not rec:
        return jsonify({"error": "Domaine privé introuvable."}), 404

    is_verified, msg = verify_domain_ownership(
        rec["domain"],
        rec["verification_token"],
        rec["verification_method"]
    )

    if is_verified:
        verify_admin_private_domain(domain_id)
        log_event("ADMIN_DOMAIN_VERIFIED", "INFO", "ADMIN_SPACE", f"Domaine privé vérifié avec succès : {rec['domain']}")
        return jsonify({"success": True, "message": msg, "verified": True})
    else:
        return jsonify({"success": False, "message": msg, "verified": False}), 400


@bp.route("/api/admin/domains/<int:domain_id>/config", methods=["POST"])
@admin_owner_required
def update_admin_domain_config(domain_id):
    """Updates custom headers and notes for authenticated scans on a private domain."""
    rec = get_admin_private_domain(domain_id)
    if not rec:
        return jsonify({"error": "Domaine privé introuvable."}), 404

    data = request.get_json(silent=True) or {}
    custom_headers = data.get("custom_headers", {})
    notes = data.get("notes", "")

    headers_json = json.dumps(custom_headers) if isinstance(custom_headers, dict) else "{}"
    update_admin_private_domain_config(domain_id, headers_json, str(notes))
    log_event("ADMIN_DOMAIN_CONFIG_UPDATED", "INFO", "ADMIN_SPACE", f"Configuration mise à jour pour le domaine privé : {rec['domain']}")
    return jsonify({"success": True})


@bp.route("/api/admin/domains/<int:domain_id>", methods=["DELETE"])
@admin_owner_required
def delete_admin_domain(domain_id):
    """Deletes an admin private domain."""
    delete_admin_private_domain(domain_id)
    log_event("ADMIN_DOMAIN_DELETED", "WARN", "ADMIN_SPACE", f"Domaine privé #{domain_id} supprimé.")
    return jsonify({"success": True})


@bp.route("/api/admin/scan", methods=["POST"])
@admin_owner_required
def run_admin_private_scan():
    """
    Executes an in-depth security audit on an admin private domain.
    Includes:
    - Custom authentication headers/cookies support.
    - Deep crawl surface.
    - Full DAST/SAST/SCA/CVE checks.
    - Advanced Non-Destructive Differential SQLi audit.
    - Guaranteed zero exfiltration and zero data destruction.
    """
    data = request.get_json(silent=True) or {}
    target_url = (data.get("target_url") or "").strip()
    custom_headers = data.get("custom_headers", {})
    auth_cookie = (data.get("auth_cookie") or "").strip()
    include_advanced_sqli = bool(data.get("include_advanced_sqli", True))

    if not target_url:
        return jsonify({"error": "L'URL cible est requise."}), 400

    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(":")[0].lower()

    # Scope authorization: must be an admin verified private domain or educational lab host
    if not is_admin_private_domain_authorized(domain):
        return jsonify({
            "error": f"Le domaine '{domain}' n'est pas encore vérifié dans votre espace administrateur privé. Veuillez d'abord valider son enregistrement DNS TXT."
        }), 403

    log_event("ADMIN_SCAN_STARTED", "INFO", "ADMIN_SPACE", f"Audit approfondi lancé par l'administrateur sur {target_url}")

    # Prepare custom session with admin headers/cookies
    import requests
    admin_session = requests.Session()
    admin_session.headers.update({
        "User-Agent": "CyberLab-Admin-DeepAuditor/2.4 (Security Research Engine)"
    })
    if isinstance(custom_headers, dict):
        for h_k, h_v in custom_headers.items():
            if h_k and h_v:
                admin_session.headers[str(h_k)] = str(h_v)

    if auth_cookie:
        admin_session.headers["Cookie"] = auth_cookie

    # 1. Run baseline target scan
    scan_result = scan_target(target_url)
    if not scan_result.get("success"):
        return jsonify(scan_result), 400

    # 2. If advanced SQLi check requested: run differential non-destructive tests
    if include_advanced_sqli:
        try:
            # Crawl surface to gather forms & parameters
            r = admin_session.get(target_url, timeout=5)
            crawl_data = deep_crawl_surface(admin_session, target_url, r.text, max_pages=6)
            adv_sqli_findings = audit_sqli_advanced_differential(
                admin_session,
                crawl_data.get("forms", []),
                crawl_data.get("query_targets", [])
            )
            if adv_sqli_findings:
                # Merge findings and recalculate score
                existing_ids = {f["id"] for f in scan_result["findings"]}
                for f in adv_sqli_findings:
                    if f["id"] not in existing_ids:
                        scan_result["findings"].append(f)

                # Re-compute counts and score
                crit = sum(1 for f in scan_result["findings"] if f["severity"] == "CRITICAL")
                hi = sum(1 for f in scan_result["findings"] if f["severity"] == "HIGH")
                med = sum(1 for f in scan_result["findings"] if f["severity"] == "MEDIUM")
                lo = sum(1 for f in scan_result["findings"] if f["severity"] == "LOW")

                penalty = (crit * 25) + (hi * 15) + (med * 8) + (lo * 3)
                score = max(5, 100 - penalty)
                scan_result["risk_score"] = score
                scan_result["grade"] = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
                scan_result["counts"] = {"critical": crit, "high": hi, "medium": med, "low": lo}

                # Save updated scan in database
                save_scan(scan_result)

        except Exception as e:
            log_event("ADMIN_SCAN_WARN", "WARN", "ADMIN_SPACE", f"Erreur lors du module SQLi approfondi : {str(e)}")

    log_event("ADMIN_SCAN_COMPLETED", "INFO", "ADMIN_SPACE", f"Audit terminé pour {target_url}. Score : {scan_result.get('risk_score')}/100")
    return jsonify(scan_result)


@bp.route("/api/admin/scans/compare", methods=["GET"])
@admin_owner_required
def compare_admin_scans():
    """Compares two historical scans to calculate posture improvements and regressions."""
    try:
        scan_a = int(request.args.get("scan_a", 0))
        scan_b = int(request.args.get("scan_b", 0))
    except (ValueError, TypeError):
        return jsonify({"error": "Paramètres scan_a et scan_b numériques requis."}), 400

    if not scan_a or not scan_b:
        return jsonify({"error": "Veuillez spécifier deux identifiants de scans valides."}), 400

    diff = compare_scans(scan_a, scan_b)
    if not diff:
        return jsonify({"error": "Impossible de comparer les deux scans spécifiés (introuvables)."}), 404

    return jsonify(diff)


@bp.route("/api/admin/scans/history", methods=["GET"])
@admin_owner_required
def get_admin_scans_history():
    """Lists recent scans available for comparison."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT id, target_url, timestamp, risk_score, grade, critical_count, high_count, medium_count, low_count
        FROM scans
        ORDER BY id DESC
        LIMIT 40
    """)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"scans": rows})


# ==============================================================================
# PROJET SENTINEL AI — AGENT INTELLIGENT DE CYBERSÉCURITÉ
# ==============================================================================

from .sentinel import (
    SentinelAgent, AgentMessage, get_provider, guardian,
    init_sentinel_tables, get_sentinel_config, save_sentinel_config,
    list_conversations, create_conversation, get_conversation_messages,
    save_message, delete_conversation, skills_registry,
    init_asset_tables, create_project, list_projects, register_asset,
    list_assets, get_asset, grant_authorization, revoke_authorization,
    is_target_in_universal_scope, VALID_ASSET_TYPES, VALID_TEST_TYPES,
    emergency_shield, ShieldTier, init_shield_tables,
    audit_linux_server_config, audit_windows_server_config, audit_database_config,
    init_remediation_tables, create_remediation_plan, list_remediations,
    get_remediation, approve_remediation, reject_remediation,
    apply_remediation, rollback_remediation, verify_remediation_post_fix
)
from .sentinel.realtime import (
    init_realtime_tables, provision_agent_key, revoke_agent_key,
    resolve_agent_key, list_agent_keys, ingest_request_event,
    get_active_blocklist, list_incidents
)

@bp.route("/sentinel")
def sentinel_workspace():
    """Renders the Sentinel AI dedicated interactive cyber workspace."""
    config = get_sentinel_config()
    return render_template(
        "security/sentinel.html",
        lab_url=lab_url(),
        active_provider=config.get("active_provider", "mock"),
        kill_switch=guardian.is_kill_switch_active()
    )


@bp.route("/api/sentinel/config", methods=["GET", "POST"])
def sentinel_config_api():
    """Gets or updates the Multi-LLM provider configuration (BYOK)."""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        active_provider = data.get("active_provider", "mock")
        provider_id = data.get("provider_id", active_provider)
        api_key = data.get("api_key")
        model = data.get("model")
        base_url = data.get("base_url")

        save_sentinel_config(
            active_provider=active_provider,
            provider_id=provider_id,
            api_key=api_key,
            model=model,
            base_url=base_url
        )
        return jsonify({"success": True, "message": "Configuration Sentinel mise à jour."})

    cfg = get_sentinel_config()
    # Mask API keys for safe UI presentation
    masked_providers = {}
    for p_id, p_data in cfg.get("providers", {}).items():
        masked_p = dict(p_data)
        if masked_p.get("api_key"):
            key = masked_p["api_key"]
            masked_p["api_key_masked"] = key[:4] + "..." + key[-4:] if len(key) > 8 else "********"
            masked_p["has_key"] = True
            del masked_p["api_key"]
        else:
            masked_p["has_key"] = False
        masked_providers[p_id] = masked_p

    return jsonify({
        "active_provider": cfg.get("active_provider", "mock"),
        "providers": masked_providers,
        "kill_switch": guardian.is_kill_switch_active()
    })


@bp.route("/api/sentinel/conversations", methods=["GET", "POST"])
def sentinel_conversations_api():
    """Lists recent conversations or creates a new one."""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        title = data.get("title", "Nouvel audit Sentinel")
        conv_id = create_conversation(title=title)
        return jsonify({"success": True, "conversation_id": conv_id})

    return jsonify({"conversations": list_conversations()})


@bp.route("/api/sentinel/conversations/<conv_id>", methods=["GET", "DELETE"])
def sentinel_conversation_item_api(conv_id):
    """Retrieves message history or deletes a conversation."""
    if request.method == "DELETE":
        delete_conversation(conv_id)
        return jsonify({"success": True})

    messages = get_conversation_messages(conv_id)
    return jsonify({"conversation_id": conv_id, "messages": messages})


@bp.route("/api/sentinel/chat", methods=["POST"])
def sentinel_chat_api():
    """Processes a user message via the selected Multi-LLM provider & Guardian."""
    data = request.get_json(silent=True) or {}
    user_prompt = (data.get("message") or "").strip()
    conv_id = data.get("conversation_id")

    if not user_prompt:
        return jsonify({"error": "Message vide."}), 400

    if not conv_id:
        conv_id = create_conversation(title=user_prompt[:35] + "...")

    # Load provider configuration
    cfg = get_sentinel_config()
    active_p_id = data.get("provider") or cfg.get("active_provider", "mock")
    p_data = cfg.get("providers", {}).get(active_p_id, {})

    api_key = data.get("api_key") or p_data.get("api_key", "")
    model = data.get("model") or p_data.get("model", "")
    base_url = data.get("base_url") or p_data.get("base_url", "")

    # Save user message to persistent DB
    save_message(conv_id, role="user", content=user_prompt)

    # Reconstruct conversation history for LLM
    db_msgs = get_conversation_messages(conv_id)
    history: List[AgentMessage] = []
    for m in db_msgs:
        history.append(AgentMessage(
            role=m["role"],
            content=m["content"],
            tool_call_id=m.get("tool_call_id")
        ))

    # Initialize Provider & Agent
    provider = get_provider(provider_id=active_p_id, api_key=api_key, model=model, base_url=base_url)
    agent = SentinelAgent(provider=provider)

    # Process step
    try:
        res = agent.process_message(conversation_history=history)
        reply_text = res.get("reply", "")
        tools_executed = res.get("tools_executed", [])

        # Save assistant message to persistent DB
        save_message(conv_id, role="assistant", content=reply_text, tool_results=tools_executed)

        return jsonify({
            "success": True,
            "conversation_id": conv_id,
            "reply": reply_text,
            "tools_executed": tools_executed,
            "provider": active_p_id,
            "finish_reason": res.get("finish_reason")
        })
    except Exception as e:
        err_msg = f"Erreur d'exécution de Sentinel AI: {str(e)}"
        save_message(conv_id, role="assistant", content=err_msg)
        return jsonify({"error": err_msg, "conversation_id": conv_id}), 500


@bp.route("/api/sentinel/guardian/killswitch", methods=["POST"])
def sentinel_killswitch_api():
    """Toggles or triggers the Sentinel emergency kill-switch."""
    data = request.get_json(silent=True) or {}
    activate = data.get("activate", True)
    if activate:
        guardian.trigger_kill_switch()
    else:
        guardian.reset_kill_switch()

    return jsonify({
        "success": True,
        "kill_switch_active": guardian.is_kill_switch_active()
    })


# ==============================================================================
# SENTINEL — PROTECTION TEMPS RÉEL (agents installés sur des sites autorisés)
# ==============================================================================

def _authenticate_agent() -> Optional[str]:
    """Resolves the calling agent's scoped domain from its API key, or None."""
    api_key = request.headers.get("X-Sentinel-Agent-Key") or (request.get_json(silent=True) or {}).get("api_key")
    return resolve_agent_key(api_key)


@bp.route("/api/sentinel/agent/provision", methods=["POST"])
@admin_owner_required
def sentinel_agent_provision_api():
    """Issues an agent key for a domain - requires proven ownership first."""
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    result = provision_agent_key(domain)
    return jsonify(result), (200 if result.get("success") else 400)


@bp.route("/api/sentinel/agent/keys", methods=["GET"])
@admin_owner_required
def sentinel_agent_list_keys_api():
    return jsonify({"keys": list_agent_keys()})


@bp.route("/api/sentinel/agent/revoke", methods=["POST"])
@admin_owner_required
def sentinel_agent_revoke_api():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    ok = revoke_agent_key(domain)
    return jsonify({"success": ok})


@bp.route("/api/sentinel/agent/report", methods=["POST"])
def sentinel_agent_report_api():
    """Ingestion endpoint called by the installed middleware for every
    request it wants correlated centrally. Authenticated by the per-domain
    agent key - never by session cookie, since the caller is a server, not a browser."""
    domain = _authenticate_agent()
    if not domain:
        return jsonify({"error": "Clé d'agent invalide ou révoquée."}), 401

    data = request.get_json(silent=True) or {}
    directive = ingest_request_event(
        domain=domain,
        source_ip=(data.get("source_ip") or request.remote_addr or "unknown"),
        method=data.get("method", "GET"),
        path=data.get("path", ""),
        query_string=data.get("query_string", ""),
        body=data.get("body", ""),
        headers=data.get("headers", {})
    )
    return jsonify(directive)


@bp.route("/api/sentinel/agent/blocklist", methods=["GET"])
def sentinel_agent_blocklist_api():
    """Polled periodically by the installed agent to refresh its local block cache."""
    domain = _authenticate_agent()
    if not domain:
        return jsonify({"error": "Clé d'agent invalide ou révoquée."}), 401
    return jsonify({"domain": domain, "blocked_ips": get_active_blocklist(domain)})


@bp.route("/api/sentinel/incidents", methods=["GET"])
@admin_owner_required
def sentinel_incidents_api():
    domain = request.args.get("domain")
    return jsonify({"incidents": list_incidents(domain=domain)})


# --- SENTINEL SKILLS LIBRARY API ---

@bp.route("/api/sentinel/skills", methods=["GET"])
def sentinel_skills_list_api():
    """Returns the skills registry statistics (total count, categories)."""
    return jsonify(skills_registry.get_stats())


@bp.route("/api/sentinel/skills/search", methods=["GET"])
def sentinel_skills_search_api():
    """Searches the 818 cybersecurity skills by keyword query."""
    query = request.args.get("q", "")
    limit = min(int(request.args.get("limit", 10)), 50)
    results = skills_registry.search_skills(query=query, limit=limit)
    return jsonify({"results": results, "count": len(results), "query": query, "total_available": skills_registry.count()})


@bp.route("/api/sentinel/skills/<path:skill_name>", methods=["GET"])
def sentinel_skill_detail_api(skill_name):
    """Returns the full SKILL.md content for a specific security skill."""
    skill = skills_registry.get_skill(skill_name)
    if not skill:
        return jsonify({"error": f"Compétence '{skill_name}' introuvable."}), 404
    return jsonify(skill.load_full_content())


# --- UNIVERSAL ASSET & SCOPE AUTHORIZATION API ---

@bp.route("/api/sentinel/projects", methods=["GET", "POST"])
def sentinel_projects_api():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        name = data.get("name", "")
        company = data.get("company_name", "")
        desc = data.get("description", "")
        if not name or not company:
            return jsonify({"error": "Nom du projet et nom de l'entreprise obligatoires."}), 400
        proj = create_project(name=name, company_name=company, description=desc)
        return jsonify({"success": True, "project": proj})
    return jsonify({"projects": list_projects()})


@bp.route("/api/sentinel/assets", methods=["GET", "POST"])
def sentinel_assets_api():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        name = data.get("name", "")
        asset_type = data.get("asset_type", "domain")
        target = data.get("target", "")
        proj_id = data.get("project_id")
        env = data.get("environment", "production")
        meta = data.get("metadata", {})
        try:
            asset = register_asset(name=name, asset_type=asset_type, target=target, project_id=proj_id, environment=env, metadata=meta)
            return jsonify({"success": True, "asset": asset})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    proj_id = request.args.get("project_id")
    asset_type = request.args.get("asset_type")
    return jsonify({"assets": list_assets(project_id=proj_id, asset_type=asset_type)})


@bp.route("/api/sentinel/authorizations", methods=["POST"])
def sentinel_authorizations_api():
    data = request.get_json(silent=True) or {}
    asset_id = data.get("asset_id", "")
    auth_by = data.get("authorized_by", "")
    valid_from = data.get("valid_from", "")
    valid_until = data.get("valid_until", "")
    mandate_ref = data.get("mandate_ref", "")
    tests = data.get("allowed_test_types", ["dast"])
    rate_limit = int(data.get("max_rate_limit", 120))

    if not asset_id or not auth_by or not valid_from or not valid_until:
        return jsonify({"error": "asset_id, authorized_by, valid_from et valid_until sont obligatoires."}), 400

    try:
        mandate = grant_authorization(
            asset_id=asset_id,
            authorized_by=auth_by,
            valid_from=valid_from,
            valid_until=valid_until,
            mandate_ref=mandate_ref,
            allowed_test_types=tests,
            max_rate_limit=rate_limit
        )
        return jsonify({"success": True, "authorization": mandate})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/sentinel/authorizations/revoke", methods=["POST"])
def sentinel_authorizations_revoke_api():
    data = request.get_json(silent=True) or {}
    auth_id = data.get("authorization_id", "")
    reason = data.get("reason", "Révocation administrative immédiate")
    if not auth_id:
        return jsonify({"error": "authorization_id requis."}), 400
    revoked = revoke_authorization(auth_id, reason=reason)
    return jsonify({"success": revoked, "authorization_id": auth_id})


@bp.route("/api/sentinel/scope/verify", methods=["POST"])
def sentinel_scope_verify_api():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    test_type = data.get("test_type")
    is_auth, msg, ctx = is_target_in_universal_scope(target, test_type=test_type)
    return jsonify({"is_authorized": is_auth, "message": msg, "context": ctx})


# --- EMERGENCY SHIELD 4-TIER ACTIVE DEFENSE API ---

@bp.route("/api/sentinel/shield/status", methods=["GET"])
def sentinel_shield_status_api():
    """Returns the current Emergency Shield operational tier and active mitigations."""
    return jsonify(emergency_shield.get_status())


@bp.route("/api/sentinel/shield/tier", methods=["POST"])
def sentinel_shield_set_tier_api():
    """Sets the Emergency Shield operational tier (NORMAL, ALERT, DEFENSIVE, EMERGENCY)."""
    data = request.get_json(silent=True) or {}
    tier_str = (data.get("tier") or "NORMAL").upper()
    reason = data.get("reason", "Modification manuelle via l'API SOC")
    try:
        tier_enum = ShieldTier(tier_str)
        updated = emergency_shield.set_tier(tier_enum, reason, manual=True)
        return jsonify({"success": True, "shield": updated})
    except ValueError:
        return jsonify({"error": f"Palier invalide. Valeurs acceptées: {[t.value for t in ShieldTier]}"}), 400


@bp.route("/api/sentinel/shield/forensics", methods=["GET"])
def sentinel_shield_forensics_api():
    """Lists forensic evidence snapshots captured during attacks."""
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({"forensics": emergency_shield.list_forensic_evidence(limit=limit)})


@bp.route("/api/sentinel/shield/revoke_session", methods=["POST"])
def sentinel_shield_revoke_session_api():
    """Immediately revokes a compromised session token across all protected assets."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "all")
    source_ip = data.get("source_ip", "0.0.0.0")
    token = data.get("session_token", "")
    reason = data.get("reason", "Révocation d'urgence suite à détection d'attaque")
    if not token:
        return jsonify({"error": "session_token obligatoire."}), 400
    revoked = emergency_shield.revoke_session(target=target, source_ip=source_ip, session_token=token, reason=reason)
    return jsonify({"success": revoked, "revoked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})


# --- SYSTEM & DATABASE CONFIGURATION AUDIT API ---

@bp.route("/api/sentinel/audit/system", methods=["POST"])
def sentinel_audit_system_api():
    """Audits Linux or Windows server configuration for an authorized asset."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    os_family = (data.get("os_family") or "linux").lower()
    config_text = data.get("config_text")

    if not target:
        return jsonify({"error": "target est obligatoire."}), 400

    # Scope validation via Guardian
    ok, reason = guardian.validate_target(target, test_type="config_audit")
    if not ok:
        return jsonify({"error": f"Cible rejetée par le Guardian: {reason}"}), 403

    if os_family == "windows":
        res = audit_windows_server_config(target=target, config_text=config_text)
    else:
        res = audit_linux_server_config(target=target, config_text=config_text)
    return jsonify({"success": True, "result": res})


@bp.route("/api/sentinel/audit/database", methods=["POST"])
def sentinel_audit_database_api():
    """Audits database posture (PostgreSQL, MySQL, Redis, MongoDB) for an authorized asset."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    db_type = data.get("db_type", "postgres")
    config_text = data.get("config_text")

    if not target:
        return jsonify({"error": "target est obligatoire."}), 400

    ok, reason = guardian.validate_target(target, test_type="config_audit")
    if not ok:
        return jsonify({"error": f"Cible rejetée par le Guardian: {reason}"}), 403

    res = audit_database_config(db_type=db_type, target=target, config_text=config_text)
    return jsonify({"success": True, "result": res})


# --- REMEDIATION & POST-FIX COUNTER-VALIDATION API ---

@bp.route("/api/sentinel/remediations", methods=["GET"])
def sentinel_remediations_list_api():
    """Lists remediation plans filtered by target or status."""
    target = request.args.get("target")
    status = request.args.get("status")
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({"remediations": list_remediations(target=target, status=status, limit=limit)})


@bp.route("/api/sentinel/remediations/create", methods=["POST"])
def sentinel_remediations_create_api():
    """Creates a formal remediation proposal with unified diff patch."""
    data = request.get_json(silent=True) or {}
    v_type = data.get("vulnerability_type", "sqli")
    target = data.get("target", "")
    title = data.get("title")
    desc = data.get("description")
    root = data.get("root_cause")
    orig = data.get("original_code")
    fixed = data.get("fixed_code")
    diff = data.get("patch_diff")
    proj_id = data.get("project_id")
    asset_id = data.get("asset_id")

    if not target:
        return jsonify({"error": "target est obligatoire."}), 400

    plan = create_remediation_plan(
        vulnerability_type=v_type,
        target=target,
        title=title,
        description=desc,
        root_cause=root,
        patch_diff=diff,
        original_code=orig,
        fixed_code=fixed,
        project_id=proj_id,
        asset_id=asset_id
    )
    return jsonify({"success": True, "remediation": plan})


@bp.route("/api/sentinel/remediations/approve", methods=["POST"])
def sentinel_remediations_approve_api():
    """Formally approves a remediation plan (human in the loop required)."""
    data = request.get_json(silent=True) or {}
    rem_id = data.get("remediation_id", "")
    approved_by = data.get("approved_by", "Responsable Sécurité")
    if not rem_id:
        return jsonify({"error": "remediation_id est obligatoire."}), 400
    try:
        res = approve_remediation(remediation_id=rem_id, approved_by=approved_by)
        return jsonify({"success": True, "result": res})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/sentinel/remediations/reject", methods=["POST"])
def sentinel_remediations_reject_api():
    """Rejects a remediation plan."""
    data = request.get_json(silent=True) or {}
    rem_id = data.get("remediation_id", "")
    reason = data.get("reason", "Refusé par l'administrateur")
    if not rem_id:
        return jsonify({"error": "remediation_id est obligatoire."}), 400
    try:
        res = reject_remediation(remediation_id=rem_id, reason=reason)
        return jsonify({"success": True, "result": res})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/sentinel/remediations/apply", methods=["POST"])
def sentinel_remediations_apply_api():
    """Applies an approved remediation patch."""
    data = request.get_json(silent=True) or {}
    rem_id = data.get("remediation_id", "")
    if not rem_id:
        return jsonify({"error": "remediation_id est obligatoire."}), 400
    try:
        res = apply_remediation(remediation_id=rem_id)
        return jsonify({"success": True, "result": res})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/sentinel/remediations/rollback", methods=["POST"])
def sentinel_remediations_rollback_api():
    """Rolls back an applied patch using the pre-fix backup."""
    data = request.get_json(silent=True) or {}
    rem_id = data.get("remediation_id", "")
    reason = data.get("reason", "Rollback demandé suite à régression")
    if not rem_id:
        return jsonify({"error": "remediation_id est obligatoire."}), 400
    try:
        res = rollback_remediation(remediation_id=rem_id, reason=reason)
        return jsonify({"success": True, "result": res})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/sentinel/remediations/verify", methods=["POST"])
def sentinel_remediations_verify_api():
    """Executes counter-validation post-fix to prove remediation effectiveness."""
    data = request.get_json(silent=True) or {}
    rem_id = data.get("remediation_id", "")
    recheck_report = data.get("recheck_report")
    if not rem_id:
        return jsonify({"error": "remediation_id est obligatoire."}), 400
    try:
        res = verify_remediation_post_fix(remediation_id=rem_id, test_recheck_result=recheck_report)
        return jsonify({"success": True, "verification": res})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


def init_security(app):
    init_db()
    init_sentinel_tables()
    init_asset_tables()
    init_shield_tables()
    init_remediation_tables()
    init_realtime_tables()
    from .scheduler import start_background_scheduler
    start_background_scheduler(interval_seconds=60)
    app.register_blueprint(bp)
