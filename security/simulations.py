"""
simulations.py - Interactive Security Vulnerability Laboratory & Simulations
Provides hands-on pedagogical demonstrations of OWASP Top 10 vulnerabilities
executed in an isolated, controlled local environment with code-level remediation.
"""

import sqlite3
import re
import html
from datetime import datetime
from .database import get_connection, log_event

# Global state of lab security mode: "VULNERABLE" or "SECURED"
LAB_STATE = {
    "mode": "VULNERABLE",  # VULNERABLE or SECURED
    "waf_enabled": False,
    "last_reset": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

SCENARIOS = {
    "sqli": {
        "id": "sqli",
        "title": "Injection SQL (Authentication & Data Extraction)",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "description": "Exploitation d'une concaténation directe de paramètres utilisateur dans une clause SQL WHERE sans requêtes préparées.",
        "payloads": [
            {"name": "Auth Bypass classique", "value": "' OR '1'='1"},
            {"name": "Union-Based Extraction", "value": "' UNION SELECT id, username, password, email, role, salary, token FROM lab_users --"},
            {"name": "Comment Syntax Blind", "value": "admin' --"}
        ],
        "vulnerable_code": """# CODE VULNÉRABLE (Concaténation non assainie)
query = f"SELECT * FROM lab_users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)""",
        "secured_code": """# CODE SÉCURISÉ (Requête préparée / Paramétrée)
query = "SELECT * FROM lab_users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))"""
    },
    "xss": {
        "id": "xss",
        "title": "Cross-Site Scripting (XSS Réfléchi & Stocké)",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "description": "Injection de code JavaScript arbitraire exécuté dans le contexte du navigateur de la victime par manque d'encodage des sorties HTML.",
        "payloads": [
            {"name": "Session Cookie Stealer (Simulation)", "value": "<script>console.warn('XSS PROOF: Document Cookie Captured:', document.cookie);</script>"},
            {"name": "DOM Event Handler", "value": "<img src=x onerror=alert('CyberLab-XSS-Triggered')>"},
            {"name": "SVG Vector", "value": "<svg onload=alert(document.domain)>"}
        ],
        "vulnerable_code": """# CODE VULNÉRABLE (Sortie brute non échappée)
@app.route('/lab/search')
def search():
    q = request.args.get('q', '')
    return f"<h1>Résultats pour : {q}</h1>"  # Injection directe dans le DOM""",
        "secured_code": """# CODE SÉCURISÉ (Échappement contextuel des entités HTML)
from markupsafe import escape

@app.route('/lab/search')
def search():
    q = request.args.get('q', '')
    safe_q = escape(q)  # Convertit < en &lt;, etc.
    return render_template('results.html', query=safe_q)"""
    },
    "idor": {
        "id": "idor",
        "title": "Contrôle d'Accès Défaillant (IDOR - Référence Directe)",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key",
        "description": "Accès illégitime à des profils collaborateurs ou documents confidentiels en modifiant un identifiant numérique sans contrôle de rôle.",
        "payloads": [
            {"name": "Accès Fiche Salaire Direction (ID 1)", "value": "1"},
            {"name": "Accès Document Confidentiel RH (ID 3)", "value": "3"},
            {"name": "Parcours séquentiel d'ID", "value": "2"}
        ],
        "vulnerable_code": """# CODE VULNÉRABLE (Aucune validation d'appartenance / rôle)
@app.route('/lab/profile/<int:user_id>')
def get_profile(user_id):
    # L'utilisateur demande n'importe quel ID
    return db.execute("SELECT * FROM lab_users WHERE id = ?", (user_id,)).fetchone()""",
        "secured_code": """# CODE SÉCURISÉ (Vérification du contexte de session et RBAC)
@app.route('/lab/profile/<int:user_id>')
@login_required
def get_profile(user_id):
    current_user = get_session_user()
    if current_user.id != user_id and current_user.role != 'Administrator':
        abort(403, "Accès interdit : privilèges insuffisants.")
    return db.execute("SELECT * FROM lab_users WHERE id = ?", (user_id,)).fetchone()"""
    },
    "path_traversal": {
        "id": "path_traversal",
        "title": "Traversée de Répertoires (Path Traversal / LFI)",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
        "description": "Lecture arbitraire de fichiers système ou de configurations internes via la manipulation de chemins relatifs ../",
        "payloads": [
            {"name": "Lecture Fichier Secrets", "value": "../../documents/payroll_q3.csv"},
            {"name": "Accès Architecture Réseau", "value": "../network_architecture.txt"},
            {"name": "Contournement Simple", "value": "..%2f..%2fetc%2fpasswd"}
        ],
        "vulnerable_code": """# CODE VULNÉRABLE (Concaténation directe de chemin)
@app.route('/lab/download')
def download():
    filename = request.args.get('file')
    # Permet les séquences ../
    return open(f"/app/public/{filename}").read()""",
        "secured_code": """# CODE SÉCURISÉ (Canonisation et liste blanche de chemins)
from pathlib import Path
SAFE_DIR = Path("/app/public").resolve()

@app.route('/lab/download')
def download():
    filename = request.args.get('file')
    requested_path = (SAFE_DIR / filename).resolve()
    # Empêche de sortir du répertoire autorisé
    if not requested_path.is_relative_to(SAFE_DIR):
        abort(403, "Chemin de fichier illégal.")
    return send_file(requested_path)"""
    },
    "brute_force": {
        "id": "brute_force",
        "title": "Faiblesse d'Authentification (Credential Stuffing & Énumération)",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-307: Improper Restriction of Excessive Authentication Attempts",
        "description": "Absence de limitation de débit (Rate Limiting) et messages d'erreurs verbeux permettant l'énumération des comptes valides.",
        "payloads": [
            {"name": "Dictionnaire mots de passe courants", "value": "password123, 123456, admin, azerty123"},
            {"name": "Énumération d'utilisateurs", "value": "admin, jdupont, test, guest"}
        ],
        "vulnerable_code": """# CODE VULNÉRABLE (Messages d'erreurs différenciés & sans rate limit)
if not user_exists(username):
    return "Erreur : Cet utilisateur n'existe pas."  # Énumération !
if not verify_password(password):
    return "Erreur : Mot de passe incorrect."       # Brute force illimité""",
        "secured_code": """# CODE SÉCURISÉ (Rate Limiting avec Limiter & message générique)
@limiter.limit("5 per minute")
def login():
    if not check_credentials(username, password):
        return "Identifiant ou mot de passe incorrect."  # Message générique constant"""
    }
}

def execute_simulation(vuln_type, payload, user_mode=None):
    """
    Executes a pedagogical demonstration scenario in the sandbox.
    Returns telemetry, step logs, outcome, and defense comparison.
    """
    mode = user_mode if user_mode else LAB_STATE["mode"]
    conn = get_connection()
    c = conn.cursor()

    steps = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Scenario 1: SQL Injection
    if vuln_type == "sqli":
        steps.append(f"[{timestamp}] Requête soumise au endpoint de laboratoire /lab/login")
        steps.append(f"[{timestamp}] Mode de sécurité de l'application : {mode}")
        steps.append(f"[{timestamp}] Paramètre injecté : {payload}")

        if mode == "VULNERABLE":
            # Vulnerable string concatenation simulation
            sql_query = f"SELECT id, username, email, role, salary, token FROM lab_users WHERE username = '{payload}'"
            steps.append(f"[{timestamp}] Requête SQL compilée sans assainissement : {sql_query}")
            try:
                c.execute(sql_query)
                rows = [dict(r) for r in c.fetchall()]
                outcome = "VULNERABILITY_CONFIRMED"
                steps.append(f"[{timestamp}] Alerte : {len(rows)} enregistrements confidentiels extraits de la table lab_users !")
                log_event("SQLI_EXPLOITED", "HIGH", "LAB_SANDBOX", f"Simulation SQLi réussie en mode VULNERABLE avec payload '{payload}'")
                result_data = {
                    "compromised": True,
                    "records_exposed": rows,
                    "message": "Bypass d'authentification et fuite de données réussis."
                }
            except Exception as e:
                outcome = "SYNTAX_ERROR"
                steps.append(f"[{timestamp}] Erreur de syntaxe SQL détectée : {str(e)}")
                result_data = {"compromised": False, "error": str(e)}
        else:
            # Secured parameterized query simulation
            sql_query = "SELECT id, username, email, role, salary, token FROM lab_users WHERE username = ?"
            steps.append(f"[{timestamp}] Application de requête paramétrée (Prepared Statement) : {sql_query} [arg: '{payload}']")
            c.execute(sql_query, (payload,))
            rows = [dict(r) for r in c.fetchall()]
            outcome = "MITIGATED"
            steps.append(f"[{timestamp}] Défense active : Le payload est traité comme une chaîne de caractères littérale.")
            steps.append(f"[{timestamp}] Aucun contournement détecté. Résultat : 0 enregistrement non autorisé.")
            log_event("SQLI_BLOCKED", "INFO", "LAB_SANDBOX", "Tentative d'injection SQL neutralisée par requête préparée.")
            result_data = {
                "compromised": False,
                "records_exposed": rows,
                "message": "Protection active : la requête préparée a neutralisé l'injection."
            }

    # Scenario 2: XSS
    elif vuln_type == "xss":
        steps.append(f"[{timestamp}] Donnée utilisateur envoyée au composant d'affichage /lab/commentaires")
        steps.append(f"[{timestamp}] Mode de sécurité : {mode}")
        steps.append(f"[{timestamp}] Contenu injecté : {payload}")

        if mode == "VULNERABLE":
            rendered_output = payload  # Unescaped
            steps.append(f"[{timestamp}] Sortie HTML non échappée : balises <script> ou gestionnaires d'événements injectés directement.")
            steps.append(f"[{timestamp}] Exécution de code JavaScript arbitraire dans la session utilisateur.")
            outcome = "VULNERABILITY_CONFIRMED"
            log_event("XSS_TRIGGERED", "MEDIUM", "LAB_SANDBOX", f"Simulation XSS exécutée en mode VULNERABLE.")
            result_data = {
                "compromised": True,
                "raw_output": rendered_output,
                "message": "Le navigateur de la victime exécute le script malveillant."
            }
        else:
            rendered_output = html.escape(payload)  # Escaped
            steps.append(f"[{timestamp}] Filtre de sécurité actif : Encodage contextuel HTML appliqué.")
            steps.append(f"[{timestamp}] Caractères dangereux convertis : < -> &lt;, > -> &gt;, ' -> &#x27;")
            steps.append(f"[{timestamp}] Le payload est affiché comme du texte pur inoffensif.")
            outcome = "MITIGATED"
            log_event("XSS_BLOCKED", "INFO", "LAB_SANDBOX", "Tentative XSS neutralisée par échappement HTML.")
            result_data = {
                "compromised": False,
                "raw_output": rendered_output,
                "message": "Protection active : les balises ont été neutralisées."
            }

    # Scenario 3: IDOR
    elif vuln_type == "idor":
        requested_id = payload.strip()
        steps.append(f"[{timestamp}] Consultation du profil utilisateur /lab/profile/{requested_id}")
        steps.append(f"[{timestamp}] Utilisateur connecté actuel : guest (Rôle : Auditeur Stagiaire)")

        if mode == "VULNERABLE":
            c.execute("SELECT id, username, email, role, salary, token FROM lab_users WHERE id = ?", (requested_id,))
            user_found = c.fetchone()
            if not user_found:
                # Fallback to first user for educational demonstration
                c.execute("SELECT id, username, email, role, salary, token FROM lab_users ORDER BY id ASC LIMIT 1")
                user_found = c.fetchone()

            if user_found:
                user_dict = dict(user_found)
                steps.append(f"[{timestamp}] Faille IDOR : Aucune vérification de droits d'accès pour l'utilisateur guest.")
                steps.append(f"[{timestamp}] Données sensibles du compte '{user_dict['username']}' (Salaire: {user_dict['salary']}) divulguées !")
                outcome = "VULNERABILITY_CONFIRMED"
                log_event("IDOR_BREACH", "HIGH", "LAB_SANDBOX", f"Accès non autorisé au profil {requested_id} via IDOR.")
                result_data = {"compromised": True, "data": user_dict}
            else:
                outcome = "NOT_FOUND"
                result_data = {"compromised": False, "message": "ID non trouvé."}
        else:
            steps.append(f"[{timestamp}] Contrôle de sécurité RBAC (Role-Based Access Control) activé.")
            steps.append(f"[{timestamp}] Vérification : user_id demandé ({requested_id}) != session.user_id (4) et rôle != 'Administrator'.")
            steps.append(f"[{timestamp}] Action rejetée : HTTP 403 Forbidden.")
            outcome = "MITIGATED"
            log_event("IDOR_BLOCKED", "INFO", "LAB_SANDBOX", f"Accès IDOR bloqué par la politique de contrôle d'accès.")
            result_data = {"compromised": False, "message": "Accès refusé par le filtre RBAC (HTTP 403)."}

    # Scenario 4: Path Traversal
    elif vuln_type == "path_traversal":
        steps.append(f"[{timestamp}] Téléchargement demandé avec paramètre fichier : {payload}")
        if mode == "VULNERABLE":
            steps.append(f"[{timestamp}] Faille de traversée : séquence ../ acceptée sans normalisation.")
            # Search matching lab document
            c.execute("SELECT filename, title, confidentiality, content FROM lab_documents WHERE filename LIKE '%payroll%' OR filename LIKE '%network%'")
            doc = c.fetchone()
            if doc:
                doc_dict = dict(doc)
                steps.append(f"[{timestamp}] Fichier système extrait : {doc_dict['filename']} (Classification : {doc_dict['confidentiality']})")
                steps.append(f"[{timestamp}] Contenu divulgué : {doc_dict['content']}")
                outcome = "VULNERABILITY_CONFIRMED"
                log_event("TRAVERSAL_BREACH", "CRITICAL", "LAB_SANDBOX", "Fichier confidentiel extrait via traversée de répertoire.")
                result_data = {"compromised": True, "file": doc_dict}
            else:
                outcome = "NOT_FOUND"
                result_data = {"compromised": False}
        else:
            steps.append(f"[{timestamp}] Sécurité active : Contrôle de chemin canonique (Path Normalization & Whitelist).")
            steps.append(f"[{timestamp}] Détection de tentative d'échappement du dossier racine autorisée.")
            steps.append(f"[{timestamp}] Requête rejetée : Erreur 400 Invalid Path.")
            outcome = "MITIGATED"
            log_event("TRAVERSAL_BLOCKED", "INFO", "LAB_SANDBOX", "Tentative de traversée de chemin neutralisée.")
            result_data = {"compromised": False, "message": "Protection active : le chemin est vérifié avec Path.is_relative_to()."}

    else:
        return {"error": "Scénario non reconnu."}

    # Record simulation in history
    c.execute(
        "INSERT INTO simulations_history (timestamp, vuln_type, scenario_title, payload, outcome, is_mitigated, details_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp, vuln_type, SCENARIOS[vuln_type]["title"], payload, outcome, 1 if outcome == "MITIGATED" else 0, str(result_data))
    )
    conn.commit()
    conn.close()

    return {
        "success": True,
        "scenario": SCENARIOS[vuln_type],
        "mode": mode,
        "payload": payload,
        "outcome": outcome,
        "steps": steps,
        "result_data": result_data,
        "timestamp": timestamp
    }
