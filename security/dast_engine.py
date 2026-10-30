"""
dast_engine.py - Non-Destructive Active Dynamic Application Security Testing (DAST) Engine
Audits web applications for SQL Injection, XSS, Path Traversal, and Rate Limiting
using benign, non-destructive differential probes within authorized scopes.
"""

import re
import secrets
import time
import urllib.parse
from typing import List, Dict, Any, Tuple
from bs4 import BeautifulSoup
import requests

from .network_guard import validate_target_url

# Standard SGBD Error Signatures (used exclusively for passive error-based SQLi detection)
SQL_ERROR_PATTERNS = [
    ("MySQL", re.compile(r"you have an error in your sql syntax|warning: mysql_|mysql_fetch_array\(\)|check the manual that corresponds to your (mysql|mariadb) server version", re.I)),
    ("PostgreSQL", re.compile(r"postgresql query failed|syntax error at or near \"|pg_query\(\)|pg_exec\(\)", re.I)),
    ("SQLite", re.compile(r"sqlite3\.operationalerror|sqlite3::|unrecognized token:|near \"[^\"]+\": syntax error", re.I)),
    ("Microsoft SQL Server", re.compile(r"microsoft ole db provider for sql server|unclosed quotation mark after the character string|syntax error converting the varchar value", re.I)),
    ("Oracle", re.compile(r"ora-00933: sql command not properly ended|ora-01756: quoted string not properly terminated|ora-00900: invalid sql statement", re.I)),
]

# Sensitive Path Traversal Error Patterns
PATH_TRAVERSAL_ERRORS = [
    re.compile(r"open_basedir restriction in effect", re.I),
    re.compile(r"failed to open stream: no such file or directory", re.I),
    re.compile(r"java\.io\.filenotfoundexception", re.I),
    re.compile(r"directory traversal", re.I),
    re.compile(r"illegal characters in path", re.I),
]

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

API_ROUTE_PATTERN = re.compile(r"""(?:['"`])(/(?:api|v[1-9]|rest|auth|admin|users?|account)/[a-zA-Z0-9_\-/?&=]+)(?:['"`])""", re.I)
SWAGGER_PATHS = ["/swagger.json", "/openapi.json", "/api/swagger.json", "/v2/api-docs"]

def discover_api_endpoints_and_specs(session: requests.Session, base_url: str, html_content: str) -> List[str]:
    """
    Extracts API endpoints hidden inside script tags and probes standard OpenAPI/Swagger locations.
    """
    discovered = []
    base_parsed = urllib.parse.urlparse(base_url)
    origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

    # 1. Regex scan on HTML and inline scripts
    for match in API_ROUTE_PATTERN.finditer(html_content or ""):
        endpoint = match.group(1)
        full = urllib.parse.urljoin(origin, endpoint)
        if full not in discovered:
            discovered.append(full)

    # 2. Check for Swagger/OpenAPI documentation
    for sw_path in SWAGGER_PATHS:
        sw_url = urllib.parse.urljoin(origin, sw_path)
        try:
            r = session.get(sw_url, timeout=3, allow_redirects=False)
            if r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower()):
                try:
                    data = r.json()
                    paths = data.get("paths", {})
                    for p in paths.keys():
                        full = urllib.parse.urljoin(origin, p)
                        if full not in discovered:
                            discovered.append(full)
                except Exception:
                    pass
        except Exception:
            continue

    return discovered

def extract_parameters_and_forms(html_content: str, base_url: str) -> Dict[str, Any]:
    """
    Parses HTML to find interactive attack surfaces:
    - Forms with inputs (GET and POST)
    - Links with query parameters
    - Script tags for client-side code analysis
    """
    soup = BeautifulSoup(html_content or "", "lxml")
    forms = []
    query_targets = []
    scripts = []

    # 1. Parse Forms
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        target_action = urllib.parse.urljoin(base_url, action)

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inp_type = (inp.get("type") or "text").lower()
            val = inp.get("value") or "test"
            inputs.append({"name": name, "type": inp_type, "default": val})

        if inputs:
            forms.append({
                "action": target_action,
                "method": method,
                "inputs": inputs
            })

    # 2. Parse Links with query parameters & internal pages
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full_url = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(full_url)
        base_parsed = urllib.parse.urlparse(base_url)

        # Stay on the same host
        if parsed.netloc.lower() == base_parsed.netloc.lower() and parsed.query:
            params = urllib.parse.parse_qsl(parsed.query)
            if params and full_url not in query_targets:
                query_targets.append(full_url)

    # 3. Add base_url itself if it has query parameters
    base_parsed = urllib.parse.urlparse(base_url)
    if base_parsed.query and base_url not in query_targets:
        query_targets.append(base_url)

    # 4. Extract script contents for DOM XSS and API analysis
    for s in soup.find_all("script"):
        if s.string:
            scripts.append(s.string)

    return {"forms": forms, "query_targets": query_targets, "scripts": scripts}

def deep_crawl_surface(session: requests.Session, start_url: str, initial_html: str, max_pages: int = 8) -> Dict[str, Any]:
    """
    Recursively crawls same-origin links and aggregates forms and query targets across pages.
    """
    base_parsed = urllib.parse.urlparse(start_url)
    origin = f"{base_parsed.scheme}://{base_parsed.netloc}"
    start_clean = urllib.parse.urldefrag(start_url)[0]

    visited = {start_clean}
    queue = []
    
    # Extract links from initial HTML
    init_surface = extract_parameters_and_forms(initial_html, start_url)
    all_forms = list(init_surface["forms"])
    all_query_targets = list(init_surface["query_targets"])
    all_scripts = list(init_surface["scripts"])

    soup = BeautifulSoup(initial_html or "", "lxml")
    for a in soup.find_all("a", href=True):
        link = urllib.parse.urljoin(start_url, a["href"])
        link_clean = urllib.parse.urldefrag(link)[0]
        p = urllib.parse.urlparse(link_clean)
        if p.netloc.lower() == base_parsed.netloc.lower() and link_clean not in visited:
            # Exclude media, static assets, logout
            ext = p.path.split(".")[-1].lower() if "." in p.path else ""
            if ext not in ("jpg", "png", "gif", "svg", "css", "pdf", "zip") and "logout" not in p.path.lower():
                visited.add(link_clean)
                queue.append(link_clean)

    # Also include API routes discovered in scripts
    api_routes = discover_api_endpoints_and_specs(session, start_url, initial_html)
    for api_url in api_routes:
        if api_url not in all_query_targets and "?" in api_url:
            all_query_targets.append(api_url)

    # Bounded crawl loop
    while queue and len(visited) <= max_pages:
        page_url = queue.pop(0)
        try:
            r = session.get(page_url, timeout=4, allow_redirects=True)
            if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
                surf = extract_parameters_and_forms(r.text, page_url)
                all_forms.extend(surf["forms"])
                for qt in surf["query_targets"]:
                    if qt not in all_query_targets:
                        all_query_targets.append(qt)
                all_scripts.extend(surf["scripts"])
        except Exception:
            continue

    return {
        "forms": all_forms,
        "query_targets": all_query_targets,
        "scripts": all_scripts,
        "api_endpoints": api_routes,
        "pages_visited": len(visited)
    }

# ----------------- SQL INJECTION AUDIT (NON-DESTRUCTIVE) -----------------

def audit_sqli(session: requests.Session, forms: List[Dict[str, Any]], query_targets: List[str]) -> List[Dict[str, Any]]:
    """
    Tests for SQL injection vulnerabilities using benign syntax disturbance probes.
    Never alters or drops data. Only checks for syntax error reflections and boolean differential behavior.
    """
    findings = []
    tested_params = set()

    # 1. Audit Form Inputs
    for form in forms:
        action = form["action"]
        method = form["method"]

        # Baseline request
        try:
            base_data = {inp["name"]: inp["default"] for inp in form["inputs"]}
            if method == "POST":
                base_resp = session.post(action, data=base_data, timeout=5, allow_redirects=True)
            else:
                base_resp = session.get(action, params=base_data, timeout=5, allow_redirects=True)
            base_text = base_resp.text
        except Exception:
            continue

        for inp in form["inputs"]:
            param_name = inp["name"]
            key = f"{action}:{param_name}"
            if key in tested_params:
                continue
            tested_params.add(key)

            # Benign syntax test probe (unmatched single quote)
            probe_val = f"{inp['default']}'"
            probe_data = dict(base_data)
            probe_data[param_name] = probe_val

            try:
                if method == "POST":
                    probe_resp = session.post(action, data=probe_data, timeout=5, allow_redirects=True)
                else:
                    probe_resp = session.get(action, params=probe_data, timeout=5, allow_redirects=True)

                probe_text = probe_resp.text

                # Check for SGBD error patterns that were NOT in baseline
                for sgbd, pat in SQL_ERROR_PATTERNS:
                    if pat.search(probe_text) and not pat.search(base_text):
                        findings.append(_finding(
                            f"SQLI_ERROR_{param_name}",
                            f"Vulnérabilité potentielle d'Injection SQL ({sgbd}) sur '{param_name}'",
                            "CRITICAL",
                            "A03:2021-Injection (OWASP Top 10)",
                            f"Le paramètre '{param_name}' a provoqué un message d'erreur de syntaxe de base de données {sgbd} lorsqu'un guillemet simple a été injecté.",
                            f"Formulaire {method} sur {action}. Message détecté : {pat.pattern[:50]}...",
                            "Un assaillant pourrait extraire, modifier ou supprimer des données de la base de données, voire contourner l'authentification.",
                            "Utilisez impérativement des requêtes préparées avec des requêtes paramétrées (Prepared Statements / ORM) et désactivez l'affichage des erreurs détaillées en production."
                        ))
                        break
            except Exception:
                continue

    # 2. Audit URL Query Parameters
    for target_url in query_targets[:6]:
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qsl(parsed.query)
        base_clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

        try:
            base_resp = session.get(target_url, timeout=5, allow_redirects=True)
            base_text = base_resp.text
        except Exception:
            continue

        for p_name, p_val in params:
            key = f"{base_clean}:{p_name}"
            if key in tested_params:
                continue
            tested_params.add(key)

            # Test single quote probe
            probe_params = dict(params)
            probe_params[p_name] = f"{p_val}'"

            try:
                probe_resp = session.get(base_clean, params=probe_params, timeout=5, allow_redirects=True)
                probe_text = probe_resp.text

                for sgbd, pat in SQL_ERROR_PATTERNS:
                    if pat.search(probe_text) and not pat.search(base_text):
                        findings.append(_finding(
                            f"SQLI_QUERY_ERROR_{p_name}",
                            f"Injection SQL ({sgbd}) sur paramètre d'URL '{p_name}'",
                            "CRITICAL",
                            "A03:2021-Injection (OWASP Top 10)",
                            f"Le paramètre GET '{p_name}' sur {base_clean} provoque une erreur de syntaxe {sgbd} non capturée.",
                            f"Requête GET avec probe '{p_name}={probe_params[p_name]}'. Signature détectée : {sgbd}.",
                            "Accès direct non autorisé au contenu de la base de données.",
                            "Paramétrez systématiquement toutes les requêtes SQL (ex: PDO en PHP, psycopg2 en Python, PreparedStatement en Java)."
                        ))
                        break
            except Exception:
                continue

    return findings


# ----------------- ADVANCED NON-DESTRUCTIVE SQLI AUDIT (ADMIN SPACE) -----------------

FORBIDDEN_SQLI_KEYWORDS = re.compile(
    r"\b(UNION|SELECT|FROM|INFORMATION_SCHEMA|SYS\.|DATABASE|VERSION|USER|SCHEMA|DROP|DELETE|UPDATE|INSERT|TRUNCATE|ALTER|EXEC|XP_|SLEEP|BENCHMARK|INTO\s+OUTFILE|DUMP)\b",
    re.I
)

def assert_safe_sqli_probe(probe: str) -> bool:
    """Enforces strict safety guardrails: strictly forbids exfiltration, schema dumps and data alteration."""
    if FORBIDDEN_SQLI_KEYWORDS.search(probe):
        raise ValueError(f"Offensive or destructive SQL keyword prohibited: {probe}")
    return True

def audit_sqli_advanced_differential(session: requests.Session, forms: List[Dict[str, Any]], query_targets: List[str]) -> List[Dict[str, Any]]:
    """
    Deep, strictly non-destructive SQL Injection diagnostic engine for the Admin Private Space.
    
    Evaluates:
    1. Boolean-differential sensitivity (True balance vs False balance).
    2. Syntax delimiter inversion (unpaired single quote vs paired double single quote '').
    3. Structural response disparity and exposed SGBD error patterns.
    
    Strictly forbids exfiltration, dumps, schema probing and destructive operations.
    """
    findings = []
    tested = set()

    # Differential probe pairs (strictly non-destructive, non-exfiltrating)
    # Pair structure: (Probe True, Probe False, probe_description)
    DIFFERENTIAL_PAIRS = [
        # String concatenation balances
        ("' AND '1'='1", "' AND '1'='2", "Concaténation de chaînes avec condition booléenne"),
        ("1' AND '1'='1", "1' AND '1'='2", "Entier délimité avec condition booléenne"),
        # Delimiter pairing test (' errors vs '' escapes cleanly)
        ("'", "''", "Inversion de délimiteur de syntaxe (guillemet simple vs double guillemet échappé)")
    ]

    for p_true, p_false, _ in DIFFERENTIAL_PAIRS:
        assert_safe_sqli_probe(p_true)
        assert_safe_sqli_probe(p_false)

    # 1. Audit Form Inputs with Differential Probes
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        # Get baseline response
        try:
            base_data = {inp["name"]: inp.get("default", "test") for inp in inputs}
            if method == "POST":
                base_resp = session.post(action, data=base_data, timeout=5, allow_redirects=True)
            else:
                base_resp = session.get(action, params=base_data, timeout=5, allow_redirects=True)
            base_len = len(base_resp.text)
            base_code = base_resp.status_code
        except Exception:
            continue

        for inp in inputs:
            param_name = inp.get("name", "")
            if not param_name or param_name.lower() in ("csrf", "token", "_token"):
                continue

            dedup_key = f"{action}:{param_name}"
            if dedup_key in tested:
                continue
            tested.add(dedup_key)

            default_val = inp.get("default", "1")

            for probe_true_sfx, probe_false_sfx, technique in DIFFERENTIAL_PAIRS:
                probe_true = f"{default_val}{probe_true_sfx}"
                probe_false = f"{default_val}{probe_false_sfx}"

                data_true = dict(base_data)
                data_true[param_name] = probe_true

                data_false = dict(base_data)
                data_false[param_name] = probe_false

                try:
                    if method == "POST":
                        r_true = session.post(action, data=data_true, timeout=5, allow_redirects=True)
                        r_false = session.post(action, data=data_false, timeout=5, allow_redirects=True)
                    else:
                        r_true = session.get(action, params=data_true, timeout=5, allow_redirects=True)
                        r_false = session.get(action, params=data_false, timeout=5, allow_redirects=True)

                    len_t = len(r_true.text)
                    len_f = len(r_false.text)
                    code_t = r_true.status_code
                    code_f = r_false.status_code

                    # Check 1: SGBD error leakage in false/true probe
                    for sgbd, pat in SQL_ERROR_PATTERNS:
                        if pat.search(r_true.text) or pat.search(r_false.text):
                            matched = pat.search(r_true.text) or pat.search(r_false.text)
                            findings.append(_finding(
                                f"SQLI_ADV_ERROR_{param_name}",
                                f"Injection SQL confirmée par fuite d'erreur SGBD ({sgbd}) sur '{param_name}'",
                                "CRITICAL",
                                "A03:2021-Injection (OWASP Top 10)",
                                f"Le paramètre '{param_name}' déclenche des erreurs de syntaxe internes du SGBD {sgbd}. Cela prouve techniquement que la valeur utilisateur est concaténée directement dans la commande SQL sans paramétrage sécurisé.",
                                f"Méthode {method} sur {action}. Sonde injectée : '{param_name}={probe_true}'. Erreur SGBD relevée : '{matched.group(0)[:90]}'.",
                                "Risque critique de compromission de la base de données. Possibilité de contourner l'authentification et de manipuler les flux logiques applicatifs.",
                                "Remplacez impérativement la concaténation de chaînes par des requêtes préparées avec paramètres typés (ex: PDO::prepare() avec bindParam() en PHP, requêtes paramétrées SQLAlchemy/psycopg2 en Python)."
                            ))
                            break

                    # Check 2: Significant boolean response disparity
                    # If TRUE condition behaves similarly to baseline, but FALSE condition diverts significantly
                    is_code_divergent = (code_t == base_code and code_f != base_code) or (code_t != code_f and code_f in (404, 500))
                    len_delta = abs(len_t - len_f)
                    len_pct = len_delta / max(base_len, 1)

                    if (is_code_divergent or len_pct > 0.18) and len_t != len_f:
                        findings.append(_finding(
                            f"SQLI_ADV_DIFF_{param_name}",
                            f"Injection SQL confirmée par comportement différentiel sur '{param_name}'",
                            "CRITICAL",
                            "A03:2021-Injection (OWASP Top 10)",
                            f"L'application a retourné des réponses significativement divergentes lors de l'évaluation de conditions booléennes ({technique}) sur le paramètre '{param_name}'. Cela confirme que la logique SQL est directement influencée par l'entrée utilisateur.",
                            f"Action: {action}. Réponse VRAI (taille: {len_t} octets, code: {code_t}) vs Réponse FAUX (taille: {len_f} octets, code: {code_f}). Écart: {int(len_pct*100)}%.",
                            "Un attaquant peut manipuler les conditions WHERE des requêtes applicatives pour altérer les contrôles d'accès et la logique métier.",
                            "Utilisez des requêtes préparées et des déclarations paramétrées. N'insérez jamais de variables utilisateur directement dans le corps de la requête SQL."
                        ))
                        break

                except Exception:
                    continue

    # 2. Audit Query Targets (URL parameters)
    for q_url in query_targets:
        parsed = urllib.parse.urlparse(q_url)
        params = urllib.parse.parse_qsl(parsed.query)
        if not params:
            continue

        base_clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        try:
            base_r = session.get(q_url, timeout=5, allow_redirects=True)
            base_len = len(base_r.text)
            base_code = base_r.status_code
        except Exception:
            continue

        for p_name, p_val in params:
            dedup_key = f"{base_clean}:{p_name}"
            if dedup_key in tested:
                continue
            tested.add(dedup_key)

            for probe_true_sfx, probe_false_sfx, technique in DIFFERENTIAL_PAIRS:
                probe_true = f"{p_val}{probe_true_sfx}"
                probe_false = f"{p_val}{probe_false_sfx}"

                dict_t = dict(params)
                dict_t[p_name] = probe_true
                url_t = f"{base_clean}?{urllib.parse.urlencode(dict_t)}"

                dict_f = dict(params)
                dict_f[p_name] = probe_false
                url_f = f"{base_clean}?{urllib.parse.urlencode(dict_f)}"

                try:
                    r_t = session.get(url_t, timeout=5, allow_redirects=True)
                    r_f = session.get(url_f, timeout=5, allow_redirects=True)

                    len_t = len(r_t.text)
                    len_f = len(r_f.text)
                    code_t = r_t.status_code
                    code_f = r_f.status_code

                    # Check SGBD errors
                    for sgbd, pat in SQL_ERROR_PATTERNS:
                        if pat.search(r_t.text) or pat.search(r_f.text):
                            matched = pat.search(r_t.text) or pat.search(r_f.text)
                            findings.append(_finding(
                                f"SQLI_ADV_URL_ERROR_{p_name}",
                                f"Injection SQL confirmée dans le paramètre d'URL '{p_name}' ({sgbd})",
                                "CRITICAL",
                                "A03:2021-Injection (OWASP Top 10)",
                                f"L'injection d'une sonde de syntaxe sur le paramètre d'URL '{p_name}' a exposé un message d'erreur du SGBD {sgbd}.",
                                f"URL: {base_clean}. Sonde: '{p_name}={probe_true}'. Erreur: '{matched.group(0)[:90]}'.",
                                "Compromission de la confidentialité et de l'intégrité de la base de données.",
                                "Passez par un ORM ou des requêtes préparées avec typage strict des identifiants (ex: validation que l'ID est bien un entier valide avant exécution)."
                            ))
                            break

                    len_delta = abs(len_t - len_f)
                    len_pct = len_delta / max(base_len, 1)
                    if (code_t != code_f or len_pct > 0.18) and len_t != len_f:
                        findings.append(_finding(
                            f"SQLI_ADV_URL_DIFF_{p_name}",
                            f"Injection SQL différentielle confirmée sur l'URL pour '{p_name}'",
                            "CRITICAL",
                            "A03:2021-Injection (OWASP Top 10)",
                            f"Divergence de réponse mesurée lors du test différentiel booléen ({technique}) sur le paramètre d'URL '{p_name}'.",
                            f"URL: {base_clean}. Vrai ({len_t} octets, code {code_t}) vs Faux ({len_f} octets, code {code_f}). Écart: {int(len_pct*100)}%.",
                            "Possibilité de manipuler la condition de filtrage SQL à distance.",
                            "Validez et assainissez systématiquement les paramètres d'URL ; utilisez des requêtes préparées paramétrées."
                        ))
                        break

                except Exception:
                    continue

    return findings

# ----------------- CROSS-SITE SCRIPTING (XSS) AUDIT -----------------

def audit_xss(session: requests.Session, base_url: str, forms: List[Dict[str, Any]],
              query_targets: List[str], csp_header: str = "") -> List[Dict[str, Any]]:
    """
    Audits for Cross-Site Scripting (Reflected & DOM) using unique benign markers.
    Never sends weaponized exploit payloads.
    Verifies if characters <, >, ", ' are sanitized or reflected raw in DOM contexts.
    """
    findings = []
    has_strict_csp = bool(csp_header and ("script-src" in csp_header.lower() and "'unsafe-inline'" not in csp_header.lower()))

    # Random benign canary to avoid false positives with static page content
    canary_id = secrets.token_hex(4)
    probe_tag = f"scprobe{canary_id}"
    probe_html = f"<{probe_tag}>"
    probe_attr = f'"{probe_tag}\''

    # 1. Audit Form Inputs
    for form in forms:
        action = form["action"]
        method = form["method"]

        base_data = {inp["name"]: inp["default"] for inp in form["inputs"]}

        for inp in form["inputs"]:
            if inp["type"] in ("hidden", "submit", "button"):
                continue

            param_name = inp["name"]
            probe_data = dict(base_data)
            probe_data[param_name] = probe_html

            try:
                if method == "POST":
                    resp = session.post(action, data=probe_data, timeout=5, allow_redirects=True)
                else:
                    resp = session.get(action, params=probe_data, timeout=5, allow_redirects=True)

                resp_body = resp.text

                # Check if the unescaped raw tag is reflected in response
                if probe_html.lower() in resp_body.lower():
                    severity = "MEDIUM" if has_strict_csp else "HIGH"
                    findings.append(_finding(
                        f"XSS_REFLECTED_{param_name}",
                        f"Cross-Site Scripting (XSS Réfléchi) sur le champ '{param_name}'",
                        severity,
                        "A03:2021-Injection (OWASP Top 10)",
                        f"Le paramètre '{param_name}' accepte et réinjecte des balises HTML brutes dans la page sans encodage contextuel.",
                        f"Envoi du marqueur inoffensif '{probe_html}'. Le marqueur a été retourné brut dans la réponse HTTP sans échappement en &lt;{probe_tag}&gt;.",
                        "Un attaquant pourrait injecter du code JavaScript malveillant pour voler les sessions, détourner des comptes ou falsifier l'affichage du site.",
                        "Encodez systématiquement toutes les données utilisateur lors de leur affichage dans le HTML (HTML entity encoding, ex: htmlspecialchars() en PHP, c:out en JSP, ou moteurs de template avec auto-escape comme Jinja2/Blade/React)."
                    ))
            except Exception:
                continue

    # 2. Audit URL Query Parameters
    for target_url in query_targets[:6]:
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qsl(parsed.query)
        base_clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

        for p_name, _ in params:
            probe_params = dict(params)
            probe_params[p_name] = probe_html

            try:
                resp = session.get(base_clean, params=probe_params, timeout=5, allow_redirects=True)
                if probe_html.lower() in resp.text.lower():
                    severity = "MEDIUM" if has_strict_csp else "HIGH"
                    findings.append(_finding(
                        f"XSS_QUERY_{p_name}",
                        f"Cross-Site Scripting (XSS Réfléchi) sur paramètre d'URL '{p_name}'",
                        severity,
                        "A03:2021-Injection (OWASP Top 10)",
                        f"La valeur du paramètre GET '{p_name}' est réfléchie dans le corps de la réponse sans encodage suffisant.",
                        f"URL testée: {base_clean}?{p_name}={probe_html}. Marqueur retrouvé brut dans le document.",
                        "Risque d'exécution de script dans le contexte du navigateur des utilisateurs cliquant sur un lien piégé.",
                        "Échappez les variables issues de l'URL avant leur réaffichage dans le DOM et déployez un en-tête Content-Security-Policy (CSP) robuste."
                    ))
            except Exception:
                continue

    return findings

# ----------------- PATH TRAVERSAL AUDIT (NON-DESTRUCTIVE) -----------------

def audit_path_traversal(session: requests.Session, query_targets: List[str]) -> List[Dict[str, Any]]:
    """
    Audits parameters handling filenames/paths for directory traversal weaknesses.
    Sends benign test paths looking for traversal error disclosures.
    """
    findings = []
    traversal_param_names = {"file", "path", "filename", "doc", "page", "template", "view", "download", "load", "include"}
    tested = set()

    for target_url in query_targets[:8]:
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qsl(parsed.query)
        base_clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

        for p_name, p_val in params:
            if p_name.lower() not in traversal_param_names and not any(p_name.lower().endswith(x) for x in ("file", "path", "doc")):
                continue

            key = f"{base_clean}:{p_name}"
            if key in tested:
                continue
            tested.add(key)

            # Probe with relative benign non-existent file path
            probe_name = f"sc_probe_{secrets.token_hex(4)}.tmp"
            probe_val = f"../../../../../../{probe_name}"
            probe_params = dict(params)
            probe_params[p_name] = probe_val

            try:
                resp = session.get(base_clean, params=probe_params, timeout=5, allow_redirects=False)
                for pat in PATH_TRAVERSAL_ERRORS:
                    if pat.search(resp.text):
                        findings.append(_finding(
                            f"PATH_TRAVERSAL_{p_name}",
                            f"Vulnérabilité potentielle de Traversée de Répertoires (Path Traversal) sur '{p_name}'",
                            "HIGH",
                            "A01:2021-Broken Access Control (OWASP Top 10)",
                            f"Le paramètre '{p_name}' semble accepter des séquences relatives ('../') et expose des messages du système de fichiers.",
                            f"Paramètre '{p_name}={probe_val}' a retourné : {pat.pattern}.",
                            "Un assaillant pourrait lire des fichiers sensibles de configuration ou du code source en dehors du répertoire web racine.",
                            "Ne pas utiliser directement des entrées utilisateur dans des fonctions de fichiers. Validez les chemins avec des listes blanches et utilisez des fonctions de canonicalisation (ex: os.path.basename, realpath)."
                        ))
                        break
            except Exception:
                continue

    return findings


# ----------------- ADVANCED NON-DESTRUCTIVE SQLI AUDIT (ADMIN SPACE) -----------------

FORBIDDEN_SQLI_KEYWORDS = re.compile(
    r"\b(UNION|SELECT|FROM|INFORMATION_SCHEMA|SYS\.|DATABASE|VERSION|USER|SCHEMA|DROP|DELETE|UPDATE|INSERT|TRUNCATE|ALTER|EXEC|XP_|SLEEP|BENCHMARK|INTO\s+OUTFILE|DUMP)\b",
    re.I
)

def assert_safe_sqli_probe(probe: str) -> bool:
    """Enforces strict safety guardrails: strictly forbids exfiltration, schema dumps and data alteration."""
    if FORBIDDEN_SQLI_KEYWORDS.search(probe):
        raise ValueError(f"Offensive or destructive SQL keyword prohibited: {probe}")
    return True

def audit_sqli_advanced_differential(session: requests.Session, forms: List[Dict[str, Any]], query_targets: List[str]) -> List[Dict[str, Any]]:
    """
    Deep, strictly non-destructive SQL Injection diagnostic engine for the Admin Private Space.
    
    Evaluates:
    1. Boolean-differential sensitivity (True balance vs False balance).
    2. Syntax delimiter inversion (unpaired single quote vs paired double single quote '').
    3. Structural response disparity and exposed SGBD error patterns.
    
    Strictly forbids exfiltration, dumps, schema probing and destructive operations.
    """
    findings = []
    tested = set()

    # Differential probe pairs (strictly non-destructive, non-exfiltrating)
    # Pair structure: (Probe True, Probe False, probe_description)
    DIFFERENTIAL_PAIRS = [
        # String concatenation balances
        ("' AND '1'='1", "' AND '1'='2", "Concaténation de chaînes avec condition booléenne"),
        ("1' AND '1'='1", "1' AND '1'='2", "Entier délimité avec condition booléenne"),
        # Delimiter pairing test (' errors vs '' escapes cleanly)
        ("'", "''", "Inversion de délimiteur de syntaxe (guillemet simple vs double guillemet échappé)")
    ]

    for p_true, p_false, _ in DIFFERENTIAL_PAIRS:
        assert_safe_sqli_probe(p_true)
        assert_safe_sqli_probe(p_false)

    # 1. Audit Form Inputs with Differential Probes
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        # Get baseline response
        try:
            base_data = {inp["name"]: inp.get("default", "test") for inp in inputs}
            if method == "POST":
                base_resp = session.post(action, data=base_data, timeout=5, allow_redirects=True)
            else:
                base_resp = session.get(action, params=base_data, timeout=5, allow_redirects=True)
            base_len = len(base_resp.text)
            base_code = base_resp.status_code
        except Exception:
            continue

        for inp in inputs:
            param_name = inp.get("name", "")
            if not param_name or param_name.lower() in ("csrf", "token", "_token"):
                continue

            dedup_key = f"{action}:{param_name}"
            if dedup_key in tested:
                continue
            tested.add(dedup_key)

            default_val = inp.get("default", "1")

            for probe_true_sfx, probe_false_sfx, technique in DIFFERENTIAL_PAIRS:
                probe_true = f"{default_val}{probe_true_sfx}"
                probe_false = f"{default_val}{probe_false_sfx}"

                data_true = dict(base_data)
                data_true[param_name] = probe_true

                data_false = dict(base_data)
                data_false[param_name] = probe_false

                try:
                    if method == "POST":
                        r_true = session.post(action, data=data_true, timeout=5, allow_redirects=True)
                        r_false = session.post(action, data=data_false, timeout=5, allow_redirects=True)
                    else:
                        r_true = session.get(action, params=data_true, timeout=5, allow_redirects=True)
                        r_false = session.get(action, params=data_false, timeout=5, allow_redirects=True)

                    len_t = len(r_true.text)
                    len_f = len(r_false.text)
                    code_t = r_true.status_code
                    code_f = r_false.status_code

                    # Check 1: SGBD error leakage in false/true probe
                    for sgbd, pat in SQL_ERROR_PATTERNS:
                        if pat.search(r_true.text) or pat.search(r_false.text):
                            matched = pat.search(r_true.text) or pat.search(r_false.text)
                            findings.append(_finding(
                                f"SQLI_ADV_ERROR_{param_name}",
                                f"Injection SQL confirmée par fuite d'erreur SGBD ({sgbd}) sur '{param_name}'",
                                "CRITICAL",
                                "A03:2021-Injection (OWASP Top 10)",
                                f"Le paramètre '{param_name}' déclenche des erreurs de syntaxe internes du SGBD {sgbd}. Cela prouve techniquement que la valeur utilisateur est concaténée directement dans la commande SQL sans paramétrage sécurisé.",
                                f"Méthode {method} sur {action}. Sonde injectée : '{param_name}={probe_true}'. Erreur SGBD relevée : '{matched.group(0)[:90]}'.",
                                "Risque critique de compromission de la base de données. Possibilité de contourner l'authentification et de manipuler les flux logiques applicatifs.",
                                "Remplacez impérativement la concaténation de chaînes par des requêtes préparées avec paramètres typés (ex: PDO::prepare() avec bindParam() en PHP, requêtes paramétrées SQLAlchemy/psycopg2 en Python)."
                            ))
                            break

                    # Check 2: Significant boolean response disparity
                    # If TRUE condition behaves similarly to baseline, but FALSE condition diverts significantly
                    is_code_divergent = (code_t == base_code and code_f != base_code) or (code_t != code_f and code_f in (404, 500))
                    len_delta = abs(len_t - len_f)
                    len_pct = len_delta / max(base_len, 1)

                    if (is_code_divergent or len_pct > 0.18) and len_t != len_f:
                        findings.append(_finding(
                            f"SQLI_ADV_DIFF_{param_name}",
                            f"Injection SQL confirmée par comportement différentiel sur '{param_name}'",
                            "CRITICAL",
                            "A03:2021-Injection (OWASP Top 10)",
                            f"L'application a retourné des réponses significativement divergentes lors de l'évaluation de conditions booléennes ({technique}) sur le paramètre '{param_name}'. Cela confirme que la logique SQL est directement influencée par l'entrée utilisateur.",
                            f"Action: {action}. Réponse VRAI (taille: {len_t} octets, code: {code_t}) vs Réponse FAUX (taille: {len_f} octets, code: {code_f}). Écart: {int(len_pct*100)}%.",
                            "Un attaquant peut manipuler les conditions WHERE des requêtes applicatives pour altérer les contrôles d'accès et la logique métier.",
                            "Utilisez des requêtes préparées et des déclarations paramétrées. N'insérez jamais de variables utilisateur directement dans le corps de la requête SQL."
                        ))
                        break

                except Exception:
                    continue

    # 2. Audit Query Targets (URL parameters)
    for q_url in query_targets:
        parsed = urllib.parse.urlparse(q_url)
        params = urllib.parse.parse_qsl(parsed.query)
        if not params:
            continue

        base_clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        try:
            base_r = session.get(q_url, timeout=5, allow_redirects=True)
            base_len = len(base_r.text)
            base_code = base_r.status_code
        except Exception:
            continue

        for p_name, p_val in params:
            dedup_key = f"{base_clean}:{p_name}"
            if dedup_key in tested:
                continue
            tested.add(dedup_key)

            for probe_true_sfx, probe_false_sfx, technique in DIFFERENTIAL_PAIRS:
                probe_true = f"{p_val}{probe_true_sfx}"
                probe_false = f"{p_val}{probe_false_sfx}"

                dict_t = dict(params)
                dict_t[p_name] = probe_true
                url_t = f"{base_clean}?{urllib.parse.urlencode(dict_t)}"

                dict_f = dict(params)
                dict_f[p_name] = probe_false
                url_f = f"{base_clean}?{urllib.parse.urlencode(dict_f)}"

                try:
                    r_t = session.get(url_t, timeout=5, allow_redirects=True)
                    r_f = session.get(url_f, timeout=5, allow_redirects=True)

                    len_t = len(r_t.text)
                    len_f = len(r_f.text)
                    code_t = r_t.status_code
                    code_f = r_f.status_code

                    # Check SGBD errors
                    for sgbd, pat in SQL_ERROR_PATTERNS:
                        if pat.search(r_t.text) or pat.search(r_f.text):
                            matched = pat.search(r_t.text) or pat.search(r_f.text)
                            findings.append(_finding(
                                f"SQLI_ADV_URL_ERROR_{p_name}",
                                f"Injection SQL confirmée dans le paramètre d'URL '{p_name}' ({sgbd})",
                                "CRITICAL",
                                "A03:2021-Injection (OWASP Top 10)",
                                f"L'injection d'une sonde de syntaxe sur le paramètre d'URL '{p_name}' a exposé un message d'erreur du SGBD {sgbd}.",
                                f"URL: {base_clean}. Sonde: '{p_name}={probe_true}'. Erreur: '{matched.group(0)[:90]}'.",
                                "Compromission de la confidentialité et de l'intégrité de la base de données.",
                                "Passez par un ORM ou des requêtes préparées avec typage strict des identifiants (ex: validation que l'ID est bien un entier valide avant exécution)."
                            ))
                            break

                    len_delta = abs(len_t - len_f)
                    len_pct = len_delta / max(base_len, 1)
                    if (code_t != code_f or len_pct > 0.18) and len_t != len_f:
                        findings.append(_finding(
                            f"SQLI_ADV_URL_DIFF_{p_name}",
                            f"Injection SQL différentielle confirmée sur l'URL pour '{p_name}'",
                            "CRITICAL",
                            "A03:2021-Injection (OWASP Top 10)",
                            f"Divergence de réponse mesurée lors du test différentiel booléen ({technique}) sur le paramètre d'URL '{p_name}'.",
                            f"URL: {base_clean}. Vrai ({len_t} octets, code {code_t}) vs Faux ({len_f} octets, code {code_f}). Écart: {int(len_pct*100)}%.",
                            "Possibilité de manipuler la condition de filtrage SQL à distance.",
                            "Validez et assainissez systématiquement les paramètres d'URL ; utilisez des requêtes préparées paramétrées."
                        ))
                        break

                except Exception:
                    continue

    return findings

# ----------------- RATE LIMITING AUDIT (NON-DESTRUCTIVE BURST) -----------------

def audit_rate_limiting(session: requests.Session, forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Evaluates authentication forms for rate limiting & brute force resistance.
    Sends a small, strictly bounded burst of 6 requests to measure throttling mechanisms.
    """
    findings = []
    auth_forms = []

    for form in forms:
        input_types = [inp["type"] for inp in form["inputs"]]
        if "password" in input_types:
            auth_forms.append(form)

    for form in auth_forms:
        action = form["action"]
        method = form["method"]
        dummy_data = {inp["name"]: "sc_audit_probe_test" for inp in form["inputs"]}

        # Measure 6 rapid successive requests
        status_codes = []
        retry_after_seen = False

        for _ in range(6):
            try:
                if method == "POST":
                    r = session.post(action, data=dummy_data, timeout=3, allow_redirects=False)
                else:
                    r = session.get(action, params=dummy_data, timeout=3, allow_redirects=False)
                status_codes.append(r.status_code)
                if "Retry-After" in r.headers:
                    retry_after_seen = True
                time.sleep(0.05)
            except Exception:
                break

        # Check if the server signaled rate limiting (HTTP 429 Too Many Requests or Retry-After)
        has_rate_limit = (429 in status_codes) or retry_after_seen
        if not has_rate_limit and len(status_codes) >= 5:
            # All 6 requests were processed without throttling
            findings.append(_finding(
                f"RATE_LIMIT_ABSENT_{secrets.token_hex(3)}",
                "Absence de Limitation de Cadence (Rate Limiting) sur formulaire d'authentification",
                "MEDIUM",
                "A07:2021-Identification and Authentication Failures (OWASP Top 10)",
                f"Le formulaire d'authentification sur {action} ne met en œuvre aucun mécanisme visible de blocage temporaire ou limitation de fréquence lors de tentatives rapprochées.",
                f"Une rafale de {len(status_codes)} requêtes successives a été acceptée sans réponse HTTP 429 ou en-tête Retry-After.",
                "Vulnérable aux attaques de type Credential Stuffing et Brute Force sur les mots de passe des utilisateurs.",
                "Implémentez une politique de limitation de cadence (ex: max 5 tentatives par minute par IP ou par compte utilisateur), un défi CAPTCHA progressif ou un verrouillage temporaire de compte."
            ))

    return findings

# ----------------- INSECURE DIRECT OBJECT REFERENCES (IDOR) AUDIT -----------------

ID_PARAM_NAMES = {"id", "user_id", "uid", "account", "profile_id", "order_id", "invoice", "doc_id", "item_id", "record"}
REST_ID_PATTERN = re.compile(r"/(users?|profiles?|orders?|accounts?|invoices?|docs?)/(\d+)", re.I)

def audit_idor(session: requests.Session, query_targets: List[str],
               auth_headers_user_b: Dict[str, str] = None) -> List[Dict[str, Any]]:
    """
    Audits for Insecure Direct Object References (IDOR / Broken Object Level Authorization).
    Detects whether sequential object IDs or direct references can be accessed without
    access control or across different tenant credentials.
    """
    findings = []
    tested = set()

    # 1. Query parameters with numerical or direct IDs
    for target_url in query_targets[:8]:
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qsl(parsed.query)
        base_clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

        for p_name, p_val in params:
            if p_name.lower() not in ID_PARAM_NAMES and not p_name.lower().endswith(("_id", "Id")):
                continue

            # Must look like an ID (integer or hex)
            if not p_val.isdigit() and len(p_val) < 4:
                continue

            key = f"{base_clean}:{p_name}"
            if key in tested:
                continue
            tested.add(key)

            try:
                base_resp = session.get(target_url, timeout=5, allow_redirects=False)
                if base_resp.status_code != 200 or len(base_resp.text) < 20:
                    continue

                # Test differential access with User B credentials if configured
                if auth_headers_user_b:
                    b_resp = session.get(target_url, headers=auth_headers_user_b, timeout=5, allow_redirects=False)
                    if b_resp.status_code == 200 and len(b_resp.text) > 20:
                        findings.append(_finding(
                            f"IDOR_CROSS_TENANT_{p_name}",
                            f"Contrôle d'accès défaillant (IDOR / BOLA) sur '{p_name}' entre locataires",
                            "CRITICAL",
                            "A01:2021-Broken Access Control (OWASP Top 10)",
                            f"La ressource '{target_url}' appartenant au compte A a pu être lue directement avec la session du compte B sans vérification d'autorisation.",
                            f"Requête rejouée avec les en-têtes du compte B : statut HTTP {b_resp.status_code} ({len(b_resp.text)} octets retournés).",
                            "Fuite massive de données personnelles ou confidentielles entre utilisateurs de la plateforme.",
                            "Validez systématiquement côté serveur que l'utilisateur authentifié possède bien les droits sur l'objet ciblé (ex: WHERE id = :id AND tenant_id = :current_user_tenant)."
                        ))
                        continue

                # Single-user test: probe adjacent ID (e.g., id + 1 or id - 1)
                if p_val.isdigit():
                    adj_id = str(int(p_val) + 1 if int(p_val) > 1 else 2)
                    adj_params = dict(params)
                    adj_params[p_name] = adj_id

                    adj_resp = session.get(base_clean, params=adj_params, timeout=5, allow_redirects=False)
                    # If adjacent ID returns 200 OK with substantial content without auth rejection
                    if adj_resp.status_code == 200 and len(adj_resp.text) > 40:
                        # Check if response reflects structured user/record data
                        is_json = "application/json" in adj_resp.headers.get("content-type", "")
                        has_record_markers = bool(re.search(r"email|salary|order|invoice|solde|nom|prenom|client", adj_resp.text, re.I))
                        if is_json or has_record_markers:
                            findings.append(_finding(
                                f"IDOR_SEQUENTIAL_{p_name}",
                                f"Risque d'IDOR sur identifiant séquentiel prévisible '{p_name}'",
                                "HIGH",
                                "A01:2021-Broken Access Control (OWASP Top 10)",
                                f"Le paramètre '{p_name}' accepte des identifiants numériques directs ({p_val} -> {adj_id}) qui retournent des données sans contrôle d'accès strict.",
                                f"L'accès à {base_clean}?{p_name}={adj_id} a retourné le code HTTP 200 ({len(adj_resp.text)} octets).",
                                "Énumération et accès non autorisé aux enregistrements d'autres utilisateurs de l'application.",
                                "Remplacez les identifiants séquentiels par des UUID v4 non prévisibles et vérifiez l'appartenance de la ressource à l'utilisateur connecté dans la requête SQL/ORM."
                            ))
            except Exception:
                continue

    return findings

# ----------------- OPEN REDIRECT AUDIT (NON-DESTRUCTIVE) -----------------

REDIRECT_PARAM_NAMES = {"redirect", "url", "next", "return", "dest", "destination", "continue", "forward", "to", "target", "out", "r", "goto", "return_url", "redirect_url"}

def audit_open_redirect(session: requests.Session, query_targets: List[str]) -> List[Dict[str, Any]]:
    """
    Audits for Open Redirect vulnerabilities.
    Sends benign test external URLs looking for unvalidated 3xx Location headers.
    """
    findings = []
    tested = set()
    test_canary = "https://example.com"

    for target_url in query_targets[:8]:
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qsl(parsed.query)
        base_clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

        for p_name, p_val in params:
            if p_name.lower() not in REDIRECT_PARAM_NAMES and not any(p_name.lower().endswith(x) for x in ("redirect", "url", "next", "return")):
                continue

            key = f"{base_clean}:{p_name}"
            if key in tested:
                continue
            tested.add(key)

            probe_params = dict(params)
            probe_params[p_name] = test_canary

            try:
                # Do not follow redirects so we can inspect the Location header
                resp = session.get(base_clean, params=probe_params, timeout=5, allow_redirects=False)
                loc = resp.headers.get("Location", "")

                if resp.status_code in (301, 302, 303, 307, 308) and (loc.startswith(test_canary) or loc.startswith("//example.com")):
                    findings.append(_finding(
                        f"OPEN_REDIRECT_{p_name}",
                        f"Vulnérabilité de Redirection Ouverte (Open Redirect) sur '{p_name}'",
                        "HIGH",
                        "A01:2021-Broken Access Control (OWASP Top 10)",
                        f"Le paramètre '{p_name}' accepte des URLs externes non vérifiées et redirige l'utilisateur arbitrairement via le statut HTTP {resp.status_code}.",
                        f"Envoi de '{p_name}={test_canary}'. En-tête Location retourné : '{loc}'.",
                        "Facilite les attaques de phishing ciblé, le vol de jetons d'authentification OAuth (via le paramètre redirect_uri) et les attaques d'usurpation.",
                        "Validez les URLs de redirection avec une liste blanche stricte de domaines autorisés ou n'autorisez que les chemins relatifs débutant par un seul slash '/' (excluant '//')."
                    ))
            except Exception:
                continue

    return findings

# ----------------- DEEP CORS CONFIGURATION AUDIT -----------------

def audit_deep_cors(session: requests.Session, base_url: str) -> List[Dict[str, Any]]:
    """
    Audits for dangerous CORS misconfigurations that allow cross-origin credential/data theft.
    Tests arbitrary origin reflection and 'Origin: null' with credentials.
    """
    findings = []
    base_parsed = urllib.parse.urlparse(base_url)
    origin_root = f"{base_parsed.scheme}://{base_parsed.netloc}"

    # Test 1: Arbitrary External Origin
    evil_origin = "https://evil-attacker.com"
    try:
        r = session.get(origin_root, headers={"Origin": evil_origin}, timeout=4, allow_redirects=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "").strip()
        acac = r.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

        if acao == evil_origin and acac == "true":
            findings.append(_finding(
                "CORS_ARBITRARY_CREDENTIALS",
                "CORS Permissif Dangereux avec Fuite d'Identifiants (Credentials Leak)",
                "CRITICAL",
                "A05:2021-Security Misconfiguration (OWASP Top 10)",
                "Le serveur reflète dynamiquement n'importe quelle origine externe dans Access-Control-Allow-Origin TOUT EN autorisant les cookies et tokens avec Access-Control-Allow-Credentials: true.",
                f"En-tête envoyé : Origin: {evil_origin} -> Réponse : ACAO: {acao}, ACAC: true.",
                "N'importe quel site web malveillant visité par un utilisateur peut exécuter des requêtes vers votre domaine et voler ses données personnelles et sessions en arrière-plan.",
                "Ne reflétez jamais l'origine arbitraire du client si les credentials sont activés. Spécifiez une liste blanche stricte de domaines autorisés (ex: vos propres applications)."
            ))
        elif acao == "*" and acac == "true":
            findings.append(_finding(
                "CORS_WILDCARD_CREDENTIALS",
                "CORS Invalide : Wildcard avec Credentials activés",
                "HIGH",
                "A05:2021-Security Misconfiguration (OWASP Top 10)",
                "L'en-tête Access-Control-Allow-Origin vaut '*' alors que les credentials sont activés, ce qui est rejeté par les navigateurs modernes et indique une erreur de configuration.",
                f"Access-Control-Allow-Origin: * avec Access-Control-Allow-Credentials: true.",
                "Dysfonctionnement des appels cross-origin et risque d'exposition d'API.",
                "Définissez une politique CORS restreinte aux seuls domaines partenaires nécessaires."
            ))
    except Exception:
        pass

    # Test 2: Null Origin Check
    try:
        r_null = session.get(origin_root, headers={"Origin": "null"}, timeout=4, allow_redirects=False)
        acao_null = r_null.headers.get("Access-Control-Allow-Origin", "").strip()
        acac_null = r_null.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

        if acao_null == "null" and acac_null == "true":
            findings.append(_finding(
                "CORS_NULL_ORIGIN_ALLOWED",
                "CORS Dangereux : Origine 'null' acceptée avec Credentials",
                "HIGH",
                "A05:2021-Security Misconfiguration (OWASP Top 10)",
                "Le serveur accepte l'origine 'null' avec credentials activés. Les iframes sandboxed ou fichiers HTML exécutés localement peuvent interroger l'API avec les droits de la session.",
                "Origin: null a été accepté avec Access-Control-Allow-Credentials: true.",
                "Contournement de la politique de même origine (Same-Origin Policy).",
                "Rejetez expressément l'origine 'null' dans votre middleware CORS."
            ))
    except Exception:
        pass

    return findings

# ----------------- DOM-BASED XSS SOURCE-TO-SINK AUDIT -----------------

DOM_SOURCES = re.compile(r"""\b(?:location\.(?:search|hash|pathname|href)|document\.(?:referrer|URL)|window\.name)\b""")
DOM_SINKS = re.compile(r"""(?:\.innerHTML|\.outerHTML|document\.write\b|eval\s*\(|setTimeout\s*\([^,]+,\s*\d+\)|dangerouslySetInnerHTML)""")

def audit_dom_xss_sources_sinks(scripts: List[str], base_url: str) -> List[Dict[str, Any]]:
    """
    Performs static taint-flow heuristic analysis on client-side JavaScript
    to detect dangerous paths between untrusted DOM Sources and execution Sinks.
    """
    findings = []
    seen = set()

    for script_code in scripts:
        if not script_code or len(script_code) < 15:
            continue

        # Look for co-occurrence of a source and a sink in the same script block
        source_match = DOM_SOURCES.search(script_code)
        sink_match = DOM_SINKS.search(script_code)

        if source_match and sink_match:
            source_txt = source_match.group(0)
            sink_txt = sink_match.group(0)
            key = f"{source_txt}:{sink_txt}"
            if key in seen:
                continue
            seen.add(key)

            # Extract sample context line
            sample_line = ""
            for line in script_code.splitlines():
                if source_txt in line or sink_txt in line:
                    sample_line = line.strip()[:100]
                    break

            findings.append(_finding(
                f"DOM_XSS_FLOW_{source_txt.replace('.', '_')}",
                f"Risque potentiel de DOM-based XSS ({source_txt} vers {sink_txt})",
                "HIGH",
                "A03:2021-Injection (OWASP Top 10)",
                f"Le code JavaScript client manipule une source non fiable ({source_txt}) et utilise un puits d'exécution DOM dangereux ({sink_txt}).",
                f"Source détectée : '{source_txt}', Puits détecté : '{sink_txt}'. Extrait : `{sample_line}`",
                "Permet l'exécution de code JavaScript arbitraire côté client sans interaction avec le serveur, en manipulant l'ancre (#) ou les paramètres de l'URL.",
                "Utilisez des méthodes sûres comme 'textContent' ou 'innerText' au lieu de 'innerHTML', et évitez l'utilisation de 'eval()' ou de manipulations directes du DOM avec des données utilisateur."
            ))

    return findings

# ----------------- CACHE-CONTROL SENSITIVE DATA AUDIT -----------------

def audit_cache_control_sensitive_data(session: requests.Session, query_targets: List[str], html_content: str) -> List[Dict[str, Any]]:
    """
    Verifies that responses containing personal data or form fields enforce strict Cache-Control.
    """
    findings = []
    has_sensitive_data = bool(re.search(r'type=["\']password["\']|name=["\'](?:email|token|account|salary|card)["\']', html_content or "", re.I))

    for target_url in query_targets[:4]:
        try:
            r = session.get(target_url, timeout=4, allow_redirects=False)
            cc = r.headers.get("Cache-Control", "").lower()
            pragma = r.headers.get("Pragma", "").lower()

            if has_sensitive_data or r.cookies:
                if not cc or ("no-store" not in cc and "no-cache" not in cc and "private" not in cc):
                    findings.append(_finding(
                        "INSECURE_CACHE_CONTROL_SENSITIVE",
                        "Gestion Inadéquate du Cache HTTP sur Données Sensibles (Cache-Control)",
                        "MEDIUM",
                        "A05:2021-Security Misconfiguration (OWASP Top 10)",
                        f"La page {target_url} contient des champs sensibles ou des cookies de session mais n'interdit pas la mise en cache par les proxys et navigateurs.",
                        f"En-tête Cache-Control actuel : '{cc or 'Non défini'}'.",
                        "Des informations personnelles ou jetons de session peuvent être stockés dans le cache de proxys d'entreprise ou l'historique de postes partagés.",
                        "Ajoutez l'en-tête HTTP : Cache-Control: no-store, no-cache, must-revalidate, private sur toutes les pages authentifiées ou contenant des données privées."
                    ))
                    break
        except Exception:
            continue

    return findings

# ----------------- MAIN DAST ORCHESTRATOR -----------------

def run_dast_audit(target_url: str, session: requests.Session, html_content: str,
                   csp_header: str = "", auth_headers_user_b: Dict[str, str] = None) -> List[Dict[str, Any]]:
    """
    Orchestrates the active non-destructive vulnerability assessment against an authorized target.
    Utilizes a deep bounded surface crawl (pages, scripts, APIs, Swagger) and evaluates:
    SQLi, XSS, Path Traversal, Rate Limiting, IDOR, Open Redirect, Deep CORS, DOM XSS, and Cache-Control.
    """
    findings = []

    # 1. Deep Bounded Surface Crawl (discovers forms, API routes, links, scripts)
    surface = deep_crawl_surface(session, target_url, html_content, max_pages=8)
    forms = surface["forms"]
    query_targets = surface["query_targets"]
    scripts = surface["scripts"]

    # 2. SQL Injection audit (error-based & syntax disturbance)
    findings.extend(audit_sqli(session, forms, query_targets))

    # 3. Server-side XSS audit (canary tag reflection)
    findings.extend(audit_xss(session, target_url, forms, query_targets, csp_header=csp_header))

    # 4. DOM-based XSS audit (Source-to-Sink static analysis)
    findings.extend(audit_dom_xss_sources_sinks(scripts, target_url))

    # 5. Path Traversal audit
    findings.extend(audit_path_traversal(session, query_targets))

    # 6. Rate Limiting / Brute Force resistance audit
    findings.extend(audit_rate_limiting(session, forms))

    # 7. IDOR / Broken Object Level Authorization audit
    findings.extend(audit_idor(session, query_targets, auth_headers_user_b=auth_headers_user_b))

    # 8. Open Redirect audit
    findings.extend(audit_open_redirect(session, query_targets))

    # 9. Deep CORS misconfiguration audit
    findings.extend(audit_deep_cors(session, target_url))

    # 10. Cache-Control on sensitive data audit
    findings.extend(audit_cache_control_sensitive_data(session, query_targets, html_content))

    return findings
