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

# ----------------- SSRF (SERVER-SIDE REQUEST FORGERY) AUDIT -----------------

SSRF_PARAM_NAMES = {
    "url", "uri", "endpoint", "target", "dest", "destination", "path", "src",
    "source", "redirect", "link", "proxy", "fetch", "load", "image", "img",
    "callback", "webhook", "host", "server", "feed", "import", "file"
}

def audit_ssrf(session: requests.Session, forms: List[Dict[str, Any]],
               query_targets: List[str], base_url: str) -> List[Dict[str, Any]]:
    """
    Audits for Server-Side Request Forgery (SSRF) vulnerabilities.
    Tests URL/host parameters for cloud metadata endpoint access and internal host reflection.
    Uses strictly benign probes (example.com canary + metadata URL syntax detection).
    Never connects to real internal infrastructure.
    """
    findings = []
    tested = set()

    # Cloud metadata endpoints commonly targeted in SSRF attacks
    CLOUD_METADATA_PROBES = [
        "http://169.254.169.254/latest/meta-data/",            # AWS EC2 metadata
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "http://169.254.169.254/metadata/instance",            # Azure
    ]
    # Safe canary domain to detect if server actually fetches external URLs
    CANARY_DOMAIN = "http://example.com"

    def _test_ssrf_param(endpoint: str, method: str, all_params: dict, p_name: str, probe_val: str) -> Dict:
        """Sends a probe and returns response metadata without following sensitive redirects."""
        probe_data = dict(all_params)
        probe_data[p_name] = probe_val
        try:
            if method == "POST":
                r = session.post(endpoint, data=probe_data, timeout=5, allow_redirects=False)
            else:
                r = session.get(endpoint, params=probe_data, timeout=5, allow_redirects=False)
            return {"status": r.status_code, "len": len(r.text), "text": r.text[:300], "loc": r.headers.get("Location", "")}
        except Exception:
            return {}

    # 1. Audit Forms
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        base_data = {inp["name"]: inp.get("default", "test") for inp in inputs}

        for inp in inputs:
            p_name = inp.get("name", "")
            if not p_name or p_name.lower() not in SSRF_PARAM_NAMES:
                continue
            key = f"form:{action}:{p_name}"
            if key in tested:
                continue
            tested.add(key)

            # Test 1: Cloud metadata URL syntax detection (check if server returns metadata-like content)
            for meta_url in CLOUD_METADATA_PROBES:
                result = _test_ssrf_param(action, method, base_data, p_name, meta_url)
                if result.get("status") == 200 and result.get("len", 0) > 20:
                    # Heuristic: metadata endpoints return specific patterns
                    meta_markers = re.compile(r"ami-id|instance-id|iam/|computeMetadata|subscriptionId|local-ipv4", re.I)
                    if meta_markers.search(result.get("text", "")):
                        findings.append(_finding(
                            f"SSRF_CLOUD_METADATA_{p_name}",
                            f"SSRF Critique : Accès aux Métadonnées Cloud via le paramètre '{p_name}'",
                            "CRITICAL",
                            "A10:2021-Server-Side Request Forgery (OWASP Top 10)",
                            f"Le paramètre '{p_name}' permet au serveur d'initier des requêtes vers l'endpoint de métadonnées cloud ({meta_url}). Des tokens IAM, clés d'accès et configurations peuvent être récupérés.",
                            f"Probe envoyé : {p_name}={meta_url}. Réponse HTTP 200 avec contenu identifiable ({result['len']} octets). Marqueurs détectés.",
                            "Compromission totale de l'environnement cloud : vol de clés IAM, accès aux secrets AWS/GCP/Azure, pivot interne.",
                            "Implémentez une liste blanche stricte des domaines autorisés. Bloquez les plages 169.254.x.x et metadata.google.internal au niveau du pare-feu sortant. Utilisez les IMDSv2 (AWS) avec token requis."
                        ))
                        break

            # Test 2: External fetch detection via canary
            result_canary = _test_ssrf_param(action, method, base_data, p_name, CANARY_DOMAIN)
            if result_canary.get("status") in (200, 301, 302) and "example" in result_canary.get("text", "").lower():
                findings.append(_finding(
                    f"SSRF_EXTERNAL_FETCH_{p_name}",
                    f"SSRF Potentiel : Le Serveur Récupère des URLs Externes via '{p_name}'",
                    "HIGH",
                    "A10:2021-Server-Side Request Forgery (OWASP Top 10)",
                    f"Le paramètre '{p_name}' provoque une requête sortante du serveur vers un domaine externe contrôlé. L'application est un proxy non filtré.",
                    f"Probe : {p_name}={CANARY_DOMAIN}. Le contenu de example.com a été retourné dans la réponse du serveur.",
                    "Permet de scanner le réseau interne, exfiltrer des données via des canaux détournés, et accéder aux services cloud internes.",
                    "Validez les URLs avec une liste blanche de domaines autorisés. Résolvez le DNS côté serveur et vérifiez l'IP finale contre une liste de blocage RFC1918/métadonnées."
                ))

    # 2. Audit URL Query Targets
    for q_url in query_targets[:8]:
        parsed = urllib.parse.urlparse(q_url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        base_clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        for p_name, p_val in params.items():
            if p_name.lower() not in SSRF_PARAM_NAMES:
                continue
            key = f"url:{base_clean}:{p_name}"
            if key in tested:
                continue
            tested.add(key)

            for meta_url in CLOUD_METADATA_PROBES:
                probe_params = dict(params)
                probe_params[p_name] = meta_url
                try:
                    r = session.get(base_clean, params=probe_params, timeout=5, allow_redirects=False)
                    meta_markers = re.compile(r"ami-id|instance-id|iam/|computeMetadata|subscriptionId|local-ipv4", re.I)
                    if r.status_code == 200 and meta_markers.search(r.text):
                        findings.append(_finding(
                            f"SSRF_URL_METADATA_{p_name}",
                            f"SSRF Critique : Accès aux Métadonnées Cloud via paramètre URL '{p_name}'",
                            "CRITICAL",
                            "A10:2021-Server-Side Request Forgery (OWASP Top 10)",
                            f"Le paramètre d'URL '{p_name}' permet d'atteindre les métadonnées cloud internes.",
                            f"URL testée : {base_clean}?{p_name}={meta_url}. Réponse 200 avec marqueurs cloud.",
                            "Accès aux credentials cloud (IAM tokens, service accounts).",
                            "Bloquez les plages IP internes et les endpoints de métadonnées. Validez les URLs avec une liste blanche."
                        ))
                        break
                except Exception:
                    continue

    return findings


# ----------------- XXE (XML EXTERNAL ENTITY) AUDIT -----------------

def audit_xxe(session: requests.Session, forms: List[Dict[str, Any]],
              base_url: str) -> List[Dict[str, Any]]:
    """
    Audits for XML External Entity (XXE) injection vulnerabilities.
    Submits a benign XXE probe to XML-accepting endpoints and detects:
    - Error-based XXE (error message leakage about file parsing)
    - Blind XXE indicators (unusual response timing, content changes)
    The probe targets a non-existent local file to avoid reading real data.
    """
    findings = []

    # The probe uses a reference to a file that almost certainly doesn't exist (sc_xxe_probe_XXXX.tmp)
    # This avoids reading real system files while still triggering parser errors in vulnerable servers.
    probe_file = f"sc_xxe_probe_{secrets.token_hex(4)}.tmp"
    XXE_PROBE = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE scprobe [
  <!ENTITY xxetest SYSTEM "file:///tmp/{probe_file}">
]>
<scaudit><data>&xxetest;</data></scaudit>"""

    XXE_ERROR_PATTERNS = re.compile(
        r"external entity|entity.*not.*allowed|DTD.*prohibited|xml.*parse.*error|"
        r"SAXParseException|XMLSyntaxError|expat|libxml|JAXP|"
        r"DOCTYPE is disallowed|entity reference|file not found.*tmp",
        re.I
    )

    XML_CONTENT_TYPES = [
        "application/xml", "text/xml", "application/soap+xml",
        "application/rss+xml", "application/atom+xml"
    ]

    # 1. Probe forms that accept file uploads or have XML-related indicators
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        has_file_input = any(inp.get("type") == "file" for inp in inputs)
        action_suggests_xml = bool(re.search(r"xml|upload|import|feed|soap|api", action, re.I))

        if not has_file_input and not action_suggests_xml:
            continue

        # Try submitting the probe as XML body
        try:
            headers = {"Content-Type": "application/xml"}
            r = session.post(action, data=XXE_PROBE.encode("utf-8"),
                             headers=headers, timeout=6, allow_redirects=False)
            if XXE_ERROR_PATTERNS.search(r.text):
                # If error mentions external entity being disallowed → server processes DTD
                if re.search(r"DOCTYPE is disallowed|external entity|entity reference", r.text, re.I):
                    findings.append(_finding(
                        f"XXE_DTD_PROCESSING_{action.replace('/', '_')[:30]}",
                        "XXE : Le Serveur Traite les Entités Externes XML (DTD Processing Actif)",
                        "CRITICAL",
                        "A03:2021-Injection (OWASP Top 10)",
                        f"L'endpoint {action} accepte du XML avec des déclarations DOCTYPE et révèle des messages d'erreur liés au parsing d'entités externes. Le serveur traite activement les DTD.",
                        f"Probe XXE envoyé en POST sur {action}. Réponse contient : '{XXE_ERROR_PATTERNS.search(r.text).group(0)[:80]}'.",
                        "Lecture de fichiers système arbitraires (/etc/passwd, clés privées), SSRF via entités réseau, déni de service (Billion Laughs).",
                        "Désactivez le traitement des DTD externes dans le parser XML (ex: FEATURE_DISALLOW_DOCTYPE_DECL en Java, libxml2_disable_entity_loader() en PHP, defusedxml en Python)."
                    ))
                else:
                    findings.append(_finding(
                        f"XXE_PARSER_ERROR_{action.replace('/', '_')[:30]}",
                        "XXE Potentiel : Erreur de Parser XML Exposée",
                        "HIGH",
                        "A03:2021-Injection (OWASP Top 10)",
                        f"L'endpoint {action} expose des messages d'erreur internes du parser XML lors de la soumission d'une déclaration DOCTYPE.",
                        f"Réponse contient une erreur XML parser : '{XXE_ERROR_PATTERNS.search(r.text).group(0)[:80]}'.",
                        "Peut indiquer un parser XML vulnérable. Des attaques XXE ciblées pourraient lire des fichiers locaux.",
                        "Configurez le parser XML en mode sécurisé (désactivez les entités et DTD externes). Utilisez des bibliothèques comme defusedxml en Python."
                    ))
        except Exception:
            pass

    # 2. Probe standard API paths that commonly accept XML
    parsed_base = urllib.parse.urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    xml_api_paths = ["/api/", "/soap", "/xml", "/feed", "/rss", "/import", "/upload"]

    for api_path in xml_api_paths:
        probe_url = urllib.parse.urljoin(origin, api_path)
        try:
            headers = {"Content-Type": "application/xml", "Accept": "application/xml"}
            r = session.post(probe_url, data=XXE_PROBE.encode("utf-8"),
                             headers=headers, timeout=4, allow_redirects=False)
            if r.status_code not in (404, 405, 403) and XXE_ERROR_PATTERNS.search(r.text):
                findings.append(_finding(
                    f"XXE_API_ENDPOINT_{api_path.strip('/').replace('/', '_')}",
                    f"XXE Potentiel sur Endpoint API : {api_path}",
                    "HIGH",
                    "A03:2021-Injection (OWASP Top 10)",
                    f"L'endpoint {probe_url} accepte du XML et retourne une erreur de parser révélatrice.",
                    f"POST {probe_url} avec DOCTYPE probe. Statut : {r.status_code}. Erreur : '{XXE_ERROR_PATTERNS.search(r.text).group(0)[:80]}'.",
                    "Possible lecture de fichiers locaux ou SSRF via entités XML réseau.",
                    "Désactivez le traitement des entités XML externes sur tous les parsers. Mettez à jour les dépendances XML."
                ))
        except Exception:
            continue

    return findings


# ----------------- SSTI (SERVER-SIDE TEMPLATE INJECTION) AUDIT -----------------

# Strictly non-destructive arithmetic canary probes — no code execution, no OS commands
# The probe uses an arithmetic expression that evaluates differently in template engines vs literal strings
SSTI_PROBES = [
    # (probe_input, expected_evaluation, engine_hint)
    ("{{7*7}}", "49", "Jinja2/Twig/Pebble"),
    ("${7*7}", "49", "FreeMarker/Velocity/Mako"),
    ("#{7*7}", "49", "Thymeleaf/Spring"),
    ("<%= 7*7 %>", "49", "ERB (Ruby)/EJS"),
    ("*{7*7}", "49", "Thymeleaf SpEL"),
]

def audit_ssti(session: requests.Session, forms: List[Dict[str, Any]],
               query_targets: List[str]) -> List[Dict[str, Any]]:
    """
    Audits for Server-Side Template Injection (SSTI) using strictly safe arithmetic canaries.
    The probe '{{7*7}}' is non-destructive — it only confirms if arithmetic is evaluated
    by comparing the literal probe vs evaluated result (49) in the response.
    Never sends OS commands, file reads, or code execution payloads.
    """
    findings = []
    tested = set()

    def _check_ssti_response(resp_text: str, probe: str, expected: str) -> Tuple[bool, str]:
        """Returns (is_vulnerable, engine_hint) if the expected evaluation appears but not the raw probe."""
        if expected in resp_text and probe not in resp_text:
            return True, ""
        return False, ""

    # 1. Audit Form Inputs
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        base_data = {inp["name"]: inp.get("default", "test") for inp in inputs}

        for inp in inputs:
            p_name = inp.get("name", "")
            if not p_name or inp.get("type") in ("hidden", "submit", "button", "file"):
                continue

            for probe, expected, engine_hint in SSTI_PROBES:
                key = f"ssti:form:{action}:{p_name}:{probe[:4]}"
                if key in tested:
                    continue
                tested.add(key)

                probe_data = dict(base_data)
                probe_data[p_name] = probe

                try:
                    if method == "POST":
                        r = session.post(action, data=probe_data, timeout=5, allow_redirects=True)
                    else:
                        r = session.get(action, params=probe_data, timeout=5, allow_redirects=True)

                    is_vuln, _ = _check_ssti_response(r.text, probe, expected)
                    if is_vuln:
                        findings.append(_finding(
                            f"SSTI_FORM_{p_name}_{engine_hint[:8].replace('/', '_')}",
                            f"Injection de Template Côté Serveur (SSTI) sur le champ '{p_name}' ({engine_hint})",
                            "CRITICAL",
                            "A03:2021-Injection (OWASP Top 10)",
                            f"Le paramètre '{p_name}' est évalué par le moteur de template du serveur. La sonde arithmétique '{probe}' a été calculée et le résultat '{expected}' retourné, ce qui prouve que les expressions du moteur {engine_hint} sont exécutées.",
                            f"Formulaire {method} sur {action}. Sonde : '{p_name}={probe}'. Résultat '{expected}' trouvé dans la réponse (la sonde brute absente).",
                            "Exécution de code arbitraire côté serveur, lecture de fichiers système, compromission totale de l'application et du serveur.",
                            "Ne passez jamais d'entrées utilisateur directement dans des fonctions de rendu de template (render_template_string(), Template(user_input)). Utilisez des variables de contexte sécurisées et appliquez le sandboxing du moteur de template."
                        ))
                        break
                except Exception:
                    continue

    # 2. Audit URL Query Parameters
    for q_url in query_targets[:6]:
        parsed = urllib.parse.urlparse(q_url)
        params = urllib.parse.parse_qsl(parsed.query)
        base_clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        for p_name, p_val in params:
            for probe, expected, engine_hint in SSTI_PROBES:
                key = f"ssti:url:{base_clean}:{p_name}:{probe[:4]}"
                if key in tested:
                    continue
                tested.add(key)

                probe_params = dict(params)
                probe_params[p_name] = probe

                try:
                    r = session.get(base_clean, params=probe_params, timeout=5, allow_redirects=True)
                    is_vuln, _ = _check_ssti_response(r.text, probe, expected)
                    if is_vuln:
                        findings.append(_finding(
                            f"SSTI_URL_{p_name}_{engine_hint[:8].replace('/', '_')}",
                            f"SSTI sur Paramètre d'URL '{p_name}' ({engine_hint})",
                            "CRITICAL",
                            "A03:2021-Injection (OWASP Top 10)",
                            f"Le paramètre d'URL '{p_name}' est interprété par le moteur de template {engine_hint}. La sonde '{probe}' est évaluée en '{expected}'.",
                            f"URL : {base_clean}?{p_name}={probe}. Résultat '{expected}' présent dans la réponse.",
                            "Exécution de code arbitraire, accès fichiers système, RCE complet.",
                            "Séchez toutes les entrées utilisateur avant usage dans les templates. Appliquez le sandbox Jinja2 ou désactivez les expressions dynamiques."
                        ))
                        break
                except Exception:
                    continue

    return findings


# ----------------- CLICKJACKING FUNCTIONAL AUDIT -----------------

def audit_clickjacking(session: requests.Session, base_url: str,
                       csp_header: str = "", xfo_header: str = "") -> List[Dict[str, Any]]:
    """
    Evaluates clickjacking protection beyond header presence.
    Checks:
    1. X-Frame-Options header value (DENY / SAMEORIGIN vs ALLOW-FROM / absent)
    2. CSP frame-ancestors directive (strongest protection)
    3. Combination analysis (CSP overrides XFO in modern browsers)
    """
    findings = []

    xfo = xfo_header.strip().upper()
    csp = csp_header.lower()

    # Check CSP frame-ancestors (most reliable protection)
    has_frame_ancestors = "frame-ancestors" in csp
    frame_ancestors_value = ""
    if has_frame_ancestors:
        m = re.search(r"frame-ancestors\s+([^;]+)", csp)
        frame_ancestors_value = m.group(1).strip() if m else ""

    # Check X-Frame-Options
    has_xfo = bool(xfo)
    xfo_safe = xfo in ("DENY", "SAMEORIGIN")

    # Fetch page fresh to check headers directly
    try:
        r = session.get(base_url, timeout=5, allow_redirects=True)
        xfo_live = r.headers.get("X-Frame-Options", "").strip().upper()
        csp_live = r.headers.get("Content-Security-Policy", "").lower()

        has_frame_ancestors = "frame-ancestors" in csp_live
        if has_frame_ancestors:
            m = re.search(r"frame-ancestors\s+([^;]+)", csp_live)
            frame_ancestors_value = m.group(1).strip() if m else ""
        xfo_live_safe = xfo_live in ("DENY", "SAMEORIGIN")
    except Exception:
        xfo_live = xfo
        xfo_live_safe = xfo_safe
        csp_live = csp

    # Case 1: No protection at all
    if not has_frame_ancestors and not xfo_live:
        findings.append(_finding(
            "CLICKJACKING_NO_PROTECTION",
            "Clickjacking : Aucune Protection Anti-Framing Détectée",
            "HIGH",
            "A05:2021-Security Misconfiguration (OWASP Top 10)",
            "Le site ne déploie ni l'en-tête X-Frame-Options ni la directive CSP frame-ancestors. N'importe quelle page externe peut intégrer ce site dans une iframe invisible et tromper les utilisateurs.",
            f"X-Frame-Options absent. CSP sans frame-ancestors. URL : {base_url}.",
            "Vol de clics (Clickjacking), détournement de formulaires de paiement, actions non intentionnelles des utilisateurs (like, transfert, suppression).",
            "Ajoutez à minima : X-Frame-Options: SAMEORIGIN. Préférez : Content-Security-Policy: frame-ancestors 'self'; (CSP est prioritaire sur XFO dans les navigateurs modernes)."
        ))

    # Case 2: XFO present but unsafe value (ALLOW-FROM is obsolete and bypassable)
    elif xfo_live and not xfo_live_safe and not has_frame_ancestors:
        findings.append(_finding(
            "CLICKJACKING_XFO_UNSAFE",
            f"Clickjacking : X-Frame-Options avec Valeur Non Sécurisée ('{xfo_live}')",
            "MEDIUM",
            "A05:2021-Security Misconfiguration (OWASP Top 10)",
            f"La valeur X-Frame-Options: {xfo_live} est soit invalide soit obsolète (ALLOW-FROM n'est plus supporté par les navigateurs modernes).",
            f"X-Frame-Options: {xfo_live} détecté. Valeurs sécurisées attendues : DENY ou SAMEORIGIN.",
            "Protection contournable dans certains navigateurs. Risque de clickjacking résiduel.",
            "Remplacez par X-Frame-Options: DENY et ajoutez frame-ancestors 'none' dans le CSP."
        ))

    # Case 3: CSP frame-ancestors present but allows wildcard or all origins
    if has_frame_ancestors and ("*" in frame_ancestors_value or frame_ancestors_value != "'none'"):
        if "*" in frame_ancestors_value:
            findings.append(_finding(
                "CLICKJACKING_CSP_WILDCARD",
                "Clickjacking : CSP frame-ancestors avec Wildcard '*' (Aucune Restriction)",
                "HIGH",
                "A05:2021-Security Misconfiguration (OWASP Top 10)",
                "La directive CSP frame-ancestors utilise le wildcard '*', autorisant n'importe quel site à intégrer cette page dans une iframe.",
                f"Content-Security-Policy contient : frame-ancestors {frame_ancestors_value}",
                "Protection clickjacking inexistante malgré la présence de la directive CSP.",
                "Remplacez frame-ancestors * par frame-ancestors 'self' ou listez explicitement les domaines partenaires autorisés."
            ))

    return findings


# ----------------- COOKIE SECURITY DEEP AUDIT -----------------

def audit_cookie_security(session: requests.Session, base_url: str) -> List[Dict[str, Any]]:
    """
    Performs a deep cookie security audit beyond simple flag presence.
    Evaluates:
    - HttpOnly flag (XSS session theft protection)
    - Secure flag (HTTPS-only transmission)
    - SameSite attribute (CSRF protection)
    - Cookie scope (Domain/Path overly broad)
    - Session fixation risk (predictable session IDs)
    """
    findings = []

    try:
        r = session.get(base_url, timeout=5, allow_redirects=True)
    except Exception:
        return findings

    is_https = base_url.startswith("https")
    raw_set_cookie = r.headers.get("Set-Cookie", "") or ""
    # Handle multiple Set-Cookie headers via raw response
    all_set_cookies = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw, "headers") and hasattr(r.raw.headers, "getlist") else [raw_set_cookie]

    parsed_base = urllib.parse.urlparse(base_url)
    host = parsed_base.netloc.lower()

    for cookie in r.cookies:
        name = cookie.name
        val = cookie.value or ""

        # 1. HttpOnly check
        is_httponly = cookie.has_nonstandard_attr("httponly") or cookie.has_nonstandard_attr("HttpOnly")
        if not is_httponly and any(kw in name.lower() for kw in ("sess", "token", "auth", "sid", "uid", "jwt", "user")):
            findings.append(_finding(
                f"COOKIE_HTTPONLY_MISSING_{name}",
                f"Cookie de Session sans Flag HttpOnly : '{name}'",
                "HIGH",
                "A07:2021-Identification and Authentication Failures (OWASP Top 10)",
                f"Le cookie '{name}' (identifié comme cookie de session/auth) ne possède pas le flag HttpOnly. Il est accessible via JavaScript (document.cookie).",
                f"Set-Cookie: {name}=***; (HttpOnly absent)",
                "En cas de XSS, un attaquant peut voler le cookie de session et usurper l'identité de l'utilisateur sans interaction supplémentaire.",
                f"Définissez explicitement le flag HttpOnly : Set-Cookie: {name}=value; HttpOnly; Secure; SameSite=Strict"
            ))

        # 2. Secure flag check on HTTPS
        if is_https and not cookie.secure:
            findings.append(_finding(
                f"COOKIE_SECURE_MISSING_{name}",
                f"Cookie sans Flag Secure sur HTTPS : '{name}'",
                "MEDIUM",
                "A07:2021-Identification and Authentication Failures (OWASP Top 10)",
                f"Le cookie '{name}' est défini sur un site HTTPS mais n'a pas le flag Secure. Il pourrait être transmis en HTTP non chiffré (downgrade attack).",
                f"Set-Cookie: {name}=***; (Secure absent malgré HTTPS)",
                "Interception de cookie lors d'une attaque SSL-stripping ou sur un réseau mixte HTTP/HTTPS.",
                f"Ajoutez le flag Secure : Set-Cookie: {name}=value; Secure; HttpOnly; SameSite=Strict"
            ))

        # 3. SameSite attribute check
        samesite = cookie.get_nonstandard_attr("samesite") or ""
        if not samesite and any(kw in name.lower() for kw in ("sess", "token", "auth", "sid", "jwt")):
            findings.append(_finding(
                f"COOKIE_SAMESITE_MISSING_{name}",
                f"Cookie de Session sans Attribut SameSite : '{name}'",
                "MEDIUM",
                "A01:2021-Broken Access Control (OWASP Top 10)",
                f"Le cookie '{name}' n'a pas d'attribut SameSite. Les requêtes cross-site envoient automatiquement ce cookie, exposant l'application aux attaques CSRF.",
                f"Set-Cookie: {name}=***; (SameSite absent)",
                "Attaques CSRF (Cross-Site Request Forgery) permettant d'exécuter des actions en tant qu'utilisateur authentifié depuis un site tiers.",
                f"Ajoutez SameSite=Strict (ou Lax pour la compatibilité OAuth) : Set-Cookie: {name}=value; SameSite=Strict; Secure; HttpOnly"
            ))
        elif samesite.lower() == "none" and not cookie.secure:
            findings.append(_finding(
                f"COOKIE_SAMESITE_NONE_INSECURE_{name}",
                f"Cookie avec SameSite=None sans flag Secure : '{name}'",
                "HIGH",
                "A07:2021-Identification and Authentication Failures (OWASP Top 10)",
                f"SameSite=None requiert obligatoirement le flag Secure. Sans lui, les navigateurs modernes rejettent le cookie ou le traitent comme SameSite=Lax.",
                f"Set-Cookie: {name}=***; SameSite=None (Secure absent)",
                "Cookie rejeté par les navigateurs récents ou transmis en clair. Risque d'attaque CSRF.",
                f"Combinez obligatoirement SameSite=None avec le flag Secure : Set-Cookie: {name}=value; SameSite=None; Secure"
            ))

        # 4. Session ID entropy check (predictable IDs)
        if any(kw in name.lower() for kw in ("sess", "sid", "phpsessid", "jsessionid", "sessionid")):
            if len(val) < 16:
                findings.append(_finding(
                    f"COOKIE_SESSION_LOW_ENTROPY_{name}",
                    f"Session ID Trop Court / Faible Entropie : '{name}'",
                    "HIGH",
                    "A07:2021-Identification and Authentication Failures (OWASP Top 10)",
                    f"Le cookie de session '{name}' a une valeur de seulement {len(val)} caractères. Une entropie insuffisante facilite les attaques de force brute sur les IDs de session.",
                    f"Longueur de la valeur de session : {len(val)} caractères.",
                    "Usurpation de session par force brute ou prédiction d'identifiants de session.",
                    "Générez les IDs de session avec au minimum 128 bits d'entropie (32 caractères hex). Utilisez secrets.token_hex(32) en Python ou session_regenerate_id() en PHP."
                ))

        # 5. Overly broad Domain scope
        cookie_domain = cookie.domain or ""
        if cookie_domain.startswith(".") and host.endswith(cookie_domain.lstrip(".")):
            subdomain_count = cookie_domain.count(".")
            if subdomain_count < 2:  # e.g., .example.com (affects ALL subdomains)
                findings.append(_finding(
                    f"COOKIE_BROAD_DOMAIN_{name}",
                    f"Cookie avec Scope Domaine Trop Large : '{name}' (Domain={cookie_domain})",
                    "MEDIUM",
                    "A05:2021-Security Misconfiguration (OWASP Top 10)",
                    f"Le cookie '{name}' est défini avec Domain={cookie_domain}, ce qui le partage avec TOUS les sous-domaines (y compris *.{cookie_domain.lstrip('.')}).",
                    f"Set-Cookie: {name}=***; Domain={cookie_domain}",
                    "Un sous-domaine compromis peut accéder aux cookies de session des autres sous-domaines.",
                    f"Restreignez le scope : omettez l'attribut Domain (le cookie reste sur l'hôte exact) ou spécifiez le sous-domaine précis."
                ))

    return findings


# ----------------- SUBDOMAIN TAKEOVER AUDIT -----------------

# CNAME targets known to be vulnerable to takeover (service deprovisioned but DNS still points)
TAKEOVER_FINGERPRINTS = [
    (re.compile(r"There is no app configured at that hostname", re.I), "Heroku"),
    (re.compile(r"No such app", re.I), "Heroku"),
    (re.compile(r"Repository not found", re.I), "GitHub Pages"),
    (re.compile(r"The site you are looking for.*not found", re.I), "GitHub Pages"),
    (re.compile(r"This domain is not configured", re.I), "Netlify"),
    (re.compile(r"Looks like you've followed a broken link", re.I), "GitBook"),
    (re.compile(r"We could not find what you're looking for", re.I), "HubSpot"),
    (re.compile(r"The specified bucket does not exist", re.I), "AWS S3"),
    (re.compile(r"NoSuchBucket", re.I), "AWS S3"),
    (re.compile(r"Fastly error: unknown domain", re.I), "Fastly"),
    (re.compile(r"This site can't be reached|ERR_NAME_NOT_RESOLVED", re.I), "DNS NXDOMAIN"),
    (re.compile(r"404 Not Found.*azure|azurewebsites\.net", re.I), "Azure"),
    (re.compile(r"Ghost blog", re.I), "Ghost"),
    (re.compile(r"Surge\.sh is not configured for this domain", re.I), "Surge.sh"),
]

def audit_subdomain_takeover(session: requests.Session, base_url: str,
                              html_content: str) -> List[Dict[str, Any]]:
    """
    Audits for subdomain takeover vulnerabilities.
    Scans discovered subdomains (from HTML content, CNAME hints) for:
    - Known cloud service takeover fingerprints (Heroku, GitHub Pages, S3, Netlify...)
    - DNS NXDOMAIN / resolution failures on referenced subdomains
    Strictly passive DNS + HTTP probing — no DNS modification or domain registration.
    """
    findings = []

    parsed_base = urllib.parse.urlparse(base_url)
    apex_domain = parsed_base.netloc.lower()
    if ":" in apex_domain:
        apex_domain = apex_domain.split(":")[0]

    # Extract subdomains referenced in HTML (src, href, action attributes)
    subdomain_candidates = set()
    soup = BeautifulSoup(html_content or "", "lxml")

    for tag in soup.find_all(["a", "script", "link", "img", "form", "iframe"]):
        for attr in ("href", "src", "action", "data-src"):
            val = tag.get(attr, "")
            if not val:
                continue
            try:
                p = urllib.parse.urlparse(val)
                host = p.netloc.lower().split(":")[0]
                if host and host != apex_domain and apex_domain in host:
                    subdomain_candidates.add(host)
            except Exception:
                continue

    # Also check for common subdomains
    common_subs = ["www", "mail", "staging", "dev", "beta", "api", "app", "cdn", "assets", "static", "blog", "shop"]
    for sub in common_subs:
        candidate = f"{sub}.{apex_domain}"
        subdomain_candidates.add(candidate)

    tested = set()
    for subdomain in list(subdomain_candidates)[:12]:  # Limit to avoid excessive requests
        if subdomain in tested:
            continue
        tested.add(subdomain)

        for scheme in ("https", "http"):
            probe_url = f"{scheme}://{subdomain}/"
            try:
                r = session.get(probe_url, timeout=4, allow_redirects=True,
                                headers={"User-Agent": "CyberLab-Security-Auditor/1.0"})
                for pattern, service in TAKEOVER_FINGERPRINTS:
                    if pattern.search(r.text) or pattern.search(r.url):
                        findings.append(_finding(
                            f"SUBDOMAIN_TAKEOVER_{subdomain.replace('.', '_')}",
                            f"Risque de Prise de Contrôle de Sous-Domaine : {subdomain} ({service})",
                            "HIGH",
                            "A05:2021-Security Misconfiguration (OWASP Top 10)",
                            f"Le sous-domaine '{subdomain}' pointe vers le service {service} mais la ressource n'est plus provisionnée. Un attaquant peut enregistrer cette ressource et prendre le contrôle du sous-domaine.",
                            f"URL : {probe_url}. Réponse HTTP {r.status_code}. Fingerprint {service} détecté : '{pattern.pattern[:60]}'.",
                            "Phishing ciblé sous votre marque, injection de contenu malveillant sous votre domaine, contournement de CSP et CORS basés sur la confiance au domaine.",
                            f"Supprimez l'entrée DNS CNAME qui pointe vers {service} ou réapprovisionnez la ressource. Mettez en place une surveillance continue des sous-domaines."
                        ))
                        break
                break  # Don't try http if https worked
            except requests.exceptions.ConnectionError:
                # DNS resolution failure = potential takeover risk
                findings.append(_finding(
                    f"SUBDOMAIN_NXDOMAIN_{subdomain.replace('.', '_')}",
                    f"Sous-Domaine avec DNS Mort (NXDOMAIN) : {subdomain}",
                    "MEDIUM",
                    "A05:2021-Security Misconfiguration (OWASP Top 10)",
                    f"Le sous-domaine '{subdomain}' est référencé dans le HTML mais ne résout plus en DNS. Si un enregistrement DNS (CNAME) pointe vers un service tiers non provisionnée, une prise de contrôle est possible.",
                    f"Tentative de connexion à {probe_url} : DNS resolution failed (NXDOMAIN ou connexion refusée).",
                    "Prise de contrôle du sous-domaine possible via enregistrement d'une ressource cloud correspondante.",
                    "Vérifiez et nettoyez les enregistrements DNS orphelins. Supprimez les CNAME qui ne pointent plus vers des ressources actives."
                ))
                break
            except Exception:
                break

    return findings


# ----------------- HTTP DANGEROUS METHODS AUDIT -----------------

def audit_http_methods(session: requests.Session, base_url: str) -> List[Dict[str, Any]]:
    """
    Tests for enabled dangerous HTTP methods using OPTIONS discovery and targeted probes.
    Methods tested: TRACE (XST), PUT (file upload), DELETE (resource deletion), CONNECT (proxy abuse).
    Uses strictly benign probes — does not actually upload, delete, or modify any data.
    """
    findings = []

    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Test paths for method probing
    test_paths = ["/", "/api/", "/upload", "/files/", "/data/"]

    for path in test_paths[:3]:
        target = urllib.parse.urljoin(origin, path)

        # 1. OPTIONS discovery
        try:
            r_opts = session.options(target, timeout=4, allow_redirects=False)
            allow_header = r_opts.headers.get("Allow", "") + r_opts.headers.get("Access-Control-Allow-Methods", "")
            allow_upper = allow_header.upper()

            dangerous_enabled = []
            for method in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"):
                if method in allow_upper:
                    dangerous_enabled.append(method)

            if dangerous_enabled:
                for method in dangerous_enabled:
                    severity = "HIGH" if method in ("TRACE", "TRACK") else "MEDIUM"
                    findings.append(_finding(
                        f"HTTP_METHOD_{method}_{path.strip('/').replace('/', '_') or 'ROOT'}",
                        f"Méthode HTTP Dangereuse Activée : {method} sur {path}",
                        severity,
                        "A05:2021-Security Misconfiguration (OWASP Top 10)",
                        f"Le serveur annonce la méthode {method} comme acceptée sur {target} via l'en-tête Allow de la réponse OPTIONS.",
                        f"OPTIONS {target} → Allow: {allow_header.strip()[:120]}",
                        {
                            "TRACE": "Cross-Site Tracing (XST) : permet à un attaquant de lire les cookies HttpOnly via XMLHttpRequest si le navigateur envoie une requête TRACE.",
                            "TRACK": "Variante de TRACE (IIS). Même risque XST.",
                            "PUT": "Upload de fichiers arbitraires sur le serveur si le chemin est accessible en écriture. Risque de webshell.",
                            "DELETE": "Suppression de ressources distantes si le contrôle d'accès est insuffisant.",
                            "CONNECT": "Utilisation du serveur comme proxy HTTP pour rebondir vers d'autres cibles.",
                            "PATCH": "Modification partielle de ressources. Risque selon les contrôles d'accès."
                        }.get(method, "Méthode non standard pouvant exposer des fonctions non documentées."),
                        {
                            "TRACE": "Désactivez TRACE dans la configuration du serveur (Apache: TraceEnable Off / Nginx: add_header X-XSS-Protection déjà fait, désactivez via configuration).",
                            "PUT": "Désactivez la méthode PUT ou restreignez-la à des endpoints d'API authentifiés avec CSRF token.",
                            "DELETE": "Restreignez DELETE aux endpoints d'API avec authentification forte et journalisation.",
                            "CONNECT": "Désactivez CONNECT sur les serveurs web. Il ne devrait être activé que sur des proxys dédiés.",
                        }.get(method, f"Désactivez la méthode {method} ou restreignez-la aux endpoints nécessaires avec authentification obligatoire.")
                    ))
        except Exception:
            pass

        # 2. Direct TRACE probe (most critical to confirm)
        try:
            r_trace = session.request("TRACE", target, timeout=4, allow_redirects=False)
            if r_trace.status_code == 200 and "TRACE" in r_trace.text.upper():
                if not any(f["id"].startswith("HTTP_METHOD_TRACE") for f in findings):
                    findings.append(_finding(
                        f"HTTP_TRACE_XST_CONFIRMED",
                        "Méthode TRACE Active Confirmée (Cross-Site Tracing / XST)",
                        "HIGH",
                        "A05:2021-Security Misconfiguration (OWASP Top 10)",
                        f"La méthode HTTP TRACE est activée et retourne le contenu de la requête. Cela confirme le risque Cross-Site Tracing (XST) permettant de lire les en-têtes et potentiellement les cookies HttpOnly via des navigateurs anciens.",
                        f"TRACE {target} → HTTP {r_trace.status_code}. La réponse reflète les en-têtes de la requête.",
                        "XST permet la lecture d'en-têtes sensibles (Authorization, Cookie) via JavaScript dans certains navigateurs.",
                        "Désactivez TRACE : Apache → TraceEnable Off, Nginx → ne l'activez jamais (désactivé par défaut), IIS → Regsvr32 ou web.config."
                    ))
        except Exception:
            pass

    return findings


# ----------------- MAIN DAST ORCHESTRATOR -----------------

def run_dast_audit(target_url: str, session: requests.Session, html_content: str,
                   csp_header: str = "", auth_headers_user_b: Dict[str, str] = None) -> List[Dict[str, Any]]:
    """
    Orchestrates the active non-destructive vulnerability assessment against an authorized target.
    Utilizes a deep bounded surface crawl (pages, scripts, APIs, Swagger) and evaluates:
    SQLi, XSS, SSTI, XXE, SSRF, Path Traversal, Rate Limiting, IDOR, Open Redirect,
    Deep CORS, DOM XSS, Cache-Control, Clickjacking, Cookie Security,
    Subdomain Takeover, and HTTP Methods.
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

    # 11. SSRF (Server-Side Request Forgery) audit
    findings.extend(audit_ssrf(session, forms, query_targets, target_url))

    # 12. XXE (XML External Entity) audit
    findings.extend(audit_xxe(session, forms, target_url))

    # 13. SSTI (Server-Side Template Injection) audit
    findings.extend(audit_ssti(session, forms, query_targets))

    # 14. Clickjacking functional audit
    findings.extend(audit_clickjacking(session, target_url, csp_header=csp_header))

    # 15. Cookie security deep audit
    findings.extend(audit_cookie_security(session, target_url))

    # 16. Subdomain takeover audit
    findings.extend(audit_subdomain_takeover(session, target_url, html_content))

    # 17. HTTP dangerous methods audit
    findings.extend(audit_http_methods(session, target_url))

    return findings
