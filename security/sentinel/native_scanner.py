"""
native_scanner.py - Pure Python Native Autonomous Security Scanner & Audit Engine
Provides 100% independent, zero-dependency security auditing for ULTON AI (Sentinel):
1. PortScanner (Nmap equivalent in pure Python): TCP connect scan & banner grabbing
2. SurfaceCrawler (Ffuf/Gobuster equivalent): recursive path & form discovery
3. VulnerabilityEngine (Nuclei equivalent): sensitive files, CORS, security headers, cookie flags
4. SQLiDetector (Sqlmap equivalent in pure Python): error-based & differential SQL injection tests
"""

import os
import re
import socket
import ssl
import time
import json
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple

import requests
from ..database import get_connection, log_event

logger = logging.getLogger("sentinel.native_scanner")

# Default common ports to scan for infrastructure and services
COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (3000, "Node/React"),
    (3306, "MySQL"),
    (5000, "Flask/Python"),
    (5050, "SiteCloner"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8000, "HTTP-Dev"),
    (8080, "HTTP-Proxy"),
    (8443, "HTTPS-Alt"),
    (9200, "ElasticSearch"),
    (27017, "MongoDB")
]

# Sensitive paths dictionary (Nuclei-style sensitive file discovery)
SENSITIVE_PATHS = [
    (".env", "Configuration & secrets d'environnement"),
    (".git/config", "Dépôt Git exposé"),
    (".git/HEAD", "Contrôle de version Git exposé"),
    ("robots.txt", "Fichier de règles d'exploration"),
    ("sitemap.xml", "Plan du site public"),
    ("admin", "Interface d'administration potentielle"),
    ("api", "Racine des points de terminaison d'API"),
    ("swagger.json", "Documentation OpenAPI/Swagger"),
    ("api/docs", "Documentation d'API exposée"),
    ("backup.sql", "Sauvegarde de base de données"),
    ("dump.sql", "Dump SQL exposé"),
    ("config.json", "Fichier de configuration applicatif"),
    ("composer.json", "Dépendances PHP exposées"),
    ("package.json", "Dépendances Node.js exposées")
]

# Common SQL error patterns across SQLite, MySQL, PostgreSQL, MSSQL, Oracle
SQL_ERROR_PATTERNS = [
    re.compile(r"syntax error|unrecognized token", re.I),
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql_", re.I),
    re.compile(r"pg_query\(\)|psycopg2\.OperationalError", re.I),
    re.compile(r"sqlite3\.OperationalError|near \".*?\": syntax error", re.I),
    re.compile(r"ora-[0-9]{4,5}", re.I),
    re.compile(r"microsoft ole db provider for odbc drivers", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I)
]


class PortScanner:
    """Fast, multi-threaded TCP connect port scanner and banner grabber in pure Python."""

    def __init__(self, timeout: float = 1.0, max_threads: int = 15):
        self.timeout = timeout
        self.max_threads = max_threads

    def scan_port(self, host: str, port: int, service_name: str) -> Optional[Dict[str, Any]]:
        """Probes a single TCP port and grabs service banner if open."""
        target_ip = "127.0.0.1" if host in ("innotech-lab.local", "localhost", "127.0.0.1") else host
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            res = s.connect_ex((target_ip, port))
            if res == 0:
                banner = ""
                # Attempt light banner grabbing
                try:
                    s.settimeout(0.8)
                    if port in (80, 5000, 5050, 8000, 8080):
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(512).decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner = ""
                return {
                    "port": port,
                    "service": service_name,
                    "state": "open",
                    "banner": banner[:120] if banner else None
                }
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return None

    def scan_target(self, host: str, ports: Optional[List[Tuple[int, str]]] = None) -> List[Dict[str, Any]]:
        """Scans specified or default ports on the target host concurrently."""
        target_ports = ports or COMMON_PORTS
        open_services = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port, name): (port, name)
                for port, name in target_ports
            }
            for future in as_completed(future_to_port):
                try:
                    data = future.result()
                    if data:
                        open_services.append(data)
                except Exception:
                    pass

        return sorted(open_services, key=lambda x: x["port"])


class SurfaceCrawler:
    """Discovers routes, sensitive files, and forms on authorized web applications."""

    def __init__(self, timeout: int = 4):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Ulton-NativeAuditor/3.0 (Authorized Security Research Engine)"
        })

    def probe_sensitive_files(self, base_url: str) -> List[Dict[str, Any]]:
        """Probes a curated catalogue of sensitive files (Nuclei-style pattern matching)."""
        clean_base = base_url.rstrip("/")
        discovered = []

        for rel_path, desc in SENSITIVE_PATHS:
            target_url = f"{clean_base}/{rel_path}"
            try:
                resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Filter false-positive 200s returning generic HTML error pages
                    ctype = resp.headers.get("Content-Type", "").lower()
                    if rel_path.endswith((".env", ".sql", ".json", "HEAD", "config")) and "text/html" in ctype:
                        continue

                    severity = "CRITICAL" if rel_path in (".env", "backup.sql", "dump.sql", ".git/config") else "MEDIUM"
                    discovered.append({
                        "path": f"/{rel_path}",
                        "url": target_url,
                        "status_code": resp.status_code,
                        "description": desc,
                        "severity": severity,
                        "content_length": len(resp.content)
                    })
            except Exception:
                continue

        return discovered

    def discover_forms_and_params(self, base_url: str) -> List[Dict[str, Any]]:
        """Parses HTML of target to locate input forms and testable parameters."""
        inputs_found = []
        try:
            resp = self.session.get(base_url, timeout=self.timeout)
            if resp.status_code == 200:
                html = resp.text
                # Extract form actions and inputs
                form_matches = re.findall(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>(.*?)</form>", html, re.DOTALL | re.IGNORECASE)
                for action, form_body in form_matches:
                    action_url = urllib.parse.urljoin(base_url, action) if action else base_url
                    input_names = re.findall(r"<input[^>]*name=[\"']([^\"']+)[\"']", form_body, re.IGNORECASE)
                    if input_names:
                        inputs_found.append({
                            "action_url": action_url,
                            "inputs": input_names
                        })
        except Exception:
            pass
        return inputs_found


class SQLiDetector:
    """Non-destructive SQL Injection tester in pure Python (Error-based & Boolean differential)."""

    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Ulton-NativeAuditor/3.0 (SQLi-Safety-Verifier)"
        })

    def test_parameter(self, url: str, param_name: str, method: str = "GET") -> Optional[Dict[str, Any]]:
        """Tests an input parameter for error-based and boolean SQL injection weaknesses."""
        clean_url = url.split("#")[0]
        parsed = urllib.parse.urlparse(clean_url)
        params = urllib.parse.parse_qs(parsed.query)

        # Baseline request
        try:
            base_resp = self.session.get(clean_url, timeout=self.timeout)
            base_len = len(base_resp.content)
            base_status = base_resp.status_code
        except Exception:
            return None

        # 1. Error-based probe: single quote
        test_params = dict(params)
        test_params[param_name] = [test_params.get(param_name, ["test"])[0] + "'"]
        probe_query = urllib.parse.urlencode(test_params, doseq=True)
        probe_url = urllib.parse.urlunparse(parsed._replace(query=probe_query))

        try:
            err_resp = self.session.get(probe_url, timeout=self.timeout)
            for pat in SQL_ERROR_PATTERNS:
                if pat.search(err_resp.text):
                    return {
                        "parameter": param_name,
                        "type": "error_based_sqli",
                        "severity": "CRITICAL",
                        "probe": "'",
                        "evidence": f"Signature d'erreur SQL détectée ({pat.pattern})",
                        "url": probe_url
                    }
        except Exception:
            pass

        # 2. Boolean-based differential probe: AND 1=1 vs AND 1=2
        try:
            p_true = dict(params)
            p_true[param_name] = [test_params.get(param_name, ["test"])[0] + "' AND '1'='1"]
            url_true = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(p_true, doseq=True)))

            p_false = dict(params)
            p_false[param_name] = [test_params.get(param_name, ["test"])[0] + "' AND '1'='2"]
            url_false = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(p_false, doseq=True)))

            r_true = self.session.get(url_true, timeout=self.timeout)
            r_false = self.session.get(url_false, timeout=self.timeout)

            # Check if true matches baseline and false differs significantly
            if r_true.status_code == base_status and r_false.status_code != base_status:
                return {
                    "parameter": param_name,
                    "type": "boolean_blind_sqli",
                    "severity": "HIGH",
                    "probe": "' AND '1'='1' vs ' AND '1'='2'",
                    "evidence": f"Comportement différentiel observé (True HTTP {r_true.status_code} vs False HTTP {r_false.status_code})",
                    "url": url_true
                }
        except Exception:
            pass

        return None


class XSSDetector:
    """Non-destructive Reflected Cross-Site Scripting (XSS) probe detector in pure Python."""

    CANARY_TAG = "<u1t0n-probe-tag>"
    CANARY_ATTR = '" data-u1t0n="probe"'

    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Ulton-NativeAuditor/3.0 (XSS-Probe-Engine)"
        })

    def test_parameter(self, url: str, param_name: str) -> Optional[Dict[str, Any]]:
        """Tests an input parameter for reflected XSS weaknesses with safe benign canaries."""
        clean_url = url.split("#")[0]
        parsed = urllib.parse.urlparse(clean_url)
        params = urllib.parse.parse_qs(parsed.query)

        # Probe 1: Benign custom HTML tag reflection
        test_params = dict(params)
        test_params[param_name] = [self.CANARY_TAG]
        probe_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)))

        try:
            resp = self.session.get(probe_url, timeout=self.timeout)
            ctype = resp.headers.get("Content-Type", "").lower()
            if "text/html" in ctype and self.CANARY_TAG in resp.text:
                return {
                    "parameter": param_name,
                    "type": "reflected_xss",
                    "severity": "HIGH",
                    "probe": self.CANARY_TAG,
                    "evidence": f"Balise inoffensive '{self.CANARY_TAG}' reflétée telle quelle sans échappement HTML dans la réponse.",
                    "url": probe_url
                }
        except Exception:
            pass

        # Probe 2: Attribute breakout canary
        try:
            test_params[param_name] = [self.CANARY_ATTR]
            probe_attr_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)))
            resp_attr = self.session.get(probe_attr_url, timeout=self.timeout)
            ctype = resp_attr.headers.get("Content-Type", "").lower()
            if "text/html" in ctype and self.CANARY_ATTR in resp_attr.text:
                return {
                    "parameter": param_name,
                    "type": "attribute_xss",
                    "severity": "MEDIUM",
                    "probe": self.CANARY_ATTR,
                    "evidence": "Rupture d'attribut HTML détectée : injection d'attribut sans assainissement.",
                    "url": probe_attr_url
                }
        except Exception:
            pass

        return None


class SecretLeakScanner:
    """Detects leaked API keys, tokens, and credentials in crawled HTML source code and JS files."""

    PATTERNS = [
        ("OpenAI API Key", re.compile(r"\b(sk-[a-zA-Z0-9_-]{32,})\b"), "CRITICAL"),
        ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "CRITICAL"),
        ("Stripe Live Secret Key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"), "CRITICAL"),
        ("GitHub Personal Access Token", re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"), "CRITICAL"),
        ("Google Cloud API Key", re.compile(r"\b(AIza[0-9A-Za-z-_]{35})\b"), "HIGH"),
        ("Slack Bot Token", re.compile(r"\b(xoxb-[0-9]{11,13}-[0-9]{11,13}-[0-9a-zA-Z]{24})\b"), "HIGH"),
        ("Private Cryptographic Key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "CRITICAL"),
        ("Hardcoded JWT Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "MEDIUM")
    ]

    def scan_content(self, text: str, source_url: str = "") -> List[Dict[str, Any]]:
        """Scans raw text (HTML, JavaScript) for credential leaks."""
        leaks = []
        for name, pattern, severity in self.PATTERNS:
            matches = pattern.findall(text)
            for m in matches:
                raw_token = m if isinstance(m, str) else m[0]
                if len(raw_token) > 8:
                    preview = f"{raw_token[:4]}****{raw_token[-4:]}"
                else:
                    preview = "****"
                leaks.append({
                    "secret_type": name,
                    "severity": severity,
                    "preview": preview,
                    "source_url": source_url,
                    "evidence": f"Clé ou identifiant secret {name} hardcodé détecté dans le code source."
                })
        return leaks


class IDORDetector:
    """Detects predictable resource parameters prone to Insecure Direct Object Reference."""

    SUSPECT_PARAMS = {"id", "user_id", "uid", "account_id", "invoice_id", "order_id", "doc_id", "profile_id", "member_id", "client_id"}

    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Ulton-NativeAuditor/3.0 (IDOR-Verifier)"
        })

    def test_parameter(self, url: str, param_name: str) -> Optional[Dict[str, Any]]:
        """Checks if a numerical ID parameter permits unauthorized or altered object access."""
        clean_url = url.split("#")[0]
        parsed = urllib.parse.urlparse(clean_url)
        params = urllib.parse.parse_qs(parsed.query)

        val = params.get(param_name, [""])[0]
        if not val or not val.isdigit():
            return None

        orig_num = int(val)
        adjacent_num = orig_num + 1 if orig_num > 1 else 2

        try:
            base_resp = self.session.get(clean_url, timeout=self.timeout)
            if base_resp.status_code != 200:
                return None

            test_params = dict(params)
            test_params[param_name] = [str(adjacent_num)]
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)))

            adj_resp = self.session.get(test_url, timeout=self.timeout)
            if adj_resp.status_code == 200 and abs(len(adj_resp.content) - len(base_resp.content)) > 20:
                return {
                    "parameter": param_name,
                    "type": "potential_idor",
                    "severity": "HIGH",
                    "original_id": str(orig_num),
                    "tested_id": str(adjacent_num),
                    "evidence": f"Paramètre d'objet séquentiel '{param_name}' : l'ID {adjacent_num} renvoie HTTP 200 avec des données distinctes sans restriction de contrôle d'accès.",
                    "url": test_url
                }
        except Exception:
            pass

        return None


class UltonNativeAuditor:
    """
    Unified Autonomous Security Auditor for ULTON AI (Sentinel).
    Combines Port Scanning, Surface Crawling, Vulnerability Templates, SQLi,
    Reflected XSS, Secret Leaks, and IDOR testing in pure Python without
    requiring external Docker, Go, or Kali installations.
    """

    def __init__(self):
        self.port_scanner = PortScanner()
        self.crawler = SurfaceCrawler()
        self.sqli_detector = SQLiDetector()
        self.xss_detector = XSSDetector()
        self.secret_scanner = SecretLeakScanner()
        self.idor_detector = IDORDetector()

    def audit_target(self, target_url: str, depth: str = "standard") -> Dict[str, Any]:
        """
        Executes a complete, non-destructive autonomous security audit on an authorized target.
        """
        from .guardian import guardian

        # 1. GUARDIAN SCOPE GATING
        ok_target, reason = guardian.validate_target(target_url, test_type="pentagi_audit")
        if not ok_target:
            return {
                "success": False,
                "status": "blocked_by_guardian",
                "target": target_url,
                "error": reason
            }

        start_time = time.time()
        parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = parsed.netloc.split(":")[0] or parsed.path.split("/")[0]
        is_lab_mock = host in ("innotech-lab.local", "lab.local")
        probe_url = "http://127.0.0.1:5050/__sc/security/lab" if is_lab_mock else f"{parsed.scheme or 'http'}://{parsed.netloc}"
        base_http_url = probe_url

        findings: List[Dict[str, Any]] = []

        # PHASE 1: NATIVE PORT & SERVICE SCANNING (Equivalent Nmap)
        open_ports = []
        try:
            target_ports = [(80, "HTTP"), (443, "HTTPS"), (5050, "SiteCloner"), (3306, "MySQL"), (5432, "PostgreSQL")] if is_lab_mock else COMMON_PORTS
            open_ports = self.port_scanner.scan_target(host, ports=target_ports)
            # Check for exposed database or admin ports
            for p in open_ports:
                if p["port"] in (3306, 5432, 6379, 27017):
                    findings.append({
                        "id": f"PORT-DB-{p['port']}",
                        "title": f"Port de base de données exposé publiquement ({p['service']}:{p['port']})",
                        "severity": "HIGH",
                        "category": "infrastructure",
                        "description": f"Le service de base de données {p['service']} écoute sur le port {p['port']}. Il doit être restreint aux connexions localhost ou VPN.",
                        "remediation_ready": True,
                        "vulnerability_type": "db_port_exposed"
                    })
        except Exception as e:
            logger.warning(f"Erreur scan de ports sur {host}: {e}")

        # PHASE 2: HTTP HEADERS & CONFIGURATION AUDIT (Equivalent Nuclei)
        try:
            head_resp = requests.get(probe_url, timeout=1.5, allow_redirects=True)
            headers = head_resp.headers

            # 1. Missing Security Headers
            missing_headers = []
            if "Content-Security-Policy" not in headers:
                missing_headers.append("Content-Security-Policy")
            if "Strict-Transport-Security" not in headers and probe_url.startswith("https://"):
                missing_headers.append("Strict-Transport-Security")
            if "X-Frame-Options" not in headers:
                missing_headers.append("X-Frame-Options")
            if "X-Content-Type-Options" not in headers:
                missing_headers.append("X-Content-Type-Options")

            if missing_headers:
                findings.append({
                    "id": "SEC-HDR-MISSING",
                    "title": f"En-têtes de sécurité HTTP manquants ({', '.join(missing_headers)})",
                    "severity": "MEDIUM",
                    "category": "web",
                    "description": "L'absence de ces en-têtes expose l'application aux attaques de type Clickjacking, MIME-confusion et injections de scripts.",
                    "remediation_ready": True,
                    "vulnerability_type": "security_headers"
                })

            # 2. Server Banner Disclosure
            server_header = headers.get("Server") or headers.get("X-Powered-By")
            if server_header:
                findings.append({
                    "id": "SEC-INFO-BANNER",
                    "title": f"Divulgation de bannière serveur ({server_header})",
                    "severity": "LOW",
                    "category": "fingerprint",
                    "description": f"L'en-tête serveur divulgue la technologie sous-jacente '{server_header}', facilitant la reconnaissance pour un attaquant.",
                    "remediation_ready": True,
                    "vulnerability_type": "info_disclosure"
                })

            # 3. CORS Wildcard Evaluation
            cors_origin = headers.get("Access-Control-Allow-Origin")
            cors_creds = headers.get("Access-Control-Allow-Credentials")
            if cors_origin == "*" and cors_creds == "true":
                findings.append({
                    "id": "SEC-CORS-WILDCARD",
                    "title": "Mauvaise configuration CORS critique (Wildcard avec identifiants)",
                    "severity": "HIGH",
                    "category": "api",
                    "description": "Access-Control-Allow-Origin est configuré en wildcard '*' tout en autorisant les cookies d'authentification.",
                    "remediation_ready": True,
                    "vulnerability_type": "cors"
                })

            # 4. Secret Leak Detection in HTML source
            leaks = self.secret_scanner.scan_content(head_resp.text, source_url=probe_url)
            for leak in leaks:
                findings.append({
                    "id": f"SECRET-LEAK-{leak['secret_type'].replace(' ', '_').upper()}",
                    "title": f"Fuite d'identifiant secret : {leak['secret_type']} ({leak['preview']})",
                    "severity": leak["severity"],
                    "category": "credentials",
                    "description": f"{leak['evidence']} Empreinte trouvée dans {probe_url}.",
                    "remediation_ready": True,
                    "vulnerability_type": "secret_leak",
                    "url": probe_url
                })
        except Exception as e:
            logger.warning(f"Erreur audit en-têtes HTTP sur {base_http_url}: {e}")

        # PHASE 3: SENSITIVE FILES & EXPOSURE (Equivalent Nuclei sensitive discovery)
        if depth in ("standard", "deep"):
            try:
                sens_files = self.crawler.probe_sensitive_files(base_http_url)
                for sf in sens_files:
                    findings.append({
                        "id": f"FILE-EXP-{sf['path'].replace('/', '_')}",
                        "title": f"Fichier sensible accessible publiquement : {sf['path']}",
                        "severity": sf["severity"],
                        "category": "exposure",
                        "description": f"{sf['description']}. Ce fichier renvoie un code HTTP 200 et ne doit en aucun cas être public.",
                        "remediation_ready": True,
                        "vulnerability_type": "file_exposure",
                        "url": sf["url"]
                    })
            except Exception as e:
                logger.warning(f"Erreur recherche fichiers sensibles sur {base_http_url}: {e}")

        # PHASE 4: ACTIVE APPLICATION AUDIT (SQLi, XSS, IDOR)
        if depth == "deep":
            try:
                forms = self.crawler.discover_forms_and_params(base_http_url)
                for form in forms:
                    for inp in form.get("inputs", []):
                        # SQL Injection probing
                        sqli_res = self.sqli_detector.test_parameter(form["action_url"], inp)
                        if sqli_res:
                            findings.append({
                                "id": f"SQLI-{inp.upper()}",
                                "title": f"Vulnérabilité d'injection SQL sur le paramètre '{inp}'",
                                "severity": sqli_res["severity"],
                                "category": "injection",
                                "description": f"{sqli_res['evidence']} lors du test sur {form['action_url']}.",
                                "remediation_ready": True,
                                "vulnerability_type": "sqli",
                                "url": sqli_res["url"]
                            })

                        # Reflected XSS probing
                        xss_res = self.xss_detector.test_parameter(form["action_url"], inp)
                        if xss_res:
                            findings.append({
                                "id": f"XSS-{inp.upper()}",
                                "title": f"Vulnérabilité XSS réfléchi sur le paramètre '{inp}'",
                                "severity": xss_res["severity"],
                                "category": "injection",
                                "description": f"{xss_res['evidence']} sur {form['action_url']}.",
                                "remediation_ready": True,
                                "vulnerability_type": "xss",
                                "url": xss_res["url"]
                            })

                # Query parameters evaluation (IDOR & parameter tampering)
                query_params = urllib.parse.parse_qs(parsed.query)
                for qp in query_params.keys():
                    if qp.lower() in IDORDetector.SUSPECT_PARAMS:
                        idor_res = self.idor_detector.test_parameter(target_url, qp)
                        if idor_res:
                            findings.append({
                                "id": f"IDOR-{qp.upper()}",
                                "title": f"Vulnérabilité IDOR / BOLA sur le paramètre '{qp}'",
                                "severity": idor_res["severity"],
                                "category": "access_control",
                                "description": idor_res["evidence"],
                                "remediation_ready": True,
                                "vulnerability_type": "idor",
                                "url": idor_res["url"]
                            })
            except Exception as e:
                logger.warning(f"Erreur test applicatif actif sur {base_http_url}: {e}")

        duration = round(time.time() - start_time, 2)

        log_event(
            "NATIVE_AUDIT_COMPLETED",
            "INFO",
            "NATIVE_AUDITOR",
            f"Audit autonome de {target_url} terminé en {duration}s : {len(open_ports)} ports ouverts, {len(findings)} faiblesses."
        )

        return {
            "success": True,
            "target": target_url,
            "host": host,
            "depth": depth,
            "duration_seconds": duration,
            "open_ports": open_ports,
            "findings_count": len(findings),
            "findings": findings
        }


# Global singleton
native_auditor = UltonNativeAuditor()
