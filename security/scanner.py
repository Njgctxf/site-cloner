"""
scanner.py - Defensive Web Security Audit & Compliance Scanner
Performs non-destructive vulnerability and security configuration checks
strictly restricted to authorized lab environments.

Every check here is passive or configuration-level: normal HTTP requests (GET/HEAD/OPTIONS),
reading response headers/body/certificate, and comparing them against known-good practice.
Nothing here submits forms, injects payloads into application logic, brute-forces credentials,
or otherwise attempts to exploit the target - see simulations.py for that (sandboxed lab only).
"""

import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

# Whitelist of allowed scan domains to prevent misuse on arbitrary third-party targets
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0", "innotech-lab.local", "cyberlab.local", "instrumentdechrist.org", "www.instrumentdechrist.org"]

TIMEOUT = 6
UA = "CyberLab-Security-Auditor/1.0 (Educational Assessment)"

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "category": "Injection & XSS Protection",
        "description": "L'en-tête Content-Security-Policy (CSP) est absent. Il protège contre les attaques XSS et les injections de données.",
        "remediation": "Ajoutez l'en-tête HTTP: Content-Security-Policy: default-src 'self'; script-src 'self';"
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "category": "Transport Layer Security",
        "description": "L'en-tête HSTS est absent. Il force les navigateurs à utiliser exclusivement des connexions chiffrées HTTPS.",
        "remediation": "Ajoutez l'en-tête HTTP: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "category": "Clickjacking Defense",
        "description": "L'en-tête X-Frame-Options est absent. Le site peut être intégré dans une iframe malveillante (Clickjacking).",
        "remediation": "Ajoutez l'en-tête HTTP: X-Frame-Options: DENY ou SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "category": "MIME Sniffing Defense",
        "description": "L'en-tête X-Content-Type-Options est absent. Les navigateurs peuvent ignorer le type MIME déclaré (sniffing).",
        "remediation": "Ajoutez l'en-tête HTTP: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "category": "Information Disclosure",
        "description": "L'en-tête Referrer-Policy est absent. Des URLs internes ou des paramètres sensibles peuvent fuiter via l'en-tête Referer.",
        "remediation": "Ajoutez l'en-tête HTTP: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "category": "Browser Capabilities",
        "description": "L'en-tête Permissions-Policy est absent. Il permet de restreindre l'accès au micro, caméra, géolocalisation.",
        "remediation": "Ajoutez l'en-tête HTTP: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "LOW",
        "category": "Isolation Inter-Origines",
        "description": "L'en-tête COOP est absent. Il isole la fenêtre du site des fenêtres ouvertes par d'autres origines (protection contre certaines attaques side-channel).",
        "remediation": "Ajoutez l'en-tête HTTP: Cross-Origin-Opener-Policy: same-origin"
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "LOW",
        "category": "Isolation Inter-Origines",
        "description": "L'en-tête CORP est absent. Il empêche d'autres sites d'intégrer directement les ressources de ce site (images, scripts).",
        "remediation": "Ajoutez l'en-tête HTTP: Cross-Origin-Resource-Policy: same-origin"
    }
}

SENSITIVE_PATHS = [
    ("/.git/config", "Dépôt Git exposé", "CRITICAL", "L'historique Git et les clés secrètes peuvent être téléchargés."),
    ("/.env", "Fichier d'environnement (.env)", "CRITICAL", "Contient des mots de passe de base de données, clés API et secrets."),
    ("/backup.sql", "Sauvegarde de base de données", "CRITICAL", "Dump SQL brut contenant des données confidentielles."),
    ("/.svn/entries", "Dépôt SVN exposé", "CRITICAL", "L'historique SVN peut révéler du code source et des identifiants."),
    ("/id_rsa", "Clé privée SSH exposée", "CRITICAL", "Une clé privée accessible publiquement permet l'usurpation d'identité serveur."),
    ("/wp-config.php.bak", "Sauvegarde de configuration WordPress", "CRITICAL", "Contient les identifiants de la base de données WordPress en clair."),
    ("/docker-compose.yml", "Configuration Docker", "HIGH", "Expose la topologie des conteneurs internes."),
    ("/.htaccess", "Fichier .htaccess exposé", "MEDIUM", "Révèle des règles de réécriture et de sécurité internes au serveur."),
    ("/phpinfo.php", "Page de diagnostic PHP", "MEDIUM", "Révèle la configuration interne du serveur et des extensions."),
    ("/swagger.json", "Documentation API exposée (Swagger)", "MEDIUM", "Révèle la surface complète de l'API, y compris des routes non documentées publiquement."),
]

# What each file really contains: many servers (single-page apps, cloned sites, CDNs) answer 200 with their
# home page for any unknown path, which must not be reported as an exposed file.
SENSITIVE_SIGNATURES = {
    "/.git/config": re.compile(r"^\s*\[core\]", re.M),
    "/.env": re.compile(r"^\s*[A-Z][A-Z0-9_]*\s*=", re.M),
    "/backup.sql": re.compile(r"\b(?:CREATE TABLE|INSERT INTO|DROP TABLE)\b", re.I),
    "/.svn/entries": re.compile(r"^\d+\s*$", re.M),
    "/id_rsa": re.compile(r"-----BEGIN .*PRIVATE KEY-----"),
    "/wp-config.php.bak": re.compile(r"DB_PASSWORD|DB_NAME", re.I),
    "/docker-compose.yml": re.compile(r"^\s*services\s*:", re.M),
    "/.htaccess": re.compile(r"RewriteEngine|<Files|Require ", re.I),
    "/phpinfo.php": re.compile(r"PHP Version|phpinfo\(\)", re.I),
    "/swagger.json": re.compile(r'"swagger"\s*:|"openapi"\s*:'),
}
_HTML_PAGE = re.compile(r"^\s*(?:<!doctype html|<html)", re.I)

# Secrets accidentally left in page source / inline scripts (regex-based, read-only detection)
SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}"), "Clé d'accès AWS (AKIA...) trouvée dans le code source."),
    ("GOOGLE_API_KEY", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Clé API Google trouvée dans le code source."),
    ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "Bloc de clé privée trouvé directement dans le code source."),
    ("GENERIC_SECRET_ASSIGN", re.compile(r"""['"]?(?:secret|api[_-]?key|access[_-]?token|client[_-]?secret)['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]""", re.I),
     "Une variable ressemblant à un secret (clé API, token) est assignée en clair dans le code source."),
]

# jQuery versions with publicly known XSS/prototype-pollution issues (illustrative cutoff, not a CVE database)
_OLD_JQUERY = re.compile(r"jquery[.-](1\.(?:[0-9]|1[01])\.|2\.[01]\.)", re.I)

DANGEROUS_METHODS = {"TRACE", "TRACK", "PUT", "DELETE"}
LISTING_DIRS = ["/images/", "/assets/", "/uploads/", "/backup/", "/static/", "/files/"]
_DIR_LISTING_SIGNS = re.compile(r"Index of /|<title>Index of|Parent Directory</a>", re.I)


def looks_exposed(rel_path, resp):
    """True when the response is really the sensitive file, not a page the server returns for every path."""
    if resp.status_code != 200 or len(resp.text) <= 10:
        return False
    if rel_path != "/phpinfo.php" and _HTML_PAGE.match(resp.text):
        return False
    sig = SENSITIVE_SIGNATURES.get(rel_path)
    return bool(sig.search(resp.text)) if sig else True


from .database import is_domain_authorized
from .network_guard import validate_target_url
from .dast_engine import run_dast_audit
from .sast_secrets import scan_code_for_secrets
from .sca_engine import scan_vulnerable_components
from .cve_feed import detect_server_and_cms_cves

def check_target_authorization(url):
    """
    Validates that:
    1. The domain has been verified as owned by the user (or is an authorized educational lab host)
    2. The destination passes strict Anti-SSRF checks (public routable IP, no cloud metadata, no private RFC1918)
    """
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "Nom d'hôte invalide ou absent."

    if not is_domain_authorized(hostname):
        return False, f"Cible non autorisée ({hostname}). Pour auditer ce domaine, vous devez d'abord l'enregistrer et prouver sa propriété (DNS TXT ou fichier HTTP challenge)."

    is_safe, _, _, err = validate_target_url(url, allow_local_lab=True)
    if not is_safe:
        return False, f"Rejet de sécurité Anti-SSRF : {err}"

    return True, "Cible autorisée et vérifiée."


def is_target_authorized(url):
    ok, _ = check_target_authorization(url)
    return ok


def _finding(id_, title, severity, category, description, proof, impact, remediation):
    return {"id": id_, "title": title, "severity": severity, "category": category, "description": description,
            "proof": proof, "impact": impact, "remediation": remediation}


# ---------------------------------------------------------------- individual checks (each returns a list of findings)

def _check_tls(parsed):
    """Certificate expiry and protocol version, read via a plain TLS handshake (no data sent beyond SNI)."""
    findings = []
    if parsed.scheme != "https":
        return findings
    host, port = parsed.hostname, parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                proto = tls.version()
    except ssl.SSLCertVerificationError as e:
        findings.append(_finding("TLS_CERT_INVALID", "Certificat TLS invalide ou non vérifiable", "CRITICAL",
            "Transport Layer Security", "La chaîne de certificats présentée par le serveur n'a pas pu être validée.",
            f"Erreur de vérification: {e}", "Le navigateur affichera un avertissement de sécurité bloquant pour les visiteurs; vulnérable aux attaques Man-in-the-Middle.",
            "Installez un certificat valide signé par une autorité de confiance (ex: Let's Encrypt) et vérifiez la chaîne intermédiaire."))
        return findings
    except Exception:
        return findings  # connection/handshake issue unrelated to cert content: not reported as a finding

    if proto in ("TLSv1", "TLSv1.1"):
        findings.append(_finding("TLS_OLD_PROTOCOL", f"Protocole TLS obsolète ({proto})", "HIGH",
            "Transport Layer Security", f"Le serveur accepte encore {proto}, un protocole déprécié avec des faiblesses cryptographiques connues.",
            f"Négociation TLS réussie en {proto}.", "Un attaquant en position réseau peut forcer un déclassement vers ce protocole plus faible.",
            "Désactivez TLS 1.0 et 1.1 côté serveur ; n'acceptez que TLS 1.2 minimum, idéalement TLS 1.3."))

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(_finding("TLS_CERT_EXPIRED", "Certificat TLS expiré", "CRITICAL", "Transport Layer Security",
                    "Le certificat du site a dépassé sa date d'expiration.", f"Expiré depuis {-days_left} jour(s) ({not_after}).",
                    "Les navigateurs bloquent l'accès au site avec un avertissement de sécurité.",
                    "Renouvelez immédiatement le certificat TLS."))
            elif days_left < 30:
                findings.append(_finding("TLS_CERT_EXPIRING_SOON", "Certificat TLS bientôt expiré", "MEDIUM", "Transport Layer Security",
                    "Le certificat du site expire dans moins de 30 jours.", f"Expire dans {days_left} jour(s) ({not_after}).",
                    "Une expiration non anticipée rend le site inaccessible avec avertissement de sécurité.",
                    "Planifiez le renouvellement du certificat (ou activez le renouvellement automatique)."))
        except ValueError:
            pass
    return findings


def _check_cors(session, base_url):
    """Sends one normal GET with a crafted Origin header and reads the response - standard misconfiguration check,
    performed by every commercial scanner; no data is written or exploited."""
    findings = []
    probe_origin = "https://cyberlab-cors-probe.invalid"
    try:
        r = session.get(base_url, headers={"Origin": probe_origin}, timeout=TIMEOUT)
    except Exception:
        return findings
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    if acao == probe_origin or acao == "*" and acac:
        findings.append(_finding("CORS_MISCONFIGURED", "Mauvaise configuration CORS (origine arbitraire acceptée)", "CRITICAL",
            "Cross-Origin Resource Sharing",
            "Le serveur reflète n'importe quelle origine demandée dans Access-Control-Allow-Origin" + (" avec Access-Control-Allow-Credentials: true" if acac else "") + ".",
            f"Origin envoyé: {probe_origin} -> Access-Control-Allow-Origin: {acao}" + (", Access-Control-Allow-Credentials: true" if acac else ""),
            "Un site malveillant peut effectuer des requêtes authentifiées vers cette API depuis le navigateur d'une victime et lire les réponses (vol de données de session).",
            "Ne reflétez jamais l'en-tête Origin tel quel : validez-le contre une liste blanche explicite de domaines autorisés."))
    return findings


def _check_http_methods(session, base_url):
    """OPTIONS request to list the methods the server advertises (read-only, no state-changing call is issued)."""
    findings = []
    try:
        r = session.options(base_url, timeout=TIMEOUT)
    except Exception:
        return findings
    allow = {m.strip().upper() for m in r.headers.get("Allow", "").split(",") if m.strip()}
    risky = allow & DANGEROUS_METHODS
    if risky:
        findings.append(_finding("DANGEROUS_HTTP_METHODS", "Méthodes HTTP sensibles activées", "MEDIUM",
            "Configuration Serveur", f"Le serveur annonce accepter les méthodes: {', '.join(sorted(risky))}.",
            f"En-tête Allow: {r.headers.get('Allow', '')}",
            "TRACE/TRACK peuvent faciliter le vol de cookies via Cross-Site Tracing ; PUT/DELETE non restreints peuvent permettre la modification de ressources si l'autorisation est mal contrôlée côté application.",
            "Désactivez TRACE/TRACK au niveau du serveur web et restreignez PUT/DELETE aux routes qui en ont explicitement besoin, avec authentification."))
    return findings


def _check_directory_listing(session, base_url):
    """Requests a handful of common folder paths and checks for an auto-generated directory index."""
    findings = []
    for path in LISTING_DIRS:
        try:
            r = session.get(urllib.parse.urljoin(base_url, path), timeout=3)
        except Exception:
            continue
        if r.status_code == 200 and _DIR_LISTING_SIGNS.search(r.text):
            findings.append(_finding(f"DIR_LISTING_{path.strip('/')}", f"Listage de répertoire activé ({path})", "MEDIUM",
                "Information Disclosure", "Le serveur génère une page de listage automatique du contenu de ce répertoire.",
                f"URL {urllib.parse.urljoin(base_url, path)} retourne un index de répertoire.",
                "Permet à un visiteur de découvrir des fichiers non liés publiquement (sauvegardes, fichiers temporaires).",
                "Désactivez le listage automatique de répertoire (ex: Options -Indexes sur Apache, autoindex off sur Nginx)."))
            break  # one example is enough to make the point; avoid redundant findings
    return findings


def _check_mixed_content(parsed, html):
    findings = []
    if parsed.scheme != "https":
        return findings
    refs = re.findall(r'(?:src|href)=["\']http://[^"\']+["\']', html, re.I)
    if refs:
        findings.append(_finding("MIXED_CONTENT", "Contenu mixte (ressources HTTP sur une page HTTPS)", "MEDIUM",
            "Transport Layer Security", "La page HTTPS charge des ressources (script, image, style) via HTTP non chiffré.",
            f"{len(refs)} référence(s) HTTP trouvée(s), ex: {refs[0][:120]}",
            "Ces ressources peuvent être interceptées ou modifiées en transit (injection de script via une ressource HTTP compromise).",
            "Servez toutes les ressources de la page en HTTPS, ou utilisez des URLs relatives au protocole."))
    return findings


def _check_outdated_components(html, headers):
    findings = []
    m = _OLD_JQUERY.search(html)
    if m:
        findings.append(_finding("OUTDATED_JQUERY", "Bibliothèque jQuery obsolète détectée", "MEDIUM",
            "Composants Obsolètes", "Une version ancienne de jQuery est chargée par la page.",
            f"Référence trouvée: {m.group(0)}",
            "Les anciennes versions de jQuery contiennent des failles XSS/prototype-pollution corrigées dans les versions récentes.",
            "Mettez à jour vers la dernière version stable de jQuery (3.x) ou retirez la dépendance si elle n'est plus nécessaire."))
    gen = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', html, re.I)
    if gen:
        findings.append(_finding("CMS_VERSION_DISCLOSED", "Version du CMS divulguée (balise generator)", "LOW",
            "Information Disclosure", "La page expose le nom et la version exacte du CMS utilisé.",
            f"<meta name=\"generator\" content=\"{gen.group(1)}\">",
            "Facilite le ciblage de vulnérabilités connues pour cette version précise du CMS.",
            "Supprimez ou videz la balise meta generator dans le thème/template du site."))
    return findings


def _check_secrets_in_source(html):
    findings = []
    for id_, pattern, desc in SECRET_PATTERNS:
        m = pattern.search(html)
        if m:
            masked = m.group(0)[:10] + "..." if len(m.group(0)) > 10 else m.group(0)
            findings.append(_finding(f"SECRET_{id_}", "Secret potentiel exposé dans le code source", "CRITICAL",
                "Sensitive Data Exposure", desc, f"Motif détecté (masqué): {masked}",
                "Un attaquant récupérant ce secret peut accéder à des services tiers (cloud, API) au nom du propriétaire du site.",
                "Retirez immédiatement ce secret du code côté client, révoquez-le et régénérez-en un nouveau stocké côté serveur uniquement."))
    return findings


def _check_robots_sitemap(session, base_url):
    findings = []
    try:
        r = session.get(urllib.parse.urljoin(base_url, "/robots.txt"), timeout=3)
    except Exception:
        return findings
    if r.status_code != 200:
        return findings
    disallowed = re.findall(r"(?i)^Disallow:\s*(\S+)", r.text, re.M)
    sensitive = [p for p in disallowed if re.search(r"admin|backup|config|\.git|private|internal", p, re.I)]
    if sensitive:
        findings.append(_finding("ROBOTS_SENSITIVE_PATHS", "robots.txt révèle des chemins sensibles", "LOW",
            "Information Disclosure", "Le fichier robots.txt liste des chemins qui, bien qu'exclus des moteurs de recherche, restent accessibles et révèlent la structure interne du site.",
            f"Chemins listés: {', '.join(sensitive[:8])}",
            "Un attaquant consulte robots.txt en premier pour cartographier les zones sensibles d'un site.",
            "Évitez de lister des chemins sensibles dans robots.txt ; protégez-les plutôt par authentification côté serveur."))
    return findings


def _check_forms(base_url, html):
    """Static analysis of <form> markup already fetched - no form is submitted."""
    findings = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return findings
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        resolved = urllib.parse.urljoin(base_url, action)
        has_password = form.find("input", {"type": "password"}) is not None
        if has_password and urllib.parse.urlparse(resolved).scheme == "http":
            findings.append(_finding("FORM_PASSWORD_OVER_HTTP", "Formulaire de mot de passe soumis en clair (HTTP)", "CRITICAL",
                "Session Security", "Un formulaire contenant un champ mot de passe soumet ses données vers une URL non chiffrée.",
                f"Action du formulaire: {resolved}", "Le mot de passe transite en clair sur le réseau et peut être intercepté.",
                "Servez le formulaire et son URL de soumission exclusivement en HTTPS."))
        if method == "post":
            has_token = any(re.search(r"csrf|token|_token|authenticity", (i.get("name") or ""), re.I)
                            for i in form.find_all("input", {"type": "hidden"}))
            if not has_token:
                findings.append(_finding(f"FORM_NO_CSRF_TOKEN_{len(findings)}", "Formulaire POST sans jeton anti-CSRF apparent", "MEDIUM",
                    "Cross-Site Request Forgery", "Aucun champ caché ressemblant à un jeton CSRF n'a été trouvé dans ce formulaire POST.",
                    f"Formulaire action=\"{action or '(page actuelle)'}\" method=\"POST\" sans champ hidden csrf/token détecté.",
                    "Un site tiers peut potentiellement forcer la soumission de ce formulaire au nom d'une victime connectée.",
                    "Ajoutez un jeton CSRF unique par session, vérifié côté serveur à chaque soumission."))
    return findings


# ---------------------------------------------------------------- orchestration

def scan_target(target_url, auth_headers_user_b=None):
    """
    Performs a comprehensive, non-destructive audit of the target: HTTP security headers, cookie flags,
    TLS/certificate health, CORS configuration, dangerous HTTP methods, directory listing, mixed content,
    outdated components, exposed secrets in page source, robots.txt disclosure, exposed sensitive files,
    basic form hygiene, and active DAST modules (SQLi, XSS, Path Traversal, Rate Limiting, IDOR).
    """
    auth_ok, auth_reason = check_target_authorization(target_url)
    if not auth_ok:
        return {
            "success": False,
            "error": auth_reason
        }

    findings = []
    headers_audited = {}
    cookies_audited = []

    session = requests.Session()
    session.headers.update({"User-Agent": UA})

    try:
        resp = session.get(target_url, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        return {"success": False, "error": f"Impossible de joindre la cible: {str(e)}"}

    parsed = urllib.parse.urlparse(resp.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # 1. HTTP security headers
    for header_name, meta in SECURITY_HEADERS.items():
        val = resp.headers.get(header_name)
        headers_audited[header_name] = val or "Non configuré"
        if not val:
            findings.append(_finding(f"MISSING_{header_name.upper().replace('-', '_')}",
                f"En-tête de sécurité manquant : {header_name}", meta["severity"], meta["category"], meta["description"],
                f"Header '{header_name}' absent de la réponse HTTP.",
                "Facilite l'exploitation de failles côté client ou des attaques de type Man-in-the-Middle.", meta["remediation"]))

    server_header, powered_by = resp.headers.get("Server"), resp.headers.get("X-Powered-By")
    if server_header or powered_by:
        findings.append(_finding("SERVER_BANNER_DISCLOSURE", "Divulgation des versions de technologies (Server Banner)", "LOW",
            "Information Disclosure", "Le serveur web divulgue sa signature logicielle et ses versions exactes, aidant un assaillant à cibler des vulnérabilités connues pour ces versions précises.",
            f"Server: {server_header or 'N/A'}, X-Powered-By: {powered_by or 'N/A'}",
            "Facilite la reconnaissance passive et le ciblage des composants obsolètes.",
            "Masquez la signature dans la configuration du serveur (ex: ServerTokens Prod, expose_php = Off)."))

    # 2. Cookie security flags
    for cookie in resp.cookies:
        is_httponly = cookie.has_nonstandard_attr("httponly") or cookie.has_nonstandard_attr("HttpOnly")
        is_secure = cookie.secure
        samesite = cookie.get_nonstandard_attr("samesite", "None")
        cookies_audited.append({"name": cookie.name, "httponly": is_httponly, "secure": is_secure, "samesite": samesite})
        if not is_httponly:
            findings.append(_finding(f"COOKIE_NO_HTTPONLY_{cookie.name}", f"Cookie sensible sans flag HttpOnly ({cookie.name})", "HIGH",
                "Session Security", f"Le cookie '{cookie.name}' est accessible via JavaScript document.cookie.",
                f"Set-Cookie: {cookie.name}=***; HttpOnly non défini.",
                "En cas d'attaque XSS, la session utilisateur peut être volée directement.",
                "Définissez le paramètre httpOnly = True lors de la création du cookie de session."))
        if not is_secure and target_url.startswith("https"):
            findings.append(_finding(f"COOKIE_NO_SECURE_{cookie.name}", f"Cookie sensible sans flag Secure ({cookie.name})", "HIGH",
                "Session Security", f"Le cookie '{cookie.name}' peut être transmis en clair sur des requêtes non chiffrées.",
                f"Set-Cookie: {cookie.name}=***; Secure non défini.",
                "Interception de session par écoute sur le réseau local (Wifi non sécurisé, ARP spoofing).",
                "Définissez le paramètre secure = True sur tous les cookies de production."))

    # 3. Exposed sensitive files
    for rel_path, file_title, severity, desc in SENSITIVE_PATHS:
        try:
            probe_resp = session.get(urllib.parse.urljoin(base_url, rel_path), timeout=3, allow_redirects=False)
        except Exception:
            continue
        if looks_exposed(rel_path, probe_resp):
            findings.append(_finding(f"EXPOSED_FILE_{rel_path.replace('/', '_').replace('.', '')}",
                f"Fichier sensible accessible publiquement ({file_title})", severity, "Sensitive Data Exposure", desc,
                f"URL {urllib.parse.urljoin(base_url, rel_path)} a retourné le code HTTP 200 ({len(probe_resp.text)} octets).",
                "Fuite majeure d'informations d'infrastructure ou de clés privées.",
                "Interdisez l'accès à ce fichier via le serveur web ou supprimez-le du répertoire public."))

    # 4. Extended checks (TLS, CORS, methods, directory listing, mixed content, outdated libs, secrets, robots.txt, forms)
    findings += _check_tls(parsed)
    findings += _check_cors(session, base_url)
    findings += _check_http_methods(session, base_url)
    findings += _check_directory_listing(session, base_url)
    findings += _check_mixed_content(parsed, resp.text)
    findings += _check_outdated_components(resp.text, resp.headers)
    findings += _check_secrets_in_source(resp.text)
    findings += _check_robots_sitemap(session, base_url)
    findings += _check_forms(resp.url, resp.text)

    # 5. Active DAST audit (SQL Injection, XSS, Path Traversal, Rate Limiting, IDOR)
    csp_val = resp.headers.get("Content-Security-Policy", "")
    findings += run_dast_audit(target_url, session, resp.text, csp_header=csp_val, auth_headers_user_b=auth_headers_user_b)

    # 6. Static Code Secret Analysis (SAST - AWS, Stripe, OpenAI, GitHub tokens)
    findings += scan_code_for_secrets(resp.text, source_name="Code Source / Scripts Client")

    # 7. Software Composition Analysis (SCA - CVEs jQuery, Lodash, Bootstrap)
    findings += scan_vulnerable_components(resp.text)

    # 8. Server & CMS Infrastructure CVEs (NIST NVD / OSV)
    findings += detect_server_and_cms_cves(server_header, powered_by, resp.text)

    # 9. Risk score & grade
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")

    penalty = (critical_count * 25) + (high_count * 15) + (medium_count * 8) + (low_count * 3)
    risk_score = max(5, 100 - penalty)
    grade = "A" if risk_score >= 90 else "B" if risk_score >= 75 else "C" if risk_score >= 60 else "D" if risk_score >= 40 else "F"

    return {
        "success": True,
        "target_url": target_url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": risk_score,
        "grade": grade,
        "counts": {"critical": critical_count, "high": high_count, "medium": medium_count, "low": low_count, "total": len(findings)},
        "headers_audited": headers_audited,
        "cookies_audited": cookies_audited,
        "findings": findings,
    }
