"""
patch_generator.py - Automated Security Remediation & Patch Generator
Produces production-ready web server configurations (Nginx, Apache) and
ready-to-paste secure code snippets (Python, PHP, Node.js) to resolve identified vulnerabilities.
"""

import urllib.parse
from typing import List, Dict, Any

def generate_nginx_security_conf(target_url: str, findings: List[Dict[str, Any]]) -> str:
    """Generates a hardened Nginx configuration block tailored to the scan findings."""
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.hostname or "example.com"

    conf = f"""# ==============================================================================
# CyberLab Hardened Nginx Security Configuration for {domain}
# Generated automatically based on audit findings
# ==============================================================================

# 1. Rate Limiting Protection (Anti-Brute Force on Auth endpoints)
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;

server {{
    listen 443 ssl http2;
    server_name {domain};

    # 2. SSL/TLS Hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # 3. Mask Web Server Banners (Prevent Information Disclosure)
    server_tokens off;

    # 4. Mandatory Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https: data:; frame-ancestors 'self';" always;

    # 5. Block Access to Sensitive Files (.git, .env, backups, sql, config)
    location ~ /\\.(?!well-known) {{
        deny all;
        access_log off;
        log_not_found off;
    }}

    location ~* \\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|env)$ {{
        deny all;
        access_log off;
        log_not_found off;
    }}

    # 6. Restrict Dangerous HTTP Methods (TRACE, TRACK, DELETE)
    if ($request_method !~ ^(GET|HEAD|POST|PUT|OPTIONS)$ ) {{
        return 405;
    }}

    # 7. Apply Rate Limiting on Login & Sensitive Form Routes
    location ~* /(login|signin|auth|api/token) {{
        limit_req zone=login_limit burst=3 nodelay;
        try_files $uri $uri/ /index.php?$args;
    }}
}}
"""
    return conf

def generate_apache_htaccess(findings: List[Dict[str, Any]]) -> str:
    """Generates an Apache .htaccess configuration file applying defensive headers."""
    conf = """# ==============================================================================
# CyberLab Defensive Apache .htaccess Security Rules
# ==============================================================================

# 1. Disable Directory Browsing / File Listing
Options -Indexes

# 2. Block Access to Sensitive Files (.env, .git, backups, sql)
<FilesMatch "^\\.(env|git|svn|htaccess)|\\.(sql|bak|config|ini|log)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# 3. HTTP Security Headers
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'self';"
</IfModule>

# 4. Hide Apache Server Version
ServerSignature Off
"""
    return conf

def generate_code_remediation_bundle(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generates exact code patches (Before vs. After) for detected vulnerabilities across frameworks.
    """
    patches = []
    has_sqli = any("SQL" in f.get("title", "") for f in findings)
    has_xss = any("XSS" in f.get("title", "") for f in findings)
    has_cors = any("CORS" in f.get("title", "") for f in findings)
    has_redirect = any("Redirection Ouverte" in f.get("title", "") for f in findings)
    has_idor = any("IDOR" in f.get("title", "") for f in findings)

    if has_sqli:
        patches.append({
            "vuln_type": "SQL Injection (SQLi)",
            "languages": {
                "PHP (PDO)": {
                    "vulnerable": "$stmt = $db->query(\"SELECT * FROM users WHERE email = '\" . $_POST['email'] . \"'\");",
                    "secured": "$stmt = $db->prepare('SELECT * FROM users WHERE email = :email');\n$stmt->execute(['email' => $_POST['email']]);\n$user = $stmt->fetch();"
                },
                "Python (SQLAlchemy / SQLite)": {
                    "vulnerable": "query = f\"SELECT * FROM users WHERE username = '{username}'\"\ncursor.execute(query)",
                    "secured": "# Requête paramétrée sécurisée\ncursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
                },
                "Node.js (PostgreSQL)": {
                    "vulnerable": "const query = `SELECT * FROM users WHERE id = ${req.query.id}`;\nawait client.query(query);",
                    "secured": "const query = 'SELECT * FROM users WHERE id = $1';\nawait client.query(query, [req.query.id]);"
                }
            }
        })

    if has_xss:
        patches.append({
            "vuln_type": "Cross-Site Scripting (XSS)",
            "languages": {
                "PHP": {
                    "vulnerable": "echo '<div>Résultats pour : ' . $_GET['q'] . '</div>';",
                    "secured": "echo '<div>Résultats pour : ' . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') . '</div>';"
                },
                "JavaScript / DOM": {
                    "vulnerable": "document.getElementById('welcome').innerHTML = 'Bonjour ' + userName;",
                    "secured": "document.getElementById('welcome').textContent = 'Bonjour ' + userName;"
                }
            }
        })

    if has_cors:
        patches.append({
            "vuln_type": "CORS Misconfiguration",
            "languages": {
                "Node.js (Express)": {
                    "vulnerable": "// Réflexion aveugle de l'origine avec credentials (TRÈS DANGEREUX)\napp.use((req, res, next) => {\n  res.header('Access-Control-Allow-Origin', req.headers.origin);\n  res.header('Access-Control-Allow-Credentials', 'true');\n  next();\n});",
                    "secured": "const ALLOWED_ORIGINS = ['https://monentreprise.com', 'https://app.monentreprise.com'];\n\napp.use((req, res, next) => {\n  const origin = req.headers.origin;\n  if (ALLOWED_ORIGINS.includes(origin)) {\n    res.header('Access-Control-Allow-Origin', origin);\n    res.header('Access-Control-Allow-Credentials', 'true');\n  }\n  next();\n});"
                }
            }
        })

    if has_redirect:
        patches.append({
            "vuln_type": "Open Redirect",
            "languages": {
                "Python (Flask)": {
                    "vulnerable": "target = request.args.get('next')\nreturn redirect(target) # Redirige n'importe où",
                    "secured": "from urllib.parse import urlparse\n\ndef is_safe_url(target):\n    ref_url = urlparse(request.host_url)\n    test_url = urlparse(target)\n    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc\n\ntarget = request.args.get('next')\nif not target or not is_safe_url(target):\n    target = '/dashboard'\nreturn redirect(target)"
                }
            }
        })

    if has_idor:
        patches.append({
            "vuln_type": "IDOR (Insecure Direct Object Reference)",
            "languages": {
                "Python / SQL": {
                    "vulnerable": "# Faille : n'importe qui peut lire l'ordre avec order_id\nSELECT * FROM orders WHERE id = :order_id",
                    "secured": "# Sécurisé : filtre impérativement par l'utilisateur actuellement connecté\nSELECT * FROM orders WHERE id = :order_id AND user_id = :current_authenticated_user_id"
                }
            }
        })

    return {"patches": patches}
