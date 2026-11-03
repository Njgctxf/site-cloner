"""
upload_engine.py - Non-Destructive File Upload Security Analyzer
Audits file upload endpoints for:
- Executable extension acceptance (.php, .phtml, .jsp, .asp)
- Double extension handling (.jpg.php)
- MIME-type vs extension validation mismatches
- Insecure SVG upload acceptance (Stored XSS vector)
All probes use completely harmless, non-executable text content.
"""

import io
import re
from typing import Dict, Any, List, Optional
import requests

BENIGN_PROBE_CONTENT = b"<!-- Sentinel Non-Destructive Security Audit Test Probe -->\n"

# Harmless SVG file containing a text element but checking if the server strips or validates SVG
BENIGN_SVG_CONTENT = b"""<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="100" height="100" fill="green" />
   <text x="10" y="50" font-size="14" fill="white">Sentinel Test</text>
</svg>
"""

def audit_file_upload_endpoint(
    session: requests.Session,
    upload_url: str,
    file_field_name: str = "file",
    extra_data: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Submits strictly non-destructive probe files to evaluate server-side validation.
    """
    findings = []
    extra_fields = extra_data or {}

    # 1. Test executable extension acceptance (.php)
    try:
        files = {
            file_field_name: ("sentinel_probe.php", io.BytesIO(BENIGN_PROBE_CONTENT), "application/x-php")
        }
        r = session.post(upload_url, data=extra_fields, files=files, timeout=6, allow_redirects=False)
        # If the server accepts the file with 200/201 without rejecting the extension
        if r.status_code in (200, 201) and not re.search(r"invalide|refus|error|interdit|non autorisé|extension", r.text, re.I):
            findings.append({
                "id": "UPLOAD_EXECUTABLE_EXTENSION_ACCEPTED",
                "title": "Téléversement d'Extension Exécutable (.php) Accepté",
                "severity": "CRITICAL",
                "category": "A04:2021-Insecure Design",
                "description": f"L'endpoint {upload_url} a accepté un fichier portant l'extension '.php' sans rejet immédiat.",
                "proof": f"POST {upload_url} avec sentinel_probe.php -> Réponse HTTP {r.status_code} ({len(r.text)} octets).",
                "impact": "Risque majeur d'exécution de code à distance (RCE) si le fichier est placé dans un répertoire accessible par le serveur web avec exécution PHP activée.",
                "remediation": "Restreignez strictement les extensions autorisées via une liste blanche stricte (.jpg, .png, .pdf). Ne vous fiez jamais au nom fourni par le client. Renommez les fichiers de façon aléatoire côté serveur (ex: UUID.ext)."
            })
    except Exception:
        pass

    # 2. Test double extension (.jpg.php)
    try:
        files = {
            file_field_name: ("sentinel_probe.jpg.php", io.BytesIO(BENIGN_PROBE_CONTENT), "image/jpeg")
        }
        r = session.post(upload_url, data=extra_fields, files=files, timeout=6, allow_redirects=False)
        if r.status_code in (200, 201) and not re.search(r"invalide|refus|error|interdit", r.text, re.I):
            findings.append({
                "id": "UPLOAD_DOUBLE_EXTENSION_ACCEPTED",
                "title": "Contournement par Double Extension (.jpg.php) Potentiel",
                "severity": "HIGH",
                "category": "A04:2021-Insecure Design",
                "description": "L'endpoint accepte des noms de fichiers comportant une double extension où la dernière extension est exécutable.",
                "proof": f"POST {upload_url} avec fichier sentinel_probe.jpg.php et Content-Type 'image/jpeg' -> Code HTTP {r.status_code}.",
                "impact": "Sur des serveurs mal configurés (Apache avec mod_php où toute extension correspondante est exécutée), le fichier peut être exécuté comme script serveur.",
                "remediation": "Vérifiez uniquement l'extension finale après le dernier point. Rejetez tout fichier comportant des points multiples dans le nom."
            })
    except Exception:
        pass

    # 3. Test SVG upload acceptance
    try:
        files = {
            file_field_name: ("sentinel_probe.svg", io.BytesIO(BENIGN_SVG_CONTENT), "image/svg+xml")
        }
        r = session.post(upload_url, data=extra_fields, files=files, timeout=6, allow_redirects=False)
        if r.status_code in (200, 201) and not re.search(r"invalide|refus|error|interdit", r.text, re.I):
            findings.append({
                "id": "UPLOAD_SVG_ALLOWED_XSS_RISK",
                "title": "Téléversement de Fichiers SVG Vectoriels Autorisé",
                "severity": "MEDIUM",
                "category": "A03:2021-Injection",
                "description": "L'application accepte le téléversement de fichiers SVG XML. Les fichiers SVG peuvent contenir du code JavaScript interne susceptible de s'exécuter dans le navigateur lorsqu'ils sont consultés directement.",
                "proof": f"POST {upload_url} avec sentinel_probe.svg -> Réponse HTTP {r.status_code}.",
                "impact": "Risque de Stored XSS (Cross-Site Scripting stocké) si les SVG sont servis directement avec le type MIME 'image/svg+xml' sans désinfection XML.",
                "remediation": "Désinfectez les fichiers SVG à l'aide d'une bibliothèque dédiée (ex: DOMPurify ou svg-sanitizer), ou forcez le téléchargement avec 'Content-Disposition: attachment; filename=...'."
            })
    except Exception:
        pass

    # 4. MIME-Type Mismatch Spoofing
    try:
        # Send a text content but declare it as image/png
        files = {
            file_field_name: ("sentinel_probe.png", io.BytesIO(b"Not a real PNG header, just plain text"), "image/png")
        }
        r = session.post(upload_url, data=extra_fields, files=files, timeout=6, allow_redirects=False)
        if r.status_code in (200, 201):
            findings.append({
                "id": "UPLOAD_MIME_SPOOFING_ACCEPTED",
                "title": "Validation du Contenu Réel de Fichier Défaillante (Magic Bytes Absents)",
                "severity": "MEDIUM",
                "category": "A04:2021-Insecure Design",
                "description": "L'application se fie uniquement au type MIME déclaré par le client sans vérifier la signature binaire réelle du fichier (Magic Bytes).",
                "proof": "Un fichier texte brut envoyé avec le header 'Content-Type: image/png' a été accepté sans rejet.",
                "impact": "Possibilité de contourner les filtres en falsifiant l'en-tête Content-Type lors de la requête multipart/form-data.",
                "remediation": "Vérifiez les octets magiques (magic numbers) du fichier côté serveur (ex: avec python-magic, libmagic ou finfo_file en PHP)."
            })
    except Exception:
        pass

    return findings
