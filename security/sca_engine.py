"""
sca_engine.py - Software Composition Analysis (SCA) & Vulnerable Dependency Scanner
Analyzes third-party frontend dependencies, framework versions, and JavaScript libraries
against known CVE vulnerability databases (OWASP A06:2021).
"""

import re
from typing import List, Dict, Any

from .cve_feed import query_live_cve_feed

# Component Version Signatures & Known Vulnerability Database
COMPONENT_CHECKS = [
    {
        "name": "jQuery",
        "pattern": re.compile(r"""(?:jQuery|jquery)[/.-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", re.I),
        "vulnerable_until": "3.5.0",
        "cves": ["CVE-2020-11022", "CVE-2020-11023", "CVE-2015-9251"],
        "severity": "HIGH",
        "title": "Bibliothèque jQuery vulnérable aux attaques XSS",
        "description": "Les versions de jQuery inférieures à 3.5.0 présentent des failles de contournement de nettoyage HTML lors de l'utilisation de $.htmlPrefilter(), permettant l'exécution de code XSS même si les balises semblent filtrées.",
        "remediation": "Mettez à jour jQuery vers la version 3.6.0 ou supérieure."
    },
    {
        "name": "Lodash",
        "pattern": re.compile(r"""(?:lodash)[/.-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", re.I),
        "vulnerable_until": "4.17.21",
        "cves": ["CVE-2019-10744", "CVE-2020-8203", "CVE-2021-23337"],
        "severity": "CRITICAL",
        "title": "Bibliothèque Lodash vulnérable à la Prototype Pollution",
        "description": "Les versions de Lodash inférieures à 4.17.21 permettent la pollution de prototypes d'objets via les fonctions merge(), cloneDeep(), ou zipObjectDeep(), pouvant conduire à des contournements d'authentification ou du déni de service.",
        "remediation": "Mettez à jour lodash vers la version 4.17.21 ou supérieure."
    },
    {
        "name": "Bootstrap",
        "pattern": re.compile(r"""(?:bootstrap)[/.-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", re.I),
        "vulnerable_until": "4.3.1",
        "cves": ["CVE-2019-8331", "CVE-2018-14041", "CVE-2018-20677"],
        "severity": "MEDIUM",
        "title": "Composants Bootstrap vulnérables aux attaques XSS",
        "description": "Les versions de Bootstrap antérieures à 4.3.1 (notamment 3.x et début 4.x) contiennent des vulnérabilités XSS dans les plugins tooltip, popover, scrollspy et collapse.",
        "remediation": "Mettez à jour Bootstrap vers la version 5.x ou au minimum 4.6.2."
    },
    {
        "name": "AngularJS",
        "pattern": re.compile(r"""angular(?:js)?[/.-]v?(1\.[0-9]+(?:\.[0-9]+)?)""", re.I),
        "vulnerable_until": "2.0.0",
        "cves": ["CVE-2022-25869", "CVE-2020-7676", "EOL-RETIRED"],
        "severity": "HIGH",
        "title": "Framework obsolète AngularJS 1.x (End of Life)",
        "description": "AngularJS 1.x est officiellement obsolète (EOL depuis janvier 2022) et ne reçoit plus aucun correctif de sécurité officiel. Il présente des faiblesses d'évasion de bac à sable (Template Injection).",
        "remediation": "Migrez vos interfaces vers une version moderne supportée d'Angular (v17+), React ou Vue."
    },
    {
        "name": "Moment.js",
        "pattern": re.compile(r"""moment(?:js)?[/.-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)""", re.I),
        "vulnerable_until": "2.29.4",
        "cves": ["CVE-2022-24785", "CVE-2022-31129"],
        "severity": "MEDIUM",
        "title": "Moment.js vulnérable au déni de service par expression régulière (ReDoS)",
        "description": "Les versions antérieures à 2.29.4 sont sujettes à des attaques par déni de service (ReDoS) lors de l'analyse de dates fournies par les utilisateurs avec des formats RFC2822 non stricts.",
        "remediation": "Mettez à jour Moment.js vers la version 2.29.4 ou remplacez-le par des bibliothèques modernes et plus légères (date-fns, Day.js)."
    }
]

# Prototype Pollution Construction Signatures
PROTO_POLLUTION_PATTERNS = [
    re.compile(r"""(?:\[['"]__proto__['"]\]|\b__proto__\b)\s*="""),
    re.compile(r"""constructor\s*\.\s*prototype\s*\["""),
    re.compile(r"""Object\.assign\s*\(\s*\{\}\s*,\s*[^)]*__proto__"""),
]

def parse_semver(v_str: str) -> List[int]:
    """Parses a version string into a list of integers for comparison."""
    parts = []
    for s in v_str.split("."):
        clean = "".join(filter(str.isdigit, s))
        parts.append(int(clean) if clean else 0)
    while len(parts) < 3:
        parts.append(0)
    return parts[:3]

def is_version_lower(v_current: str, v_threshold: str) -> bool:
    """Returns True if v_current is strictly lower than v_threshold."""
    return parse_semver(v_current) < parse_semver(v_threshold)

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

def scan_vulnerable_components(html_content: str, script_contents: List[str] = None) -> List[Dict[str, Any]]:
    """
    Scans HTML, script tags, and imported JS files for vulnerable third-party components and CVEs.
    """
    findings = []
    seen_components = set()
    all_text = (html_content or "") + "\n" + "\n".join(script_contents or [])

    # 1. Component CVE matching
    for comp in COMPONENT_CHECKS:
        name = comp["name"]
        match = comp["pattern"].search(all_text)
        if match:
            version_str = match.group(1)
            key = f"{name}:{version_str}"
            if key in seen_components:
                continue
            seen_components.add(key)

            if is_version_lower(version_str, comp["vulnerable_until"]):
                # Enrich with live CVE feed (NVD / OSV)
                live_cves = query_live_cve_feed(name, version_str)
                all_cve_ids = list(set(comp["cves"] + [c["cve_id"] for c in live_cves]))
                cve_list = ", ".join(all_cve_ids)
                findings.append(_finding(
                    f"VULNERABLE_DEP_{name.upper()}_{version_str.replace('.', '_')}",
                    f"{comp['title']} (version détectée : {version_str})",
                    comp["severity"],
                    "A06:2021-Vulnerable and Outdated Components (OWASP Top 10)",
                    comp["description"],
                    f"Composant : {name} v{version_str}. Vulnérabilités associées : {cve_list}. Version sécurisée requise : >= {comp['vulnerable_until']}.",
                    "Exploitation de failles publiques documentées permettant l'injection de scripts, le déni de service ou la manipulation d'objets globaux.",
                    comp["remediation"]
                ))

    # 2. Prototype Pollution pattern detection in custom scripts
    for idx, script in enumerate(script_contents or []):
        for pat in PROTO_POLLUTION_PATTERNS:
            m = pat.search(script)
            if m:
                snippet = m.group(0)
                findings.append(_finding(
                    f"PROTOTYPE_POLLUTION_CODE_{idx}",
                    "Assignation dangereuse sur prototype d'objet (Prototype Pollution)",
                    "HIGH",
                    "A03:2021-Injection / JavaScript Engine",
                    "Le code JavaScript de l'application modifie directement __proto__ ou le prototype de constructor sans vérification préalable de la clé.",
                    f"Motif détecté dans script #{idx+1} : '{snippet}'.",
                    "Un attaquant injectant un objet JSON avec une propriété '__proto__' peut altérer les propriétés globales de tous les objets de l'application, causant des contournements de sécurité ou l'exécution de code.",
                    "Filtrez les clés sensibles '__proto__', 'constructor' et 'prototype' lors de la fusion d'objets, ou utilisez Map ou Object.create(null) pour les structures de données dynamiques."
                ))
                break

    return findings
