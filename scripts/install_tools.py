"""
install_tools.py - Downloads and installs every external binary Sentinel's
scanners/shield need, into security/sentinel/tools_bin/ (gitignored on
purpose - see SETUP_TOOLS.md at the project root for why).

Usage: python scripts/install_tools.py
Safe to re-run - skips any tool that's already present.
"""
import io
import os
import sys
import zipfile
from pathlib import Path

try:
    import requests
except ImportError:
    print("Le paquet 'requests' est requis: pip install requests")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "security" / "sentinel" / "tools_bin"

TOOLS = [
    {
        "name": "Nuclei",
        "check": TOOLS_DIR / "nuclei" / "nuclei.exe",
        "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_windows_amd64.zip",
        "extract_to": TOOLS_DIR / "nuclei",
    },
    {
        "name": "Trivy",
        "check": TOOLS_DIR / "trivy" / "trivy.exe",
        "url": "https://github.com/aquasecurity/trivy/releases/download/v0.56.2/trivy_0.56.2_windows-64bit.zip",
        "extract_to": TOOLS_DIR / "trivy",
    },
    {
        "name": "Gitleaks",
        "check": TOOLS_DIR / "gitleaks" / "gitleaks.exe",
        "url": "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_windows_x64.zip",
        "extract_to": TOOLS_DIR / "gitleaks",
    },
    {
        "name": "Redis (Windows)",
        "check": TOOLS_DIR / "redis" / "redis-server.exe",
        "url": "https://github.com/tporadowski/redis/releases/download/v5.0.14.1/Redis-x64-5.0.14.1.zip",
        "extract_to": TOOLS_DIR / "redis",
    },
    # OWASP ZAP and the JRE it needs are large multi-file installs - see
    # SETUP_TOOLS.md for the manual steps; most scanner coverage (Nuclei,
    # Trivy, Gitleaks, Semgrep) works fine without them.
]


def install(tool: dict) -> bool:
    if tool["check"].exists():
        print(f"[OK] {tool['name']} déjà installé.")
        return True

    print(f"[...] Téléchargement de {tool['name']}...")
    try:
        resp = requests.get(tool["url"], timeout=120)
        resp.raise_for_status()
        tool["extract_to"].mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            z.extractall(tool["extract_to"])
        print(f"[OK] {tool['name']} installé dans {tool['extract_to']}")
        return True
    except Exception as e:
        print(f"[ERREUR] {tool['name']} : {e}")
        return False


def main():
    print(f"Dossier cible : {TOOLS_DIR}\n")
    results = {t["name"]: install(t) for t in TOOLS}

    print("\n--- Résumé ---")
    for name, ok in results.items():
        print(f"  {'OK' if ok else 'ÉCHEC'} : {name}")
    print("\nSemgrep : pip install semgrep (pas de binaire à télécharger).")
    print("OWASP ZAP + JRE : installation manuelle, voir SETUP_TOOLS.md.")


if __name__ == "__main__":
    main()
