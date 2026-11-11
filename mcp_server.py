"""
mcp_server.py - SiteCloner MCP connector.

Exposes a curated, explicitly scoped set of SiteCloner actions as MCP tools so
Claude (Desktop, Code) or any other MCP-compatible agent can drive this tool
the way Claude drives Figma - by calling a defined action, not by having raw
code/shell access to the project.

Scope (deliberately limited - matches what was agreed on, nothing more):
  - Cloning: start a clone, check its status, list cloned sites.
  - Security: run a PASSIVE scan only (the active/offensive probe category is
    hard-disabled here, regardless of what the caller asks for), manage
    domain verification (list / start / check).
  - Sentinel: read-only incident list (no write actions, no agent-key
    provisioning, no Kali connector exposed here).

Nothing destructive (no delete/stop/publish), no active DAST probing, no
Kali/exploitation tooling is exposed through this server. If you want more
surface later, extend TOOLS explicitly - don't widen scope by accident.

--------------------------------------------------------------------------
HOW TO USE
--------------------------------------------------------------------------
1. Make sure SiteCloner's own Flask app (app.py) is running locally - the
   cloning tools call its REST API (http://127.0.0.1:<SITECLONER_PORT>).
   The security/domain/incident tools work even if it isn't running, since
   they call the project's Python modules directly.
2. Add this to your MCP client config (e.g. Claude Desktop's
   claude_desktop_config.json, or Claude Code's .mcp.json):

    {
      "mcpServers": {
        "sitecloner": {
          "command": "python",
          "args": ["C:/Users/RCK COMPUTERS/Documents/boostlocal/SiteCloner-SaaS/mcp_server.py"]
        }
      }
    }

3. Restart the client. The tools below become available to it.
--------------------------------------------------------------------------
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests

try:
    from mcp.server.fastmcp import FastMCP as MCPServer
except ImportError:  # mcp >= 2.x compatibility
    from mcp.server.mcpserver import MCPServer

from security.database import (
    list_domains as _list_domains,
    get_domain_record,
    add_pending_domain,
    mark_domain_as_verified,
)
from security.domain_verifier import generate_challenge_token, normalize_domain, verify_domain_ownership
from security.scanner import scan_target
from security.sentinel.realtime import list_incidents as _list_incidents
from security.sentinel import skills_registry

SITECLONER_PORT = int(os.environ.get("PORT", 5050))
SITECLONER_BASE_URL = (
    os.environ.get("SITECLONER_BASE_URL") or f"http://127.0.0.1:{SITECLONER_PORT}"
).rstrip("/")

# Hard safety floor: the MCP connector can NEVER run the active-probe category,
# no matter what a caller asks for. Same passive set offered as default in the
# Scanner tab's checkboxes.
SAFE_PASSIVE_CATEGORIES = [
    "headers", "files", "tls", "cors", "methods", "directory", "mixed",
    "outdated", "sca", "cve", "secrets", "sast", "robots", "forms",
]

mcp = MCPServer("sitecloner")


# --------------------------------------------------------------------------
# Cloning (calls the running SiteCloner Flask app's own REST API)
# --------------------------------------------------------------------------

@mcp.tool()
def start_clone(url: str, max_pages: int = 15) -> dict:
    """Starts cloning a website with SiteCloner. Returns a job_id to poll with
    get_clone_status. Requires the SiteCloner app (app.py) to be running locally."""
    try:
        res = requests.post(
            f"{SITECLONER_BASE_URL}/__sc/api/clone",
            json={"url": url, "max_pages": max_pages},
            timeout=10,
        )
        return res.json()
    except requests.exceptions.ConnectionError:
        return {"error": f"SiteCloner n'est pas accessible sur {SITECLONER_BASE_URL}. Lancez d'abord app.py."}


@mcp.tool()
def get_clone_status(job_id: str) -> dict:
    """Checks the progress/result of a clone job started with start_clone."""
    try:
        res = requests.get(f"{SITECLONER_BASE_URL}/__sc/api/status/{job_id}", timeout=10)
        return res.json()
    except requests.exceptions.ConnectionError:
        return {"error": f"SiteCloner n'est pas accessible sur {SITECLONER_BASE_URL}."}


@mcp.tool()
def list_cloned_sites() -> dict:
    """Lists every site already cloned by SiteCloner, with basic metadata (title, url, page/file counts)."""
    try:
        res = requests.get(f"{SITECLONER_BASE_URL}/__sc/api/sites", timeout=10)
        return res.json()
    except requests.exceptions.ConnectionError:
        return {"error": f"SiteCloner n'est pas accessible sur {SITECLONER_BASE_URL}."}


# --------------------------------------------------------------------------
# Security - passive scanning only (direct Python calls, no server required)
# --------------------------------------------------------------------------

@mcp.tool()
def run_passive_security_scan(target_url: str) -> dict:
    """Runs a PASSIVE security scan on a domain you have already verified in
    CyberLab (headers, cookies, TLS, CORS, exposed files, outdated components,
    secrets, robots.txt, form hygiene). This never sends attack payloads - the
    active-probe category (SQLi/XSS/IDOR/etc.) is not reachable through this
    tool. Fails if the domain isn't verified yet - use start_domain_verification first."""
    return scan_target(target_url, categories=SAFE_PASSIVE_CATEGORIES)


@mcp.tool()
def list_authorized_domains() -> dict:
    """Lists all domains registered in CyberLab, with their verification status."""
    return {"domains": _list_domains()}


@mcp.tool()
def start_domain_verification(domain: str, method: str = "dns_txt") -> dict:
    """Begins the ownership-verification process for a domain so it can later
    be scanned. Returns a challenge token: publish it as a DNS TXT record
    (_sc-audit.<domain>) or at https://<domain>/.well-known/security-audit-challenge.txt,
    then call check_domain_verification."""
    clean = normalize_domain(domain)
    if not clean:
        return {"success": False, "error": "Domaine invalide."}
    token = generate_challenge_token()
    record = add_pending_domain(clean, token, method)
    return {
        "success": True,
        "domain": clean,
        "token": token,
        "method": method,
        "instructions": (
            f"Publiez le TXT '{token}' sur _sc-audit.{clean}, ou le fichier "
            f"https://{clean}/.well-known/security-audit-challenge.txt contenant ce jeton, "
            f"puis appelez check_domain_verification."
        ),
        "record": record,
    }


@mcp.tool()
def check_domain_verification(domain: str, method: str = "auto") -> dict:
    """Checks whether the ownership challenge for a domain (from
    start_domain_verification) has been satisfied yet, and marks it verified if so."""
    clean = normalize_domain(domain)
    record = get_domain_record(clean)
    if not record:
        return {"success": False, "error": "Aucune vérification en cours pour ce domaine. Utilisez start_domain_verification."}

    result = verify_domain_ownership(clean, record["verification_token"], method=method)
    if result.get("success"):
        mark_domain_as_verified(clean, result.get("method", method))
    return result


# --------------------------------------------------------------------------
# Sentinel - read-only
# --------------------------------------------------------------------------

@mcp.tool()
def list_security_incidents(domain: str = "") -> dict:
    """Lists recent real-time security incidents Sentinel has detected and
    responded to (read-only - no action is taken by this tool)."""
    return {"incidents": _list_incidents(domain=domain or None)}


@mcp.tool()
def search_security_skills(query: str, limit: int = 8) -> dict:
    """Searches Sentinel's defensive cybersecurity skills library (OWASP, MITRE ATT&CK, CWE)
    for analysis procedures (read-only)."""
    capped = max(1, min(int(limit), 15))
    results = skills_registry.search_skills(query=query or "", limit=capped)
    return {"query": query, "count": len(results), "results": results}


if __name__ == "__main__":
    mcp.run(transport=os.environ.get("MCP_TRANSPORT", "stdio"))
