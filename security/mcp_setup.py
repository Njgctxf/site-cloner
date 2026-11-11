"""
mcp_setup.py - Helpers for connecting Claude Desktop / Claude Code (Pro/Max)
to SiteCloner & Sentinel via the curated local MCP server (mcp_server.py).
"""

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

_FALLBACK_TOOLS: List[Dict[str, str]] = [
    {"name": "start_clone", "category": "Cloneur", "description": "Demarre le clonage d'un site web via SiteCloner."},
    {"name": "get_clone_status", "category": "Cloneur", "description": "Verifie l'avancement d'un clonage en cours."},
    {"name": "list_cloned_sites", "category": "Cloneur", "description": "Liste tous les sites deja clones et leurs metadonnees."},
    {"name": "run_passive_security_scan", "category": "CyberLab", "description": "Execute un scan de securite passif sur un domaine verifie."},
    {"name": "list_authorized_domains", "category": "CyberLab", "description": "Liste les domaines enregistres et leur statut de verification."},
    {"name": "start_domain_verification", "category": "CyberLab", "description": "Genere un jeton de verification DNS/HTTP pour un domaine."},
    {"name": "check_domain_verification", "category": "CyberLab", "description": "Valide la preuve de propriete d'un domaine."},
    {"name": "list_security_incidents", "category": "Sentinel", "description": "Consulte les incidents temps reel detectes par Sentinel."},
    {"name": "search_security_skills", "category": "Sentinel", "description": "Recherche dans les procedures OWASP / MITRE ATT&CK / CWE."},
]


def _categorize_tool(name: str) -> str:
    if "clone" in name:
        return "Cloneur"
    if "incident" in name or "skill" in name:
        return "Sentinel"
    return "CyberLab"


def get_claude_desktop_config_path() -> Path:
    """Returns the standard Claude Desktop config path for the current OS."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        return base / "Claude" / "claude_desktop_config.json"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "Claude" / "claude_desktop_config.json"


def _build_server_entry(base_url: str, is_local: bool) -> Dict[str, Any]:
    python_cmd = Path(sys.executable).as_posix() if is_local else "python"
    mcp_path = (_PROJECT_ROOT / "mcp_server.py").as_posix() if is_local else "/chemin/vers/SiteCloner-SaaS/mcp_server.py"
    return {
        "command": python_cmd,
        "args": [mcp_path],
        "env": {
            "SITECLONER_BASE_URL": base_url.rstrip("/"),
        },
    }


def _check_local_installation(cfg_path: Path) -> bool:
    if not cfg_path.is_file():
        return False
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        servers = data.get("mcpServers") or {}
        return isinstance(servers, dict) and "sitecloner" in servers
    except Exception:
        return False


def inspect_mcp_tools() -> List[Dict[str, str]]:
    """Inspects tools currently registered in mcp_server.py."""
    try:
        import mcp_server  # noqa: WPS433

        raw_tools = asyncio.run(mcp_server.mcp.list_tools())
        out: List[Dict[str, str]] = []
        for tool in raw_tools:
            first_line = (tool.description or "").strip().splitlines()[0] if tool.description else ""
            out.append({
                "name": tool.name,
                "category": _categorize_tool(tool.name),
                "description": first_line,
            })
        return out or _FALLBACK_TOOLS
    except Exception:
        return _FALLBACK_TOOLS


def build_mcp_setup_payload(base_url: str, is_local: bool) -> Dict[str, Any]:
    """Builds 1-click setup snippets and metadata for Claude Desktop & Claude Code."""
    clean_url = (base_url or "http://127.0.0.1:5050").rstrip("/")
    entry = _build_server_entry(clean_url, is_local=is_local)
    desktop_doc = {"mcpServers": {"sitecloner": entry}}
    desktop_json = json.dumps(desktop_doc, indent=2, ensure_ascii=False)

    cmd = entry["command"]
    script_arg = entry["args"][0]
    claude_code_cmd = (
        f'claude mcp add sitecloner -e SITECLONER_BASE_URL={clean_url} -- "{cmd}" "{script_arg}"'
    )

    cfg_path = get_claude_desktop_config_path() if is_local else None
    already_installed = _check_local_installation(cfg_path) if cfg_path else False

    return {
        "success": True,
        "is_local": is_local,
        "base_url": clean_url,
        "already_installed": already_installed,
        "desktop_config_path": str(cfg_path) if cfg_path else None,
        "server_entry": entry,
        "claude_desktop_json": desktop_json,
        "claude_code_command": claude_code_cmd,
        "cursor_json": desktop_json,
        "tools": _FALLBACK_TOOLS,
        "note": (
            "Votre abonnement Claude Pro/Max s'execute dans Claude Desktop ou Claude Code "
            "cote client et pilote SiteCloner / Sentinel via les outils MCP securises."
        ),
    }


def install_in_claude_desktop(base_url: str) -> Dict[str, Any]:
    """Merges the sitecloner MCP entry into the local Claude Desktop config."""
    cfg_path = get_claude_desktop_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)

    existing: Dict[str, Any] = {}
    backup_path = None
    if cfg_path.is_file():
        raw = cfg_path.read_text(encoding="utf-8").strip()
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                return {
                    "success": False,
                    "error": f"Le fichier existant n'est pas un JSON valide ({exc}). Copiez la config manuellement.",
                    "config_path": str(cfg_path),
                }
            if not isinstance(parsed, dict):
                return {
                    "success": False,
                    "error": "Format inattendu dans claude_desktop_config.json (objet JSON requis).",
                    "config_path": str(cfg_path),
                }
            existing = parsed
        bak = cfg_path.with_suffix(".json.bak")
        shutil.copy2(cfg_path, bak)
        backup_path = str(bak)

    servers = existing.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        existing["mcpServers"] = servers

    entry = _build_server_entry(base_url, is_local=True)
    servers["sitecloner"] = entry
    cfg_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return {
        "success": True,
        "config_path": str(cfg_path),
        "backup_path": backup_path,
        "entry": entry,
        "restart_required": True,
        "message": "Serveur MCP 'sitecloner' installe. Redemarrez Claude Desktop pour activer les outils.",
    }


def test_mcp_server_health() -> Dict[str, Any]:
    """Verifies that mcp_server.py imports cleanly and exposes its MCP tools."""
    try:
        import mcp_server  # noqa: WPS433

        raw_tools = asyncio.run(mcp_server.mcp.list_tools())
        tools = [
            {
                "name": t.name,
                "category": _categorize_tool(t.name),
                "description": (t.description or "").strip().splitlines()[0] if t.description else "",
            }
            for t in raw_tools
        ]
        return {
            "healthy": True,
            "tool_count": len(tools),
            "tools": tools,
            "message": f"Serveur MCP operationnel ({len(tools)} outils prets).",
        }
    except Exception as exc:
        return {
            "healthy": False,
            "tool_count": 0,
            "tools": [],
            "error": str(exc),
            "message": f"Echec de chargement MCP : {exc}",
        }
