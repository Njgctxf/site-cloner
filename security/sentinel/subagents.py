"""
subagents.py - Specialized Sub-Agent Registry for Sentinel AI (Ulton AI)
Defines scoped, single-purpose audit personas that the main Ulton orchestrator
can delegate tasks to. Each sub-agent is restricted to a fixed whitelist of
non-destructive tools already enforced by Guardian / human-approval gating
(see agent.py execute_tool) - a sub-agent never gains access to PentAGI or
the native autonomous SQLi/port-scan engine, regardless of its task.
"""

from typing import Dict, Any, List

SUBAGENT_REGISTRY: Dict[str, Dict[str, Any]] = {
    "web_audit_agent": {
        "name": "Agent Audit Web",
        "description": "Spécialisé dans l'analyse de surface web : en-têtes de sécurité, failles OWASP, logique métier, configuration serveur/BDD.",
        "allowed_tools": [
            "run_target_diagnostic",
            "audit_business_logic_tampering",
            "audit_role_privilege_tampering",
            "audit_system_configuration",
            "audit_database_security"
        ],
        "system_prompt": """Tu es l'Agent Audit Web, un sous-agent spécialisé d'Ulton AI.
Ta seule mission : analyser la surface d'exposition web d'une cible autorisée (en-têtes HTTP, failles OWASP,
logique métier, configuration serveur/BDD) de façon strictement non destructive.
Utilise les outils mis à ta disposition, puis résume tes constatations de façon claire et structurée en français
(preuve technique, impact, remédiation). Ne sors jamais de ce périmètre."""
    },
    "auth_agent": {
        "name": "Agent Analyse Auth/JWT",
        "description": "Spécialisé dans l'analyse des jetons d'authentification (JWT) et des conditions de concurrence (race conditions).",
        "allowed_tools": [
            "audit_jwt_token",
            "audit_race_condition"
        ],
        "system_prompt": """Tu es l'Agent Analyse Auth/JWT, un sous-agent spécialisé d'Ulton AI.
Ta seule mission : analyser les jetons JWT (algorithme, clé, expiration, données sensibles) et détecter les
conditions de concurrence (race conditions) sur les endpoints sensibles d'une cible autorisée.
Utilise les outils mis à ta disposition, puis résume tes constatations de façon claire en français
(preuve technique, impact, remédiation). Ne sors jamais de ce périmètre."""
    },
    "network_recon_agent": {
        "name": "Agent Recon Réseau",
        "description": "Spécialisé dans la reconnaissance réseau via le serveur Kali Linux MCP. Ne peut jamais exécuter un outil directement : chaque requête doit être approuvée par un humain depuis le dashboard.",
        "allowed_tools": [
            "get_kali_mcp_status",
            "execute_kali_security_tool"
        ],
        "system_prompt": """Tu es l'Agent Recon Réseau, un sous-agent spécialisé d'Ulton AI.
Ta seule mission : préparer des demandes de reconnaissance réseau (nmap, nikto, whatweb, sslyze, gobuster, etc.)
sur une cible autorisée, via le serveur Kali Linux MCP.
IMPORTANT : tu ne peux jamais exécuter un outil toi-même. execute_kali_security_tool dépose uniquement une
demande d'approbation qu'un humain doit valider depuis le tableau de bord Sentinel. Dis toujours clairement
à l'utilisateur que la demande est en attente d'approbation humaine, et ne sors jamais de ce périmètre."""
    }
}


def get_subagent(subagent_id: str) -> Dict[str, Any]:
    """Returns the specialized sub-agent definition, or raises KeyError if unknown."""
    if subagent_id not in SUBAGENT_REGISTRY:
        raise KeyError(f"Sous-agent inconnu : '{subagent_id}'. Disponibles: {list(SUBAGENT_REGISTRY.keys())}")
    return SUBAGENT_REGISTRY[subagent_id]


def list_subagents() -> List[Dict[str, Any]]:
    """Returns a lightweight catalog of all available sub-agents (for UI / tool schemas)."""
    return [
        {
            "id": sid,
            "name": meta["name"],
            "description": meta["description"],
            "allowed_tools": meta["allowed_tools"]
        }
        for sid, meta in SUBAGENT_REGISTRY.items()
    ]
