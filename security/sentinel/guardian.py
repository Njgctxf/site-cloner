"""
guardian.py - Deterministic Zero-Trust Security Guardian for Sentinel AI
The LLM has NO direct network execution permissions.
Every single action must be verified, sanitized, and approved by this Guardian.
"""

import re
import time
import urllib.parse
from typing import Dict, Any, Tuple, Optional

from ..network_guard import validate_target_url
from ..database import is_domain_authorized, is_admin_private_domain_authorized, log_event

FORBIDDEN_DESTRUCTIVE_PATTERNS = [
    re.compile(r"\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b", re.I),
    re.compile(r"\b(rm\s+-rf|del\s+/f|format\s+[a-z]:|shutdown|reboot)\b", re.I),
    re.compile(r"\b(xp_cmdshell|exec\s+master\.\.xp_|INTO\s+OUTFILE|LOAD_FILE)\b", re.I),
]

class SecurityViolation(Exception):
    pass

class SentinelGuardian:
    """
    Enforces deterministic boundaries around the Sentinel AI agent.
    """

    def __init__(self):
        self._kill_switch_active = False
        self._recent_requests = []
        self._rate_limit_per_minute = 120

    def trigger_kill_switch(self):
        """Immediately blocks all active and upcoming operations."""
        self._kill_switch_active = True
        log_event("SENTINEL_KILL_SWITCH", "CRITICAL", "GUARDIAN", "Le Kill-Switch de Ulton AI a été enclenché.")

    def reset_kill_switch(self):
        self._kill_switch_active = False

    def is_kill_switch_active(self) -> bool:
        return self._kill_switch_active

    def validate_target(self, url: str, test_type: Optional[str] = None) -> Tuple[bool, str]:
        """
        Ensures the target is:
        1. Formatted correctly
        2. Authorized in universal scope (verified domain, enterprise asset mandate, or local lab)
        3. Protected against SSRF / unauthorized internal targeting
        """
        if self._kill_switch_active:
            return False, "Opération bloquée : Le Kill-Switch de sécurité est actif."

        if not url:
            return False, "URL cible manquante."

        target_eval = url if ("://" in url or url.startswith("//")) else f"http://{url}"
        parsed = urllib.parse.urlparse(target_eval)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False, f"Nom d'hôte invalide dans l'URL: {url}"

        # 1. Universal Scope Authorization Check
        from .asset_registry import is_target_in_universal_scope
        is_auth, auth_msg, auth_ctx = is_target_in_universal_scope(url, test_type=test_type)
        if not is_auth:
            return False, f"Domaine ou actif non autorisé ({hostname}). Vous devez d'abord vérifier la propriété de ce domaine dans le CyberLab ou enregistrer un mandat d'autorisation d'audit."

        # 2. Anti-SSRF and Network boundary
        allow_internal = bool(auth_ctx and auth_ctx.get("scope") in ("local_lab", "enterprise_mandate", "enterprise_cidr"))
        if not allow_internal:
            is_safe, _, _, err = validate_target_url(url, allow_local_lab=True)
            if not is_safe:
                return False, f"Rejet Anti-SSRF Guardian : {err}"

        # 3. Rate limiting check
        now = time.time()
        self._recent_requests = [t for t in self._recent_requests if now - t < 60]
        rate_limit = (auth_ctx or {}).get("rate_limit") or self._rate_limit_per_minute
        if len(self._recent_requests) >= rate_limit:
            return False, f"Plafond de requêtes atteint (Rate Limit Guardian: {rate_limit} req/min). Veuillez patienter."
        self._recent_requests.append(now)

        return True, f"Cible validée et autorisée par le Guardian ({auth_msg})."

    def validate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Deep-inspects tool arguments to prevent harmful, destructive, or weaponized actions.
        """
        if self._kill_switch_active:
            return False, "Opération bloquée : Kill-Switch activé."

        # Stringify all arguments to scan for forbidden destructive commands
        args_str = " ".join(str(v) for v in arguments.values())
        for pat in FORBIDDEN_DESTRUCTIVE_PATTERNS:
            if pat.search(args_str):
                log_event("SENTINEL_GUARD_VIOLATION", "HIGH", "GUARDIAN", f"Tentative d'exécution d'une commande destructrice bloquée : {pat.pattern}")
                return False, f"Action rejetée par le Guardian : Détection d'un motif destructeur interdit ({pat.pattern[:30]})."

        # Specific Kali Linux MCP Tool Verification
        if tool_name == "execute_kali_security_tool":
            from .kali_connector import PERMITTED_KALI_TOOLS, SHELL_INJECTION_PATTERN
            kali_tool = (arguments.get("tool_name") or arguments.get("tool") or "").lower().strip()
            if kali_tool not in PERMITTED_KALI_TOOLS:
                return False, f"Outil Kali non autorisé par le Guardian ({kali_tool}). Outils permis : {list(PERMITTED_KALI_TOOLS.keys())}"

            target = arguments.get("target", "")
            if not target:
                return False, "Cible d'audit manquante pour l'outil Kali."
            ok_target, reason_target = self.validate_target(target, test_type="kali_audit")
            if not ok_target:
                return False, f"Cible non autorisée pour l'audit Kali : {reason_target}"

            custom_args = arguments.get("custom_args") or arguments.get("arguments") or []
            if isinstance(custom_args, list):
                for a in custom_args:
                    if SHELL_INJECTION_PATTERN.search(str(a)):
                        return False, f"Motif d'injection de commande shell détecté dans les arguments Kali : '{a}'"
                    disallowed = PERMITTED_KALI_TOOLS[kali_tool].get("disallowed_flags", [])
                    for dis in disallowed:
                        if dis.endswith("*") and str(a).startswith(dis[:-1]):
                            return False, f"Option de commande interdite par le Guardian ({a})"
                        elif str(a) == dis:
                            return False, f"Option de commande interdite par le Guardian ({a})"

        # Specific PentAGI Autonomous Pentesting Campaign Verification
        if tool_name in ("launch_pentagi_audit", "execute_pentagi_campaign"):
            target = arguments.get("target", "")
            if not target:
                return False, "Cible d'audit manquante pour PentAGI."
            ok_target, reason_target = self.validate_target(target, test_type="pentagi_audit")
            if not ok_target:
                return False, f"Cible non autorisée pour la campagne PentAGI : {reason_target}"

        # Check target URL inside tool arguments if present
        for key in ("url", "target_url", "upload_url", "endpoint", "target"):
            if key in arguments and isinstance(arguments[key], str):
                ok, reason = self.validate_target(arguments[key])
                if not ok:
                    return False, reason

        return True, "Appel d'outil validé."

# Global singleton
guardian = SentinelGuardian()
