"""
agent.py - Sentinel AI Core Reasoning & Tool Orchestration Engine
Coordinates Multi-LLM inference, Guardian policy enforcement, and specialized audit execution.
"""

import json
import logging
from typing import List, Dict, Any, Optional

import requests

from .models import AgentMessage, AgentResponse, ToolCall, ToolResult
from .providers import LLMProvider, get_provider
from .guardian import guardian
from ..safe_session import build_safe_session
from .jwt_engine import audit_jwt
from .upload_engine import audit_file_upload_endpoint
from .race_engine import audit_race_condition
from .logic_engine import audit_price_tampering, audit_role_parameter_tampering
from ..scanner import scan_target
from ..dast_engine import run_dast_audit

logger = logging.getLogger("sentinel.agent")

SENTINEL_SYSTEM_PROMPT = """Tu es ULTON AI, l'architecte et agent intelligent expert en cybersécurité applicative et audit de vulnérabilités web.
Ton rôle est d'analyser, diagnostiquer et guider les audits de sécurité sur les applications web autorisées du propriétaire.

Règles fondamentales et éthiques absolues :
1. Tu opères UNIQUEMENT dans un cadre défensif, bienveillant et non destructif.
2. Tu n'exécutes aucune suppression de données, aucun dump complet de base de données, aucune attaque déstabilisante.
3. Toutes les actions techniques sont strictement soumises au Guardian de sécurité (contrôle de scope, anti-SSRF, rate limiting).
4. Pour chaque problème identifié, fournis une explication claire en français, la preuve technique constatée (statut HTTP, en-tête, comportement différentiel), l'impact potentiel et la recommandation de remédiation concrète.
5. Lorsque l'utilisateur te demande d'analyser une URL ou un composant (JWT, upload, formulaire, concurrence), utilise les outils mis à ta disposition.
6. Tu disposes d'un référentiel de 818 procédures opérationnelles de cybersécurité (MITRE ATT&CK, NIST CSF, OWASP). Utilise search_security_skills pour trouver des procédures pertinentes, puis load_skill_detail pour charger leurs instructions complètes avant d'agir.
7. Tu as accès au serveur officiel Kali Linux MCP (mcp-kali-server) pour orchestrer des outils réputés (nmap, nikto, whatweb, sslyze, gobuster, etc.) sur des cibles vérifiées via get_kali_mcp_status et execute_kali_security_tool.
"""

# OpenAPI / JSON-Schema tool declarations provided to the LLM
SENTINEL_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "run_target_diagnostic",
            "description": "Exécute un audit de sécurité complet non destructif (DAST, en-têtes HTTP, failles OWASP, cookies, secrets exposés) sur une URL autorisée.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "L'URL complète de l'application à auditer (ex: https://monsite.com ou https://innotech-lab.local)"
                    }
                },
                "required": ["target_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_jwt_token",
            "description": "Analyse un jeton JWT (algorithme 'none', clé secrète faible, expiration, données sensibles).",
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "La chaîne du token JWT complet à analyser"
                    },
                    "verify_endpoint_url": {
                        "type": "string",
                        "description": "URL optionnelle d'un point d'accès pour tester si le serveur accepte le token forgé sans signature"
                    }
                },
                "required": ["token"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_file_upload",
            "description": "Vérifie la robustesse d'un formulaire de téléversement (extensions exécutables, doubles extensions, SVG, validation MIME) avec des sondes inoffensives.",
            "parameters": {
                "type": "object",
                "properties": {
                    "upload_url": {
                        "type": "string",
                        "description": "URL de l'endpoint qui accepte les téléversements (POST multipart/form-data)"
                    },
                    "file_field_name": {
                        "type": "string",
                        "description": "Nom du champ de fichier dans le formulaire (par défaut: 'file')"
                    }
                },
                "required": ["upload_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_race_condition",
            "description": "Teste les vulnérabilités de concurrence (Race Condition / TOCTOU) par envoi de requêtes synchronisées à la milliseconde près sur une action à usage unique.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL de l'action à tester (ex: utilisation de coupon ou confirmation d'opération)"
                    },
                    "method": {
                        "type": "string",
                        "enum": ["POST", "GET"],
                        "description": "Méthode HTTP à utiliser (par défaut: POST)"
                    }
                },
                "required": ["target_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_business_logic_tampering",
            "description": "Évalue si un endpoint accepte la falsification de montants ou quantités négatives (Price Tampering).",
            "parameters": {
                "type": "object",
                "properties": {
                    "checkout_url": {
                        "type": "string",
                        "description": "URL du panier ou du point d'encaissement"
                    }
                },
                "required": ["checkout_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_role_privilege_tampering",
            "description": "Teste si un endpoint de profil permet une élévation de privilèges par injection de paramètres (Mass Assignment / role: admin).",
            "parameters": {
                "type": "object",
                "properties": {
                    "profile_url": {
                        "type": "string",
                        "description": "URL de mise à jour du profil utilisateur"
                    }
                },
                "required": ["profile_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_security_skills",
            "description": "Recherche parmi les 818 procédures opérationnelles de cybersécurité (MITRE ATT&CK, NIST CSF, OWASP) du référentiel Anthropic-Cybersecurity-Skills. Utilise cet outil automatiquement quand tu as besoin d'une procédure ou guide pour une technique de sécurité spécifique. Retourne les compétences les plus pertinentes avec leur description.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Requête de recherche (ex: 'jwt token forgery', 'memory forensics', 'cobalt strike detection', 'api security', 'race condition')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Nombre max de résultats à retourner (défaut: 5, max: 20)"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "load_skill_detail",
            "description": "Charge et retourne les instructions complètes d'une compétence de sécurité spécifique (SKILL.md complet avec procédures, commandes et étapes d'exécution). Appelle cet outil après search_security_skills pour obtenir le contenu détaillé d'une compétence pertinente.",
            "parameters": {
                "type": "object",
                "properties": {
                    "skill_name": {
                        "type": "string",
                        "description": "Nom exact de la compétence tel que retourné par search_security_skills"
                    }
                },
                "required": ["skill_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_authorized_scope",
            "description": "Consulte le registre des actifs et périmètres autorisés (domaines vérifiés, serveurs Linux/Windows, APIs, BDD, mandats d'autorisation actifs). Utilise cet outil pour vérifier ce que tu as le droit d'auditer.",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset_type": {
                        "type": "string",
                        "description": "Filtre optionnel par type d'actif ('domain', 'ip', 'api', 'linux_server', 'windows_server', 'database', etc.)"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "verify_asset_authorization",
            "description": "Vérifie si une cible spécifique (URL, IP, domaine, serveur) dispose d'un mandat d'autorisation actif et valide selon les règles du Guardian.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "L'URL, domaine ou adresse IP de la cible à vérifier"
                    },
                    "test_type": {
                        "type": "string",
                        "description": "Type de test envisagé ('dast', 'jwt', 'upload', 'race_condition', 'config_audit', 'all')"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_shield_status",
            "description": "Consulte l'état actuel de l'Emergency Shield (Palier NORMAL, ALERT, DEFENSIVE, ou EMERGENCY) et la liste des mesures de protection actives.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "trigger_emergency_defenses",
            "description": "Modifie le palier de protection de l'Emergency Shield en cas d'attaque détectée ou place le système en mode de défense renforcée (DEFENSIVE / EMERGENCY).",
            "parameters": {
                "type": "object",
                "properties": {
                    "tier": {
                        "type": "string",
                        "enum": ["NORMAL", "ALERT", "DEFENSIVE", "EMERGENCY"],
                        "description": "Nouveau palier d'urgence à appliquer"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Justification technique du changement de palier"
                    }
                },
                "required": ["tier", "reason"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_system_configuration",
            "description": "Audite la configuration de sécurité d'un serveur Linux (SSH, ANSSI/CIS, permissions /etc/shadow) ou Windows (SMBv1, RDP NLA, null sessions). L'actif cible doit être préalablement autorisé.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Nom d'hôte, IP ou URL de l'actif serveur autorisé"
                    },
                    "os_family": {
                        "type": "string",
                        "enum": ["linux", "windows"],
                        "description": "Famille d'OS du serveur (linux ou windows)"
                    },
                    "config_text": {
                        "type": "string",
                        "description": "Contenu textuel optionnel du fichier de configuration à auditer (ex: sshd_config)"
                    }
                },
                "required": ["target", "os_family"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_database_security",
            "description": "Évalue la posture de sécurité d'une base de données autorisée (PostgreSQL, MySQL, Redis, MongoDB) contre les mauvaises configurations, accès non chiffrés et mode protégé.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Hôte ou IP de l'instance de base de données autorisée"
                    },
                    "db_type": {
                        "type": "string",
                        "enum": ["postgres", "mysql", "redis", "mongodb"],
                        "description": "Moteur de base de données"
                    },
                    "config_text": {
                        "type": "string",
                        "description": "Contenu textuel optionnel du fichier de configuration (ex: my.cnf, redis.conf, mongod.conf)"
                    }
                },
                "required": ["target", "db_type"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_vulnerability_remediation",
            "description": "Génère un plan de remédiation formel (patch diff unifié, cause racine, code corrigé) pour une vulnérabilité identifiée (sqli, xss, jwt, upload, race_condition, ssh_hardening, db_hardening). Soumis à validation humaine obligatoire.",
            "parameters": {
                "type": "object",
                "properties": {
                    "vulnerability_type": {
                        "type": "string",
                        "enum": ["sqli", "xss", "jwt", "upload", "race_condition", "ssh_hardening", "db_hardening"],
                        "description": "Catégorie de la vulnérabilité"
                    },
                    "target": {
                        "type": "string",
                        "description": "Cible ou endpoint concerné"
                    },
                    "title": {
                        "type": "string",
                        "description": "Titre du correctif"
                    },
                    "original_code": {
                        "type": "string",
                        "description": "Extrait de code ou configuration vulnérable (optionnel)"
                    },
                    "fixed_code": {
                        "type": "string",
                        "description": "Extrait de code ou configuration corrigée (optionnel)"
                    }
                },
                "required": ["vulnerability_type", "target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_remediations",
            "description": "Consulte les plans de remédiation en attente d'approbation humaine, appliqués ou contre-validés.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Filtre optionnel par cible"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["pending", "approved", "applied", "rejected", "rolled_back"],
                        "description": "Filtre optionnel par statut"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "verify_remediation_effectiveness",
            "description": "Exécute une contre-validation technique pour prouver si un correctif appliqué a définitivement éliminé la vulnérabilité ciblée.",
            "parameters": {
                "type": "object",
                "properties": {
                    "remediation_id": {
                        "type": "string",
                        "description": "Identifiant du plan de remédiation à contre-valider (ex: rem_xxx)"
                    }
                },
                "required": ["remediation_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_project_memory_context",
            "description": "Consulte la mémoire d'audit persistante d'un projet (architecture connue, audits antérieurs, vulnérabilités résolues). Permet d'éviter de reposer des questions déjà clarifiées.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Identifiant du projet (ex: proj_xxx)"
                    }
                },
                "required": ["project_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "compare_audit_snapshots",
            "description": "Compare deux audits de sécurité historiques pour mesurer l'évolution de la posture (nouvelles failles, failles récurrentes, failles résolues).",
            "parameters": {
                "type": "object",
                "properties": {
                    "previous_memory_id": {
                        "type": "string",
                        "description": "Identifiant du premier audit (ex: mem_xxx)"
                    },
                    "current_memory_id": {
                        "type": "string",
                        "description": "Identifiant du second audit à comparer (ex: mem_yyy)"
                    }
                },
                "required": ["previous_memory_id", "current_memory_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_soc_executive_report",
            "description": "Génère un rapport exécutif consolidé du SOC (posture globale, statut Emergency Shield, inventaire des actifs, métriques des remédiations).",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Identifiant optionnel du projet pour restreindre le rapport"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_kali_mcp_status",
            "description": "Consulte l'état de connexion, la version et l'inventaire des outils de sécurité disponibles sur le serveur officiel Kali Linux MCP (mcp-kali-server).",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "execute_kali_security_tool",
            "description": "Exécute un outil de sécurité officiel de Kali Linux (nmap, nikto, whatweb, sslyze, testssl.sh, dnsrecon, gobuster, whois, sqlmap) via le serveur MCP Kali sur une cible strictement autorisée.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "enum": ["nmap", "nikto", "whatweb", "sslyze", "testssl.sh", "dnsrecon", "gobuster", "whois", "sqlmap"],
                        "description": "Nom de l'outil Kali officiel à exécuter"
                    },
                    "target": {
                        "type": "string",
                        "description": "URL, domaine ou adresse IP de la cible autorisée"
                    },
                    "custom_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Arguments CLI optionnels complémentaires (ex: ['-sV', '-p', '80,443'])"
                    }
                },
                "required": ["tool_name", "target"]
            }
        }
    }
]

class SentinelAgent:
    """
    Main orchestration class handling user interaction, tool invocation, and Guardian enforcement.
    """

    def __init__(self, provider: LLMProvider):
        self.provider = provider
        self.session = build_safe_session(allow_local_lab=True)
        self.session.headers.update({"User-Agent": "Ulton-AI-Auditor/1.0 (Defensive Assessment)"})

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> ToolResult:
        """
        Executes a security tool strictly vetted by the Guardian.
        Skills tools (search_security_skills, load_skill_detail) bypass Guardian
        as they only read local files — no network, no destructive action.
        """
        # Skills tools are read-only local operations — no Guardian check needed
        if tool_name == "search_security_skills":
            try:
                from .skills_registry import skills_registry
                query = arguments.get("query", "")
                limit = min(int(arguments.get("limit", 5)), 20)
                results = skills_registry.search_skills(query=query, limit=limit)
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result={
                        "skills": results,
                        "count": len(results),
                        "total_available": skills_registry.count(),
                        "query": query
                    }
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "load_skill_detail":
            try:
                from .skills_registry import skills_registry
                skill_name = arguments.get("skill_name", "")
                skill = skills_registry.get_skill(skill_name)
                if skill:
                    content = skill.load_full_content()
                    return ToolResult(tool_call_id="", name=tool_name, result=content)
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result={"error": f"Compétence '{skill_name}' introuvable. Utilisez search_security_skills pour trouver le nom exact."},
                    is_error=True
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "list_authorized_scope":
            try:
                from .asset_registry import list_assets
                asset_type = arguments.get("asset_type")
                assets = list_assets(asset_type=asset_type)
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result={"authorized_assets": assets, "count": len(assets)}
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "verify_asset_authorization":
            try:
                from .asset_registry import is_target_in_universal_scope
                target = arguments.get("target", "")
                test_type = arguments.get("test_type")
                is_auth, msg, ctx = is_target_in_universal_scope(target, test_type=test_type)
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result={"is_authorized": is_auth, "message": msg, "details": ctx}
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "get_shield_status":
            try:
                from .shield import emergency_shield
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result=emergency_shield.get_status()
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "trigger_emergency_defenses":
            try:
                from .shield import emergency_shield, ShieldTier
                tier_str = arguments.get("tier", "DEFENSIVE").upper()
                reason = arguments.get("reason", "Déclenchement défensif par Ulton AI")
                tier_enum = ShieldTier(tier_str)
                res = emergency_shield.set_tier(tier_enum, reason, manual=False)
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result={"shield_updated": True, "state": res}
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "generate_vulnerability_remediation":
            try:
                from .remediation import create_remediation_plan
                v_type = arguments.get("vulnerability_type", "sqli")
                target = arguments.get("target", "")
                title = arguments.get("title")
                orig = arguments.get("original_code")
                fixed = arguments.get("fixed_code")
                plan = create_remediation_plan(
                    vulnerability_type=v_type,
                    target=target,
                    title=title,
                    original_code=orig,
                    fixed_code=fixed
                )
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result={"remediation_plan": plan, "requires_human_approval": True}
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "list_remediations":
            try:
                from .remediation import list_remediations
                target = arguments.get("target")
                status = arguments.get("status")
                items = list_remediations(target=target, status=status)
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result={"remediations": items, "count": len(items)}
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "verify_remediation_effectiveness":
            try:
                from .remediation import verify_remediation_post_fix
                rem_id = arguments.get("remediation_id", "")
                res = verify_remediation_post_fix(remediation_id=rem_id)
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result=res
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "get_project_memory_context":
            try:
                from .memory import get_project_knowledge_context
                p_id = arguments.get("project_id", "")
                ctx = get_project_knowledge_context(project_id=p_id)
                return ToolResult(tool_call_id="", name=tool_name, result=ctx)
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "compare_audit_snapshots":
            try:
                from .memory import compare_audit_snapshots
                p_id = arguments.get("previous_memory_id", "")
                c_id = arguments.get("current_memory_id", "")
                diff = compare_audit_snapshots(previous_memory_id=p_id, current_memory_id=c_id)
                return ToolResult(tool_call_id="", name=tool_name, result=diff)
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "generate_soc_executive_report":
            try:
                from .reporting import generate_consolidated_soc_report
                p_id = arguments.get("project_id")
                rep = generate_consolidated_soc_report(project_id=p_id)
                return ToolResult(tool_call_id="", name=tool_name, result=rep)
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        if tool_name == "get_kali_mcp_status":
            try:
                from .kali_connector import kali_connector
                health = kali_connector.health_check()
                discovery = kali_connector.discover_tools()
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result={"health": health, "discovery": discovery}
                )
            except Exception as e:
                return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

        # 1. Guardian Policy Check for all other tools
        is_allowed, reason = guardian.validate_tool_call(tool_name, arguments)
        if not is_allowed:
            return ToolResult(
                tool_call_id="",
                name=tool_name,
                result={"error": f"Bloqué par le Guardian: {reason}", "status": "blocked"},
                is_error=True
            )

        try:
            if tool_name == "run_target_diagnostic":
                url = arguments.get("target_url", "")
                res = scan_target(url)
                return ToolResult(tool_call_id="", name=tool_name, result=res)

            elif tool_name == "audit_jwt_token":
                token = arguments.get("token", "")
                endpoint = arguments.get("verify_endpoint_url")
                findings = audit_jwt(token, verify_endpoint_url=endpoint, session=self.session)
                return ToolResult(tool_call_id="", name=tool_name, result={"findings": findings, "count": len(findings)})

            elif tool_name == "audit_file_upload":
                url = arguments.get("upload_url", "")
                field = arguments.get("file_field_name", "file")
                findings = audit_file_upload_endpoint(self.session, url, file_field_name=field)
                return ToolResult(tool_call_id="", name=tool_name, result={"findings": findings, "count": len(findings)})

            elif tool_name == "audit_race_condition":
                url = arguments.get("target_url", "")
                method = arguments.get("method", "POST")
                findings = audit_race_condition(self.session, url, method=method)
                return ToolResult(tool_call_id="", name=tool_name, result={"findings": findings, "count": len(findings)})

            elif tool_name == "audit_business_logic_tampering":
                url = arguments.get("checkout_url", "")
                findings = audit_price_tampering(self.session, url)
                return ToolResult(tool_call_id="", name=tool_name, result={"findings": findings, "count": len(findings)})

            elif tool_name == "audit_role_privilege_tampering":
                url = arguments.get("profile_url", "")
                findings = audit_role_parameter_tampering(self.session, url)
                return ToolResult(tool_call_id="", name=tool_name, result={"findings": findings, "count": len(findings)})

            elif tool_name == "audit_system_configuration":
                from .system_engine import audit_linux_server_config, audit_windows_server_config
                target = arguments.get("target", "")
                os_family = (arguments.get("os_family") or "linux").lower()
                cfg = arguments.get("config_text")
                if os_family == "windows":
                    res = audit_windows_server_config(target=target, config_text=cfg)
                else:
                    res = audit_linux_server_config(target=target, config_text=cfg)
                return ToolResult(tool_call_id="", name=tool_name, result=res)

            elif tool_name == "audit_database_security":
                from .system_engine import audit_database_config
                target = arguments.get("target", "")
                db_type = arguments.get("db_type", "postgres")
                cfg = arguments.get("config_text")
                res = audit_database_config(db_type=db_type, target=target, config_text=cfg)
                return ToolResult(tool_call_id="", name=tool_name, result=res)

            elif tool_name == "execute_kali_security_tool":
                from .kali_connector import kali_connector
                k_tool = arguments.get("tool_name", "")
                target = arguments.get("target", "")
                c_args = arguments.get("custom_args")
                res = kali_connector.execute_tool(tool_name=k_tool, target=target, custom_args=c_args, triggered_by="sentinel_agent")
                return ToolResult(
                    tool_call_id="",
                    name=tool_name,
                    result=res,
                    is_error=not res.get("success", False)
                )

            return ToolResult(tool_call_id="", name=tool_name, result={"error": f"Outil inconnu: {tool_name}"}, is_error=True)
        except Exception as e:
            return ToolResult(tool_call_id="", name=tool_name, result={"error": str(e)}, is_error=True)

    def process_message(self, conversation_history: List[AgentMessage], max_steps: int = 3) -> Dict[str, Any]:
        """
        Executes an agent loop step:
        1. Prepend system prompt if missing
        2. Call LLM provider with tools schema
        3. If tool calls returned, execute via Guardian and recurse for final response
        """
        messages = list(conversation_history)
        if not messages or messages[0].role != "system":
            messages.insert(0, AgentMessage(role="system", content=SENTINEL_SYSTEM_PROMPT))

        step = 0
        executed_tool_records = []

        while step < max_steps:
            step += 1
            response = self.provider.chat(messages, tools=SENTINEL_TOOLS_SCHEMA)

            # If no tool calls, return conversational text
            if not response.tool_calls:
                return {
                    "reply": response.content,
                    "tools_executed": executed_tool_records,
                    "finish_reason": response.finish_reason
                }

            # Append assistant message with tool calls
            messages.append(AgentMessage(
                role="assistant",
                content=response.content or "",
                tool_calls=response.tool_calls
            ))

            # Execute requested tool calls
            for tc in response.tool_calls:
                res = self.execute_tool(tc.name, tc.arguments)
                executed_tool_records.append({
                    "id": tc.id,
                    "name": tc.name,
                    "arguments": tc.arguments,
                    "result": res.result,
                    "is_error": res.is_error
                })
                # Append tool result back to dialogue
                messages.append(AgentMessage(
                    role="tool",
                    content=json.dumps(res.result, ensure_ascii=False),
                    tool_call_id=tc.id
                ))

        # Final response if max_steps reached
        final_resp = self.provider.chat(messages, tools=None)
        return {
            "reply": final_resp.content,
            "tools_executed": executed_tool_records,
            "finish_reason": "completed"
        }
