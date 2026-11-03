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
from .jwt_engine import audit_jwt
from .upload_engine import audit_file_upload_endpoint
from .race_engine import audit_race_condition
from .logic_engine import audit_price_tampering, audit_role_parameter_tampering
from ..scanner import scan_target
from ..dast_engine import run_dast_audit

logger = logging.getLogger("sentinel.agent")

SENTINEL_SYSTEM_PROMPT = """Tu es SENTINEL AI, l'architecte et agent intelligent expert en cybersécurité applicative et audit de vulnérabilités web.
Ton rôle est d'analyser, diagnostiquer et guider les audits de sécurité sur les applications web autorisées du propriétaire.

Règles fondamentales et éthiques absolues :
1. Tu opères UNIQUEMENT dans un cadre défensif, bienveillant et non destructif.
2. Tu n'exécutes aucune suppression de données, aucun dump complet de base de données, aucune attaque déstabilisante.
3. Toutes les actions techniques sont strictement soumises au Guardian de sécurité (contrôle de scope, anti-SSRF, rate limiting).
4. Pour chaque problème identifié, fournis une explication claire en français, la preuve technique constatée (statut HTTP, en-tête, comportement différentiel), l'impact potentiel et la recommandation de remédiation concrète.
5. Lorsque l'utilisateur te demande d'analyser une URL ou un composant (JWT, upload, formulaire, concurrence), utilise les outils mis à ta disposition.
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
    }
]

class SentinelAgent:
    """
    Main orchestration class handling user interaction, tool invocation, and Guardian enforcement.
    """

    def __init__(self, provider: LLMProvider):
        self.provider = provider
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Sentinel-AI-Auditor/1.0 (Defensive Assessment)"})

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> ToolResult:
        """
        Executes a security tool strictly vetted by the Guardian.
        """
        # 1. Guardian Policy Check
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
