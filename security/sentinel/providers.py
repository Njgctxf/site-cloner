"""
providers.py - Multi-LLM Unified Adapter for Sentinel AI
Supports Google Gemini, Anthropic Claude, OpenAI, DeepSeek, Mistral, Ollama, and any OpenAI-compatible API.
"""

import json
import logging
import requests
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from .models import AgentMessage, AgentResponse, ToolCall

logger = logging.getLogger("sentinel.providers")

class LLMProvider(ABC):
    """Abstract interface that all LLM backends must implement."""

    def __init__(self, api_key: str = "", model: str = "", base_url: str = ""):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    @abstractmethod
    def chat(self, messages: List[AgentMessage], tools: Optional[List[Dict[str, Any]]] = None) -> AgentResponse:
        """Sends chat history and tool schemas, returns normalized AgentResponse."""
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Validates API key or endpoint availability."""
        pass


class OpenAICompatibleProvider(LLMProvider):
    """
    Adapter for OpenAI, DeepSeek, Mistral, Groq, Ollama, and generic /v1 endpoints.
    """

    DEFAULT_BASE_URLS = {
        "openai": "https://api.openai.com/v1",
        "deepseek": "https://api.deepseek.com/v1",
        "mistral": "https://api.mistral.ai/v1",
        "ollama": "http://localhost:11434/v1",
        "generic": "https://api.openai.com/v1"
    }

    def __init__(self, provider_id: str = "openai", api_key: str = "", model: str = "", base_url: str = ""):
        resolved_url = base_url or self.DEFAULT_BASE_URLS.get(provider_id, "https://api.openai.com/v1")
        resolved_model = model or ("gpt-4o" if provider_id == "openai" else "deepseek-chat" if provider_id == "deepseek" else "mistral-large-latest" if provider_id == "mistral" else "llama3:latest")
        super().__init__(api_key=api_key, model=resolved_model, base_url=resolved_url)
        self.provider_id = provider_id

    def chat(self, messages: List[AgentMessage], tools: Optional[List[Dict[str, Any]]] = None) -> AgentResponse:
        endpoint = f"{self.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Content-Type": "application/json"
        }
        if self.api_key and self.provider_id != "ollama":
            headers["Authorization"] = f"Bearer {self.api_key}"

        formatted_msgs = []
        for m in messages:
            msg_dict: Dict[str, Any] = {"role": m.role, "content": m.content or ""}
            if m.tool_calls:
                msg_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments) if isinstance(tc.arguments, dict) else str(tc.arguments)
                        }
                    }
                    for tc in m.tool_calls
                ]
            if m.tool_call_id:
                msg_dict["tool_call_id"] = m.tool_call_id
            formatted_msgs.append(msg_dict)

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": formatted_msgs,
            "temperature": 0.2
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        try:
            resp = requests.post(endpoint, headers=headers, json=payload, timeout=60)
            if resp.status_code != 200:
                err_body = resp.text[:300]
                return AgentResponse(
                    content=f"Erreur du fournisseur {self.provider_id.upper()} (HTTP {resp.status_code}): {err_body}",
                    finish_reason="error"
                )

            data = resp.json()
            choice = data.get("choices", [{}])[0]
            msg = choice.get("message", {})
            content = msg.get("content") or ""
            raw_tool_calls = msg.get("tool_calls") or []

            parsed_calls = []
            for rtc in raw_tool_calls:
                func = rtc.get("function", {})
                args_str = func.get("arguments", "{}")
                try:
                    args = json.loads(args_str) if isinstance(args_str, str) else args_str
                except Exception:
                    args = {"raw": args_str}
                parsed_calls.append(ToolCall(
                    id=rtc.get("id", f"call_{len(parsed_calls)}"),
                    name=func.get("name", ""),
                    arguments=args
                ))

            return AgentResponse(
                content=content,
                tool_calls=parsed_calls,
                raw_response=data,
                finish_reason=choice.get("finish_reason")
            )
        except Exception as e:
            return AgentResponse(
                content=f"Échec de connexion au service LLM ({self.provider_id}): {str(e)}",
                finish_reason="network_error"
            )

    def health_check(self) -> Dict[str, Any]:
        endpoint = f"{self.base_url.rstrip('/')}/models"
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            r = requests.get(endpoint, headers=headers, timeout=5)
            if r.status_code in (200, 201):
                return {"healthy": True, "provider": self.provider_id, "message": "Connexion établie avec succès"}
            return {"healthy": False, "provider": self.provider_id, "status": r.status_code, "error": r.text[:200]}
        except Exception as e:
            return {"healthy": False, "provider": self.provider_id, "error": str(e)}


class GeminiProvider(LLMProvider):
    """
    Adapter for Google Gemini API (v1beta).
    """

    def __init__(self, api_key: str = "", model: str = ""):
        resolved_model = model or "gemini-1.5-flash"
        base_url = "https://generativelanguage.googleapis.com/v1beta"
        super().__init__(api_key=api_key, model=resolved_model, base_url=base_url)

    def chat(self, messages: List[AgentMessage], tools: Optional[List[Dict[str, Any]]] = None) -> AgentResponse:
        endpoint = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        
        contents = []
        system_instruction = None

        for m in messages:
            if m.role == "system":
                system_instruction = {"parts": [{"text": m.content}]}
                continue

            role = "model" if m.role == "assistant" else "user"
            parts = []
            if m.content:
                parts.append({"text": m.content})
            
            if m.tool_calls:
                for tc in m.tool_calls:
                    parts.append({
                        "functionCall": {
                            "name": tc.name,
                            "args": tc.arguments
                        }
                    })
            if m.role == "tool":
                parts.append({
                    "functionResponse": {
                        "name": m.tool_call_id or "tool_result",
                        "response": {"output": m.content}
                    }
                })

            if parts:
                contents.append({"role": role, "parts": parts})

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": 0.2}
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction

        if tools:
            gemini_tools = []
            func_decls = []
            for t in tools:
                func = t.get("function", t)
                func_decls.append({
                    "name": func.get("name"),
                    "description": func.get("description", ""),
                    "parameters": func.get("parameters", {})
                })
            gemini_tools.append({"functionDeclarations": func_decls})
            payload["tools"] = gemini_tools

        try:
            resp = requests.post(endpoint, json=payload, timeout=60)
            if resp.status_code != 200:
                return AgentResponse(
                    content=f"Erreur Google Gemini API (HTTP {resp.status_code}): {resp.text[:300]}",
                    finish_reason="error"
                )

            data = resp.json()
            candidates = data.get("candidates", [{}])
            if not candidates:
                return AgentResponse(content="Aucune réponse reçue de Gemini.", finish_reason="empty")

            cand = candidates[0]
            parts = cand.get("content", {}).get("parts", [])
            text_chunks = []
            parsed_calls = []

            for part in parts:
                if "text" in part:
                    text_chunks.append(part["text"])
                if "functionCall" in part:
                    fc = part["functionCall"]
                    parsed_calls.append(ToolCall(
                        id=f"gemini_{fc.get('name')}",
                        name=fc.get("name", ""),
                        arguments=fc.get("args", {})
                    ))

            return AgentResponse(
                content="".join(text_chunks),
                tool_calls=parsed_calls,
                raw_response=data,
                finish_reason=cand.get("finishReason")
            )
        except Exception as e:
            return AgentResponse(
                content=f"Échec de connexion à Google Gemini: {str(e)}",
                finish_reason="network_error"
            )

    def health_check(self) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/models?key={self.api_key}"
        try:
            r = requests.get(endpoint, timeout=5)
            if r.status_code == 200:
                return {"healthy": True, "provider": "gemini", "message": "Clé Gemini valide"}
            return {"healthy": False, "provider": "gemini", "status": r.status_code, "error": r.text[:200]}
        except Exception as e:
            return {"healthy": False, "provider": "gemini", "error": str(e)}


class ClaudeProvider(LLMProvider):
    """
    Adapter for Anthropic Claude API (v1).
    """

    def __init__(self, api_key: str = "", model: str = ""):
        resolved_model = model or "claude-3-5-sonnet-20241022"
        base_url = "https://api.anthropic.com/v1"
        super().__init__(api_key=api_key, model=resolved_model, base_url=base_url)

    def chat(self, messages: List[AgentMessage], tools: Optional[List[Dict[str, Any]]] = None) -> AgentResponse:
        endpoint = f"{self.base_url}/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }

        system_prompt = ""
        claude_messages = []

        for m in messages:
            if m.role == "system":
                system_prompt = m.content
                continue

            if m.role == "tool":
                claude_messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": m.tool_call_id or "call_unknown",
                            "content": m.content
                        }
                    ]
                })
            elif m.role == "assistant":
                content_blocks = []
                if m.content:
                    content_blocks.append({"type": "text", "text": m.content})
                if m.tool_calls:
                    for tc in m.tool_calls:
                        content_blocks.append({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments
                        })
                claude_messages.append({"role": "assistant", "content": content_blocks or [{"type": "text", "text": ""}]})
            else:
                claude_messages.append({"role": "user", "content": m.content})

        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": claude_messages,
            "temperature": 0.2
        }
        if system_prompt:
            payload["system"] = system_prompt

        if tools:
            claude_tools = []
            for t in tools:
                func = t.get("function", t)
                claude_tools.append({
                    "name": func.get("name"),
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {"type": "object", "properties": {}})
                })
            payload["tools"] = claude_tools

        try:
            resp = requests.post(endpoint, headers=headers, json=payload, timeout=60)
            if resp.status_code != 200:
                return AgentResponse(
                    content=f"Erreur Anthropic Claude (HTTP {resp.status_code}): {resp.text[:300]}",
                    finish_reason="error"
                )

            data = resp.json()
            blocks = data.get("content", [])
            text_parts = []
            tool_calls = []

            for b in blocks:
                if b.get("type") == "text":
                    text_parts.append(b.get("text", ""))
                elif b.get("type") == "tool_use":
                    tool_calls.append(ToolCall(
                        id=b.get("id", f"call_{len(tool_calls)}"),
                        name=b.get("name", ""),
                        arguments=b.get("input", {})
                    ))

            return AgentResponse(
                content="".join(text_parts),
                tool_calls=tool_calls,
                raw_response=data,
                finish_reason=data.get("stop_reason")
            )
        except Exception as e:
            return AgentResponse(
                content=f"Échec de connexion à Anthropic Claude: {str(e)}",
                finish_reason="network_error"
            )

    def health_check(self) -> Dict[str, Any]:
        # Claude doesn't have a simple GET /models endpoint with API keys, so we test with a minimal payload
        endpoint = f"{self.base_url}/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": self.model,
            "max_tokens": 5,
            "messages": [{"role": "user", "content": "ping"}]
        }
        try:
            r = requests.post(endpoint, headers=headers, json=payload, timeout=5)
            if r.status_code == 200:
                return {"healthy": True, "provider": "claude", "message": "Clé Claude valide"}
            return {"healthy": False, "provider": "claude", "status": r.status_code, "error": r.text[:200]}
        except Exception as e:
            return {"healthy": False, "provider": "claude", "error": str(e)}


class MockProvider(LLMProvider):
    """
    Offline deterministic testing provider with simulated security reasoning.
    Used for unit testing and offline demonstrations.
    """

    def __init__(self, model: str = "mock-sentinel"):
        super().__init__(api_key="mock_key", model=model, base_url="local://mock")

    def chat(self, messages: List[AgentMessage], tools: Optional[List[Dict[str, Any]]] = None) -> AgentResponse:
        last_user_msg = next((m.content.lower() for m in reversed(messages) if m.role == "user"), "")

        # If user explicitly asks for security procedures / skills, search catalog first
        if any(w in last_user_msg for w in ("skill", "procédure", "compétence", "technique", "mitre", "owasp")):
            return AgentResponse(
                content="Je recherche les procédures opérationnelles de cybersécurité pertinentes dans le référentiel de 818 compétences MITRE ATT&CK/NIST CSF/OWASP.",
                tool_calls=[ToolCall(id="mock_call_5", name="search_security_skills", arguments={"query": last_user_msg[:60], "limit": 5})]
            )
        elif "jwt" in last_user_msg:
            return AgentResponse(
                content="J'ai détecté une demande d'analyse JWT. Je vais inspecter les signatures et les algorithmes acceptés.",
                tool_calls=[ToolCall(id="mock_call_1", name="audit_jwt_token", arguments={"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"})]
            )
        elif "upload" in last_user_msg:
            return AgentResponse(
                content="Je vais auditer le point de terminaison de téléversement de fichier pour détecter d'éventuelles failles de type MIME ou extensions dangereuses.",
                tool_calls=[ToolCall(id="mock_call_2", name="audit_file_upload", arguments={"upload_url": "https://innotech-lab.local/upload"})]
            )
        elif "race" in last_user_msg or "concurrence" in last_user_msg:
            return AgentResponse(
                content="Je vais vérifier si l'application est sujette aux Race Conditions en envoyant des requêtes concurrentes synchronisées.",
                tool_calls=[ToolCall(id="mock_call_3", name="audit_race_condition", arguments={"target_url": "https://innotech-lab.local/api/coupon/apply", "param_name": "coupon"})]
            )
        elif "scan" in last_user_msg or "audit" in last_user_msg:
            return AgentResponse(
                content="Bonjour, je suis Ulton AI. Pour débuter l'audit, j'ai vérifié que le domaine cible est autorisé. Je commence les tests non destructifs.",
                tool_calls=[ToolCall(id="mock_call_4", name="run_target_diagnostic", arguments={"target_url": "https://innotech-lab.local"})]
            )

        return AgentResponse(
            content=f"Ulton AI (Mode Simulation Active) : J'ai bien reçu votre consigne : '{messages[-1].content}'. Que souhaitez-vous analyser ? (JWT, Upload de fichier, Race condition, diagnostic complet, ou recherche de compétences cybersécurité)."
        )

    def health_check(self) -> Dict[str, Any]:
        return {"healthy": True, "provider": "mock", "message": "Fournisseur local mock actif"}


def get_provider(provider_id: str, api_key: str = "", model: str = "", base_url: str = "") -> LLMProvider:
    """
    Factory creating the appropriate LLM provider instance.
    """
    p_id = (provider_id or "mock").lower()
    if p_id == "gemini":
        return GeminiProvider(api_key=api_key, model=model)
    elif p_id == "claude":
        return ClaudeProvider(api_key=api_key, model=model)
    elif p_id in ("openai", "deepseek", "mistral", "ollama", "generic"):
        return OpenAICompatibleProvider(provider_id=p_id, api_key=api_key, model=model, base_url=base_url)
    return MockProvider(model=model or "mock-sentinel")
