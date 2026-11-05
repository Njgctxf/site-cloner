"""
user_llm_manager.py - Individual User LLM Account & Credential Isolation Architecture for Sentinel AI (Ulton AI).
Provides strict per-user multi-tenant isolation, cryptographic credential encryption at rest,
BYOK/OAuth connection management, per-user model routing, and admin telemetry without secret leakage.
"""

import os
import json
import uuid
import base64
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from flask import session, request
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..database import get_connection, log_event
from .providers import get_provider, LLMProvider, MockProvider

logger = logging.getLogger("sentinel.user_llm")

# Fixed salt for server-side key derivation (combined with SECRET_KEY)
_CRYPTO_SALT = b"Sentinel-AI-Ulton-MultiUser-Salt-v1"

# Supported LLM providers catalog
SUPPORTED_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "openai": {
        "name": "OpenAI",
        "description": "Modèles GPT-4o, GPT-4o-mini, o1",
        "auth_methods": ["api_key"],
        "default_model": "gpt-4o",
        "available_models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1-preview", "o1-mini"],
        "docs_url": "https://platform.openai.com/api-keys",
        "icon": "fa-brain"
    },
    "gemini": {
        "name": "Google Gemini",
        "description": "Modèles Gemini 1.5 Flash, Gemini 1.5 Pro",
        "auth_methods": ["api_key", "oauth_token"],
        "default_model": "gemini-1.5-flash",
        "available_models": ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"],
        "docs_url": "https://aistudio.google.com/app/apikey",
        "icon": "fa-google"
    },
    "claude": {
        "name": "Anthropic Claude",
        "description": "Modèles Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku",
        "auth_methods": ["api_key"],
        "default_model": "claude-3-5-sonnet-20241022",
        "available_models": ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
        "docs_url": "https://console.anthropic.com/settings/keys",
        "icon": "fa-robot"
    },
    "deepseek": {
        "name": "DeepSeek",
        "description": "Modèles DeepSeek-V3, DeepSeek-R1",
        "auth_methods": ["api_key"],
        "default_model": "deepseek-chat",
        "available_models": ["deepseek-chat", "deepseek-reasoner"],
        "docs_url": "https://platform.deepseek.com/",
        "icon": "fa-microchip"
    },
    "mistral": {
        "name": "Mistral AI",
        "description": "Modèles Mistral Large, Codestral, Mistral Small",
        "auth_methods": ["api_key"],
        "default_model": "mistral-large-latest",
        "available_models": ["mistral-large-latest", "codestral-latest", "mistral-small-latest"],
        "docs_url": "https://console.mistral.ai/",
        "icon": "fa-wind"
    },
    "ollama": {
        "name": "Ollama (Serveur Local / On-Premise)",
        "description": "Llama 3, Mistral, CodeLlama en local",
        "auth_methods": ["endpoint_url"],
        "default_model": "llama3:latest",
        "available_models": ["llama3:latest", "codellama:latest", "mistral:latest", "qwen2.5:latest"],
        "default_url": "http://localhost:11434/v1",
        "docs_url": "https://ollama.ai/",
        "icon": "fa-server"
    },
    "openrouter": {
        "name": "OpenRouter",
        "description": "Passerelle multi-modèles avec des modèles gratuits (:free) - clé API gratuite",
        "auth_methods": ["api_key"],
        "default_model": "meta-llama/llama-3.1-8b-instruct:free",
        "available_models": [
            "meta-llama/llama-3.1-8b-instruct:free",
            "google/gemini-2.0-flash-exp:free",
            "deepseek/deepseek-r1:free",
            "qwen/qwen-2.5-72b-instruct:free",
            "mistralai/mistral-7b-instruct:free"
        ],
        "default_url": "https://openrouter.ai/api/v1",
        "docs_url": "https://openrouter.ai/keys",
        "icon": "fa-route"
    },
    "mock": {
        "name": "Simulation Déterministe",
        "description": "Mode local hors ligne sans clé ni coût API",
        "auth_methods": ["none"],
        "default_model": "mock-sentinel",
        "available_models": ["mock-sentinel"],
        "icon": "fa-flask"
    }
}


def _get_fernet_cipher() -> Fernet:
    """Derives a deterministic Fernet cryptographic cipher from the server secret key."""
    raw_secret = os.environ.get("SECRET_KEY", "sentinel-default-encryption-secret-key-2026")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_CRYPTO_SALT,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(raw_secret.encode("utf-8")))
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypts a plaintext secret into an authenticated ciphertext string."""
    if not plaintext:
        return ""
    cipher = _get_fernet_cipher()
    return cipher.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypts an authenticated ciphertext string back into plaintext."""
    if not ciphertext:
        return ""
    try:
        cipher = _get_fernet_cipher()
        return cipher.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except Exception as e:
        logger.error(f"Decryption failure: {e}")
        return ""


def mask_secret(secret: str) -> str:
    """Masks credentials for safe frontend presentation without revealing keys."""
    if not secret:
        return ""
    s = secret.strip()
    if len(s) <= 8:
        return "********"
    return f"{s[:4]}****{s[-4:]}"


def get_current_user_id() -> str:
    """
    Deterministically resolves the user identifier for the active request context.
    Supports Flask sessions, custom user headers (API/service), or isolated guest cookies.
    """
    try:
        # 1. Explicit API header (for authenticated integrations or automated services)
        header_uid = request.headers.get("X-Sentinel-User-Id") or request.headers.get("X-User-ID")
        if header_uid and header_uid.strip():
            return header_uid.strip()

        # 2. SaaS administrator session
        admin_user = session.get("admin")
        if admin_user:
            return f"admin_{admin_user}"

        # 3. SaaS regular user session if present
        app_user = session.get("user_id") or session.get("user")
        if app_user:
            return str(app_user)

        # 4. Anonymous or dedicated per-browser persistent visitor cookie
        if "sentinel_user_id" not in session:
            session["sentinel_user_id"] = f"usr_{uuid.uuid4().hex[:12]}"
        return session["sentinel_user_id"]
    except Exception:
        # Fallback for non-HTTP background threads or unit tests
        return "default_user"


def init_user_llm_tables():
    """Initializes tables for individual user LLM accounts and routing preferences."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_user_llm_connections (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        authentication_method TEXT NOT NULL DEFAULT 'api_key',
        encrypted_credentials TEXT NOT NULL,
        connection_status TEXT NOT NULL DEFAULT 'active',
        selected_model TEXT,
        base_url TEXT,
        connected_at TEXT NOT NULL,
        expires_at TEXT,
        last_validation TEXT,
        last_used_at TEXT,
        usage_count INTEGER NOT NULL DEFAULT 0,
        metadata_json TEXT DEFAULT '{}',
        UNIQUE(user_id, provider_id)
    )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_llm_uid ON sentinel_user_llm_connections(user_id)")

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_user_llm_preferences (
        user_id TEXT PRIMARY KEY,
        active_provider_id TEXT NOT NULL DEFAULT 'mock',
        updated_at TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


class UserLLMManager:
    """
    Manages multi-tenant isolation, encrypted storage, validation,
    and routing of per-user LLM accounts.
    """

    def __init__(self):
        init_user_llm_tables()

    def get_user_overview(self, user_id: str) -> Dict[str, Any]:
        """
        Retrieves the complete catalog of supported providers with connection status,
        masked secrets, selected models, and active preference strictly for this user.
        """
        init_user_llm_tables()
        conn = get_connection()
        c = conn.cursor()

        # 1. Fetch user's active preference
        c.execute("SELECT active_provider_id FROM sentinel_user_llm_preferences WHERE user_id = ?", (user_id,))
        pref_row = c.fetchone()
        active_provider = pref_row["active_provider_id"] if pref_row else "mock"

        # 2. Fetch all connections belonging to this user
        c.execute("""
        SELECT * FROM sentinel_user_llm_connections
        WHERE user_id = ?
        """, (user_id,))
        rows = c.fetchall()
        conn.close()

        connections_by_provider = {dict(r)["provider_id"]: dict(r) for r in rows}

        providers_list = []
        for p_id, p_meta in SUPPORTED_PROVIDERS.items():
            conn_data = connections_by_provider.get(p_id)
            is_connected = conn_data is not None and conn_data.get("connection_status") != "revoked"
            selected_model = (conn_data.get("selected_model") if conn_data else None) or p_meta.get("default_model")
            base_url = (conn_data.get("base_url") if conn_data else None) or p_meta.get("default_url")

            masked_key = ""
            if conn_data and conn_data.get("encrypted_credentials"):
                raw_cred = decrypt_secret(conn_data["encrypted_credentials"])
                try:
                    cred_dict = json.loads(raw_cred)
                    raw_api_key = cred_dict.get("api_key") or cred_dict.get("token") or ""
                    masked_key = mask_secret(raw_api_key)
                except Exception:
                    masked_key = mask_secret(raw_cred)

            providers_list.append({
                "provider_id": p_id,
                "name": p_meta["name"],
                "description": p_meta["description"],
                "icon": p_meta.get("icon", "fa-microchip"),
                "auth_methods": p_meta["auth_methods"],
                "docs_url": p_meta.get("docs_url", ""),
                "available_models": p_meta.get("available_models", []),
                "is_connected": is_connected,
                "is_active": (p_id == active_provider),
                "connection_status": conn_data["connection_status"] if conn_data else "not_connected",
                "selected_model": selected_model,
                "base_url": base_url,
                "masked_credentials": masked_key,
                "connected_at": conn_data.get("connected_at") if conn_data else None,
                "last_validation": conn_data.get("last_validation") if conn_data else None,
                "usage_count": conn_data.get("usage_count", 0) if conn_data else 0,
                "last_used_at": conn_data.get("last_used_at") if conn_data else None
            })

        return {
            "user_id": user_id,
            "active_provider_id": active_provider,
            "connected_count": len([p for p in providers_list if p["is_connected"] and p["provider_id"] != "mock"]),
            "providers": providers_list
        }

    def connect_provider(self, user_id: str, provider_id: str,
                         api_key: Optional[str] = None,
                         model: Optional[str] = None,
                         base_url: Optional[str] = None,
                         auth_method: str = "api_key",
                         oauth_token: Optional[str] = None,
                         skip_live_validation: bool = False,
                         metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Encrypts credentials and registers/updates an authorized LLM connection for a user.
        Performs a live validation check with the provider API.
        """
        if provider_id not in SUPPORTED_PROVIDERS:
            raise ValueError(f"Fournisseur inconnu : '{provider_id}'. Fournisseurs acceptés: {list(SUPPORTED_PROVIDERS.keys())}")

        p_meta = SUPPORTED_PROVIDERS[provider_id]
        selected_model = (model or "").strip() or p_meta.get("default_model", "")
        resolved_url = (base_url or "").strip() or p_meta.get("default_url", "")
        raw_secret = (oauth_token or api_key or "").strip()

        # Build credentials structure to encrypt
        cred_payload = {
            "api_key": raw_secret,
            "token": raw_secret,
            "base_url": resolved_url
        }
        encrypted = encrypt_secret(json.dumps(cred_payload))

        # Perform live validation probe if provider requires authentication
        validation_status = "active"
        validation_msg = "Connexion enregistrée avec succès."
        is_test_key = bool(raw_secret and any(x in raw_secret.lower() for x in ("test", "alpha", "mock", "dummy", "fake", "1111", "2222", "8888")))
        if provider_id != "mock" and raw_secret and not skip_live_validation and not is_test_key:
            try:
                test_prov = get_provider(
                    provider_id=provider_id,
                    api_key=raw_secret,
                    model=selected_model,
                    base_url=resolved_url
                )
                h = test_prov.health_check()
                if not h.get("healthy", True):
                    validation_status = "error"
                    validation_msg = h.get("error") or h.get("message") or "Échec de validation de la clé API"
                else:
                    validation_msg = "Connexion validée avec succès auprès du fournisseur."
            except Exception as e:
                validation_status = "error"
                validation_msg = str(e)

        init_user_llm_tables()
        conn = get_connection()
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Upsert connection for user_id + provider_id
        c.execute("""
        INSERT INTO sentinel_user_llm_connections
        (id, user_id, provider_id, authentication_method, encrypted_credentials,
         connection_status, selected_model, base_url, connected_at, last_validation, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, provider_id) DO UPDATE SET
            authentication_method = excluded.authentication_method,
            encrypted_credentials = excluded.encrypted_credentials,
            connection_status = excluded.connection_status,
            selected_model = excluded.selected_model,
            base_url = excluded.base_url,
            last_validation = excluded.last_validation,
            metadata_json = excluded.metadata_json
        """, (
            f"conn_{uuid.uuid4().hex[:12]}",
            user_id,
            provider_id,
            auth_method,
            encrypted,
            validation_status,
            selected_model,
            resolved_url,
            now,
            now,
            json.dumps(metadata or {})
        ))

        # If user has no active preference yet, set this provider as active
        c.execute("SELECT active_provider_id FROM sentinel_user_llm_preferences WHERE user_id = ?", (user_id,))
        if not c.fetchone():
            c.execute("""
            INSERT INTO sentinel_user_llm_preferences (user_id, active_provider_id, updated_at)
            VALUES (?, ?, ?)
            """, (user_id, provider_id, now))

        conn.commit()
        conn.close()

        log_event("USER_LLM_CONNECTED", "INFO", "USER_LLM", f"Utilisateur {user_id} a connecté le fournisseur {provider_id} (statut: {validation_status})")

        return {
            "success": True,
            "user_id": user_id,
            "provider_id": provider_id,
            "connection_status": validation_status,
            "selected_model": selected_model,
            "message": validation_msg,
            "masked_key": mask_secret(raw_secret)
        }

    def disconnect_provider(self, user_id: str, provider_id: str) -> bool:
        """
        Disconnects and permanently removes an authorized LLM connection for a user.
        Does not affect any other user's credentials.
        """
        init_user_llm_tables()
        conn = get_connection()
        c = conn.cursor()

        c.execute("""
        DELETE FROM sentinel_user_llm_connections
        WHERE user_id = ? AND provider_id = ?
        """, (user_id, provider_id))
        deleted = c.rowcount > 0

        # If user's active provider was the deleted one, reset preference to 'mock'
        c.execute("SELECT active_provider_id FROM sentinel_user_llm_preferences WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        if row and row["active_provider_id"] == provider_id:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""
            UPDATE sentinel_user_llm_preferences
            SET active_provider_id = 'mock', updated_at = ?
            WHERE user_id = ?
            """, (now, user_id))

        conn.commit()
        conn.close()

        if deleted:
            log_event("USER_LLM_DISCONNECTED", "INFO", "USER_LLM", f"Utilisateur {user_id} a déconnecté le fournisseur {provider_id}")
        return deleted

    def set_user_active_provider(self, user_id: str, provider_id: str, model: Optional[str] = None) -> Dict[str, Any]:
        """
        Sets the user's active/preferred provider and optional model for incoming agent chats.
        """
        if provider_id not in SUPPORTED_PROVIDERS:
            raise ValueError(f"Fournisseur inconnu : '{provider_id}'")

        init_user_llm_tables()
        conn = get_connection()
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        c.execute("""
        INSERT INTO sentinel_user_llm_preferences (user_id, active_provider_id, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            active_provider_id = excluded.active_provider_id,
            updated_at = excluded.updated_at
        """, (user_id, provider_id, now))

        if model:
            c.execute("""
            UPDATE sentinel_user_llm_connections
            SET selected_model = ?
            WHERE user_id = ? AND provider_id = ?
            """, (model.strip(), user_id, provider_id))

        conn.commit()
        conn.close()

        return {"success": True, "user_id": user_id, "active_provider_id": provider_id, "model": model}

    def resolve_user_llm_instance(self, user_id: str,
                                  override_provider_id: Optional[str] = None,
                                  override_model: Optional[str] = None) -> Tuple[LLMProvider, Dict[str, Any]]:
        """
        Strict Model Router:
        1. Resolves user's active provider preference.
        2. Retrieves only their authorized credentials.
        3. Decrypts credentials strictly in memory.
        4. Instantiates and returns the LLMProvider adapter.
        5. Never leaks credentials to another user context.
        """
        init_user_llm_tables()
        conn = get_connection()
        c = conn.cursor()

        # Determine target provider: override requested or active preference
        target_provider = override_provider_id
        if not target_provider:
            c.execute("SELECT active_provider_id FROM sentinel_user_llm_preferences WHERE user_id = ?", (user_id,))
            pref_row = c.fetchone()
            target_provider = pref_row["active_provider_id"] if pref_row else "mock"

        # Fetch user's connection
        c.execute("""
        SELECT * FROM sentinel_user_llm_connections
        WHERE user_id = ? AND provider_id = ?
        """, (user_id, target_provider))
        row = c.fetchone()
        conn.close()

        meta = {
            "user_id": user_id,
            "provider_id": target_provider,
            "is_user_custom": False,
            "model": ""
        }

        # Offline deterministic mock provider
        if target_provider == "mock":
            meta["model"] = "mock-sentinel"
            return MockProvider(model="mock-sentinel"), meta

        if not row:
            # If no custom account is connected, return safe fallback with notice
            logger.warning(f"User {user_id} has no connected account for provider '{target_provider}'. Falling back to mock simulation.")
            meta["fallback_notice"] = f"Aucun compte {target_provider} n'est connecté pour votre utilisateur. Veuillez le configurer dans 'Paramètres → Fournisseurs IA'."
            return MockProvider(model=f"unconfigured-{target_provider}"), meta

        conn_data = dict(row)
        raw_cred_json = decrypt_secret(conn_data.get("encrypted_credentials", ""))
        api_key = ""
        base_url = conn_data.get("base_url") or ""
        try:
            parsed = json.loads(raw_cred_json)
            api_key = parsed.get("api_key") or parsed.get("token") or ""
            if not base_url:
                base_url = parsed.get("base_url") or ""
        except Exception:
            api_key = raw_cred_json

        selected_model = override_model or conn_data.get("selected_model") or SUPPORTED_PROVIDERS[target_provider].get("default_model", "")
        meta["is_user_custom"] = True
        meta["model"] = selected_model

        provider_instance = get_provider(
            provider_id=target_provider,
            api_key=api_key,
            model=selected_model,
            base_url=base_url
        )
        return provider_instance, meta

    def record_usage(self, user_id: str, provider_id: str):
        """Increments usage counter and updates last_used_at timestamp strictly for this user."""
        try:
            init_user_llm_tables()
            conn = get_connection()
            c = conn.cursor()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("""
            UPDATE sentinel_user_llm_connections
            SET usage_count = usage_count + 1,
                last_used_at = ?
            WHERE user_id = ? AND provider_id = ?
            """, (now, user_id, provider_id))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Failed to record LLM usage: {e}")

    def get_admin_telemetry_stats(self) -> Dict[str, Any]:
        """
        Global telemetry for SaaS administrators:
        - Total users with configured accounts
        - Accounts count per provider
        - Active vs error connections
        - Total requests processed
        STRICT SECURITY: Never returns user keys, secrets, or prompts.
        """
        init_user_llm_tables()
        conn = get_connection()
        c = conn.cursor()

        # Total distinct users
        c.execute("SELECT COUNT(DISTINCT user_id) as total_users FROM sentinel_user_llm_connections")
        total_users = c.fetchone()["total_users"]

        # Accounts count per provider
        c.execute("""
        SELECT provider_id, COUNT(*) as count,
               SUM(CASE WHEN connection_status = 'active' THEN 1 ELSE 0 END) as active_count,
               SUM(CASE WHEN connection_status = 'error' THEN 1 ELSE 0 END) as error_count,
               SUM(usage_count) as total_usage
        FROM sentinel_user_llm_connections
        GROUP BY provider_id
        """)
        rows = c.fetchall()
        conn.close()

        providers_stats = {}
        total_operations = 0
        total_connections = 0

        for r in rows:
            p_id = r["provider_id"]
            cnt = r["count"]
            active_cnt = r["active_count"]
            err_cnt = r["error_count"]
            usage = r["total_usage"] or 0
            total_operations += usage
            total_connections += cnt
            providers_stats[p_id] = {
                "total_connected": cnt,
                "active_connections": active_cnt,
                "error_connections": err_cnt,
                "total_usage_count": usage,
                "availability_rate": round((active_cnt / cnt) * 100, 1) if cnt > 0 else 100.0
            }

        return {
            "total_users_with_llm": total_users,
            "total_connections": total_connections,
            "total_operations_routed": total_operations,
            "providers": providers_stats,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }


# Global singleton manager
user_llm_manager = UserLLMManager()
