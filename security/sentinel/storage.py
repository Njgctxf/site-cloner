"""
storage.py - SQLite Persistence for Sentinel AI
Manages Sentinel conversations, chat history, and BYOK provider configurations.
"""

import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from ..database import get_connection

def init_sentinel_tables():
    """Initializes dedicated tables for Sentinel AI."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        active_provider TEXT NOT NULL DEFAULT 'mock',
        provider_configs_json TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_conversations (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        tool_calls_json TEXT DEFAULT '[]',
        tool_results_json TEXT DEFAULT '[]',
        created_at TEXT NOT NULL,
        FOREIGN KEY (conversation_id) REFERENCES sentinel_conversations(id) ON DELETE CASCADE
    )
    """)

    # Ensure default settings row exists
    c.execute("SELECT id FROM sentinel_settings WHERE id = 1")
    if not c.fetchone():
        c.execute("""
        INSERT INTO sentinel_settings (id, active_provider, provider_configs_json, updated_at)
        VALUES (1, 'mock', '{}', ?)
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))

    conn.commit()
    conn.close()

def get_sentinel_config() -> Dict[str, Any]:
    """Retrieves current BYOK configuration with masked API keys."""
    init_sentinel_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT active_provider, provider_configs_json, updated_at FROM sentinel_settings WHERE id = 1")
    row = c.fetchone()
    conn.close()

    if not row:
        return {"active_provider": "mock", "providers": {}}

    try:
        providers = json.loads(row["provider_configs_json"])
    except Exception:
        providers = {}

    return {
        "active_provider": row["active_provider"],
        "providers": providers,
        "updated_at": row["updated_at"]
    }

def save_sentinel_config(active_provider: str, provider_id: str, api_key: Optional[str] = None, model: Optional[str] = None, base_url: Optional[str] = None):
    """Saves or updates BYOK provider configuration."""
    init_sentinel_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT provider_configs_json FROM sentinel_settings WHERE id = 1")
    row = c.fetchone()
    try:
        configs = json.loads(row["provider_configs_json"]) if row else {}
    except Exception:
        configs = {}

    p_conf = configs.get(provider_id, {})
    if api_key is not None:
        p_conf["api_key"] = api_key.strip()
    if model is not None:
        p_conf["model"] = model.strip()
    if base_url is not None:
        p_conf["base_url"] = base_url.strip()

    configs[provider_id] = p_conf

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
    UPDATE sentinel_settings
    SET active_provider = ?, provider_configs_json = ?, updated_at = ?
    WHERE id = 1
    """, (active_provider, json.dumps(configs), now))
    conn.commit()
    conn.close()

def list_conversations() -> List[Dict[str, Any]]:
    init_sentinel_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT id, title, created_at, updated_at
    FROM sentinel_conversations
    ORDER BY updated_at DESC
    LIMIT 50
    """)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def create_conversation(title: str = "Nouvel audit Sentinel") -> str:
    init_sentinel_tables()
    conv_id = str(uuid.uuid4())
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_conversations (id, title, created_at, updated_at)
    VALUES (?, ?, ?, ?)
    """, (conv_id, title, now, now))
    conn.commit()
    conn.close()
    return conv_id

def get_conversation_messages(conversation_id: str) -> List[Dict[str, Any]]:
    init_sentinel_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT id, role, content, tool_calls_json, tool_results_json, created_at
    FROM sentinel_messages
    WHERE conversation_id = ?
    ORDER BY id ASC
    """, (conversation_id,))
    rows = []
    for r in c.fetchall():
        d = dict(r)
        try:
            d["tool_calls"] = json.loads(d["tool_calls_json"])
        except Exception:
            d["tool_calls"] = []
        try:
            d["tool_results"] = json.loads(d["tool_results_json"])
        except Exception:
            d["tool_results"] = []
        rows.append(d)
    conn.close()
    return rows

def save_message(conversation_id: str, role: str, content: str, tool_calls: Optional[List[Any]] = None, tool_results: Optional[List[Any]] = None) -> int:
    init_sentinel_tables()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tc_json = json.dumps(tool_calls or [], ensure_ascii=False)
    tr_json = json.dumps(tool_results or [], ensure_ascii=False)
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_messages (conversation_id, role, content, tool_calls_json, tool_results_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (conversation_id, role, content, tc_json, tr_json, now))
    msg_id = c.lastrowid
    c.execute("UPDATE sentinel_conversations SET updated_at = ? WHERE id = ?", (now, conversation_id))
    conn.commit()
    conn.close()
    return msg_id

def delete_conversation(conversation_id: str):
    init_sentinel_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM sentinel_messages WHERE conversation_id = ?", (conversation_id,))
    c.execute("DELETE FROM sentinel_conversations WHERE id = ?", (conversation_id,))
    conn.commit()
    conn.close()
