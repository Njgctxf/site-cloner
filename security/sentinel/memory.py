"""
memory.py - Project Memory, Architecture Learning & Comparative History
Preserves sanitized technical audit context across sessions, tracks vulnerability evolutions
between audits (new, recurring, resolved), and provides condensed memory context
without storing credentials, tokens, or plaintext secrets.
"""

import json
import re
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from ..database import get_connection, log_event

logger = logging.getLogger("sentinel.memory")

# Redaction patterns for secrets (Bearer tokens, API keys, private keys, passwords)
SECRET_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|secret|api_key|token)\s*[:=]\s*['\"][^'\"]+['\"]"), r"\1='[REDACTED]'"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.I), "Bearer [REDACTED]"),
    (re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"), "[JWT_REDACTED]"),
    (re.compile(r"AIza[0-9A-Za-z-_]{35}"), "[GEMINI_KEY_REDACTED]"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,T}"), "[API_KEY_REDACTED]"),
]


def sanitize_secrets(text_or_obj: Any) -> Any:
    """Strips secrets and sensitive tokens from strings, dicts, or lists."""
    if isinstance(text_or_obj, str):
        cleaned = text_or_obj
        for pat, repl in SECRET_PATTERNS:
            cleaned = pat.sub(repl, cleaned)
        return cleaned
    elif isinstance(text_or_obj, dict):
        return {k: sanitize_secrets(v) for k, v in text_or_obj.items()}
    elif isinstance(text_or_obj, list):
        return [sanitize_secrets(x) for x in text_or_obj]
    return text_or_obj


def init_memory_tables():
    """Initializes tables for persistent project memory and architecture components."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_audit_memory (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        asset_id TEXT,
        target TEXT NOT NULL,
        audit_type TEXT NOT NULL,
        findings_summary_json TEXT NOT NULL,
        risk_score INTEGER NOT NULL DEFAULT 0,
        grade TEXT NOT NULL DEFAULT 'B',
        architecture_notes TEXT,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_architecture_knowledge (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        asset_id TEXT,
        component_name TEXT NOT NULL,
        component_type TEXT NOT NULL,
        technology_stack TEXT,
        observations_json TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Memory Ingestion & Queries
# --------------------------------------------------------------------------

def save_audit_memory(
    project_id: str,
    target: str,
    audit_type: str,
    findings_summary: List[Dict[str, Any]],
    risk_score: int = 0,
    grade: str = "B",
    asset_id: Optional[str] = None,
    architecture_notes: str = ""
) -> Dict[str, Any]:
    """
    Persists a sanitized audit snapshot for historical tracking and comparative learning.
    """
    init_memory_tables()
    mem_id = f"mem_{uuid.uuid4().hex[:10]}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Sanitize findings before storage
    safe_findings = sanitize_secrets(findings_summary)
    safe_notes = sanitize_secrets(architecture_notes)

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_audit_memory (
        id, project_id, asset_id, target, audit_type,
        findings_summary_json, risk_score, grade, architecture_notes, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        mem_id, project_id.strip(), asset_id, target.strip(), audit_type.strip(),
        json.dumps(safe_findings), risk_score, grade, safe_notes, now
    ))
    conn.commit()
    conn.close()

    log_event("SENTINEL_MEMORY_SAVED", "INFO", "MEMORY",
              f"Mémoire d'audit enregistrée [{mem_id}] pour {target} ({audit_type}, {len(safe_findings)} vulnérabilités)")

    return {
        "id": mem_id,
        "project_id": project_id,
        "target": target,
        "audit_type": audit_type,
        "risk_score": risk_score,
        "grade": grade,
        "findings_count": len(safe_findings),
        "created_at": now
    }


def list_audit_memory(project_id: Optional[str] = None, target: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    init_memory_tables()
    conn = get_connection()
    c = conn.cursor()

    query = "SELECT * FROM sentinel_audit_memory WHERE 1=1"
    params = []
    if project_id:
        query += " AND project_id = ?"
        params.append(project_id)
    if target:
        query += " AND target = ?"
        params.append(target)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    c.execute(query, params)
    rows = []
    for r in c.fetchall():
        d = dict(r)
        d["findings"] = json.loads(d.get("findings_summary_json") or "[]")
        rows.append(d)
    conn.close()
    return rows


def get_audit_memory(memory_id: str) -> Optional[Dict[str, Any]]:
    init_memory_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sentinel_audit_memory WHERE id = ?", (memory_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["findings"] = json.loads(d.get("findings_summary_json") or "[]")
    return d


# --------------------------------------------------------------------------
# Comparative Learning (Evolution: New vs Recurring vs Resolved)
# --------------------------------------------------------------------------

def compare_audit_snapshots(previous_memory_id: str, current_memory_id: str) -> Dict[str, Any]:
    """
    Compares two audit memory snapshots to evaluate security progress:
      - New findings discovered
      - Persistent recurring findings
      - Resolved findings (successfully mitigated)
    """
    prev = get_audit_memory(previous_memory_id)
    curr = get_audit_memory(current_memory_id)

    if not prev or not curr:
        raise ValueError("L'un des identifiants d'audit est introuvable pour la comparaison.")

    prev_findings = {f.get("rule_id") or f.get("id") or f.get("title", ""): f for f in prev.get("findings", [])}
    curr_findings = {f.get("rule_id") or f.get("id") or f.get("title", ""): f for f in curr.get("findings", [])}

    prev_keys = set(prev_findings.keys())
    curr_keys = set(curr_findings.keys())

    new_keys = curr_keys - prev_keys
    recurring_keys = curr_keys & prev_keys
    resolved_keys = prev_keys - curr_keys

    return {
        "previous_audit": {
            "id": prev["id"],
            "date": prev["created_at"],
            "risk_score": prev["risk_score"],
            "grade": prev["grade"]
        },
        "current_audit": {
            "id": curr["id"],
            "date": curr["created_at"],
            "risk_score": curr["risk_score"],
            "grade": curr["grade"]
        },
        "target": curr["target"],
        "new_findings": [curr_findings[k] for k in new_keys if k],
        "recurring_findings": [curr_findings[k] for k in recurring_keys if k],
        "resolved_findings": [prev_findings[k] for k in resolved_keys if k],
        "summary": {
            "new_count": len(new_keys),
            "recurring_count": len(recurring_keys),
            "resolved_count": len(resolved_keys),
            "score_delta": curr["risk_score"] - prev["risk_score"]
        }
    }


# --------------------------------------------------------------------------
# Architecture Components Knowledge
# --------------------------------------------------------------------------

def record_architecture_knowledge(
    project_id: str,
    component_name: str,
    component_type: str,
    technology_stack: str,
    asset_id: Optional[str] = None,
    observations: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Remembers architectural building blocks (e.g. reverse proxies, web servers, databases, microservices)
    discovered during investigations.
    """
    init_memory_tables()
    arch_id = f"arch_{uuid.uuid4().hex[:10]}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    safe_obs = sanitize_secrets(observations or {})

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_architecture_knowledge (
        id, project_id, asset_id, component_name, component_type,
        technology_stack, observations_json, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        arch_id, project_id.strip(), asset_id, component_name.strip(),
        component_type.strip(), technology_stack.strip(), json.dumps(safe_obs), now
    ))
    conn.commit()
    conn.close()

    return {
        "id": arch_id,
        "project_id": project_id,
        "component_name": component_name,
        "component_type": component_type,
        "technology_stack": technology_stack,
        "updated_at": now
    }


def get_project_knowledge_context(project_id: str, target: Optional[str] = None) -> Dict[str, Any]:
    """
    Provides condensed memory context for the LLM system prompt:
    known components, past audits, and previously resolved findings.
    """
    init_memory_tables()
    conn = get_connection()
    c = conn.cursor()

    # Past audits
    c.execute("SELECT * FROM sentinel_audit_memory WHERE project_id = ? ORDER BY created_at DESC LIMIT 5", (project_id,))
    recent_audits = [dict(r) for r in c.fetchall()]

    # Architecture components
    c.execute("SELECT * FROM sentinel_architecture_knowledge WHERE project_id = ? ORDER BY updated_at DESC LIMIT 10", (project_id,))
    components = [dict(r) for r in c.fetchall()]
    conn.close()

    return {
        "project_id": project_id,
        "recent_audits_count": len(recent_audits),
        "recent_audits": [
            {
                "id": a["id"],
                "target": a["target"],
                "audit_type": a["audit_type"],
                "grade": a["grade"],
                "risk_score": a["risk_score"],
                "created_at": a["created_at"]
            }
            for a in recent_audits
        ],
        "architecture_components": [
            {
                "name": comp["component_name"],
                "type": comp["component_type"],
                "tech_stack": comp["technology_stack"]
            }
            for comp in components
        ]
    }
