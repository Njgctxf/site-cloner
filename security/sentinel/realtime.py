"""
realtime.py - Sentinel AI real-time protection: agent provisioning, event
ingestion, correlation, automated response, and live alerting.

Scope rule (same as every other Sentinel capability): an agent key can only be
issued for a domain that is ALREADY verified as owned (is_domain_authorized /
is_admin_private_domain_authorized), or the local lab. No key, no ingestion -
nobody can plug an agent into a domain they have not proven they control.
"""

import json
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ..database import get_connection, log_event, is_domain_authorized, is_admin_private_domain_authorized
from ..network_guard import LAB_HOSTS
from .waf_signatures import inspect_request, highest_severity

KEY_PREFIX = "sk_sentinel_"

# Correlation window / thresholds for escalating a stream of events into an incident
CORRELATION_WINDOW_SECONDS = 300
EVENT_COUNT_THRESHOLD = 5           # N suspicious events from the same IP within the window
IMMEDIATE_ESCALATION_SEVERITIES = {"CRITICAL", "HIGH"}


def init_realtime_tables():
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_agent_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        api_key TEXT UNIQUE NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        last_seen_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        method TEXT,
        path TEXT,
        findings_json TEXT NOT NULL,
        severity TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        event_count INTEGER NOT NULL DEFAULT 1,
        action_taken TEXT NOT NULL DEFAULT 'none',
        summary TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_blocklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        reason TEXT NOT NULL,
        blocked_until TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(domain, source_ip)
    )
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Agent key provisioning - requires proven domain ownership
# --------------------------------------------------------------------------

def _domain_is_authorized(domain: str) -> bool:
    clean = (domain or "").strip().lower()
    if clean in LAB_HOSTS:
        return True
    return is_domain_authorized(clean) or is_admin_private_domain_authorized(clean)


def provision_agent_key(domain: str) -> Dict[str, Any]:
    """Issues (or rotates) an agent key scoped to one verified domain only."""
    clean = (domain or "").strip().lower()
    if not clean:
        return {"success": False, "error": "Domaine manquant."}
    if not _domain_is_authorized(clean):
        return {"success": False, "error": f"Le domaine '{clean}' n'est pas vérifié. Vérifiez-en la propriété avant d'installer l'agent."}

    conn = get_connection()
    c = conn.cursor()
    new_key = f"{KEY_PREFIX}{secrets.token_hex(24)}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("SELECT id FROM sentinel_agent_keys WHERE domain = ?", (clean,))
    existing = c.fetchone()
    if existing:
        c.execute("UPDATE sentinel_agent_keys SET api_key = ?, is_active = 1, created_at = ? WHERE domain = ?",
                   (new_key, now, clean))
    else:
        c.execute("INSERT INTO sentinel_agent_keys (domain, api_key, is_active, created_at) VALUES (?, ?, 1, ?)",
                   (clean, new_key, now))
    conn.commit()
    conn.close()

    log_event("SENTINEL_AGENT_PROVISIONED", "INFO", "SENTINEL", f"Clé d'agent émise pour le domaine {clean}.")
    return {"success": True, "domain": clean, "api_key": new_key}


def revoke_agent_key(domain: str) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sentinel_agent_keys SET is_active = 0 WHERE domain = ?", (domain.strip().lower(),))
    conn.commit()
    changed = c.rowcount > 0
    conn.close()
    if changed:
        log_event("SENTINEL_AGENT_REVOKED", "WARN", "SENTINEL", f"Clé d'agent révoquée pour {domain}.")
    return changed


def resolve_agent_key(api_key: str) -> Optional[str]:
    """Returns the domain this key is scoped to, or None if invalid/revoked."""
    if not api_key or not api_key.startswith(KEY_PREFIX):
        return None
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT domain FROM sentinel_agent_keys WHERE api_key = ? AND is_active = 1", (api_key,))
    row = c.fetchone()
    if row:
        c.execute("UPDATE sentinel_agent_keys SET last_seen_at = ? WHERE api_key = ?",
                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), api_key))
        conn.commit()
    conn.close()
    return row["domain"] if row else None


def list_agent_keys() -> List[Dict[str, Any]]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, domain, is_active, created_at, last_seen_at FROM sentinel_agent_keys ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# --------------------------------------------------------------------------
# Event ingestion, correlation, automated response
# --------------------------------------------------------------------------

def _is_ip_blocked(domain: str, source_ip: str) -> bool:
    conn = get_connection()
    c = conn.cursor()
    c.execute("""SELECT 1 FROM sentinel_blocklist
                 WHERE domain = ? AND source_ip = ? AND blocked_until > ?""",
              (domain, source_ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    row = c.fetchone()
    conn.close()
    return row is not None


def _block_ip(domain: str, source_ip: str, reason: str, minutes: int = 30):
    conn = get_connection()
    c = conn.cursor()
    until = (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT INTO sentinel_blocklist (domain, source_ip, reason, blocked_until, created_at)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(domain, source_ip) DO UPDATE SET
                    reason = excluded.reason, blocked_until = excluded.blocked_until""",
              (domain, source_ip, reason, until, now))
    conn.commit()
    conn.close()
    log_event("SENTINEL_IP_BLOCKED", "HIGH", "SENTINEL", f"IP {source_ip} bloquée sur {domain} ({minutes} min) : {reason}")


def get_active_blocklist(domain: str) -> List[str]:
    """IPs currently blocked for a domain - polled by the installed agent."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT source_ip FROM sentinel_blocklist WHERE domain = ? AND blocked_until > ?",
              (domain, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    ips = [r["source_ip"] for r in c.fetchall()]
    conn.close()
    return ips


def _open_or_update_incident(domain: str, source_ip: str, severity: str, event_count: int, summary: str) -> Dict[str, Any]:
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""SELECT id, event_count FROM sentinel_incidents
                 WHERE domain = ? AND source_ip = ? AND status = 'open'""", (domain, source_ip))
    row = c.fetchone()
    if row:
        c.execute("""UPDATE sentinel_incidents SET event_count = ?, severity = ?, summary = ?, updated_at = ?
                     WHERE id = ?""", (event_count, severity, summary, now, row["id"]))
        incident_id = row["id"]
    else:
        c.execute("""INSERT INTO sentinel_incidents
                     (domain, source_ip, severity, status, event_count, action_taken, summary, created_at, updated_at)
                     VALUES (?, ?, ?, 'open', ?, 'none', ?, ?, ?)""",
                  (domain, source_ip, severity, event_count, summary, now, now))
        incident_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"id": incident_id, "domain": domain, "source_ip": source_ip, "severity": severity}


def _mark_incident_action(incident_id: int, action: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sentinel_incidents SET action_taken = ?, updated_at = ? WHERE id = ?",
              (action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), incident_id))
    conn.commit()
    conn.close()


def _recent_event_count(domain: str, source_ip: str) -> int:
    conn = get_connection()
    c = conn.cursor()
    window_start = (datetime.now() - timedelta(seconds=CORRELATION_WINDOW_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""SELECT COUNT(*) AS n FROM sentinel_events
                 WHERE domain = ? AND source_ip = ? AND created_at > ?""",
              (domain, source_ip, window_start))
    row = c.fetchone()
    conn.close()
    return row["n"] if row else 0


def ingest_request_event(domain: str, source_ip: str, method: str, path: str,
                          query_string: str = "", body: str = "",
                          headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Main entry point called for every request an installed agent reports.
    Runs passive signature detection, stores the event, correlates it against
    recent history from the same IP, and - if the evidence crosses the
    threshold - opens/escalates an incident, triggers an automatic response
    (temporary IP block) and fires a live alert.
    Returns a directive the calling agent can act on immediately.
    """
    headers = headers or {}
    findings = inspect_request(method, path, query_string, body, headers)

    directive = {"block": False, "attack_detected": False, "incident": None}

    if _is_ip_blocked(domain, source_ip):
        directive["block"] = True
        return directive

    if not findings:
        return directive

    severity = highest_severity(findings)
    conn = get_connection()
    c = conn.cursor()
    c.execute("""INSERT INTO sentinel_events (domain, source_ip, method, path, findings_json, severity, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)""",
              (domain, source_ip, method, path, json.dumps(findings), severity,
               datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

    directive["attack_detected"] = True
    event_count = _recent_event_count(domain, source_ip)
    categories = sorted({f["category"] for f in findings})
    summary = f"{event_count} requête(s) suspecte(s) depuis {source_ip} sur {domain} ({', '.join(categories)})"

    should_escalate = severity in IMMEDIATE_ESCALATION_SEVERITIES or event_count >= EVENT_COUNT_THRESHOLD
    if should_escalate:
        incident = _open_or_update_incident(domain, source_ip, severity, event_count, summary)
        directive["incident"] = incident

        _block_ip(domain, source_ip, summary, minutes=30)
        _mark_incident_action(incident["id"], "ip_blocked_30min")
        directive["block"] = True

        log_event("SENTINEL_ATTACK_DETECTED", severity, "SENTINEL", summary)
        _fire_live_alert(domain, source_ip, severity, summary)

    return directive


def _fire_live_alert(domain: str, source_ip: str, severity: str, summary: str):
    try:
        from .. import alerts
        alerts.dispatch_live_attack_alert(domain, source_ip, severity, summary)
    except Exception as e:
        log_event("SENTINEL_ALERT_FAILED", "WARN", "SENTINEL", f"Échec de l'alerte live: {e}")


def list_incidents(domain: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    c = conn.cursor()
    if domain:
        c.execute("""SELECT * FROM sentinel_incidents WHERE domain = ?
                     ORDER BY updated_at DESC LIMIT ?""", (domain, limit))
    else:
        c.execute("SELECT * FROM sentinel_incidents ORDER BY updated_at DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows
