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
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ..database import get_connection, log_event, is_domain_authorized, is_admin_private_domain_authorized
from ..network_guard import LAB_HOSTS
from .waf_signatures import inspect_request, highest_severity

KEY_PREFIX = "sk_sentinel_"

# A load test exposed real external-API concurrency as the actual bottleneck:
# bounding each AI call's wall-clock time (see _bounded_semantic_check /
# _llm_judge_ambiguous) stops any ONE request from hanging, but under load
# many ambiguous requests still queue up waiting their turn for a slow/
# rate-limited provider, pushing tail latency past 5-15s. This caps how many
# such calls run AT ONCE across the whole process; past that, a request skips
# the AI opinion immediately (fail-open, zero added latency) instead of
# waiting in line - throughput stays flat under load instead of degrading.
_AI_CALL_CONCURRENCY_LIMIT = 4
_ai_call_semaphore = threading.Semaphore(_AI_CALL_CONCURRENCY_LIMIT)

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

    # Every request hits _is_ip_blocked and _recent_event_count - these need
    # to stay fast as traffic/history grows, not degrade into full table scans.
    c.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_lookup ON sentinel_blocklist(domain, source_ip, blocked_until)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_lookup ON sentinel_events(domain, source_ip, created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_incidents_lookup ON sentinel_incidents(domain, source_ip, status)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_incidents_domain_updated ON sentinel_incidents(domain, updated_at)")

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

def _is_ip_blocked(domain: str, source_ip: str, conn=None) -> bool:
    owns_conn = conn is None
    conn = conn or get_connection()
    c = conn.cursor()
    c.execute("""SELECT 1 FROM sentinel_blocklist
                 WHERE domain = ? AND source_ip = ? AND blocked_until > ?""",
              (domain, source_ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    row = c.fetchone()
    if owns_conn:
        conn.close()
    return row is not None


def _block_ip(domain: str, source_ip: str, reason: str, minutes: int = 30, conn=None):
    owns_conn = conn is None
    conn = conn or get_connection()
    c = conn.cursor()
    until = (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""INSERT INTO sentinel_blocklist (domain, source_ip, reason, blocked_until, created_at)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(domain, source_ip) DO UPDATE SET
                    reason = excluded.reason, blocked_until = excluded.blocked_until""",
              (domain, source_ip, reason, until, now))
    # Always commit (even on a shared connection): log_event() below opens its
    # own separate connection - leaving this write open would lock it out.
    conn.commit()
    if owns_conn:
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


def _open_or_update_incident(domain: str, source_ip: str, severity: str, event_count: int, summary: str, conn=None) -> Dict[str, Any]:
    owns_conn = conn is None
    conn = conn or get_connection()
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
    if owns_conn:
        conn.commit()
        conn.close()
    return {"id": incident_id, "domain": domain, "source_ip": source_ip, "severity": severity}


def _mark_incident_action(incident_id: int, action: str, conn=None):
    owns_conn = conn is None
    conn = conn or get_connection()
    c = conn.cursor()
    c.execute("UPDATE sentinel_incidents SET action_taken = ?, updated_at = ? WHERE id = ?",
              (action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), incident_id))
    if owns_conn:
        conn.commit()
        conn.close()


def _recent_event_count(domain: str, source_ip: str, conn=None) -> int:
    owns_conn = conn is None
    conn = conn or get_connection()
    c = conn.cursor()
    window_start = (datetime.now() - timedelta(seconds=CORRELATION_WINDOW_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""SELECT COUNT(*) AS n FROM sentinel_events
                 WHERE domain = ? AND source_ip = ? AND created_at > ?""",
              (domain, source_ip, window_start))
    row = c.fetchone()
    if owns_conn:
        conn.close()
    return row["n"] if row else 0


def ingest_request_event(domain: str, source_ip: str, method: str, path: str,
                          query_string: str = "", body: str = "",
                          headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Main entry point called for every request an installed agent reports.
    Runs passive signature detection, stores the event, correlates it against
    recent history from the same IP, evaluates the Emergency Shield threat tier,
    and triggers deterministic mitigations (IP block, session revocation, forensic snapshot).
    """
    from .shield import emergency_shield, ShieldTier

    headers = headers or {}
    shield_status = emergency_shield.get_status()
    directive = {
        "block": False,
        "attack_detected": False,
        "incident": None,
        "shield_tier": shield_status["tier"]
    }

    # Check revoked sessions in incoming auth or cookie headers
    auth_val = headers.get("Authorization") or headers.get("authorization") or headers.get("Cookie") or headers.get("cookie") or ""
    if auth_val and emergency_shield.is_session_revoked(auth_val):
        directive["block"] = True
        directive["reason"] = "session_revoked"
        return directive

    # One shared connection for the rest of this request's DB work instead of a
    # fresh open/close per helper call (a load test showed those adding up to
    # real tail latency under concurrent attack traffic). Closed in `finally`
    # so every early-return path below still releases it.
    conn = get_connection()
    try:
        return _ingest_request_event_inner(domain, source_ip, method, path, query_string,
                                            body, headers, directive, conn)
    finally:
        conn.close()


def _ingest_request_event_inner(domain, source_ip, method, path, query_string, body,
                                 headers, directive, conn) -> Dict[str, Any]:
    from .shield import emergency_shield, ShieldTier

    if _is_ip_blocked(domain, source_ip, conn=conn):
        directive["block"] = True
        return directive

    findings = inspect_request(method, path, query_string, body, headers, domain=domain)

    # Behavioral layer: catches zero-day/brute-force activity with NO payload
    # signature at all, just by noticing an abnormal request rate.
    from . import anomaly
    anomaly_finding = anomaly.record_and_check(domain, source_ip)
    if anomaly_finding:
        findings.append(anomaly_finding)

    # Similarity layer: even with zero exact/regex hit, check if this request
    # closely resembles a previously confirmed attack (reordered params, tweaked
    # literal, light obfuscation) - catches near-variants a strict regex misses.
    semantic_already_confirmed = False
    if not findings:
        from .learned_signatures import find_similar_signature, find_similar_signature_semantic, _resolve_system_llm_user_id
        combined_text = f"{path}?{query_string} {body}".strip()

        # Stage 1: free local shingle match - confident hit used directly.
        # (domain-scoped: a provisional, uncorroborated signature only applies
        # to the domain that produced it - see anti-poisoning note above)
        similar = find_similar_signature(combined_text, domain=domain, threshold=0.45)

        # Stage 2: a WEAK lexical overlap alone isn't trusted, but it's cheap
        # enough to use as a pre-filter for the one case that justifies an
        # embedding API call - true semantic confirmation (catches a known
        # attack rephrased/encoded so differently the shingle score stays low).
        if not similar and find_similar_signature(combined_text, domain=domain, threshold=0.20):
            uid = _resolve_system_llm_user_id()
            if uid:
                similar = _bounded_semantic_check(combined_text, uid, domain)
                if similar:
                    semantic_already_confirmed = True  # skip the redundant LLM judge below

        if similar:
            findings.append({
                "category": similar["category"], "severity": "MEDIUM",
                "source": similar.get("source", "similarity"),
                "pattern": f"similar_to#{similar['id']} ({similar['score']:.2f})"
            })

    if not findings:
        return directive

    severity = highest_severity(findings)
    categories = sorted({f["category"] for f in findings})
    primary_category = categories[0] if categories else "generic_attack"

    # Intelligence layer: for genuinely ambiguous signals (nothing CRITICAL/HIGH
    # fired - only a weak static hit or a behavioral anomaly), ask an LLM to
    # judge intent/context like a human analyst would, instead of blindly
    # trusting a pattern match. Fails open on timeout/error: if the judge can't
    # decide in time, the existing threshold logic below still applies
    # unchanged. Skipped when the embedding similarity layer ALREADY spent its
    # own bounded AI call confirming this request - a load test showed the two
    # intelligence layers stacking their timeouts sequentially (up to ~4s on
    # one request); one AI opinion per request is the point, not two.
    if severity in ("LOW", "MEDIUM") and not semantic_already_confirmed:
        verdict = _llm_judge_ambiguous(domain, source_ip, method, path, query_string, body, findings)
        if verdict == "benign":
            return directive  # judged as noise - don't escalate, don't pollute the incident feed
        elif verdict == "attack":
            severity = "HIGH"

    # Evaluate Emergency Shield deterministic tier
    combined_payload = f"Path: {path}?{query_string}\nBody: {body}"
    new_tier = emergency_shield.evaluate_incident_stream(
        target=domain,
        source_ip=source_ip,
        severity=severity,
        attack_type=primary_category,
        raw_payload=combined_payload
    )
    directive["shield_tier"] = new_tier.value

    c = conn.cursor()
    c.execute("""INSERT INTO sentinel_events (domain, source_ip, method, path, findings_json, severity, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)""",
              (domain, source_ip, method, path, json.dumps(findings), severity,
               datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()

    directive["attack_detected"] = True
    event_count = _recent_event_count(domain, source_ip, conn=conn)
    summary = f"{event_count} requête(s) suspecte(s) depuis {source_ip} sur {domain} ({', '.join(categories)})"

    should_escalate = (
        severity in IMMEDIATE_ESCALATION_SEVERITIES or
        event_count >= EVENT_COUNT_THRESHOLD or
        new_tier in (ShieldTier.DEFENSIVE, ShieldTier.EMERGENCY)
    )

    if should_escalate:
        incident = _open_or_update_incident(domain, source_ip, severity, event_count, summary, conn=conn)
        directive["incident"] = incident

        block_minutes = 120 if new_tier == ShieldTier.EMERGENCY else (60 if new_tier == ShieldTier.DEFENSIVE else 30)
        _block_ip(domain, source_ip, summary, minutes=block_minutes, conn=conn)
        _mark_incident_action(incident["id"], f"ip_blocked_{block_minutes}min", conn=conn)
        conn.commit()
        directive["block"] = True

        log_event("SENTINEL_ATTACK_DETECTED", severity, "SENTINEL", summary)
        _fire_live_alert(domain, source_ip, severity, summary)
        clean_payload = f"{path}?{query_string} {body}".strip()
        _learn_from_confirmed_attack(domain, source_ip, severity, primary_category, clean_payload)

    return directive


def _learn_from_confirmed_attack(domain: str, source_ip: str, severity: str, category: str, raw_payload: str):
    """Every escalated incident is a confirmed attack technique - fingerprint it
    into a signature immediately, shared across every domain/app/tool Ultron
    protects, so the exact same trick never works twice anywhere."""
    try:
        from .learned_signatures import learn_from_payload
        learn_from_payload(category=category, severity=severity, raw_payload=raw_payload,
                            domain=domain, source_ip=source_ip, origin="auto_incident")
    except Exception as e:
        log_event("SENTINEL_SIGNATURE_LEARN_FAILED", "WARN", "SENTINEL", f"Échec de l'apprentissage auto: {e}")


_SEMANTIC_CHECK_TIMEOUT_SECONDS = 1.5


def _bounded_semantic_check(combined_text: str, uid: str, domain: str) -> Optional[Dict[str, Any]]:
    """find_similar_signature_semantic() makes a real network call to an
    embedding API with its own ~10s HTTP timeout - way too long to block the
    request path on. A load test surfaced this: a slow/unavailable embedding
    provider was driving p99 latency past 5s. This bounds it the same way as
    the LLM judge - a hard wall-clock timeout, fail-open (no match) past it."""
    if not _ai_call_semaphore.acquire(blocking=False):
        return None  # at capacity - skip the AI opinion rather than queue behind it

    from .learned_signatures import find_similar_signature_semantic
    result_box: Dict[str, Any] = {}

    def _run():
        try:
            r = find_similar_signature_semantic(combined_text, uid, domain=domain)
            if r:
                result_box["result"] = r
        finally:
            _ai_call_semaphore.release()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=_SEMANTIC_CHECK_TIMEOUT_SECONDS)
    return result_box.get("result")


def _llm_judge_ambiguous(domain: str, source_ip: str, method: str, path: str,
                          query_string: str, body: str, findings: List[Dict[str, Any]]) -> Optional[str]:
    """Live gray-zone judge: runs in a background thread with a hard timeout so
    a slow/unavailable LLM can never add latency to the request path or block
    traffic by default. Returns 'attack', 'benign', or None (couldn't decide
    in time - caller keeps its existing behavior unchanged)."""
    from .learned_signatures import _resolve_system_llm_user_id, get_domain_threat_memory
    user_id = _resolve_system_llm_user_id()
    if not user_id:
        return None

    if not _ai_call_semaphore.acquire(blocking=False):
        return None  # at capacity - skip the AI opinion rather than queue behind it

    result_box: Dict[str, str] = {}

    def _run():
        try:
            from .user_llm_manager import user_llm_manager
            from .models import AgentMessage
            provider, _meta = user_llm_manager.resolve_user_llm_instance(user_id=user_id)

            memory = get_domain_threat_memory(domain)
            memory_block = ""
            if memory:
                lines = "\n".join(f"- {m['n']} incident(s) de sévérité {m['severity']}" for m in memory)
                memory_block = f"\nHistorique récent connu sur ce domaine (14 derniers jours) :\n{lines}\n"

            prompt = (
                "Tu es un analyste SOC expérimenté. Évalue si cette requête HTTP est une "
                "tentative d'attaque ou simplement du trafic normal, en jugeant le contexte "
                "global plutôt qu'un seul motif textuel isolé. Utilise l'historique du domaine "
                "pour ajuster ta vigilance - un domaine déjà ciblé récemment mérite plus de suspicion.\n"
                f"Domaine: {domain}\nIP source: {source_ip}\nMéthode: {method}\nChemin: {path}\n"
                f"Query: {query_string[:300]}\nBody: {(body or '')[:300]}\n"
                f"Signaux faibles détectés: {json.dumps(findings)[:400]}\n"
                f"{memory_block}"
                'Réponds UNIQUEMENT avec un JSON : {"verdict": "attack"|"benign", "reason": "..."} - rien d\'autre.'
            )
            resp = provider.chat([AgentMessage(role="user", content=prompt)], tools=None)
            content = (resp.content or "").strip()
            if content.startswith("```"):
                content = content.strip("`")
                if content.lower().startswith("json"):
                    content = content[4:].strip()
            data = json.loads(content)
            verdict = data.get("verdict")
            if verdict in ("attack", "benign"):
                result_box["verdict"] = verdict
        except Exception:
            pass
        finally:
            _ai_call_semaphore.release()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=2.5)
    return result_box.get("verdict")


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
