"""
learned_signatures.py - Self-learning detection layer for the Sentinel Real-Time Shield.

Two feeds turn a confirmed attack into a brand-new detection rule, active
immediately across EVERY protected domain/app/tool (not just the one that was hit):

1. auto_incident - every time realtime.py escalates an incident (a real attack,
   not noise), the exact payload fragment that triggered it is fingerprinted and
   turned into a narrow literal signature. Fast, synchronous, no LLM call (this
   runs on the hot request path), so Ultron "remembers" the exact technique the
   instant it is used anywhere.

2. human_taught - a SOC admin who defeats the shield during an authorized
   pentest/red-team drill (or a client who got hit by something novel) feeds the
   exact technique into "Teach Ultron" from the dashboard. Since this path has no
   latency pressure, the admin's own connected LLM is used to generalize the
   payload into a slightly broader, still-conservative regex (e.g. keep the SQL
   structure, drop the specific literal) before activating it everywhere.

Deliberately NOT auto-enforcement-only: deactivate_signature() is the admin
escape hatch in case an auto-learned rule turns out to be a false-positive magnet.
"""

import hashlib
import json
import logging
import math
import re
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ..database import get_connection, log_event

logger = logging.getLogger("sentinel.learned_signatures")

_CACHE: Dict[str, Any] = {"compiled": [], "loaded_at": None}
_CACHE_TTL_SECONDS = 15


def init_learned_signature_tables():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_learned_signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT UNIQUE NOT NULL,
        pattern_regex TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'HIGH',
        origin TEXT NOT NULL,
        source_domain TEXT,
        source_ip TEXT,
        example_payload TEXT,
        hit_count INTEGER NOT NULL DEFAULT 1,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        last_hit_at TEXT
    )
    """)
    for col_sql in (
        "ALTER TABLE sentinel_learned_signatures ADD COLUMN embedding_json TEXT",
        "ALTER TABLE sentinel_learned_signatures ADD COLUMN deactivation_reason TEXT",
        "ALTER TABLE sentinel_learned_signatures ADD COLUMN scope TEXT NOT NULL DEFAULT 'provisional'",
    ):
        try:
            c.execute(col_sql)
        except Exception:
            pass  # column already exists

    # Anti-poisoning: WHO sighted this signature and from where, so a single
    # attacker spamming one domain can never unilaterally make a rule trusted
    # everywhere - promotion to global scope requires independent corroboration.
    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_signature_sightings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        signature_id INTEGER NOT NULL,
        domain TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(signature_id, domain, source_ip)
    )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_sightings_sig ON sentinel_signature_sightings(signature_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_learned_sig_fingerprint ON sentinel_learned_signatures(fingerprint)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_learned_sig_active ON sentinel_learned_signatures(is_active)")
    conn.commit()
    conn.close()


# A signature becomes trusted GLOBALLY (applied to every protected domain) only
# once independently corroborated - otherwise one attacker could "teach" Ultron
# a bogus rule against their own traffic and have it instantly block unrelated
# clients everywhere. Until then it only protects the domain that produced it.
MIN_DISTINCT_DOMAINS_FOR_GLOBAL = 2
MIN_DISTINCT_IPS_FOR_GLOBAL = 3


def _record_sighting_and_maybe_promote(signature_id: int, domain: str, source_ip: str):
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute("""INSERT INTO sentinel_signature_sightings (signature_id, domain, source_ip, created_at)
                     VALUES (?, ?, ?, ?)""", (signature_id, domain or "", source_ip or "", now))
    except Exception:
        pass  # already sighted from this exact (domain, source_ip) - no new corroboration signal

    c.execute("""SELECT COUNT(DISTINCT domain) as d, COUNT(DISTINCT source_ip) as i
                 FROM sentinel_signature_sightings WHERE signature_id = ?""", (signature_id,))
    row = c.fetchone()
    distinct_domains, distinct_ips = (row["d"], row["i"]) if row else (0, 0)

    c.execute("SELECT scope FROM sentinel_learned_signatures WHERE id = ?", (signature_id,))
    cur = c.fetchone()
    if cur and cur["scope"] == "provisional" and (
        distinct_domains >= MIN_DISTINCT_DOMAINS_FOR_GLOBAL or distinct_ips >= MIN_DISTINCT_IPS_FOR_GLOBAL
    ):
        c.execute("UPDATE sentinel_learned_signatures SET scope = 'confirmed' WHERE id = ?", (signature_id,))
        conn.commit()
        conn.close()
        _CACHE["loaded_at"] = None
        log_event("SENTINEL_SIGNATURE_PROMOTED", "INFO", "SENTINEL",
                   f"Signature #{signature_id} corroborée par {distinct_domains} domaine(s)/{distinct_ips} IP(s) distincts - passée en portée globale.")
        return
    conn.commit()
    conn.close()


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode("utf-8", errors="replace")).hexdigest()


def _extract_payload_token(raw_text: str, max_len: int = 120) -> Optional[str]:
    """Pulls the suspicious fragment worth signature-matching out of a raw request
    chunk. Kept deliberately simple/fast - this is called on the hot request path."""
    text = (raw_text or "").strip()
    if not text:
        return None
    core = text[:max_len].strip()
    return core if len(core) >= 4 else None


def learn_from_payload(category: str, severity: str, raw_payload: str,
                        domain: str = "", source_ip: str = "",
                        origin: str = "auto_incident",
                        pattern_regex_override: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Converts a confirmed-malicious payload fragment into a signature and
    activates it immediately. Synchronous and local-only - safe to call from the
    request-handling hot path."""
    init_learned_signature_tables()
    token = _extract_payload_token(raw_payload)
    if not token:
        return None

    fp = _fingerprint(f"{category}:{token}")
    pattern_regex = pattern_regex_override or re.escape(token)

    try:
        re.compile(pattern_regex, re.I)
    except re.error:
        pattern_regex = re.escape(token)

    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("SELECT id, hit_count FROM sentinel_learned_signatures WHERE fingerprint = ?", (fp,))
    existing = c.fetchone()
    if existing:
        c.execute("UPDATE sentinel_learned_signatures SET hit_count = ?, last_hit_at = ? WHERE id = ?",
                   (existing["hit_count"] + 1, now, existing["id"]))
        conn.commit()
        conn.close()
        # Corroboration check happens on every repeat sighting too - this is how
        # a provisional (single-domain) rule earns global trust over time.
        _record_sighting_and_maybe_promote(existing["id"], domain, source_ip)
        return {"new": False, "id": existing["id"]}

    # human_taught comes from an admin who directly vouches for it (gated by
    # admin_owner_required) - no poisoning risk, trusted globally immediately.
    # auto_incident is attacker-influenced input - starts provisional, scoped
    # to the domain that produced it, until independently corroborated.
    initial_scope = "confirmed" if origin == "human_taught" else "provisional"

    c.execute("""
    INSERT INTO sentinel_learned_signatures
    (fingerprint, pattern_regex, category, severity, origin, source_domain, source_ip,
     example_payload, hit_count, is_active, scope, created_at, last_hit_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?)
    """, (fp, pattern_regex, category, severity, origin, domain, source_ip, token[:300], initial_scope, now, now))
    new_id = c.lastrowid
    conn.commit()
    conn.close()

    if initial_scope == "provisional":
        _record_sighting_and_maybe_promote(new_id, domain, source_ip)

    _CACHE["loaded_at"] = None  # force reload on next detection pass
    log_event("SENTINEL_SIGNATURE_LEARNED", "INFO", "SENTINEL",
              f"Nouvelle signature apprise [{category}/{origin}/{initial_scope}] depuis {domain or 'inconnu'} : {token[:60]}")

    if origin == "auto_incident" and not pattern_regex_override:
        # Learned instantly as a safe literal match; upgrade it to an
        # AI-generalized regex in the background so it also catches variants.
        schedule_background_generalization(new_id, category, token)

    return {"new": True, "id": new_id, "pattern": pattern_regex, "category": category}


def get_active_learned_patterns() -> List[Dict[str, Any]]:
    """Compiled regex + metadata for every active learned signature. Cached briefly
    so the hot detection path doesn't hit SQLite on every single request.
    Also builds a shingle -> signature-ids inverted index alongside it, so
    similarity lookups scale past a few hundred signatures (see
    find_similar_signature) instead of comparing against every single one."""
    init_learned_signature_tables()
    now = datetime.now()
    if _CACHE["loaded_at"] and (now - _CACHE["loaded_at"]).total_seconds() < _CACHE_TTL_SECONDS:
        return _CACHE["compiled"]

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sentinel_learned_signatures WHERE is_active = 1")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    compiled = []
    shingle_index: Dict[str, set] = {}
    by_id: Dict[int, Dict[str, Any]] = {}
    for r in rows:
        try:
            sig = {**r, "_compiled": re.compile(r["pattern_regex"], re.I)}
        except re.error:
            continue
        sig["_shingles"] = _shingles(sig.get("example_payload") or "")
        compiled.append(sig)
        by_id[sig["id"]] = sig
        for sh in sig["_shingles"]:
            shingle_index.setdefault(sh, set()).add(sig["id"])

    _CACHE["compiled"] = compiled
    _CACHE["shingle_index"] = shingle_index
    _CACHE["by_id"] = by_id
    _CACHE["loaded_at"] = now
    return compiled


def _resolve_system_llm_user_id() -> Optional[str]:
    """For background jobs with no HTTP request context (async generalization,
    the live ambiguous-traffic judge): picks the most recently active LLM
    connection as the system's own 'brain' for passive intelligence tasks."""
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("""SELECT user_id FROM sentinel_user_llm_connections
                     WHERE connection_status = 'active'
                     ORDER BY (last_used_at IS NULL) ASC, last_used_at DESC LIMIT 1""")
        row = c.fetchone()
        conn.close()
        return row["user_id"] if row else None
    except Exception:
        return None


def upgrade_signature_pattern(signature_id: int, new_regex: str) -> bool:
    """Replaces a signature's literal regex with a generalized one (validated first)."""
    try:
        re.compile(new_regex, re.I)
    except re.error:
        return False
    init_learned_signature_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sentinel_learned_signatures SET pattern_regex = ? WHERE id = ?", (new_regex, signature_id))
    conn.commit()
    changed = c.rowcount > 0
    conn.close()
    _CACHE["loaded_at"] = None
    return changed


def embed_text(text: str, user_id: Optional[str]) -> Optional[List[float]]:
    """True semantic vector for a piece of text, via whichever LLM backend the
    resolved user/system identity has connected. Returns None (never raises)
    if there's no usable identity, the backend has no embeddings API (e.g.
    Anthropic Claude), or the call failed - callers must fall back to the
    local shingle-based similarity in that case."""
    if not user_id or not (text or "").strip():
        return None
    try:
        from .user_llm_manager import user_llm_manager
        provider, _meta = user_llm_manager.resolve_user_llm_instance(user_id=user_id)
        vectors = provider.embed([text[:2000]])
        if vectors and vectors[0]:
            return vectors[0]
    except Exception as e:
        logger.warning(f"Échec de génération d'embedding: {e}")
    return None


def store_signature_embedding(signature_id: int, vector: List[float]):
    init_learned_signature_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sentinel_learned_signatures SET embedding_json = ? WHERE id = ?",
              (json.dumps(vector), signature_id))
    conn.commit()
    conn.close()
    _CACHE["loaded_at"] = None


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def find_similar_signature_semantic(text: str, user_id: Optional[str], threshold: float = 0.82,
                                     domain: str = "") -> Optional[Dict[str, Any]]:
    """Real semantic similarity via embeddings - catches variants that read
    completely differently but mean the same attack (paraphrased, encoded,
    reordered), which the local shingle layer would miss. Deliberately kept as
    a CONFIRMATION step on top of the free shingle pre-filter (see realtime.py)
    rather than run on every request, since it costs one embedding API call.
    `domain` applies the same anti-poisoning scoping as the exact-match layer."""
    vector = embed_text(text, user_id)
    if not vector:
        return None
    best = None
    for sig in get_active_learned_patterns():
        if sig.get("scope") == "provisional" and sig.get("source_domain") != domain:
            continue
        emb_json = sig.get("embedding_json")
        if not emb_json:
            continue
        sig_vec = sig.get("_embedding")
        if sig_vec is None:
            try:
                sig_vec = json.loads(emb_json)
            except Exception:
                sig_vec = None
            sig["_embedding"] = sig_vec
        if not sig_vec:
            continue
        score = _cosine(vector, sig_vec)
        if score >= threshold and (best is None or score > best["score"]):
            best = {"id": sig["id"], "category": sig["category"], "severity": sig["severity"], "score": score}
    return best


# A load test exposed this: with no cap, a burst of new signatures (e.g. an
# attack wave hitting many distinct payloads at once) spawns one background AI
# call PER signature, all hitting the same real provider concurrently. That
# congestion was severe enough to slow down even the live request path's own
# (separately bounded) AI calls, since it's the same external API/quota being
# hammered. This queues excess background jobs instead of firing them all at
# once - still off the hot path, just throttled to a sane concurrency.
_BACKGROUND_AI_CONCURRENCY_LIMIT = 2
_background_ai_semaphore = threading.Semaphore(_BACKGROUND_AI_CONCURRENCY_LIMIT)


def schedule_background_generalization(signature_id: int, category: str, example_payload: str):
    """auto_incident signatures start as a narrow literal match (safe, instant).
    This upgrades them in the background to an AI-generalized regex AND
    computes its embedding for semantic matching - off the hot request path,
    so neither ever adds latency to the detection pipeline itself."""
    def _run():
        _background_ai_semaphore.acquire()  # blocking is fine here - we're off the hot path
        try:
            _do_generalize_and_embed()
        finally:
            _background_ai_semaphore.release()

    def _do_generalize_and_embed():
        user_id = _resolve_system_llm_user_id()
        try:
            regex = _generalize_payload_with_ai(example_payload, category, user_id)
            if regex:
                upgrade_signature_pattern(signature_id, regex)
                log_event("SENTINEL_SIGNATURE_GENERALIZED", "INFO", "SENTINEL",
                          f"Signature #{signature_id} ({category}) généralisée par l'IA en arrière-plan.")
        except Exception as e:
            logger.warning(f"Généralisation IA asynchrone échouée pour signature {signature_id}: {e}")

        try:
            vector = embed_text(example_payload, user_id)
            if vector:
                store_signature_embedding(signature_id, vector)
        except Exception as e:
            logger.warning(f"Embedding asynchrone échoué pour signature {signature_id}: {e}")

    threading.Thread(target=_run, daemon=True).start()


def _shingles(text: str, n: int = 4) -> set:
    """Character n-grams of normalized text, for cheap local similarity matching."""
    norm = re.sub(r"\s+", " ", (text or "").strip().lower())
    if not norm:
        return set()
    if len(norm) < n:
        return {norm}
    return {norm[i:i + n] for i in range(len(norm) - n + 1)}


def find_similar_signature(text: str, threshold: float = 0.45, domain: str = "") -> Optional[Dict[str, Any]]:
    """Approximate local text-similarity (shingle/Jaccard) against learned
    signatures - catches near-variants of a known attack (reordered params,
    tweaked literals, light obfuscation) that an exact regex would miss
    entirely. Not true semantic embeddings, but cheap and fully local.

    Scales via an inverted shingle index (built in get_active_learned_patterns)
    instead of a full O(n) scan: only signatures that share at least one
    4-gram with the query text are ever compared, so this stays fast even
    with thousands of signatures. `domain` applies the anti-poisoning scope
    rule (a provisional signature only matches the domain that produced it)."""
    if not text or len(text.strip()) < 6:
        return None
    query_shingles = _shingles(text)
    if not query_shingles:
        return None

    get_active_learned_patterns()  # ensures _CACHE is warm
    shingle_index = _CACHE.get("shingle_index") or {}
    by_id = _CACHE.get("by_id") or {}

    candidate_ids: set = set()
    for sh in query_shingles:
        candidate_ids |= shingle_index.get(sh, set())

    best = None
    for sig_id in candidate_ids:
        sig = by_id.get(sig_id)
        if not sig:
            continue
        if sig.get("scope") == "provisional" and sig.get("source_domain") != domain:
            continue
        sig_shingles = sig.get("_shingles") or set()
        union = len(query_shingles | sig_shingles)
        if not union:
            continue
        score = len(query_shingles & sig_shingles) / union
        if score >= threshold and (best is None or score > best["score"]):
            best = {"id": sig["id"], "category": sig["category"], "severity": sig["severity"], "score": score}
    return best


def _generalize_payload_with_ai(payload: str, category: str, user_id: Optional[str]) -> Optional[str]:
    """Human-taught path only (no latency pressure): asks the admin's own connected
    LLM to generalize a one-off exploit payload into a conservative regex that
    keeps the attack's structure but drops the specific literal, so near-variants
    get caught too. Falls back to None (literal match) on any failure."""
    if not user_id:
        return None
    try:
        from .user_llm_manager import user_llm_manager
        from .models import AgentMessage
        provider, _meta = user_llm_manager.resolve_user_llm_instance(user_id=user_id)

        lessons = get_false_positive_lessons(limit=5)
        lessons_block = ""
        if lessons:
            lessons_lines = "\n".join(
                f"- Catégorie '{l['category']}', exemple {json.dumps((l.get('example_payload') or '')[:120])} "
                f"-> ERREUR: {l.get('deactivation_reason')}"
                for l in lessons
            )
            lessons_block = (
                "\nERREURS PASSÉES À NE PAS RÉPÉTER (règles précédemment désactivées car trop larges/fausses) :\n"
                f"{lessons_lines}\n"
            )

        prompt = (
            "Tu es un expert WAF. On a confirmé que ce payload est une attaque réelle "
            f"de catégorie '{category}'. Payload exact : {json.dumps(payload[:300])}\n"
            "Génère UNE expression régulière Python (re module) qui détecterait ce payload "
            "ET ses variantes directes (même structure/technique), sans être si générique "
            "qu'elle déclencherait sur du trafic normal."
            f"{lessons_block}"
            'Réponds UNIQUEMENT avec un objet JSON : {"regex": "..."} - rien d\'autre, pas de markdown.'
        )
        resp = provider.chat([AgentMessage(role="user", content=prompt)], tools=None)
        content = (resp.content or "").strip()
        if content.startswith("```"):
            content = content.strip("`")
            if content.lower().startswith("json"):
                content = content[4:].strip()
        data = json.loads(content)
        candidate = data.get("regex")
        if candidate:
            re.compile(candidate, re.I)  # validate before trusting it
            return candidate
    except Exception as e:
        logger.warning(f"Généralisation IA de signature échouée, repli sur correspondance littérale: {e}")
    return None


def teach_signature(category: str, severity: str, example_payload: str,
                     taught_by: str, notes: str = "", user_id: Optional[str] = None) -> Dict[str, Any]:
    """Human-in-the-loop: feed in a technique that defeated the shield (during an
    authorized pentest/red-team drill, or reported by a protected client) and it
    is generalized, activated, and shared across every protected domain/app/tool
    immediately - the entire point of a collective-learning shield."""
    if not (example_payload or "").strip():
        return {"success": False, "error": "Payload d'exemple vide."}

    regex_override = _generalize_payload_with_ai(example_payload, category or "human_taught_technique", user_id)

    result = learn_from_payload(
        category=category or "human_taught_technique",
        severity=severity or "HIGH",
        raw_payload=example_payload,
        domain="manual_teach",
        source_ip="",
        origin="human_taught",
        pattern_regex_override=regex_override
    )
    if not result:
        return {"success": False, "error": "Payload trop court pour être généralisé en signature."}

    if result.get("new"):
        vector = embed_text(example_payload, user_id)
        if vector:
            store_signature_embedding(result["id"], vector)

    log_event("SENTINEL_SIGNATURE_TAUGHT", "INFO", "SENTINEL",
              f"Signature enseignée manuellement par {taught_by}: {notes or '(sans note)'}")
    return {"success": True, "ai_generalized": regex_override is not None, **result}


def list_learned_signatures(limit: int = 100) -> List[Dict[str, Any]]:
    init_learned_signature_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sentinel_learned_signatures ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def deactivate_signature(signature_id: int, reason: str = "") -> bool:
    """Owner-only escape hatch if an auto-learned rule turns out to be a
    false-positive magnet. The reason (why it was wrong) is kept permanently -
    it's not thrown away, it becomes a lesson fed into future AI
    generalizations (see get_false_positive_lessons / _generalize_payload_with_ai),
    so Ultron doesn't just forget a bad rule, it learns to avoid repeating the
    same mistake."""
    init_learned_signature_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sentinel_learned_signatures SET is_active = 0, deactivation_reason = ? WHERE id = ?",
              (reason or "Désactivée manuellement (faux positif présumé)", signature_id))
    conn.commit()
    changed = c.rowcount > 0
    conn.close()
    _CACHE["loaded_at"] = None
    if changed:
        log_event("SENTINEL_SIGNATURE_LESSON_RECORDED", "INFO", "SENTINEL",
                   f"Signature #{signature_id} désactivée - leçon retenue: {reason or '(aucune raison fournie)'}")
    return changed


def get_false_positive_lessons(limit: int = 8) -> List[Dict[str, Any]]:
    """Every rule that was ever deactivated as a false positive, with why -
    permanent memory of past mistakes, used to steer future AI generalizations
    away from repeating them."""
    init_learned_signature_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("""SELECT category, example_payload, deactivation_reason FROM sentinel_learned_signatures
                 WHERE is_active = 0 AND deactivation_reason IS NOT NULL
                 ORDER BY id DESC LIMIT ?""", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_domain_threat_memory(domain: str, days: int = 14, limit: int = 6) -> List[Dict[str, Any]]:
    """Recent confirmed-attack history for one domain - gives the live
    ambiguous-traffic judge situational memory ('this domain has seen 5 SQLi
    attempts this week') instead of judging every request from a blank slate."""
    init_learned_signature_tables()
    conn = get_connection()
    c = conn.cursor()
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""SELECT severity, COUNT(*) as n, GROUP_CONCAT(DISTINCT action_taken) as actions
                 FROM sentinel_incidents WHERE domain = ? AND updated_at > ?
                 GROUP BY severity ORDER BY n DESC LIMIT ?""", (domain, since, limit))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def reactivate_signature(signature_id: int) -> bool:
    init_learned_signature_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE sentinel_learned_signatures SET is_active = 1 WHERE id = ?", (signature_id,))
    conn.commit()
    changed = c.rowcount > 0
    conn.close()
    _CACHE["loaded_at"] = None
    return changed
