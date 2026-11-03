"""
shield.py - Emergency Shield & Deterministic Multi-Tier Active Defense
Operates completely independently of the LLM to provide instant, automated,
proportional infrastructure protection across 4 graduated tiers:
  - NORMAL (0): Continuous monitoring & telemetry collection
  - ALERT (1): Detection & notification of suspicious activity
  - DEFENSIVE (2): Proportional automated mitigations (IP block, rate-tightening, session kill)
  - EMERGENCY (3): Reinforced perimeter protection, forensic evidence snapshot, critical alerts
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple

from ..database import get_connection, log_event

logger = logging.getLogger("sentinel.shield")


class ShieldTier(str, Enum):
    NORMAL = "NORMAL"
    ALERT = "ALERT"
    DEFENSIVE = "DEFENSIVE"
    EMERGENCY = "EMERGENCY"


TIER_SEVERITY_WEIGHTS = {
    ShieldTier.NORMAL: 0,
    ShieldTier.ALERT: 1,
    ShieldTier.DEFENSIVE: 2,
    ShieldTier.EMERGENCY: 3,
}


def init_shield_tables():
    """Initializes tables for Emergency Shield multi-tier defense and forensics."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_shield_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        current_tier TEXT NOT NULL DEFAULT 'NORMAL',
        reason TEXT NOT NULL DEFAULT 'Système nominal',
        manual_override INTEGER NOT NULL DEFAULT 0,
        active_mitigations_json TEXT NOT NULL DEFAULT '[]',
        updated_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_forensics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER,
        target TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_revoked_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        session_hash TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    # Ensure default shield state exists
    c.execute("SELECT id FROM sentinel_shield_state WHERE id = 1")
    if not c.fetchone():
        c.execute("""
        INSERT INTO sentinel_shield_state (id, current_tier, reason, manual_override, active_mitigations_json, updated_at)
        VALUES (1, 'NORMAL', 'Démarrage nominal du système', 0, '[]', ?)
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))

    conn.commit()
    conn.close()


class EmergencyShield:
    """
    Central deterministic defensive engine.
    Continuously computes current threat tier and executes proportional mitigations.
    """

    def __init__(self):
        init_shield_tables()

    def get_status(self) -> Dict[str, Any]:
        """Returns the current operational tier and active defensive parameters."""
        init_shield_tables()
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM sentinel_shield_state WHERE id = 1")
        row = c.fetchone()
        conn.close()

        if not row:
            return {
                "tier": ShieldTier.NORMAL.value,
                "tier_level": 0,
                "reason": "Nominal",
                "manual_override": False,
                "active_mitigations": [],
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        tier_val = row["current_tier"]
        return {
            "tier": tier_val,
            "tier_level": TIER_SEVERITY_WEIGHTS.get(ShieldTier(tier_val), 0),
            "reason": row["reason"],
            "manual_override": bool(row["manual_override"]),
            "active_mitigations": json.loads(row["active_mitigations_json"] or "[]"),
            "updated_at": row["updated_at"]
        }

    def set_tier(self, tier: ShieldTier, reason: str, manual: bool = False) -> Dict[str, Any]:
        """Sets the shield operational tier manually or programmatically."""
        init_shield_tables()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mitigations = self._resolve_mitigations_for_tier(tier)

        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        UPDATE sentinel_shield_state
        SET current_tier = ?, reason = ?, manual_override = ?, active_mitigations_json = ?, updated_at = ?
        WHERE id = 1
        """, (tier.value, reason, 1 if manual else 0, json.dumps(mitigations), now))
        conn.commit()
        conn.close()

        log_event("SENTINEL_SHIELD_TIER_CHANGED", "CRITICAL" if tier == ShieldTier.EMERGENCY else "WARN", "EMERGENCY_SHIELD",
                  f"Palier Emergency Shield modifié vers [{tier.value}] : {reason} (Override: {manual})")

        return {
            "tier": tier.value,
            "tier_level": TIER_SEVERITY_WEIGHTS[tier],
            "reason": reason,
            "manual_override": manual,
            "active_mitigations": mitigations,
            "updated_at": now
        }

    def _resolve_mitigations_for_tier(self, tier: ShieldTier) -> List[str]:
        if tier == ShieldTier.NORMAL:
            return ["telemetry_monitoring", "standard_rate_limiting"]
        elif tier == ShieldTier.ALERT:
            return ["telemetry_monitoring", "detailed_audit_logging", "soc_live_alerts"]
        elif tier == ShieldTier.DEFENSIVE:
            return [
                "telemetry_monitoring",
                "detailed_audit_logging",
                "soc_live_alerts",
                "dynamic_ip_blocking",
                "rate_limit_tightening_50pct",
                "suspicious_session_revocation"
            ]
        elif tier == ShieldTier.EMERGENCY:
            return [
                "telemetry_monitoring",
                "forensic_evidence_snapshot",
                "strict_ip_isolation",
                "emergency_soc_dispatch",
                "rate_limit_tightening_80pct",
                "suspicious_session_revocation"
            ]
        return []

    def evaluate_incident_stream(self, target: str, source_ip: str, severity: str, attack_type: str, raw_payload: str = "") -> ShieldTier:
        """
        Deterministic state transition evaluation triggered when attacks are reported.
        Automatically elevates the shield tier based on evidence without waiting for LLM.
        """
        init_shield_tables()
        # Save forensic evidence
        self.record_forensic_evidence(target, source_ip, attack_type, raw_payload)

        status = self.get_status()
        if status["manual_override"]:
            return ShieldTier(status["tier"])

        current_tier = ShieldTier(status["tier"])

        # Determine target tier based on attack severity
        if severity == "CRITICAL":
            target_tier = ShieldTier.EMERGENCY
            reason = f"Attaque critique confirmée ({attack_type}) depuis {source_ip} ciblant {target}"
        elif severity == "HIGH":
            target_tier = ShieldTier.DEFENSIVE
            reason = f"Tentative d'exploitation de sévérité élevée ({attack_type}) depuis {source_ip}"
        elif severity in ("MEDIUM", "LOW"):
            target_tier = ShieldTier.ALERT if current_tier == ShieldTier.NORMAL else current_tier
            reason = f"Activité anormale détectée ({attack_type}) depuis {source_ip}"
        else:
            target_tier = current_tier
            reason = status["reason"]

        # Only escalate automatically, never de-escalate without cooldown/manual review
        if TIER_SEVERITY_WEIGHTS[target_tier] > TIER_SEVERITY_WEIGHTS[current_tier]:
            self.set_tier(target_tier, reason, manual=False)
            return target_tier

        return current_tier

    def record_forensic_evidence(self, target: str, source_ip: str, attack_type: str, raw_payload: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Saves tamper-evident snapshot of attack evidence with SHA-256 fingerprint."""
        init_shield_tables()
        payload_bytes = (raw_payload or "").encode("utf-8", errors="replace")
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        evidence = {
            "target": target,
            "source_ip": source_ip,
            "attack_type": attack_type,
            "payload_snippet": raw_payload[:500] if raw_payload else "",
            "metadata": metadata or {},
            "timestamp": now
        }

        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        INSERT INTO sentinel_forensics (target, source_ip, attack_type, payload_hash, evidence_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (target, source_ip, attack_type, payload_hash, json.dumps(evidence), now))
        record_id = c.lastrowid
        conn.commit()
        conn.close()

        return {"id": record_id, "payload_hash": payload_hash, "created_at": now}

    def list_forensic_evidence(self, limit: int = 50) -> List[Dict[str, Any]]:
        init_shield_tables()
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM sentinel_forensics ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = []
        for r in c.fetchall():
            d = dict(r)
            d["evidence"] = json.loads(d.get("evidence_json") or "{}")
            rows.append(d)
        conn.close()
        return rows

    def revoke_session(self, target: str, source_ip: str, session_token: str, reason: str = "Compromission suspectée") -> bool:
        """Immediately blacklists and revokes a compromised session token."""
        init_shield_tables()
        session_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        INSERT INTO sentinel_revoked_sessions (target, source_ip, session_hash, reason, created_at)
        VALUES (?, ?, ?, ?, ?)
        """, (target, source_ip, session_hash, reason, now))
        conn.commit()
        conn.close()

        log_event("SENTINEL_SESSION_REVOKED", "HIGH", "EMERGENCY_SHIELD",
                  f"Session révoquée pour {source_ip} sur {target} (Hash: {session_hash[:12]}...)")
        return True

    def is_session_revoked(self, session_token: str) -> bool:
        init_shield_tables()
        session_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM sentinel_revoked_sessions WHERE session_hash = ?", (session_hash,))
        found = bool(c.fetchone())
        conn.close()
        return found

    def reset_to_normal(self, reason: str = "Rétablissement manuel par l'administrateur") -> Dict[str, Any]:
        """Returns the Emergency Shield to NORMAL operational state."""
        return self.set_tier(ShieldTier.NORMAL, reason, manual=False)


# Global singleton
emergency_shield = EmergencyShield()
