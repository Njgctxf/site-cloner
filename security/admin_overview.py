"""
admin_overview.py - Unified SaaS admin telemetry across Cloneur, Shop,
CyberLab security audits, Sentinel WAF/LLM, and 3-tier subscriptions.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from .database import get_connection, init_db
from .plans import PLANS, CLONER_PLANS, compute_subscription_mrr_eur, init_plan_tables, list_all_subscriptions
from .sentinel.realtime import init_realtime_tables, list_incidents
from .sentinel.shield import emergency_shield
from .sentinel.user_llm_manager import user_llm_manager


def _bucket_day(raw_ts: Any) -> str:
    """Normalizes a datetime string or Unix timestamp to YYYY-MM-DD."""
    if raw_ts is None:
        return ""
    if isinstance(raw_ts, (int, float)):
        return datetime.fromtimestamp(float(raw_ts)).strftime("%Y-%m-%d")
    text = str(raw_ts).strip()
    return text[:10] if len(text) >= 10 else ""


def _build_14d_timeline(
    manifest: Dict[str, Dict[str, Any]],
    shop_orders: List[Dict[str, Any]],
    scan_rows: List[Dict[str, Any]],
    log_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Builds aligned 14-day daily counters for clones, scans, orders, and alerts."""
    today = datetime.now().date()
    day_keys = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(13, -1, -1)]
    labels = [(today - timedelta(days=i)).strftime("%d/%m") for i in range(13, -1, -1)]
    idx_map = {k: i for i, k in enumerate(day_keys)}

    clones = [0] * 14
    scans = [0] * 14
    orders = [0] * 14
    alerts = [0] * 14

    for item in (manifest or {}).values():
        k = _bucket_day(item.get("date"))
        if k in idx_map:
            clones[idx_map[k]] += 1

    for row in shop_orders or []:
        k = _bucket_day(row.get("created_at"))
        if k in idx_map:
            orders[idx_map[k]] += 1

    for row in scan_rows:
        k = _bucket_day(row.get("timestamp"))
        if k in idx_map:
            scans[idx_map[k]] += 1

    alert_levels = {"WARN", "WARNING", "HIGH", "CRITICAL", "ERROR"}
    for row in log_rows:
        sev = str(row.get("severity") or "").upper()
        if sev in alert_levels:
            k = _bucket_day(row.get("timestamp"))
            if k in idx_map:
                alerts[idx_map[k]] += 1

    return {
        "days": day_keys,
        "labels": labels,
        "clones": clones,
        "scans": scans,
        "orders": orders,
        "alerts": alerts,
    }


def _collect_merged_subscriptions(conn) -> List[Dict[str, Any]]:
    """Returns explicit subscriptions merged with active current-month free users."""
    subs = list_all_subscriptions(limit=150)
    by_id = {s["user_id"]: s for s in subs}
    month_key = datetime.now(timezone.utc).strftime("%Y-%m")
    free_audit = conn.execute(
        """
        SELECT user_id, MAX(first_scan_at) AS updated_at, COUNT(site_host) AS sites_used_month
        FROM monthly_audit_usage
        WHERE month_key = ?
        GROUP BY user_id
        ORDER BY updated_at DESC
        LIMIT 100
        """,
        (month_key,),
    ).fetchall()
    for r in free_audit:
        if r["user_id"] not in by_id:
            entry = {
                "user_id": r["user_id"],
                "plan_id": "free",
                "cloner_plan_id": "free",
                "bundle_id": "",
                "status": "active",
                "source": "default",
                "email": "",
                "updated_at": r["updated_at"],
                "sites_used_month": r["sites_used_month"],
                "clones_used_month": 0,
            }
            subs.append(entry)
            by_id[r["user_id"]] = entry

    free_clone = conn.execute(
        """
        SELECT user_id, MAX(first_clone_at) AS updated_at, COUNT(site_host) AS clones_used_month
        FROM monthly_clone_usage
        WHERE month_key = ?
        GROUP BY user_id
        ORDER BY updated_at DESC
        LIMIT 100
        """,
        (month_key,),
    ).fetchall()
    for r in free_clone:
        if r["user_id"] in by_id:
            by_id[r["user_id"]]["clones_used_month"] = r["clones_used_month"]
        else:
            entry = {
                "user_id": r["user_id"],
                "plan_id": "free",
                "cloner_plan_id": "free",
                "bundle_id": "",
                "status": "active",
                "source": "default",
                "email": "",
                "updated_at": r["updated_at"],
                "sites_used_month": 0,
                "clones_used_month": r["clones_used_month"],
            }
            subs.append(entry)
            by_id[r["user_id"]] = entry

    has_users = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
    if has_users:
        for u in conn.execute("SELECT user_id, email, username, display_name, created_at FROM users ORDER BY created_at DESC LIMIT 150").fetchall():
            uid = u["user_id"]
            if uid in by_id:
                by_id[uid]["email"] = by_id[uid].get("email") or u["email"]
                by_id[uid]["username"] = u["username"]
                by_id[uid]["display_name"] = u["display_name"]
            else:
                entry = {
                    "user_id": uid,
                    "plan_id": "free",
                    "cloner_plan_id": "free",
                    "bundle_id": "",
                    "status": "active",
                    "source": "registered",
                    "email": u["email"],
                    "username": u["username"],
                    "display_name": u["display_name"],
                    "updated_at": u["created_at"],
                    "sites_used_month": 0,
                    "clones_used_month": 0,
                }
                subs.append(entry)
                by_id[uid] = entry
    return subs


def build_platform_admin_overview(
    manifest: Dict[str, Dict[str, Any]],
    jobs: Dict[str, Dict[str, Any]],
    active_servers: Dict[str, Any],
    shop_orders: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Aggregates security scans, domains, plans, WAF incidents, logs, and LLM usage."""
    init_db()
    init_plan_tables()
    init_realtime_tables()

    conn = get_connection()
    try:
        scan_rows = [
            dict(r)
            for r in conn.execute(
                "SELECT id, target_url, timestamp, risk_score, grade, critical_count, high_count, medium_count, low_count FROM scans ORDER BY id DESC LIMIT 200"
            ).fetchall()
        ]
        scan_totals = dict(
            conn.execute(
                """
                SELECT COUNT(*) AS total_scans,
                       COALESCE(AVG(risk_score), 0) AS avg_score,
                       COALESCE(SUM(critical_count), 0) AS critical,
                       COALESCE(SUM(high_count), 0) AS high,
                       COALESCE(SUM(medium_count), 0) AS medium,
                       COALESCE(SUM(low_count), 0) AS low
                FROM scans
                """
            ).fetchone()
        )
        grade_rows = conn.execute("SELECT grade, COUNT(*) AS n FROM scans GROUP BY grade").fetchall()
        domains_rows = [
            dict(r)
            for r in conn.execute(
                "SELECT id, domain, status, verification_method, verified_at, created_at FROM verified_domains ORDER BY id DESC LIMIT 100"
            ).fetchall()
        ]
        admin_domains_rows = [
            dict(r)
            for r in conn.execute(
                """
                SELECT id, domain,
                       CASE WHEN is_verified = 1 THEN 'verified' ELSE 'pending' END AS status,
                       verification_method, created_at
                FROM admin_private_domains
                ORDER BY id DESC LIMIT 50
                """
            ).fetchall()
        ]
        log_rows = [
            dict(r)
            for r in conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
        ]
        month_key = datetime.now(timezone.utc).strftime("%Y-%m")
        monthly_sites_audited = conn.execute(
            "SELECT COUNT(*) FROM monthly_audit_usage WHERE month_key = ?", (month_key,)
        ).fetchone()[0]
        monthly_sites_cloned = conn.execute(
            "SELECT COUNT(*) FROM monthly_clone_usage WHERE month_key = ?", (month_key,)
        ).fetchone()[0]
        subscriptions = _collect_merged_subscriptions(conn)
        has_users = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
        registered_users = [
            dict(r)
            for r in conn.execute(
                "SELECT user_id, email, username, display_name, company, created_at, last_login_at FROM users ORDER BY created_at DESC LIMIT 100"
            ).fetchall()
        ] if has_users else []
    finally:
        conn.close()

    plan_counts = {"free": 0, "pro": 0, "enterprise": 0}
    cloner_counts = {"free": 0, "pro": 0, "agency": 0}
    mrr_eur = 0
    for sub in subscriptions:
        pid = sub.get("plan_id") or "free"
        cpid = sub.get("cloner_plan_id") or "free"
        bid = sub.get("bundle_id") or ""
        if pid in plan_counts:
            plan_counts[pid] += 1
        if cpid in cloner_counts:
            cloner_counts[cpid] += 1
        mrr_eur += compute_subscription_mrr_eur(pid, cpid, bid)

    incidents = list_incidents(limit=30)
    open_incidents = sum(1 for inc in incidents if str(inc.get("status") or "").lower() != "resolved")
    shield_status = emergency_shield.get_status()
    llm_stats = user_llm_manager.get_admin_telemetry_stats()

    grade_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for g in grade_rows:
        bucket = (str(g["grade"] or "C")[0]).upper()
        if bucket in grade_counts:
            grade_counts[bucket] += g["n"]

    alert_levels = {"WARN", "WARNING", "HIGH", "CRITICAL", "ERROR"}
    warn_logs = sum(1 for r in log_rows if str(r.get("severity") or "").upper() in alert_levels)

    return {
        "timeline_14d": _build_14d_timeline(manifest, shop_orders, scan_rows, log_rows),
        "security": {
            "total_scans": int(scan_totals["total_scans"] or 0),
            "avg_score": round(float(scan_totals["avg_score"] or 0), 1),
            "severity_totals": {
                "critical": int(scan_totals["critical"] or 0),
                "high": int(scan_totals["high"] or 0),
                "medium": int(scan_totals["medium"] or 0),
                "low": int(scan_totals["low"] or 0),
            },
            "grade_counts": grade_counts,
            "recent_scans": scan_rows[:15],
        },
        "domains": {
            "verified": sum(1 for d in domains_rows if d.get("status") == "verified"),
            "pending": sum(1 for d in domains_rows if d.get("status") != "verified"),
            "admin_private": len(admin_domains_rows),
            "items": domains_rows[:25],
            "admin_items": admin_domains_rows[:25],
        },
        "plans": {
            "counts": plan_counts,
            "cloner_counts": cloner_counts,
            "mrr_eur": mrr_eur,
            "monthly_sites_audited": int(monthly_sites_audited or 0),
            "monthly_sites_cloned": int(monthly_sites_cloned or 0),
            "subscriptions": subscriptions[:80],
        },
        "shield": {
            "tier": shield_status.get("tier", "NORMAL"),
            "incidents_total": len(incidents),
            "incidents_open": open_incidents,
            "recent_incidents": incidents[:15],
        },
        "llm": llm_stats,
        "logs": {
            "warn_count": warn_logs,
            "recent": log_rows[:25],
        },
        "cloner": {
            "sites_count": len(manifest or {}),
            "active_previews": len(active_servers or {}),
            "jobs_running": sum(1 for j in (jobs or {}).values() if j.get("status") == "running"),
        },
        "accounts": {
            "total": len(registered_users),
            "items": registered_users,
        },
    }
