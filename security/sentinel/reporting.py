"""
reporting.py - Enterprise SOC Dashboard Aggregation & Executive Reporting Engine
Synthesizes infrastructure health, Emergency Shield status, multi-asset audit findings,
incident streams, and remediation efficacy into unified executive reports.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from ..database import get_connection
from .shield import emergency_shield
from .asset_registry import list_assets, list_projects
from .remediation import list_remediations
from .memory import list_audit_memory


def generate_consolidated_soc_report(project_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Builds a comprehensive real-time SOC security report across all dimensions:
    Infrastructures, Shield Tier, Incidents, Vulnerabilities, and Remediations.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Assets
    assets = list_assets(project_id=project_id)
    assets_by_type: Dict[str, int] = {}
    for a in assets:
        t = a.get("asset_type", "domain")
        assets_by_type[t] = assets_by_type.get(t, 0) + 1

    # 2. Emergency Shield Status
    shield_status = emergency_shield.get_status()

    # 3. Incidents
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT severity, status, COUNT(*) as count
    FROM sentinel_incidents
    GROUP BY severity, status
    """)
    incident_stats = {"total": 0, "open": 0, "resolved": 0, "by_severity": {}}
    for row in c.fetchall():
        sev = row["severity"]
        stat = row["status"]
        cnt = row["count"]
        incident_stats["total"] += cnt
        if stat == "open":
            incident_stats["open"] += cnt
        else:
            incident_stats["resolved"] += cnt
        incident_stats["by_severity"][sev] = incident_stats["by_severity"].get(sev, 0) + cnt
    conn.close()

    # 4. Remediation Progress
    remediations = list_remediations(limit=100)
    rem_stats = {
        "total": len(remediations),
        "pending_approval": sum(1 for r in remediations if r["status"] == "pending"),
        "applied": sum(1 for r in remediations if r["status"] == "applied"),
        "verified_fixed": sum(1 for r in remediations if r.get("post_validation_status") == "verified_fixed"),
        "rolled_back": sum(1 for r in remediations if r["status"] == "rolled_back")
    }

    # 5. Audits Memory
    audits = list_audit_memory(project_id=project_id, limit=20)
    avg_score = int(sum(a["risk_score"] for a in audits) / len(audits)) if audits else 15
    posture_grade = "A" if avg_score < 20 else ("B" if avg_score < 40 else ("C" if avg_score < 60 else "D"))

    # Resolve project title
    proj_name = "Global Multi-Projets"
    if project_id:
        projs = [p for p in list_projects() if p["id"] == project_id]
        if projs:
            proj_name = f"{projs[0]['name']} ({projs[0]['company_name']})"

    return {
        "generated_at": now,
        "project_scope": proj_name,
        "project_id": project_id,
        "global_security_posture": {
            "score": avg_score,
            "grade": posture_grade,
            "threat_tier": shield_status["tier"],
            "threat_level": shield_status["tier_level"]
        },
        "shield": shield_status,
        "assets_inventory": {
            "total_assets": len(assets),
            "by_type": assets_by_type
        },
        "incidents": incident_stats,
        "remediation_metrics": rem_stats,
        "recent_audits_count": len(audits)
    }


def generate_executive_html_report(project_id: Optional[str] = None) -> str:
    """
    Renders an executive, printable HTML report of the SOC posture.
    """
    data = generate_consolidated_soc_report(project_id=project_id)
    posture = data["global_security_posture"]
    shield = data["shield"]
    assets = data["assets_inventory"]
    rems = data["remediation_metrics"]
    incs = data["incidents"]

    grade_color = "#10b981" if posture["grade"] in ("A+", "A") else ("#f59e0b" if posture["grade"] == "B" else "#ef4444")
    tier_color = "#10b981" if shield["tier"] == "NORMAL" else ("#f59e0b" if shield["tier"] == "ALERT" else "#ef4444")

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>SENTINEL AI — Rapport Exécutif de Sécurité</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 2rem; }}
        .report-card {{ max-width: 900px; margin: auto; background: #111827; border: 1px solid #374151; border-radius: 12px; padding: 2.5rem; }}
        .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #374151; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        .title {{ font-size: 1.8rem; font-weight: 800; color: #38bdf8; margin: 0; }}
        .badge {{ padding: 6px 14px; border-radius: 6px; font-weight: 700; font-size: 0.9rem; text-transform: uppercase; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.2rem; margin-bottom: 2rem; }}
        .stat-box {{ background: #1f2937; border: 1px solid #374151; border-radius: 8px; padding: 1.2rem; }}
        .stat-val {{ font-size: 1.8rem; font-weight: 800; margin-top: 6px; }}
        .stat-label {{ color: #9ca3af; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #374151; font-size: 0.88rem; }}
        th {{ color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; }}
    </style>
</head>
<body>
    <div class="report-card">
        <div class="header">
            <div>
                <h1 class="title">SENTINEL AI &bull; Rapport Exécutif SOC</h1>
                <div style="color: #9ca3af; font-size: 0.85rem; margin-top: 6px;">Périmètre : {data['project_scope']} &bull; Date : {data['generated_at']}</div>
            </div>
            <div>
                <span class="badge" style="background: {tier_color}22; color: {tier_color}; border: 1px solid {tier_color};">
                    SHIELD: {shield['tier']}
                </span>
            </div>
        </div>

        <div class="grid">
            <div class="stat-box">
                <div class="stat-label">Posture Globale</div>
                <div class="stat-val" style="color: {grade_color};">Note {posture['grade']} <span style="font-size: 1rem; color: #9ca3af;">({posture['score']}/100)</span></div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Actifs Surveillés</div>
                <div class="stat-val" style="color: #38bdf8;">{assets['total_assets']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Incidents Actifs</div>
                <div class="stat-val" style="color: {'#ef4444' if incs['open'] > 0 else '#10b981'};">{incs['open']}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Correctifs Validés</div>
                <div class="stat-val" style="color: #a78bfa;">{rems['verified_fixed']}/{rems['total']}</div>
            </div>
        </div>

        <h3 style="color: #38bdf8; border-bottom: 1px solid #374151; padding-bottom: 8px;">Inventaire des Actifs d'Entreprise</h3>
        <table>
            <thead>
                <tr><th>Catégorie d'Actif</th><th>Nombre d'unités</th></tr>
            </thead>
            <tbody>
                {''.join(f"<tr><td>{t.capitalize()}</td><td>{count}</td></tr>" for t, count in assets['by_type'].items()) if assets['by_type'] else '<tr><td colspan="2">Aucun actif enregistré</td></tr>'}
            </tbody>
        </table>

        <h3 style="color: #38bdf8; border-bottom: 1px solid #374151; padding-bottom: 8px; margin-top: 2rem;">Mesures Actives de Protection</h3>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            {''.join(f'<span style="background: #1f2937; border: 1px solid #374151; color: #cbd5e1; padding: 4px 10px; border-radius: 4px; font-size: 0.78rem;">{m}</span>' for m in shield['active_mitigations'])}
        </div>
    </div>
</body>
</html>"""
    return html
