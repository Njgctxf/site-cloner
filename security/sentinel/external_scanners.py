"""
external_scanners.py - External Open-Source Scanner Connectors for Sentinel AI
Wires locally-installed security scanners (Nuclei, OWASP ZAP, Semgrep, Trivy,
Gitleaks) into Sentinel using the exact same human-approval gate already proven
for the Kali connector (see kali_connector.py): the autonomous LLM agent can
only *request* a scan via request_execution() - nothing ever touches the
network or the filesystem beyond validation until a human calls
approve_pending() from the Sentinel dashboard.

Two families of tools, two authorization models:
  - "network"    (nuclei, zap)      -> target is a URL/host, validated by Guardian
                                        (asset registry + verified domain, exactly
                                        like Kali/native scanner targets).
  - "local_path" (trivy, gitleaks,
                   semgrep)          -> target is a path on disk (source code /
                                        dependencies), validated to be inside this
                                        project's own working directory - these
                                        tools never touch the network.
"""

import os
import json
import time
import uuid
import logging
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional

from ..database import get_connection, log_event

logger = logging.getLogger("sentinel.external_scanners")

_SENTINEL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../security
_PROJECT_ROOT = os.path.dirname(_SENTINEL_DIR)  # .../SiteCloner-SaaS
_TOOLS_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools_bin")

TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "nuclei": {
        "name": "Nuclei",
        "description": "Détection de vulnérabilités via des milliers de templates communautaires (CVE connues, mauvaises configurations, expositions).",
        "category": "vuln_scan",
        "target_type": "network",
        "binary": os.path.join(_TOOLS_BIN, "nuclei", "nuclei.exe"),
        "max_timeout": 180
    },
    "zap": {
        "name": "OWASP ZAP",
        "description": "Scan de sécurité applicatif web automatisé (OWASP Top 10) en mode rapide (quick scan).",
        "category": "web_vuln",
        "target_type": "network",
        "binary": os.path.join(_TOOLS_BIN, "zap", "ZAP_2.17.0", "zap.bat"),
        "java_home": os.path.join(_TOOLS_BIN, "jre", "jdk-17.0.21+9-jre"),
        "max_timeout": 300
    },
    "semgrep": {
        "name": "Semgrep",
        "description": "Analyse statique de code source (SAST) - détecte des dizaines de familles de failles directement dans le code, sans exécuter l'application.",
        "category": "sast",
        "target_type": "local_path",
        "binary": "semgrep",  # installed on PATH via pip
        "max_timeout": 600
    },
    "trivy": {
        "name": "Trivy",
        "description": "Scan des dépendances/librairies et fichiers pour vulnérabilités connues (CVE) et secrets exposés.",
        "category": "dependency_scan",
        "target_type": "local_path",
        "binary": os.path.join(_TOOLS_BIN, "trivy", "trivy.exe"),
        "max_timeout": 600
    },
    "gitleaks": {
        "name": "Gitleaks",
        "description": "Détection de secrets exposés dans le code source (clés API, mots de passe, tokens codés en dur).",
        "category": "secret_scan",
        "target_type": "local_path",
        "binary": os.path.join(_TOOLS_BIN, "gitleaks", "gitleaks.exe"),
        "max_timeout": 600
    }
}


def init_external_scanner_tables():
    """Creates the pending-approval queue and execution history tables."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_scanner_pending_approvals (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        tool_id TEXT NOT NULL,
        target TEXT NOT NULL,
        options TEXT NOT NULL DEFAULT '{}',
        requested_by TEXT NOT NULL,
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        decided_at TEXT,
        decided_by TEXT,
        execution_id TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_scanner_signature_updates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_id TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_scanner_executions (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        tool_id TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        returncode INTEGER,
        findings_count INTEGER DEFAULT 0,
        findings_json TEXT DEFAULT '[]',
        raw_output TEXT,
        duration_seconds REAL,
        triggered_by TEXT NOT NULL,
        error_message TEXT
    )
    """)

    conn.commit()
    conn.close()


def _is_tool_installed(tool_id: str) -> bool:
    meta = TOOL_REGISTRY.get(tool_id)
    if not meta:
        return False
    binary = meta["binary"]
    if os.path.isabs(binary) or os.sep in binary:
        return os.path.isfile(binary)
    # On PATH (e.g. semgrep via pip)
    from shutil import which
    return which(binary) is not None


def _count_nuclei_templates() -> int:
    """Counts .yaml template files in Nuclei's configured templates directory."""
    try:
        cfg_path = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "nuclei", ".templates-config.json")
        templates_dir = os.path.join(os.path.expanduser("~"), "nuclei-templates")
        if os.path.isfile(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            templates_dir = cfg.get("nuclei-templates-directory", templates_dir)
        if not os.path.isdir(templates_dir):
            return 0
        count = 0
        for root, _dirs, files in os.walk(templates_dir):
            count += sum(1 for fn in files if fn.endswith((".yaml", ".yml")))
        return count
    except Exception:
        return 0


def list_tools() -> List[Dict[str, Any]]:
    """Catalog of all registered external scanners with live installation status."""
    out = []
    for tool_id, meta in TOOL_REGISTRY.items():
        out.append({
            "id": tool_id,
            "name": meta["name"],
            "description": meta["description"],
            "category": meta["category"],
            "target_type": meta["target_type"],
            "is_installed": _is_tool_installed(tool_id)
        })
    return out


def _resolve_local_path(raw_path: str) -> Optional[str]:
    """
    Resolves a local_path target to an absolute path and ensures it stays
    inside this project's own root - these tools never scan arbitrary
    filesystem locations, only this codebase/its dependencies.
    """
    candidate = raw_path.strip() or "."
    abs_candidate = os.path.abspath(os.path.join(_PROJECT_ROOT, candidate)) if not os.path.isabs(candidate) \
        else os.path.abspath(candidate)
    try:
        common = os.path.commonpath([abs_candidate, _PROJECT_ROOT])
    except ValueError:
        return None
    if common != _PROJECT_ROOT:
        return None
    return abs_candidate


def request_execution(tool_id: str, target: str, options: Optional[Dict[str, Any]] = None,
                      requested_by: str = "sentinel_agent", reason: str = "") -> Dict[str, Any]:
    """
    Entry point for the autonomous LLM agent. Never executes anything itself -
    validates (tool whitelist, Guardian scope for network tools, path
    containment for local tools) then parks the request in
    sentinel_scanner_pending_approvals. Nothing runs until a human calls
    approve_pending() from the Sentinel dashboard.
    """
    from .guardian import guardian

    init_external_scanner_tables()
    options = options or {}

    tool_id = (tool_id or "").lower().strip()
    if tool_id not in TOOL_REGISTRY:
        return {"success": False, "status": "tool_not_permitted",
                "error": f"Outil '{tool_id}' inconnu. Outils disponibles: {list(TOOL_REGISTRY.keys())}"}

    meta = TOOL_REGISTRY[tool_id]

    if not _is_tool_installed(tool_id):
        return {
            "success": False,
            "status": "not_installed",
            "error": f"{meta['name']} n'est pas installé ou introuvable à l'emplacement attendu."
        }

    if meta["target_type"] == "network":
        ok_target, target_reason = guardian.validate_target(target, test_type="external_scan")
        if not ok_target:
            log_event("SCANNER_REQUEST_BLOCKED", "HIGH", "EXTERNAL_SCANNER",
                      f"Demande {tool_id} rejetée (cible) {target}: {target_reason}")
            return {"success": False, "status": "blocked_by_guardian", "error": target_reason}
        clean_target = target
    else:
        resolved = _resolve_local_path(target)
        if not resolved:
            return {"success": False, "status": "blocked_by_guardian",
                     "error": f"Chemin local refusé : '{target}' sort du périmètre du projet."}
        clean_target = resolved

    approval_id = f"scanapp_{uuid.uuid4().hex[:12]}"
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_scanner_pending_approvals
    (id, created_at, tool_id, target, options, requested_by, reason, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
    """, (approval_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), tool_id, clean_target,
          json.dumps(options), requested_by, reason))
    conn.commit()
    conn.close()

    log_event("SCANNER_APPROVAL_REQUESTED", "INFO", "EXTERNAL_SCANNER",
               f"{requested_by} demande l'exécution de {tool_id} sur {clean_target} (approval_id={approval_id})")

    return {
        "success": True,
        "status": "pending_approval",
        "approval_id": approval_id,
        "tool": tool_id,
        "target": clean_target,
        "message": (
            f"Demande enregistrée (approval_id={approval_id}). Cet outil ne s'exécutera PAS automatiquement : "
            f"un humain doit l'approuver depuis le tableau de bord Sentinel avant toute exécution."
        )
    }


def list_pending() -> List[Dict[str, Any]]:
    init_external_scanner_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sentinel_scanner_pending_approvals WHERE status = 'pending' ORDER BY created_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for r in rows:
        try:
            r["options"] = json.loads(r.get("options") or "{}")
        except Exception:
            pass
    return rows


def approve_pending(approval_id: str, decided_by: str = "admin", user_id: Optional[str] = None) -> Dict[str, Any]:
    """Human approval: runs the exact tool/target/options that were validated at request time."""
    init_external_scanner_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sentinel_scanner_pending_approvals WHERE id = ?", (approval_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return {"success": False, "error": "Demande d'approbation introuvable."}
    row = dict(row)
    if row["status"] != "pending":
        return {"success": False, "error": f"Cette demande est déjà '{row['status']}'."}

    try:
        options = json.loads(row.get("options") or "{}")
    except Exception:
        options = {}

    result = execute_tool(
        tool_id=row["tool_id"],
        target=row["target"],
        options=options,
        triggered_by=f"approved_by:{decided_by}",
        user_id=user_id
    )

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    UPDATE sentinel_scanner_pending_approvals
    SET status = 'approved', decided_at = ?, decided_by = ?, execution_id = ?
    WHERE id = ?
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), decided_by, result.get("execution_id"), approval_id))
    conn.commit()
    conn.close()
    log_event("SCANNER_APPROVAL_GRANTED", "INFO", "EXTERNAL_SCANNER",
               f"{decided_by} a approuvé {approval_id} ({row['tool_id']} sur {row['target']})")
    return result


def deny_pending(approval_id: str, decided_by: str = "admin", reason: str = "") -> Dict[str, Any]:
    init_external_scanner_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT status FROM sentinel_scanner_pending_approvals WHERE id = ?", (approval_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"success": False, "error": "Demande d'approbation introuvable."}
    if row["status"] != "pending":
        conn.close()
        return {"success": False, "error": f"Cette demande est déjà '{row['status']}'."}
    c.execute("""
    UPDATE sentinel_scanner_pending_approvals
    SET status = 'denied', decided_at = ?, decided_by = ?
    WHERE id = ?
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), decided_by, approval_id))
    conn.commit()
    conn.close()
    log_event("SCANNER_APPROVAL_DENIED", "INFO", "EXTERNAL_SCANNER", f"{decided_by} a refusé {approval_id}" + (f" ({reason})" if reason else ""))
    return {"success": True, "status": "denied"}


def _build_command(tool_id: str, target: str, options: Dict[str, Any], report_path: str) -> List[str]:
    meta = TOOL_REGISTRY[tool_id]
    binary = meta["binary"]

    if tool_id == "nuclei":
        return [binary, "-u", target, "-jsonl", "-o", report_path, "-silent", "-no-color",
                "-timeout", "10", "-severity", options.get("severity", "low,medium,high,critical")]

    if tool_id == "zap":
        return [binary, "-cmd", "-quickurl", target, "-quickout", report_path, "-quickprogress"]

    if tool_id == "semgrep":
        return ["semgrep", "scan", "--config", options.get("config", "auto"),
                "--json", "--output", report_path, "--quiet", target]

    if tool_id == "trivy":
        return [binary, "fs", target, "--format", "json", "--output", report_path, "--quiet"]

    if tool_id == "gitleaks":
        return [binary, "detect", "--source", target, "--no-git",
                "--report-format", "json", "--report-path", report_path, "--exit-code", "0"]

    raise ValueError(f"Aucun constructeur de commande pour l'outil '{tool_id}'.")


def _parse_findings(tool_id: str, report_path: str, raw_stdout: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        if tool_id == "nuclei":
            if os.path.isfile(report_path):
                with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            d = json.loads(line)
                            info = d.get("info", {})
                            findings.append({
                                "id": d.get("template-id"),
                                "severity": info.get("severity", "info").upper(),
                                "title": info.get("name"),
                                "url": d.get("matched-at") or d.get("host"),
                                "description": info.get("description", "")
                            })
                        except Exception:
                            continue

        elif tool_id == "trivy":
            if os.path.isfile(report_path):
                with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                for result in data.get("Results", []):
                    for v in result.get("Vulnerabilities", []) or []:
                        findings.append({
                            "id": v.get("VulnerabilityID"),
                            "severity": v.get("Severity", "UNKNOWN"),
                            "title": v.get("Title") or v.get("PkgName"),
                            "package": v.get("PkgName"),
                            "description": (v.get("Description") or "")[:300]
                        })

        elif tool_id == "gitleaks":
            if os.path.isfile(report_path):
                with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                data = json.loads(content) if content else []
                for leak in data:
                    findings.append({
                        "id": leak.get("RuleID"),
                        "severity": "HIGH",
                        "title": f"Secret exposé: {leak.get('RuleID')}",
                        "file": leak.get("File"),
                        "line": leak.get("StartLine")
                    })

        elif tool_id == "semgrep":
            if os.path.isfile(report_path):
                with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    extra = r.get("extra", {})
                    findings.append({
                        "id": r.get("check_id"),
                        "severity": extra.get("severity", "INFO"),
                        "title": extra.get("message", "")[:150],
                        "file": r.get("path"),
                        "line": r.get("start", {}).get("line")
                    })

        elif tool_id == "zap":
            # Quick-scan output is a progress report, not structured JSON; surface raw output as a single entry.
            if raw_stdout:
                findings.append({"id": "zap_quickscan", "severity": "INFO", "title": "Résultat brut ZAP quick-scan", "raw": raw_stdout[:2000]})

    except Exception as e:
        logger.warning(f"Erreur de parsing des résultats {tool_id}: {e}")

    return findings


def _triage_findings(findings: List[Dict[str, Any]], tool_id: str, target: str,
                     user_id: Optional[str]) -> List[Dict[str, Any]]:
    """
    Sends raw scanner findings through the user's connected LLM for a quick
    true/false-positive triage pass before they reach the dashboard - this is
    the single highest-leverage noise-reduction step for automated scanners.
    Every finding keeps its original data; triage only adds fields. If no
    user_id is given, or the LLM call fails for any reason, findings are
    returned unchanged with triage_verdict="non_evalue" - this step never
    blocks or drops a finding, it only annotates it.
    """
    if not findings or not user_id:
        for f in findings:
            f.setdefault("triage_verdict", "non_evalue")
        return findings

    try:
        from .user_llm_manager import user_llm_manager
        from .models import AgentMessage

        provider, _meta = user_llm_manager.resolve_user_llm_instance(user_id=user_id)

        compact = [
            {"idx": i, "id": f.get("id"), "title": f.get("title") or f.get("description", "")[:120],
             "severity": f.get("severity"), "location": f.get("url") or f.get("file") or f.get("package")}
            for i, f in enumerate(findings[:40])  # cap to keep the prompt small
        ]

        prompt = (
            f"Tu es un analyste sécurité expérimenté. Voici {len(compact)} résultat(s) brut(s) produit(s) par "
            f"l'outil automatisé '{tool_id}' sur la cible '{target}'. Pour CHAQUE résultat (identifié par 'idx'), "
            "évalue s'il s'agit probablement d'un vrai positif ou d'un faux positif, avec un niveau de confiance "
            "(0 à 100) et une raison en une phrase. Les scanners automatisés produisent souvent du bruit "
            "(faux positifs, doublons, résultats sans impact réel) : sois critique.\n\n"
            f"Résultats :\n{json.dumps(compact, ensure_ascii=False)}\n\n"
            "Réponds UNIQUEMENT avec un tableau JSON de la forme : "
            '[{"idx": 0, "verdict": "vrai_positif"|"faux_positif"|"a_verifier", "confidence": 0-100, "reason": "..."}]'
        )

        resp = provider.chat([AgentMessage(role="user", content=prompt)], tools=None)
        content = (resp.content or "").strip()

        # Models sometimes wrap JSON in a markdown code fence - strip it.
        if content.startswith("```"):
            content = content.strip("`")
            if content.lower().startswith("json"):
                content = content[4:].strip()

        triage_list = json.loads(content)
        triage_by_idx = {t.get("idx"): t for t in triage_list if isinstance(t, dict)}

        for i, f in enumerate(findings):
            t = triage_by_idx.get(i)
            if t:
                f["triage_verdict"] = t.get("verdict", "non_evalue")
                f["triage_confidence"] = t.get("confidence")
                f["triage_reason"] = t.get("reason")
            else:
                f.setdefault("triage_verdict", "non_evalue")

    except Exception as e:
        logger.warning(f"Triage IA des résultats {tool_id} impossible ({e}) - résultats conservés tels quels.")
        for f in findings:
            f.setdefault("triage_verdict", "non_evalue")

    return findings


def execute_tool(tool_id: str, target: str, options: Optional[Dict[str, Any]] = None,
                 triggered_by: str = "sentinel_agent", user_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Actually runs an external scanner binary. Called only from the human-operated
    SOC dashboard, or from approve_pending() once a human has signed off -
    never directly by the autonomous agent (see request_execution()).
    """
    init_external_scanner_tables()
    options = options or {}
    execution_id = f"scan_{uuid.uuid4().hex[:12]}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if tool_id not in TOOL_REGISTRY:
        return {"success": False, "execution_id": execution_id, "status": "tool_not_permitted",
                "error": f"Outil '{tool_id}' inconnu."}

    meta = TOOL_REGISTRY[tool_id]

    # Guardian scope check is re-validated here unconditionally (not just in
    # request_execution) so a direct call - e.g. from the manual dashboard
    # route - can never skip it, exactly like the Kali connector.
    if meta["target_type"] == "network":
        from .guardian import guardian
        ok_target, target_reason = guardian.validate_target(target, test_type="external_scan")
        if not ok_target:
            log_event("SCANNER_EXEC_BLOCKED", "HIGH", "EXTERNAL_SCANNER", f"Cible {target} rejetée par le Guardian: {target_reason}")
            _log_execution(execution_id, tool_id, target, "blocked", -1, [], "", 0.0, triggered_by, target_reason)
            return {"success": False, "execution_id": execution_id, "status": "blocked_by_guardian", "error": target_reason}
    else:
        if not _resolve_local_path(target):
            err = f"Chemin local refusé : '{target}' sort du périmètre du projet."
            return {"success": False, "execution_id": execution_id, "status": "blocked_by_guardian", "error": err}

    if not _is_tool_installed(tool_id):
        err = f"{meta['name']} n'est pas installé."
        _log_execution(execution_id, tool_id, target, "not_installed", -1, [], "", 0.0, triggered_by, err)
        return {"success": False, "execution_id": execution_id, "status": "not_installed", "error": err}

    report_path = os.path.join(_TOOLS_BIN, f"_report_{execution_id}.json")
    try:
        cmd = _build_command(tool_id, target, options, report_path)
    except Exception as e:
        return {"success": False, "execution_id": execution_id, "status": "error", "error": str(e)}

    env = os.environ.copy()
    if meta.get("java_home"):
        env["JAVA_HOME"] = meta["java_home"]
        env["PATH"] = os.path.join(meta["java_home"], "bin") + os.pathsep + env.get("PATH", "")

    start_time = time.time()
    status = "completed"
    stdout_data, stderr_data, returncode = "", "", 0
    err_msg = None

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=meta.get("max_timeout", 120),
            cwd=_PROJECT_ROOT, env=env
        )
        stdout_data, stderr_data, returncode = proc.stdout, proc.stderr, proc.returncode
        status = "completed"
    except subprocess.TimeoutExpired:
        status = "timeout"
        err_msg = f"Délai dépassé ({meta.get('max_timeout', 120)}s)."
    except Exception as e:
        status = "error"
        err_msg = str(e)

    duration = round(time.time() - start_time, 2)
    findings = _parse_findings(tool_id, report_path, stdout_data) if status == "completed" else []
    if findings:
        findings = _triage_findings(findings, tool_id, target, user_id)

    try:
        if os.path.isfile(report_path):
            os.remove(report_path)
    except Exception:
        pass

    _log_execution(execution_id, tool_id, target, status, returncode, findings,
                   (stdout_data or "")[:5000], duration, triggered_by, err_msg)

    log_event("SCANNER_EXECUTED", "INFO" if status == "completed" else "WARNING", "EXTERNAL_SCANNER",
              f"{tool_id} exécuté sur {target} par {triggered_by} (statut: {status}, {len(findings)} résultat(s))")

    return {
        "success": status == "completed",
        "execution_id": execution_id,
        "tool": tool_id,
        "target": target,
        "status": status,
        "findings_count": len(findings),
        "findings": findings,
        "duration_seconds": duration,
        "error": err_msg
    }


def get_last_signature_update(tool_id: str) -> Optional[Dict[str, Any]]:
    init_external_scanner_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT * FROM sentinel_scanner_signature_updates
    WHERE tool_id = ? ORDER BY updated_at DESC LIMIT 1
    """, (tool_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def update_signatures(tool_id: str = "nuclei") -> Dict[str, Any]:
    """
    Refreshes a scanner's vulnerability/signature database. Only Nuclei needs an
    explicit step - its templates are a local cache that goes stale. Trivy's CVE
    DB and Semgrep's "auto" ruleset are already fetched fresh on every run, so
    they're intentionally no-ops here (recorded as such for visibility).
    """
    init_external_scanner_tables()

    if tool_id not in ("nuclei", "trivy", "semgrep"):
        return {"success": False, "error": f"Pas de mise à jour de signatures définie pour '{tool_id}'."}

    status, message = "completed", ""
    if tool_id == "nuclei":
        meta = TOOL_REGISTRY["nuclei"]
        if not _is_tool_installed("nuclei"):
            status, message = "error", "Nuclei n'est pas installé."
        else:
            try:
                proc = subprocess.run(
                    [meta["binary"], "-update-templates", "-silent"],
                    capture_output=True, text=True, timeout=600, cwd=_PROJECT_ROOT
                )
                status = "completed" if proc.returncode == 0 else "error"
                message = (proc.stdout or proc.stderr or "")[:500]
            except subprocess.TimeoutExpired:
                # Nuclei's own process sometimes hangs on a post-download step
                # (e.g. reporting back to its cloud dashboard) even though the
                # actual template files were already written to disk. Verify
                # the real outcome instead of trusting the hung process.
                template_count = _count_nuclei_templates()
                if template_count > 1000:
                    status = "completed"
                    message = f"Processus bloqué après téléchargement, mais {template_count} templates confirmés présents sur disque."
                else:
                    status, message = "timeout", f"Délai dépassé (600s), seulement {template_count} template(s) trouvé(s)."
            except Exception as e:
                status, message = "error", str(e)
    else:
        # Trivy's vulnerability DB and Semgrep's "auto" ruleset are pulled live
        # on every scan invocation - nothing to pre-fetch here.
        message = f"{TOOL_REGISTRY[tool_id]['name']} récupère ses données à jour à chaque scan - aucune action nécessaire."

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO sentinel_scanner_signature_updates (tool_id, updated_at, status, message)
    VALUES (?, ?, ?, ?)
    """, (tool_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), status, message))
    conn.commit()
    conn.close()

    log_event("SCANNER_SIGNATURES_UPDATED", "INFO" if status == "completed" else "WARNING",
              "EXTERNAL_SCANNER", f"Mise à jour des signatures {tool_id}: {status}")

    return {"success": status == "completed", "tool_id": tool_id, "status": status, "message": message}


def run_due_signature_updates(min_interval_hours: int = 24) -> int:
    """
    Called periodically by the background scheduler. Runs update_signatures()
    for any tool whose last update is older than min_interval_hours (or has
    never run). Returns how many updates were executed.
    """
    from datetime import timedelta
    executed = 0
    for tool_id in ("nuclei", "trivy", "semgrep"):
        last = get_last_signature_update(tool_id)
        if last:
            try:
                last_dt = datetime.strptime(last["updated_at"], "%Y-%m-%d %H:%M:%S")
                if datetime.now() - last_dt < timedelta(hours=min_interval_hours):
                    continue
            except Exception:
                pass
        update_signatures(tool_id)
        executed += 1
    return executed


def list_history(limit: int = 50) -> List[Dict[str, Any]]:
    init_external_scanner_tables()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sentinel_scanner_executions ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for r in rows:
        try:
            r["findings_json"] = json.loads(r.get("findings_json") or "[]")
        except Exception:
            pass
    return rows


def _log_execution(execution_id: str, tool_id: str, target: str, status: str, returncode: int,
                   findings: List[Dict[str, Any]], raw_output: str, duration: float,
                   triggered_by: str, error: Optional[str]):
    try:
        init_external_scanner_tables()
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        INSERT INTO sentinel_scanner_executions
        (id, timestamp, tool_id, target, status, returncode, findings_count, findings_json,
         raw_output, duration_seconds, triggered_by, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            execution_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), tool_id, target, status,
            returncode, len(findings), json.dumps(findings, ensure_ascii=False), raw_output,
            duration, triggered_by, error
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to record scanner execution log: {e}")
