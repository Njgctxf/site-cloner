"""
scheduler.py - Background Recurring Audits Engine
Executes automated security scans at configured frequencies (daily, weekly, monthly)
and triggers alerts when regressions or new vulnerabilities are detected.
"""

import json
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

from .database import get_connection, log_event
from .scanner import scan_target
from .alerts import dispatch_scan_alerts

_SCHEDULER_THREAD: Optional[threading.Thread] = None
_RUNNING = False

def compute_next_run(frequency: str) -> str:
    """Calculates the next execution ISO timestamp based on frequency."""
    now = datetime.now()
    freq = (frequency or "weekly").lower()
    if freq == "daily":
        nxt = now + timedelta(days=1)
    elif freq == "monthly":
        nxt = now + timedelta(days=30)
    else:  # default weekly
        nxt = now + timedelta(days=7)
    return nxt.strftime("%Y-%m-%d %H:%M:%S")

def run_scheduler_cycle() -> int:
    """
    Checks all active schedules in the database and executes any that are due.
    Returns the count of executed audits.
    """
    conn = get_connection()
    c = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("""
        SELECT * FROM scheduled_audits 
        WHERE is_active = 1 AND (next_run <= ? OR next_run IS NULL OR next_run = '')
    """, (now_str,))
    due_schedules = [dict(r) for r in c.fetchall()]
    conn.close()

    executed_count = 0

    for sched in due_schedules:
        target_url = sched["target_url"]
        domain = sched["domain"]
        freq = sched.get("frequency", "weekly")
        sched_id = sched["id"]

        log_event("SCHEDULED_AUDIT_START", "INFO", "SCHEDULER", f"Exécution de l'audit automatique planifié sur {target_url}")

        try:
            res = scan_target(target_url)
            if res.get("success"):
                # Save scan result to scans table
                conn = get_connection()
                c = conn.cursor()
                c.execute("""
                    INSERT INTO scans (target_url, timestamp, risk_score, grade, critical_count, high_count,
                                      medium_count, low_count, findings_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    res["target_url"], res["timestamp"], res["risk_score"], res["grade"],
                    res["counts"]["critical"], res["counts"]["high"], res["counts"]["medium"],
                    res["counts"]["low"], json.dumps(res["findings"])
                ))
                scan_id = c.lastrowid

                # Update schedule tracking
                next_date = compute_next_run(freq)
                c.execute("""
                    UPDATE scheduled_audits 
                    SET last_run = ?, next_run = ?
                    WHERE id = ?
                """, (now_str, next_date, sched_id))
                conn.commit()
                conn.close()

                executed_count += 1
                log_event("SCHEDULED_AUDIT_SUCCESS", "INFO", "SCHEDULER",
                          f"Audit #{scan_id} achevé pour {target_url}. Prochain audit prévu : {next_date}")

                # Dispatch notifications/alerts if any critical issues were found
                dispatch_scan_alerts(target_url, res)

            else:
                log_event("SCHEDULED_AUDIT_FAILED", "WARN", "SCHEDULER",
                          f"Échec de l'audit pour {target_url} : {res.get('error')}")

        except Exception as e:
            log_event("SCHEDULED_AUDIT_ERROR", "WARN", "SCHEDULER",
                      f"Exception pendant l'audit de {target_url} : {e}")

    return executed_count

def _scheduler_loop(interval_seconds: int = 60):
    global _RUNNING
    while _RUNNING:
        try:
            run_scheduler_cycle()
        except Exception as e:
            print(f"[CyberLab Scheduler] Erreur de cycle: {e}")
        try:
            from .sentinel.external_scanners import run_due_signature_updates
            run_due_signature_updates()
        except Exception as e:
            print(f"[CyberLab Scheduler] Erreur de mise à jour des signatures: {e}")
        time.sleep(interval_seconds)

def start_background_scheduler(interval_seconds: int = 60):
    """Starts the background worker thread for automated recurring security audits."""
    global _SCHEDULER_THREAD, _RUNNING
    if _SCHEDULER_THREAD and _SCHEDULER_THREAD.is_alive():
        return

    _RUNNING = True
    _SCHEDULER_THREAD = threading.Thread(target=_scheduler_loop, args=(interval_seconds,), daemon=True)
    _SCHEDULER_THREAD.start()
    log_event("SCHEDULER_STARTED", "INFO", "SCHEDULER", f"Moteur d'audits récurrents en arrière-plan activé (intervalle: {interval_seconds}s).")

def stop_background_scheduler():
    global _RUNNING
    _RUNNING = False
