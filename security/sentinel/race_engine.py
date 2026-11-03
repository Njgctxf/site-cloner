"""
race_engine.py - Concurrency & Race Condition Diagnostic Engine
Uses high-precision multi-threaded barriers to send synchronized burst requests
and evaluate whether one-time business logic operations are vulnerable to Time-Of-Check to Time-Of-Use (TOCTOU).
"""

import time
import threading
from typing import Dict, Any, List, Optional
import requests

def audit_race_condition(
    session: requests.Session,
    target_url: str,
    method: str = "POST",
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    concurrency: int = 6
) -> List[Dict[str, Any]]:
    """
    Sends 'concurrency' precisely synchronized requests to target_url.
    Detects if the backend allows duplicate execution of what should be a singleton operation.
    """
    findings = []
    num_workers = min(max(concurrency, 2), 8)
    barrier = threading.Barrier(num_workers)

    results = []
    lock = threading.Lock()

    def _worker():
        req_headers = dict(headers or {})
        req_data = dict(data or {})

        # Wait until all threads are created and ready to fire at the exact same millisecond
        try:
            barrier.wait(timeout=5)
        except Exception:
            return

        t0 = time.time()
        try:
            if method.upper() == "POST":
                r = session.post(target_url, json=req_data if req_data else None,
                                 data=req_data if not req_data else None,
                                 headers=req_headers, timeout=5, allow_redirects=False)
            else:
                r = session.get(target_url, params=req_data, headers=req_headers, timeout=5, allow_redirects=False)
            latency = time.time() - t0

            with lock:
                results.append({
                    "status_code": r.status_code,
                    "length": len(r.text),
                    "text_snippet": r.text[:120],
                    "latency": round(latency, 3)
                })
        except Exception as e:
            with lock:
                results.append({"status_code": 0, "error": str(e)})

    threads = [threading.Thread(target=_worker) for _ in range(num_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=8)

    # Analyze outcomes
    status_codes = [r["status_code"] for r in results]
    success_codes = [s for s in status_codes if s in (200, 201)]

    # If 3 or more requests in the burst succeeded with 200 OK
    if len(success_codes) >= 2:
        findings.append({
            "id": "RACE_CONDITION_CONCURRENT_SUCCESS",
            "title": f"Vulnérabilité de Concurrence Potentielle (Race Condition / TOCTOU) sur {target_url}",
            "severity": "HIGH",
            "category": "A04:2021-Insecure Design",
            "description": f"Lors d'une rafale de {num_workers} requêtes synchronisées à la milliseconde près, le serveur a retourné {len(success_codes)} réponses de succès (HTTP 200/201).",
            "proof": f"Codes de statut reçus pour la rafale synchronisée: {status_codes}. Réponses identiques traitées en parallèle.",
            "impact": "Possibilité de doubler une dépense de solde, d'utiliser plusieurs fois un coupon à usage unique, ou de contourner les quotas et limites de stock.",
            "remediation": "Mettez en place des verrous atomiques au niveau de la base de données (ex: SELECT ... FOR UPDATE, contraintes d'unicité, ou verrous distribués Redis Redlock) pour sérialiser les opérations critiques."
        })
    elif len(results) >= 2:
        # Proper serialization observed
        pass

    return findings
