"""
anomaly.py - Lightweight behavioral anomaly detection.

Catches activity that matches NO known signature (static or learned) at all -
a zero-day technique, a brute-force attempt, or an automated scan - purely by
noticing a source hitting a protected domain far more aggressively than normal.
Pure in-memory sliding window, no DB write on the hot path, so it stays cheap
enough to run on every single request.
"""

import threading
import time
from collections import defaultdict, deque
from typing import Dict, Optional

_WINDOW_SECONDS = 60
_RATE_THRESHOLD = 60  # requests/minute from one IP to one domain considered anomalous

_lock = threading.Lock()
_hits: Dict[str, deque] = defaultdict(deque)


def record_and_check(domain: str, source_ip: str) -> Optional[dict]:
    """Records this request and returns an anomaly finding if the rate for this
    (domain, source_ip) pair is currently above threshold, else None."""
    key = f"{domain}:{source_ip}"
    now = time.monotonic()
    with _lock:
        q = _hits[key]
        q.append(now)
        while q and now - q[0] > _WINDOW_SECONDS:
            q.popleft()
        count = len(q)
        # Bound memory: drop empty/stale keys opportunistically
        if count == 0:
            del _hits[key]

    if count > _RATE_THRESHOLD:
        return {
            "category": "rate_anomaly",
            "severity": "MEDIUM",
            "source": "behavioral",
            "pattern": f"{count} requêtes en {_WINDOW_SECONDS}s"
        }
    return None
