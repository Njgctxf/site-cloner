"""
flask_shield_middleware.py - Ultron Real-Time Shield client, for ANY Flask/WSGI app.

Copy this file into the site/app you want Ultron to protect (yours or any
third party's, as long as its domain is verified in Ultron's dashboard - Bouclier
Temps Réel), set the two environment variables below, and call install() once.

    from flask_shield_middleware import install
    install(app)

What it does on every request:
  1. Checks a short-lived local cache of blocked IPs first (fast path, no network
     call) - if the caller's IP is on it, the request is rejected immediately.
  2. Reports the request's method/path/query/body-snippet/headers to Ultron's
     central API, which runs the same detection + self-learning engine Ultron
     uses on itself. If Ultron says "block", the request is rejected.
  3. Fails OPEN: if Ultron's API is unreachable or slow (ULTRON_TIMEOUT_SECONDS),
     the request is let through - a security add-on must never take your own
     site down. You still get retro-active protection on the next successful
     call once Ultron is back, and the blocklist cache keeps working offline.

Any other stack (Node/Express, PHP, Django, a Chrome extension, a desktop app,
anything that can make an HTTP call) can implement the exact same two calls
directly - no SDK required:

    POST {ULTRON_BASE_URL}/api/sentinel/agent/report
        headers: {"X-Sentinel-Agent-Key": "<your key>"}
        body: {"source_ip": "...", "method": "...", "path": "...",
               "query_string": "...", "body": "...", "headers": {...}}
        -> {"block": bool, "attack_detected": bool, "shield_tier": "..."}

    GET  {ULTRON_BASE_URL}/api/sentinel/agent/blocklist
        headers: {"X-Sentinel-Agent-Key": "<your key>"}
        -> {"blocked_ips": ["1.2.3.4", ...]}
"""

import os
import threading
import time
from typing import Optional

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

ULTRON_BASE_URL = os.environ.get("ULTRON_BASE_URL", "").rstrip("/")
ULTRON_AGENT_KEY = os.environ.get("ULTRON_AGENT_KEY", "")
ULTRON_TIMEOUT_SECONDS = float(os.environ.get("ULTRON_TIMEOUT_SECONDS", "1.5"))
ULTRON_BLOCKLIST_POLL_SECONDS = int(os.environ.get("ULTRON_BLOCKLIST_POLL_SECONDS", "30"))
ULTRON_MAX_BODY_BYTES = 4000

_blocklist_cache = set()
_blocklist_lock = threading.Lock()


def _poll_blocklist_loop():
    while True:
        try:
            if requests and ULTRON_BASE_URL and ULTRON_AGENT_KEY:
                r = requests.get(
                    f"{ULTRON_BASE_URL}/api/sentinel/agent/blocklist",
                    headers={"X-Sentinel-Agent-Key": ULTRON_AGENT_KEY},
                    timeout=ULTRON_TIMEOUT_SECONDS,
                )
                if r.ok:
                    with _blocklist_lock:
                        _blocklist_cache.clear()
                        _blocklist_cache.update(r.json().get("blocked_ips", []))
        except Exception:
            pass  # offline tolerance - keep last known cache
        time.sleep(ULTRON_BLOCKLIST_POLL_SECONDS)


def install(app, base_url: Optional[str] = None, agent_key: Optional[str] = None):
    """Registers the shield as a Flask before_request hook."""
    global ULTRON_BASE_URL, ULTRON_AGENT_KEY
    if base_url:
        ULTRON_BASE_URL = base_url.rstrip("/")
    if agent_key:
        ULTRON_AGENT_KEY = agent_key

    if not ULTRON_BASE_URL or not ULTRON_AGENT_KEY:
        raise RuntimeError(
            "ULTRON_BASE_URL et ULTRON_AGENT_KEY doivent être définis (env ou passés à install())."
        )
    if requests is None:
        raise RuntimeError("Le paquet 'requests' est requis: pip install requests")

    threading.Thread(target=_poll_blocklist_loop, daemon=True).start()

    from flask import request, Response

    @app.before_request
    def _ultron_shield_check():
        remote_ip = request.remote_addr or "unknown"

        with _blocklist_lock:
            if remote_ip in _blocklist_cache:
                return Response("Accès bloqué par Ultron Sentinel.", 403)

        try:
            body = ""
            if request.method in ("POST", "PUT", "PATCH") and (request.content_length or 0) < 50000:
                body = request.get_data(as_text=True) or ""

            r = requests.post(
                f"{ULTRON_BASE_URL}/api/sentinel/agent/report",
                headers={"X-Sentinel-Agent-Key": ULTRON_AGENT_KEY},
                json={
                    "source_ip": remote_ip,
                    "method": request.method,
                    "path": request.path,
                    "query_string": request.query_string.decode("utf-8", errors="replace"),
                    "body": body[:ULTRON_MAX_BODY_BYTES],
                    "headers": dict(request.headers),
                },
                timeout=ULTRON_TIMEOUT_SECONDS,
            )
            if r.ok and r.json().get("block"):
                return Response("Accès bloqué par Ultron Sentinel : activité suspecte détectée.", 403)
        except Exception:
            pass  # fail open - never take the protected site down because Ultron's API is slow/offline

        return None
