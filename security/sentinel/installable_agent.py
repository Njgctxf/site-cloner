"""
installable_agent.py - Sentinel Protect: the agent you install ON YOUR OWN SITE.

This is the only file a protected site actually needs. It is self-contained
(only depends on `requests`, or stdlib-only via urllib if you prefer) so it can
be copied out of this repository and dropped into any Flask application you
control and have an authorized Sentinel agent key for.

--------------------------------------------------------------------------
HOW TO INSTALL ON YOUR OWN SITE
--------------------------------------------------------------------------
1. In SiteCloner's CyberLab, verify ownership of your domain, then provision
   an agent key for it (admin-only: POST /__sc/security/api/sentinel/agent/provision).
2. Copy this file into your site's codebase.
3. In your app's entrypoint:

    from installable_agent import SentinelProtect
    app = Flask(__name__)
    SentinelProtect(app,
                     agent_key="sk_sentinel_...",
                     sentinel_url="https://your-sitecloner-instance.example/__sc/security")

That's it. Every request is now inspected locally (instant, no network
round-trip needed to block an obvious attack payload) and reported to your
central Sentinel dashboard, which correlates it with everything else it's
seeing and can push back a directive to block an IP across future requests.
--------------------------------------------------------------------------
"""

import threading
import time
from typing import Optional

try:
    import requests
except ImportError:  # pragma: no cover - keep the agent usable without the dependency installed
    requests = None

from .waf_signatures import inspect_request


class SentinelProtect:
    def __init__(self, app, agent_key: str, sentinel_url: str,
                 blocklist_refresh_seconds: int = 30, report_timeout: float = 2.0):
        self.app = app
        self.agent_key = agent_key
        self.sentinel_url = sentinel_url.rstrip("/")
        self.report_timeout = report_timeout
        self._local_blocklist = set()
        self._lock = threading.Lock()

        app.before_request(self._on_request)

        if requests is not None:
            self._refresh_blocklist()
            t = threading.Thread(target=self._blocklist_refresh_loop,
                                  args=(blocklist_refresh_seconds,), daemon=True)
            t.start()

    # -- Flask hook ---------------------------------------------------

    def _on_request(self):
        from flask import request, abort

        source_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

        with self._lock:
            if source_ip in self._local_blocklist:
                abort(403)

        body = ""
        try:
            if request.content_length and request.content_length < 65536:
                body = request.get_data(as_text=True, parse_form_data=False) or ""
        except Exception:
            body = ""

        findings = inspect_request(
            method=request.method,
            path=request.path,
            query_string=request.query_string.decode("utf-8", "ignore"),
            body=body,
            headers=dict(request.headers),
        )

        self._report_async(source_ip, request.method, request.path,
                            request.query_string.decode("utf-8", "ignore"), body,
                            dict(request.headers))

        if findings:
            from .waf_signatures import highest_severity
            if highest_severity(findings) in ("CRITICAL", "HIGH"):
                abort(403)

    # -- Central reporting ---------------------------------------------

    def _report_async(self, source_ip, method, path, query_string, body, headers):
        if requests is None:
            return
        t = threading.Thread(target=self._report_sync,
                              args=(source_ip, method, path, query_string, body, headers), daemon=True)
        t.start()

    def _report_sync(self, source_ip, method, path, query_string, body, headers):
        try:
            requests.post(
                f"{self.sentinel_url}/api/sentinel/agent/report",
                headers={"X-Sentinel-Agent-Key": self.agent_key},
                json={
                    "source_ip": source_ip, "method": method, "path": path,
                    "query_string": query_string, "body": body[:4000], "headers": headers,
                },
                timeout=self.report_timeout,
            )
        except Exception:
            pass  # never let telemetry failures affect the protected site's availability

    def _refresh_blocklist(self):
        if requests is None:
            return
        try:
            res = requests.get(
                f"{self.sentinel_url}/api/sentinel/agent/blocklist",
                headers={"X-Sentinel-Agent-Key": self.agent_key},
                timeout=self.report_timeout,
            )
            if res.status_code == 200:
                ips = res.json().get("blocked_ips", [])
                with self._lock:
                    self._local_blocklist = set(ips)
        except Exception:
            pass

    def _blocklist_refresh_loop(self, interval_seconds: int):
        while True:
            time.sleep(interval_seconds)
            self._refresh_blocklist()
