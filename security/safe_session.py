"""
safe_session.py - Connection-time Anti-SSRF enforcement for outbound scanner traffic.

network_guard.validate_target_url() only checks the hostname/IP ONCE, before the
scan starts. Every actual HTTP call afterwards (requests.Session.get/post, and
every redirect hop requests follows automatically when allow_redirects=True) goes
through the normal resolver again, with no re-check. That gap allows:

  1. DNS rebinding: an attacker-controlled domain with a very short TTL can
     resolve to a public IP at validation time, then to 127.0.0.1 / the cloud
     metadata IP (169.254.169.254) / an internal host a moment later, once the
     scanner actually connects.
  2. Redirect-based SSRF: a target can return a 3xx to an internal URL; with
     allow_redirects=True (used throughout scanner.py/dast_engine.py) requests
     follows it with no revalidation at all.

build_safe_session() returns a requests.Session whose transport adapter re-runs
the same hostname/IP safety check from network_guard on every single connection
attempt it makes - the first request AND every redirect hop - closing both gaps
without changing any call site's behavior (session.get/post, allow_redirects=...
keep working exactly as before).
"""

import urllib.parse

import requests
from requests.adapters import HTTPAdapter

from .network_guard import resolve_and_validate_hostname


class SSRFSafeAdapter(HTTPAdapter):
    def __init__(self, allow_local_lab: bool = False, *args, **kwargs):
        self.allow_local_lab = allow_local_lab
        super().__init__(*args, **kwargs)

    def send(self, request, *args, **kwargs):
        parsed = urllib.parse.urlparse(request.url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise requests.exceptions.InvalidURL(
                f"Requête bloquée par le Guardian anti-SSRF : protocole non autorisé ('{scheme}')."
            )

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise requests.exceptions.InvalidURL(
                "Requête bloquée par le Guardian anti-SSRF : nom d'hôte introuvable."
            )

        is_safe, _ips, msg = resolve_and_validate_hostname(hostname, allow_local_lab=self.allow_local_lab)
        if not is_safe:
            raise requests.exceptions.ConnectionError(
                f"Requête bloquée par le Guardian anti-SSRF (vérification au moment de la connexion) : {msg}"
            )

        return super().send(request, *args, **kwargs)


def build_safe_session(allow_local_lab: bool = False) -> requests.Session:
    """Drop-in replacement for requests.Session() that re-validates every
    outbound connection (including each redirect hop) against the anti-SSRF
    rules, instead of trusting a single check made before the scan started."""
    session = requests.Session()
    adapter = SSRFSafeAdapter(allow_local_lab=allow_local_lab)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
