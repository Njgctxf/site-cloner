"""
plans.py - Separated SaaS offer system + Suite Bundles:
  1. Ultron Security & Sentinel (`PLANS`):
     - free       (0 EUR/mo)   : 1 audited site/month, basic passive audits only.
     - pro        (29 EUR/mo)  : 10 audited sites/month, active DAST & AI copilot.
     - enterprise (149 EUR/mo) : unlimited audits, full Sentinel Console, WAF & MCP.
  2. SiteCloner & Studio (`CLONER_PLANS`):
     - free       (0 EUR/mo)   : 1 cloned site/month, max 5 pages, live preview only.
     - pro        (19 EUR/mo)  : 10 cloned sites/month, max 60 pages, ZIP, Studio Edit, GitHub & R.E.A.
     - agency     (49 EUR/mo)  : unlimited clones/month, max 150 pages, full Studio + R.E.A.
  3. Suite Bundles (`SUITE_BUNDLES`):
     - suite_pro        (39 EUR/mo)  : Cloneur Pro + Ultron Pro (saves 9 EUR/mo).
     - suite_enterprise (169 EUR/mo) : Cloneur Agence + Ultron Entreprise (saves 29 EUR/mo).
"""

import os
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .database import get_connection

PLAN_ORDER = ("free", "pro", "enterprise")
CLONER_PLAN_ORDER = ("free", "pro", "agency")

PLANS: Dict[str, Dict[str, Any]] = {
    "free": {
        "id": "free",
        "scope": "security",
        "name": "Gratuit",
        "subtitle": "Découverte Ultron",
        "badge": "Gratuit",
        "price_eur": 0,
        "price_cents": 0,
        "price_label": "0 € / mois",
        "max_sites_per_month": 1,
        "allowed_categories": ["headers", "files", "secrets"],
        "sentinel_full_access": False,
        "features": [
            "1 seul site distinct audité par mois (ré-audits illimités sur ce site)",
            "En-têtes HTTP de sécurité & cookies (HSTS, CSP, X-Frame...)",
            "Fichiers sensibles publics (.env, .git/config, backup.sql)",
            "Détection des clés API & secrets exposés dans le HTML/JS",
            "Score de sécurité A–F et constats vulgarisés",
        ],
        "excluded_features": [
            "Audits avancés : SQLi, XSS, IDOR/BOLA, SSL/TLS, CORS, CVE, SAST/SCA",
            "Copilote IA Ulton (assistant de correction)",
            "Génération de patchs Nginx/Apache & rapport HTML complet",
            "Console Sentinel complète, Claude MCP, Bouclier WAF 24/7 & CI/CD",
        ],
    },
    "pro": {
        "id": "pro",
        "scope": "security",
        "name": "Pro",
        "subtitle": "Ultron Audit Avancé",
        "badge": "Populaire",
        "price_eur": 29,
        "price_cents": 2900,
        "price_label": "29 € / mois",
        "max_sites_per_month": 10,
        "allowed_categories": [
            "headers", "files", "secrets", "tls", "cors", "methods",
            "directory", "mixed", "outdated", "sca", "cve", "sast",
            "robots", "forms", "active",
        ],
        "sentinel_full_access": False,
        "features": [
            "Jusqu'à 10 sites distincts audités par mois",
            "Tous les audits de base + Audits actifs (SQLi, XSS, IDOR/BOLA)",
            "Analyse SSL/TLS, CORS, CVE serveur, dépendances SCA & SAST",
            "Copilote IA Ulton pour expliquer et corriger chaque faille",
            "Patchs serveur (Nginx/Apache) & rapport d'audit détaillé",
        ],
        "excluded_features": [
            "Console Sentinel IA complète & connecteur Claude Pro/Max MCP",
            "Bouclier WAF temps réel 24/7 & clés de protection d'agents",
            "Scanners SOC (Nuclei, ZAP, Semgrep, Trivy, Gitleaks), PentAGI & Kali",
            "Remédiations automatiques, audits planifiés & passerelle CI/CD",
        ],
    },
    "enterprise": {
        "id": "enterprise",
        "scope": "security",
        "name": "Entreprise",
        "subtitle": "Tout Sentinel",
        "badge": "Complet",
        "price_eur": 149,
        "price_cents": 14900,
        "price_label": "149 € / mois",
        "max_sites_per_month": None,
        "allowed_categories": None,
        "sentinel_full_access": True,
        "features": [
            "Sites et audits illimités tous les mois",
            "Tous les audits web (de base + actifs + CVE/SAST/SCA)",
            "Accès complet à toute la Console Sentinel IA & multi-LLM BYOK",
            "Connecteur Claude Pro / Max via MCP en 1 clic (9 outils)",
            "Bouclier WAF temps réel 24/7, clés d'agents & blocage auto",
            "Scanners SOC, PentAGI, remédiations auto, CI/CD & rapports SOC",
        ],
        "excluded_features": [],
    },
}

CLONER_PLANS: Dict[str, Dict[str, Any]] = {
    "free": {
        "id": "free",
        "scope": "cloner",
        "name": "Cloneur Gratuit",
        "subtitle": "Découverte Frontend",
        "badge": "Gratuit",
        "price_eur": 0,
        "price_cents": 0,
        "price_label": "0 € / mois",
        "cloner_max_sites_per_month": 1,
        "cloner_max_pages": 5,
        "cloner_zip_export": False,
        "cloner_studio_edit": False,
        "cloner_github_publish": False,
        "rea_mode": False,
        "features": [
            "1 seul site distinct cloné par mois (jusqu'à 5 pages)",
            "Aperçu live hors-ligne & Studio visuel en lecture seule",
            "Inspection Design System (couleurs, polices & tokens)",
        ],
        "excluded_features": [
            "Export ZIP, export multi-pages & Code propre React/Tailwind",
            "Éditeur visuel no-code Inspect (textes, médias, 3D)",
            "Publication GitHub 1-clic & crawl jusqu'à 60–150 pages",
            "Mode R.E.A. Avancé (CDP passif, Source Maps, OpenAPI & Mocks)",
        ],
    },
    "pro": {
        "id": "pro",
        "scope": "cloner",
        "name": "Cloneur Pro",
        "subtitle": "Studio & R.E.A.",
        "badge": "Populaire",
        "price_eur": 19,
        "price_cents": 1900,
        "price_label": "19 € / mois",
        "cloner_max_sites_per_month": 10,
        "cloner_max_pages": 60,
        "cloner_zip_export": True,
        "cloner_studio_edit": True,
        "cloner_github_publish": True,
        "rea_mode": True,
        "features": [
            "10 sites distincts clonés par mois (jusqu'à 60 pages / site)",
            "Studio complet : Éditeur no-code Inspect & Code propre React/Tailwind",
            "Export ZIP complet, export par sections & publication GitHub",
            "Mode R.E.A. Avancé : CDP passif, Source Maps, OpenAPI & Mocks locaux",
        ],
        "excluded_features": [
            "Clones illimités tous les mois & crawl intégral jusqu'à 150 pages",
        ],
    },
    "agency": {
        "id": "agency",
        "scope": "cloner",
        "name": "Cloneur Agence",
        "subtitle": "Production Illimitée",
        "badge": "Illimité",
        "price_eur": 49,
        "price_cents": 4900,
        "price_label": "49 € / mois",
        "cloner_max_sites_per_month": None,
        "cloner_max_pages": 150,
        "cloner_zip_export": True,
        "cloner_studio_edit": True,
        "cloner_github_publish": True,
        "rea_mode": True,
        "features": [
            "Sites clonés illimités tous les mois",
            "Crawl intégral haute profondeur jusqu'à 150 pages / site",
            "Studio complet : Inspect no-code, Design Tokens & Code React/Tailwind",
            "Export ZIP complet, GitHub 1-clic & Mode R.E.A. Avancé complet",
        ],
        "excluded_features": [],
    },
}

SUITE_BUNDLES: Dict[str, Dict[str, Any]] = {
    "suite_pro": {
        "id": "suite_pro",
        "scope": "bundle",
        "name": "Suite Pro (Cloneur + Ultron)",
        "subtitle": "Cloneur Pro (19 €) + Ultron Pro (29 €)",
        "badge": "Économisez 9 €/mois",
        "price_eur": 39,
        "price_cents": 3900,
        "price_label": "39 € / mois",
        "ultron_plan_id": "pro",
        "cloner_plan_id": "pro",
        "features": [
            "Tout Cloneur Pro : 10 clones/mois (60 pages), ZIP, Inspect, React, GitHub & R.E.A.",
            "Tout Ultron Pro : 10 audits/mois, DAST SQLi/XSS/IDOR, CVE/SAST & Copilote IA",
            "19 € + 29 € = 48 € -> seulement 39 €/mois en Pack Suite",
        ],
    },
    "suite_enterprise": {
        "id": "suite_enterprise",
        "scope": "bundle",
        "name": "Suite Entreprise (Tout-en-un Illimité)",
        "subtitle": "Cloneur Agence (49 €) + Ultron Entreprise (149 €)",
        "badge": "Économisez 29 €/mois",
        "price_eur": 169,
        "price_cents": 16900,
        "price_label": "169 € / mois",
        "ultron_plan_id": "enterprise",
        "cloner_plan_id": "agency",
        "features": [
            "Tout Cloneur Agence : clones illimités (150 pages), Studio complet & Mode R.E.A.",
            "Tout Ultron Entreprise : audits illimités, Console Sentinel, Claude MCP & WAF 24/7",
            "49 € + 149 € = 198 € -> seulement 169 €/mois en Pack Suite",
        ],
    },
}

COMPARISON_ROWS: List[Dict[str, Any]] = [
    {"label": "Sites distincts audités / mois", "free": "1 site", "pro": "10 sites", "enterprise": "Illimité"},
    {"label": "En-têtes HTTP, fichiers sensibles (.env/.git) & secrets JS", "free": True, "pro": True, "enterprise": True},
    {"label": "Audit Actif DAST (Injections SQL, XSS, IDOR/BOLA)", "free": False, "pro": True, "enterprise": True},
    {"label": "SSL/TLS, CORS, CVE serveur, dépendances SCA & SAST", "free": False, "pro": True, "enterprise": True},
    {"label": "Patchs serveur (Nginx / Apache) & rapport HTML détaillé", "free": False, "pro": True, "enterprise": True},
    {"label": "Copilote IA Ulton (aide à la correction)", "free": False, "pro": True, "enterprise": True},
    {"label": "Console Sentinel IA complète & multi-LLM BYOK", "free": False, "pro": False, "enterprise": True},
    {"label": "Connecteur Claude Pro / Max via MCP (sans clé API)", "free": False, "pro": False, "enterprise": True},
    {"label": "Bouclier WAF temps réel 24/7 & clés d'agents", "free": False, "pro": False, "enterprise": True},
    {"label": "Scanners SOC, PentAGI, remédiations auto, CI/CD & planification", "free": False, "pro": False, "enterprise": True},
]

CLONER_COMPARISON_ROWS: List[Dict[str, Any]] = [
    {"label": "Sites distincts clonés / mois", "free": "1 site", "pro": "10 sites", "agency": "Illimité"},
    {"label": "Profondeur max de crawl par clone", "free": "5 pages", "pro": "60 pages", "agency": "150 pages"},
    {"label": "Aperçu live & Studio visuel (lecture)", "free": True, "pro": True, "agency": True},
    {"label": "Export ZIP & Export multi-pages / sections", "free": False, "pro": True, "agency": True},
    {"label": "Éditeur no-code Inspect & Code propre React/Tailwind", "free": False, "pro": True, "agency": True},
    {"label": "Publication GitHub 1-clic", "free": False, "pro": True, "agency": True},
    {"label": "Mode R.E.A. Avancé (CDP passif, Source Maps, OpenAPI & Mocks)", "free": False, "pro": True, "agency": True},
]


def init_plan_tables() -> None:
    """Initializes and migrates SQLite tables for separated Ultron/Cloner plans & monthly quotas."""
    conn = get_connection()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS user_subscriptions (
                user_id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL DEFAULT 'free',
                cloner_plan_id TEXT NOT NULL DEFAULT 'free',
                bundle_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                source TEXT NOT NULL DEFAULT 'default',
                stripe_session_id TEXT,
                email TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS monthly_audit_usage (
                user_id TEXT NOT NULL,
                month_key TEXT NOT NULL,
                site_host TEXT NOT NULL,
                first_scan_at TEXT NOT NULL,
                scan_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (user_id, month_key, site_host)
            );
            CREATE TABLE IF NOT EXISTS monthly_clone_usage (
                user_id TEXT NOT NULL,
                month_key TEXT NOT NULL,
                site_host TEXT NOT NULL,
                first_clone_at TEXT NOT NULL,
                clone_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (user_id, month_key, site_host)
            );
            """
        )
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(user_subscriptions)").fetchall()}
        if "cloner_plan_id" not in cols:
            conn.execute("ALTER TABLE user_subscriptions ADD COLUMN cloner_plan_id TEXT NOT NULL DEFAULT 'free'")
        if "bundle_id" not in cols:
            conn.execute("ALTER TABLE user_subscriptions ADD COLUMN bundle_id TEXT NOT NULL DEFAULT ''")
        conn.commit()
    finally:
        conn.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _current_month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def extract_site_host(target_url: str) -> str:
    """Extracts a normalized hostname for monthly distinct-site quota accounting."""
    raw = (target_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    host = (parsed.hostname or parsed.netloc or "").strip().lower()
    return host.removeprefix("www.")


def get_user_subscription(user_id: str) -> Dict[str, Any]:
    """Returns stored separated Ultron & Cloner subscription metadata for user_id."""
    init_plan_tables()
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT user_id, plan_id, cloner_plan_id, bundle_id, status, source, stripe_session_id, email, updated_at "
            "FROM user_subscriptions WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row or row["status"] != "active":
        return {
            "user_id": user_id,
            "plan_id": "free",
            "cloner_plan_id": "free",
            "bundle_id": "",
            "status": "active",
            "source": "default",
            "email": "",
            "updated_at": "",
        }
    d = dict(row)
    if d.get("plan_id") not in PLANS:
        d["plan_id"] = "free"
    if d.get("cloner_plan_id") not in CLONER_PLANS:
        d["cloner_plan_id"] = "free"
    d["bundle_id"] = d.get("bundle_id") or ""
    return d


def get_effective_plan_id(user_id: str, is_admin: bool = False) -> str:
    """Resolves the active Ultron security plan ID (SaaS admins always receive enterprise)."""
    if is_admin:
        return "enterprise"
    return get_user_subscription(user_id)["plan_id"]


def get_effective_cloner_plan_id(user_id: str, is_admin: bool = False) -> str:
    """Resolves the active Cloner & Studio plan ID (SaaS admins always receive agency)."""
    if is_admin:
        return "agency"
    return get_user_subscription(user_id)["cloner_plan_id"]


def get_monthly_usage(user_id: str, month_key: Optional[str] = None) -> List[str]:
    """Returns distinct site hostnames already audited by user_id in the given month."""
    key = month_key or _current_month_key()
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT site_host FROM monthly_audit_usage "
            "WHERE user_id = ? AND month_key = ? ORDER BY first_scan_at ASC",
            (user_id, key),
        ).fetchall()
        return [r["site_host"] for r in rows]
    finally:
        conn.close()


def get_monthly_clone_usage(user_id: str, month_key: Optional[str] = None) -> List[str]:
    """Returns distinct site hostnames already cloned by user_id in the given month."""
    key = month_key or _current_month_key()
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT site_host FROM monthly_clone_usage "
            "WHERE user_id = ? AND month_key = ? ORDER BY first_clone_at ASC",
            (user_id, key),
        ).fetchall()
        return [r["site_host"] for r in rows]
    finally:
        conn.close()


def stripe_enabled() -> bool:
    return bool((os.environ.get("STRIPE_SECRET_KEY") or "").strip())


def compute_subscription_mrr_eur(plan_id: str, cloner_plan_id: str, bundle_id: str = "") -> int:
    """Computes monthly recurring revenue in EUR without double-counting Suite bundles."""
    if bundle_id in SUITE_BUNDLES:
        return int(SUITE_BUNDLES[bundle_id]["price_eur"])
    sec_eur = int(PLANS.get(plan_id, PLANS["free"])["price_eur"])
    cl_eur = int(CLONER_PLANS.get(cloner_plan_id, CLONER_PLANS["free"])["price_eur"])
    return sec_eur + cl_eur


def get_user_plan_status(
    user_id: str,
    is_admin: bool = False,
    is_local: bool = False,
) -> Dict[str, Any]:
    """Builds separated Ultron & Cloner plan states, monthly quotas, and Suite bundles."""
    sub = get_user_subscription(user_id)
    plan_id = "enterprise" if is_admin else sub["plan_id"]
    cloner_plan_id = "agency" if is_admin else sub["cloner_plan_id"]
    bundle_id = "" if is_admin else sub.get("bundle_id", "")

    plan = PLANS[plan_id]
    cloner_plan = CLONER_PLANS[cloner_plan_id]

    used_sites = get_monthly_usage(user_id)
    limit = plan["max_sites_per_month"]
    remaining = None if limit is None else max(0, limit - len(used_sites))

    clones_used = get_monthly_clone_usage(user_id)
    clones_limit = cloner_plan["cloner_max_sites_per_month"]
    clones_remaining = None if clones_limit is None else max(0, clones_limit - len(clones_used))

    return {
        "user_id": user_id,
        "is_admin": is_admin,
        "plan_id": plan_id,
        "plan_name": plan["name"],
        "plan_subtitle": plan["subtitle"],
        "price_label": plan["price_label"],
        "cloner_plan_id": cloner_plan_id,
        "cloner_plan_name": cloner_plan["name"],
        "cloner_plan_subtitle": cloner_plan["subtitle"],
        "cloner_price_label": cloner_plan["price_label"],
        "bundle_id": bundle_id,
        "source": "admin" if is_admin else sub.get("source", "default"),
        "month_key": _current_month_key(),
        "sites_used": len(used_sites),
        "sites_limit": limit,
        "sites_remaining": remaining,
        "sites_list": used_sites,
        "clones_used": len(clones_used),
        "clones_limit": clones_limit,
        "clones_remaining": clones_remaining,
        "clones_list": clones_used,
        "cloner_max_pages": int(cloner_plan["cloner_max_pages"]),
        "cloner_zip_export": bool(cloner_plan["cloner_zip_export"]),
        "cloner_studio_edit": bool(cloner_plan["cloner_studio_edit"]),
        "cloner_github_publish": bool(cloner_plan["cloner_github_publish"]),
        "rea_mode": bool(cloner_plan.get("rea_mode")),
        "allowed_categories": plan["allowed_categories"],
        "sentinel_full_access": bool(plan["sentinel_full_access"]),
        "stripe_enabled": stripe_enabled(),
        "can_self_activate_trial": bool(is_local or is_admin),
        "plans": [PLANS[pid] for pid in PLAN_ORDER],
        "comparison_rows": COMPARISON_ROWS,
        "cloner_plans": [CLONER_PLANS[pid] for pid in CLONER_PLAN_ORDER],
        "cloner_comparison_rows": CLONER_COMPARISON_ROWS,
        "suite_bundles": [SUITE_BUNDLES["suite_pro"], SUITE_BUNDLES["suite_enterprise"]],
    }


def check_plan_requirement(user_id: str, required_plan: str, is_admin: bool = False) -> Dict[str, Any]:
    """Checks whether user_id holds at least required_plan ('free', 'pro', 'enterprise') for Ultron."""
    current = get_effective_plan_id(user_id, is_admin=is_admin)
    cur_idx = PLAN_ORDER.index(current)
    req_idx = PLAN_ORDER.index(required_plan)
    if cur_idx >= req_idx:
        return {"allowed": True, "plan_id": current}
    req_name = PLANS[required_plan]["name"]
    cur_name = PLANS[current]["name"]
    return {
        "allowed": False,
        "status_code": 403,
        "error_code": "PLAN_UPGRADE_REQUIRED",
        "plan_scope": "security",
        "required_plan": required_plan,
        "error": f"Fonctionnalité Ultron réservée à l'offre {req_name} (offre actuelle : {cur_name}).",
    }


def check_cloner_plan_requirement(user_id: str, required_plan: str, is_admin: bool = False) -> Dict[str, Any]:
    """Checks whether user_id holds at least required_plan ('free', 'pro', 'agency') for Cloner/Studio."""
    current = get_effective_cloner_plan_id(user_id, is_admin=is_admin)
    cur_idx = CLONER_PLAN_ORDER.index(current)
    req_idx = CLONER_PLAN_ORDER.index(required_plan)
    if cur_idx >= req_idx:
        return {"allowed": True, "cloner_plan_id": current}
    req_name = CLONER_PLANS[required_plan]["name"]
    cur_name = CLONER_PLANS[current]["name"]
    return {
        "allowed": False,
        "status_code": 403,
        "error_code": "PLAN_UPGRADE_REQUIRED",
        "plan_scope": "cloner",
        "required_plan": required_plan,
        "error": f"Fonctionnalité Cloneur réservée à l'offre {req_name} (offre actuelle : {cur_name}).",
    }


def check_and_authorize_scan(
    user_id: str,
    target_url: str,
    requested_categories: Optional[List[str]] = None,
    is_admin: bool = False,
) -> Dict[str, Any]:
    """Validates monthly site quota and scan category rights for Ultron Security."""
    plan_id = get_effective_plan_id(user_id, is_admin=is_admin)
    plan = PLANS[plan_id]
    site_host = extract_site_host(target_url)
    used_sites = get_monthly_usage(user_id)
    limit = plan["max_sites_per_month"]

    if limit is not None and site_host and site_host not in used_sites and len(used_sites) >= limit:
        next_plan = "pro" if plan_id == "free" else "enterprise"
        return {
            "allowed": False,
            "status_code": 403,
            "error_code": "SITE_QUOTA_EXCEEDED",
            "plan_scope": "security",
            "required_plan": next_plan,
            "error": (
                f"Limite atteinte : l'offre {plan['name']} autorise {limit} site(s) distinct(s) "
                f"par mois ({', '.join(used_sites)}). Passez à l'offre {PLANS[next_plan]['name']} pour continuer."
            ),
        }

    allowed_cats = plan["allowed_categories"]
    if allowed_cats is None:
        return {"allowed": True, "effective_categories": requested_categories, "plan_id": plan_id}

    if not requested_categories:
        return {"allowed": True, "effective_categories": list(allowed_cats), "plan_id": plan_id}

    disallowed = [c for c in requested_categories if c not in allowed_cats]
    if disallowed:
        required_plan = "enterprise" if any(c in ("pentagi", "ports", "sentinel") for c in disallowed) else "pro"
        return {
            "allowed": False,
            "status_code": 403,
            "error_code": "PLAN_UPGRADE_REQUIRED",
            "plan_scope": "security",
            "required_plan": required_plan,
            "locked_categories": disallowed,
            "error": (
                f"Les modules ({', '.join(disallowed)}) ne sont pas inclus dans l'offre {plan['name']}. "
                f"Passez à l'offre {PLANS[required_plan]['name']}."
            ),
        }

    return {"allowed": True, "effective_categories": list(requested_categories), "plan_id": plan_id}


def check_and_authorize_clone(
    user_id: str,
    target_url: str,
    requested_max_pages: int = 5,
    rea_mode: bool = False,
    is_admin: bool = False,
) -> Dict[str, Any]:
    """Validates monthly distinct-site clone quota, crawl depth, and R.E.A. using CLONER_PLANS."""
    cplan_id = get_effective_cloner_plan_id(user_id, is_admin=is_admin)
    plan = CLONER_PLANS[cplan_id]

    if rea_mode and not plan.get("rea_mode"):
        return check_cloner_plan_requirement(user_id, "pro", is_admin=is_admin)

    site_host = extract_site_host(target_url)
    used_clones = get_monthly_clone_usage(user_id)
    limit = plan["cloner_max_sites_per_month"]
    if limit is not None and site_host and site_host not in used_clones and len(used_clones) >= limit:
        next_plan = "pro" if cplan_id == "free" else "agency"
        return {
            "allowed": False,
            "status_code": 403,
            "error_code": "CLONE_QUOTA_EXCEEDED",
            "plan_scope": "cloner",
            "required_plan": next_plan,
            "error": (
                f"Limite atteinte : l'offre {plan['name']} autorise {limit} site(s) distinct(s) "
                f"cloné(s) par mois ({', '.join(used_clones)}). Passez à l'offre {CLONER_PLANS[next_plan]['name']}."
            ),
        }

    max_allowed_pages = int(plan["cloner_max_pages"])
    req_pages = max(1, int(requested_max_pages or max_allowed_pages))
    if req_pages > max_allowed_pages:
        next_plan = "pro" if req_pages <= int(CLONER_PLANS["pro"]["cloner_max_pages"]) else "agency"
        return {
            "allowed": False,
            "status_code": 403,
            "error_code": "PLAN_UPGRADE_REQUIRED",
            "plan_scope": "cloner",
            "required_plan": next_plan,
            "error": (
                f"Profondeur de {req_pages} pages non incluse dans l'offre {plan['name']} "
                f"(max {max_allowed_pages} pages). Passez à l'offre {CLONER_PLANS[next_plan]['name']}."
            ),
        }

    return {"allowed": True, "cloner_plan_id": cplan_id, "effective_max_pages": req_pages}


def record_scan_usage(user_id: str, target_url: str) -> None:
    """Records a completed audit against the user's monthly distinct-site quota."""
    site_host = extract_site_host(target_url)
    if not site_host:
        return
    month_key = _current_month_key()
    now = _now_iso()
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO monthly_audit_usage (user_id, month_key, site_host, first_scan_at, scan_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(user_id, month_key, site_host)
            DO UPDATE SET scan_count = scan_count + 1
            """,
            (user_id, month_key, site_host, now),
        )
        conn.commit()
    finally:
        conn.close()


def record_clone_usage(user_id: str, target_url: str) -> None:
    """Records a completed site clone against the user's monthly distinct-site quota."""
    site_host = extract_site_host(target_url)
    if not site_host:
        return
    month_key = _current_month_key()
    now = _now_iso()
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO monthly_clone_usage (user_id, month_key, site_host, first_clone_at, clone_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(user_id, month_key, site_host)
            DO UPDATE SET clone_count = clone_count + 1
            """,
            (user_id, month_key, site_host, now),
        )
        conn.commit()
    finally:
        conn.close()


def _resolve_plan_target(plan_id: str, scope: Optional[str] = None) -> Tuple[str, str]:
    """Normalizes (plan_id, scope) into (resolved_scope, normalized_plan_id)."""
    clean_plan = (plan_id or "").strip().lower()
    clean_scope = (scope or "").strip().lower()

    if clean_plan in SUITE_BUNDLES or clean_scope == "bundle":
        if clean_plan not in SUITE_BUNDLES:
            raise ValueError(f"Pack Suite inconnu : {plan_id}")
        return "bundle", clean_plan

    if clean_plan.startswith("cloner_"):
        clean_plan = clean_plan[len("cloner_"):]
        clean_scope = "cloner"
    elif clean_plan == "agency" and not clean_scope:
        clean_scope = "cloner"

    target_scope = clean_scope if clean_scope in ("security", "cloner") else "security"
    catalog = CLONER_PLANS if target_scope == "cloner" else PLANS
    if clean_plan not in catalog:
        raise ValueError(f"Offre inconnue ({target_scope}) : {plan_id}")
    return target_scope, clean_plan


def set_user_plan(
    user_id: str,
    plan_id: str,
    source: str = "manual",
    stripe_session_id: str = "",
    email: str = "",
    scope: Optional[str] = None,
) -> Dict[str, Any]:
    """Assigns or updates a user's Ultron plan, Cloner plan, or Suite Bundle independently."""
    init_plan_tables()
    target_scope, clean_plan = _resolve_plan_target(plan_id, scope=scope)
    existing = get_user_subscription(user_id)

    sec_plan = existing["plan_id"]
    cl_plan = existing["cloner_plan_id"]
    bundle_id = ""

    if target_scope == "bundle":
        b = SUITE_BUNDLES[clean_plan]
        sec_plan = b["ultron_plan_id"]
        cl_plan = b["cloner_plan_id"]
        bundle_id = clean_plan
    elif target_scope == "cloner":
        cl_plan = clean_plan
    else:
        sec_plan = clean_plan

    now = _now_iso()
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO user_subscriptions (
                user_id, plan_id, cloner_plan_id, bundle_id, status, source, stripe_session_id, email, updated_at
            )
            VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                plan_id = excluded.plan_id,
                cloner_plan_id = excluded.cloner_plan_id,
                bundle_id = excluded.bundle_id,
                status = 'active',
                source = excluded.source,
                stripe_session_id = COALESCE(NULLIF(excluded.stripe_session_id, ''), user_subscriptions.stripe_session_id),
                email = COALESCE(NULLIF(excluded.email, ''), user_subscriptions.email),
                updated_at = excluded.updated_at
            """,
            (user_id, sec_plan, cl_plan, bundle_id, source, stripe_session_id, email, now),
        )
        conn.commit()
    finally:
        conn.close()

    return get_user_subscription(user_id)


def list_all_subscriptions(limit: int = 100) -> List[Dict[str, Any]]:
    """Lists user subscriptions alongside current-month audit & clone usage counts for admin review."""
    init_plan_tables()
    month_key = _current_month_key()
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT s.user_id, s.plan_id, s.cloner_plan_id, s.bundle_id, s.status, s.source, s.email, s.updated_at,
                   COUNT(DISTINCT u.site_host) AS sites_used_month,
                   COUNT(DISTINCT c.site_host) AS clones_used_month
            FROM user_subscriptions s
            LEFT JOIN monthly_audit_usage u
              ON u.user_id = s.user_id AND u.month_key = ?
            LEFT JOIN monthly_clone_usage c
              ON c.user_id = s.user_id AND c.month_key = ?
            GROUP BY s.user_id
            ORDER BY s.updated_at DESC
            LIMIT ?
            """,
            (month_key, month_key, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def create_plan_checkout(
    user_id: str,
    plan_id: str,
    origin_url: str,
    email: str = "",
    is_admin: bool = False,
    is_local: bool = False,
    scope: Optional[str] = None,
) -> Dict[str, Any]:
    """Starts Stripe subscription Checkout or local activation for Ultron, Cloner, or Suite Bundle."""
    try:
        target_scope, clean_plan = _resolve_plan_target(plan_id, scope=scope)
    except ValueError as exc:
        return {"success": False, "status_code": 400, "error": str(exc)}

    if clean_plan == "free":
        set_user_plan(user_id, "free", source="downgrade", email=email, scope=target_scope)
        lbl = "Cloneur Gratuit" if target_scope == "cloner" else "Ultron Gratuit"
        return {
            "success": True,
            "mode": "updated",
            "plan_status": get_user_plan_status(user_id, is_admin=is_admin, is_local=is_local),
            "message": f"Offre {lbl} activée.",
        }

    if target_scope == "bundle":
        offer = SUITE_BUNDLES[clean_plan]
        product_name = f"SiteCloner + Ultron — {offer['name']}"
    elif target_scope == "cloner":
        offer = CLONER_PLANS[clean_plan]
        product_name = f"SiteCloner — {offer['name']}"
    else:
        offer = PLANS[clean_plan]
        product_name = f"Ultron Sécurité — Offre {offer['name']}"

    if stripe_enabled() and not is_admin:
        import stripe

        stripe.api_key = os.environ["STRIPE_SECRET_KEY"].strip()
        base = origin_url.rstrip("/")
        cancel_base = "/__sc/" if target_scope == "cloner" else "/__sc/security/"
        session_kwargs: Dict[str, Any] = {
            "mode": "subscription",
            "line_items": [
                {
                    "price_data": {
                        "currency": "eur",
                        "unit_amount": offer["price_cents"],
                        "recurring": {"interval": "month"},
                        "product_data": {
                            "name": product_name,
                            "description": offer["subtitle"],
                        },
                    },
                    "quantity": 1,
                }
            ],
            "metadata": {"user_id": user_id, "plan_id": clean_plan, "scope": target_scope},
            "success_url": f"{base}/__sc/security/api/plans/stripe-success?session_id={{CHECKOUT_SESSION_ID}}",
            "cancel_url": f"{base}{cancel_base}?plan_canceled={clean_plan}",
        }
        if email:
            session_kwargs["customer_email"] = email
        checkout_session = stripe.checkout.Session.create(**session_kwargs)
        return {
            "success": True,
            "mode": "stripe",
            "checkout_url": checkout_session.url,
            "session_id": checkout_session.id,
        }

    if is_local or is_admin:
        source = "admin" if is_admin else "trial_local"
        set_user_plan(user_id, clean_plan, source=source, email=email, scope=target_scope)
        return {
            "success": True,
            "mode": "trial_local",
            "plan_status": get_user_plan_status(user_id, is_admin=is_admin, is_local=is_local),
            "message": f"{offer['name']} ({offer['price_label']}) activé en mode essai local.",
        }

    return {
        "success": False,
        "status_code": 402,
        "stripe_required": True,
        "error": (
            "Le paiement en ligne Stripe n'est pas configuré sur cette instance. "
            "Contactez l'administrateur ou activez STRIPE_SECRET_KEY."
        ),
    }


def confirm_stripe_checkout_session(session_id: str, expected_user_id: str) -> Dict[str, Any]:
    """Verifies a Stripe Checkout session server-side before activating the paid offer."""
    if not stripe_enabled():
        return {"success": False, "error": "Stripe non configuré."}
    if not session_id:
        return {"success": False, "error": "session_id manquant."}

    import stripe

    stripe.api_key = os.environ["STRIPE_SECRET_KEY"].strip()
    s = stripe.checkout.Session.retrieve(session_id)
    meta = dict(getattr(s, "metadata", {}) or {})
    plan_id = (meta.get("plan_id") or "").strip().lower()
    scope = (meta.get("scope") or "security").strip().lower()
    target_uid = meta.get("user_id") or expected_user_id

    try:
        resolved_scope, resolved_plan = _resolve_plan_target(plan_id, scope=scope)
    except ValueError:
        return {"success": False, "error": "Session Stripe invalide (offre inconnue)."}

    if target_uid != expected_user_id:
        return {"success": False, "error": "Session Stripe invalide pour cet utilisateur."}
    if getattr(s, "payment_status", "") not in ("paid", "no_payment_required"):
        return {"success": False, "error": "Paiement Stripe non confirmé."}

    email = ""
    details = getattr(s, "customer_details", None)
    if details:
        email = getattr(details, "email", "") or ""

    set_user_plan(
        target_uid,
        resolved_plan,
        source="stripe",
        stripe_session_id=session_id,
        email=email,
        scope=resolved_scope,
    )
    return {"success": True, "plan_id": resolved_plan, "scope": resolved_scope, "user_id": target_uid}
