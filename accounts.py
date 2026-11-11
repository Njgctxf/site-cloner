#!/usr/bin/env python3
"""
accounts.py - User accounts, registration, authentication, and SaaS profile management.
Mounted at /account by app.py through init_accounts(app).
"""

import os
import re
import sqlite3
import time
import unicodedata
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, send_file, session
from werkzeug.security import check_password_hash, generate_password_hash

from security.database import get_connection, log_event
from security.plans import get_user_plan_status, init_plan_tables

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR") or (BASE_DIR / "data"))
AVATARS_DIR = DATA_DIR / "avatars"
SHOP_DB = DATA_DIR / "shop.db"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
RESERVED_USERNAMES = {
    "admin", "root", "system", "support", "api", "account",
    "login", "register", "profile", "null", "undefined",
}
AVATAR_COLORS = (
    "#6366f1", "#3b82f6", "#06b6d4", "#10b981",
    "#8b5cf6", "#ec4899", "#f59e0b", "#ef4444",
)
MAX_AVATAR_BYTES = 2 * 1024 * 1024
MIN_PASSWORD_LEN = 6
MAX_LOGIN_ATTEMPTS = 5
LOCK_SECONDS = 300
_login_attempts: Dict[str, Tuple[int, float]] = {}

bp = Blueprint("accounts", __name__, url_prefix="/account")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_account_tables() -> None:
    """Initializes SQLite tables for user accounts and profile metadata."""
    AVATARS_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                bio TEXT NOT NULL DEFAULT '',
                company TEXT NOT NULL DEFAULT '',
                website TEXT NOT NULL DEFAULT '',
                avatar_color TEXT NOT NULL DEFAULT '#6366f1',
                avatar_file TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT 'user',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login_at TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            """
        )
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        for col, ddl in (
            ("stripe_account_id", "TEXT NOT NULL DEFAULT ''"),
            ("stripe_onboarding_complete", "INTEGER NOT NULL DEFAULT 0"),
            ("stripe_charges_enabled", "INTEGER NOT NULL DEFAULT 0"),
            ("stripe_payouts_enabled", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if col not in cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
        conn.commit()
    finally:
        conn.close()


def _normalize_email(raw: str) -> str:
    return (raw or "").strip().lower()


def _normalize_username(raw: str) -> str:
    return (raw or "").strip().lstrip("@").lower()


def _generate_unique_username(conn: sqlite3.Connection, display_name: str, email: str) -> str:
    """Derives a clean unique @username from the user's name or email local-part."""
    seed = (display_name or "").strip() or (email.split("@")[0] if "@" in email else "user")
    ascii_seed = unicodedata.normalize("NFKD", seed).encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9._-]+", ".", ascii_seed).strip("._-")
    if not slug or not slug[0].isalnum():
        slug = "u." + slug if slug else "user"
    base = slug[:24]
    if len(base) < 3:
        base = (base + "user")[:6]
    candidate = base
    for attempt in range(12):
        if attempt > 0:
            candidate = f"{base[:22]}_{uuid.uuid4().hex[:4]}"
        if candidate in RESERVED_USERNAMES or not USERNAME_RE.match(candidate):
            candidate = f"u_{uuid.uuid4().hex[:6]}"
        taken = conn.execute("SELECT 1 FROM users WHERE username = ?", (candidate,)).fetchone()
        if not taken:
            return candidate
    return f"u_{uuid.uuid4().hex[:8]}"


def _validate_website(raw: str) -> str:
    val = (raw or "").strip()[:200]
    if not val:
        return ""
    if not (val.startswith("http://") or val.startswith("https://")):
        raise ValueError("Le site web doit commencer par http:// ou https://.")
    return val


def _initials_for(display_name: str, username: str) -> str:
    src = (display_name or username or "U").strip()
    parts = [p for p in re.split(r"[\s._-]+", src) if p]
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    return src[:2].upper() or "U"


def public_user_dict(row: Any) -> Optional[Dict[str, Any]]:
    """Serializes a user SQLite row safely without exposing password_hash."""
    if not row:
        return None
    d = dict(row)
    d.pop("password_hash", None)
    avatar_file = (d.get("avatar_file") or "").strip()
    d["avatar_url"] = (
        f"/account/avatar/{d['user_id']}?v={abs(hash(avatar_file)) % 100000}"
        if avatar_file and (AVATARS_DIR / avatar_file).is_file()
        else ""
    )
    d["initials"] = _initials_for(d.get("display_name", ""), d.get("username", ""))
    d["stripe_connected"] = bool(d.get("stripe_account_id"))
    d["payouts_ready"] = bool(
        d.get("stripe_account_id") and d.get("stripe_charges_enabled") and d.get("stripe_payouts_enabled")
    )
    return d


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    if not user_id:
        return None
    init_account_tables()
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE user_id = ? AND is_active = 1", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    clean = (identifier or "").strip().lower().lstrip("@")
    if not clean:
        return None
    init_account_tables()
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE (email = ? OR username = ?) AND is_active = 1",
            (clean, clean),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_registered_users(limit: int = 150) -> List[Dict[str, Any]]:
    """Lists registered users joined with their separated Ultron & Cloner plans for admin review."""
    init_account_tables()
    init_plan_tables()
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT u.user_id, u.email, u.username, u.display_name, u.company, u.website,
                   u.avatar_color, u.avatar_file, u.role, u.is_active, u.created_at, u.last_login_at,
                   COALESCE(s.plan_id, 'free') AS plan_id,
                   COALESCE(s.cloner_plan_id, 'free') AS cloner_plan_id,
                   COALESCE(s.bundle_id, '') AS bundle_id
            FROM users u
            LEFT JOIN user_subscriptions s ON s.user_id = u.user_id
            ORDER BY u.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        out = []
        for r in rows:
            item = public_user_dict(r)
            if item:
                out.append(item)
        return out
    finally:
        conn.close()


def _safe_next_url(raw: str, fallback: str = "/account/profile") -> str:
    nxt = (raw or "").strip()
    if nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return fallback


def _is_local_request() -> bool:
    host = (request.host or "").split(":")[0].lower()
    return host in ("127.0.0.1", "localhost", "::1")


def _check_login_locked(ip: str) -> bool:
    rec = _login_attempts.get(ip)
    if not rec:
        return False
    count, first = rec
    if time.time() - first > LOCK_SECONDS:
        _login_attempts.pop(ip, None)
        return False
    return count >= MAX_LOGIN_ATTEMPTS


def _record_login_fail(ip: str) -> None:
    count, first = _login_attempts.get(ip, (0, time.time()))
    if time.time() - first > LOCK_SECONDS:
        _login_attempts[ip] = (1, time.time())
    else:
        _login_attempts[ip] = (count + 1, first)


def _migrate_guest_session(guest_uid: str, user_id: str, email: str) -> None:
    """Transfers an anonymous visitor's current-month usage and plans to a newly created account."""
    if not guest_uid or guest_uid == user_id or not guest_uid.startswith("usr_"):
        return
    init_plan_tables()
    conn = get_connection()
    try:
        # Transfer monthly audit & clone usage without creating duplicate primary keys
        conn.execute(
            """
            INSERT INTO monthly_audit_usage (user_id, month_key, site_host, first_scan_at, scan_count)
            SELECT ?, month_key, site_host, first_scan_at, scan_count
            FROM monthly_audit_usage WHERE user_id = ?
            ON CONFLICT(user_id, month_key, site_host)
            DO UPDATE SET scan_count = monthly_audit_usage.scan_count + excluded.scan_count
            """,
            (user_id, guest_uid),
        )
        conn.execute("DELETE FROM monthly_audit_usage WHERE user_id = ?", (guest_uid,))

        conn.execute(
            """
            INSERT INTO monthly_clone_usage (user_id, month_key, site_host, first_clone_at, clone_count)
            SELECT ?, month_key, site_host, first_clone_at, clone_count
            FROM monthly_clone_usage WHERE user_id = ?
            ON CONFLICT(user_id, month_key, site_host)
            DO UPDATE SET clone_count = monthly_clone_usage.clone_count + excluded.clone_count
            """,
            (user_id, guest_uid),
        )
        conn.execute("DELETE FROM monthly_clone_usage WHERE user_id = ?", (guest_uid,))

        guest_sub = conn.execute("SELECT * FROM user_subscriptions WHERE user_id = ?", (guest_uid,)).fetchone()
        if guest_sub:
            conn.execute(
                """
                INSERT INTO user_subscriptions (
                    user_id, plan_id, cloner_plan_id, bundle_id, status, source, stripe_session_id, email, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    plan_id = COALESCE(NULLIF(user_subscriptions.plan_id, 'free'), excluded.plan_id),
                    cloner_plan_id = COALESCE(NULLIF(user_subscriptions.cloner_plan_id, 'free'), excluded.cloner_plan_id),
                    email = COALESCE(NULLIF(user_subscriptions.email, ''), excluded.email),
                    updated_at = excluded.updated_at
                """,
                (
                    user_id,
                    guest_sub["plan_id"],
                    guest_sub["cloner_plan_id"],
                    guest_sub["bundle_id"],
                    guest_sub["status"],
                    guest_sub["source"],
                    guest_sub["stripe_session_id"],
                    email or guest_sub["email"],
                    _now_iso(),
                ),
            )
            conn.execute("DELETE FROM user_subscriptions WHERE user_id = ?", (guest_uid,))

        # Transfer BYOK LLM connections if user doesn't have the same provider yet
        has_llm_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sentinel_user_llm_connections'"
        ).fetchone()
        if has_llm_table:
            conn.execute(
                """
                UPDATE OR IGNORE sentinel_user_llm_connections
                SET user_id = ?
                WHERE user_id = ?
                """,
                (user_id, guest_uid),
            )

        conn.commit()
    finally:
        conn.close()


def _detect_image_ext(data: bytes) -> Optional[str]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _current_session_user() -> Optional[Dict[str, Any]]:
    uid = session.get("user_id")
    if not uid:
        return None
    return get_user_by_id(str(uid))


def has_registered_account() -> bool:
    """True if the active request has an authenticated registered user or admin session."""
    if session.get("admin"):
        return True
    if _current_session_user():
        return True
    if current_app.config.get("TESTING") and not session.get("enforce_account_gate") and session.get("sentinel_user_id"):
        return True
    return False


def account_gate_url(gate: str, next_url: str, mode: str = "register") -> str:
    """Builds the mandatory account creation/login URL that returns to next_url upon completion."""
    safe_next = _safe_next_url(next_url, "/account/profile")
    endpoint = "/account/login" if mode == "login" else "/account/register"
    params = urllib.parse.urlencode({"gate": gate, "next": safe_next})
    return f"{endpoint}?{params}"


# ---------- HTML Pages ----------


@bp.route("/")
def account_root():
    if _current_session_user():
        return redirect("/account/profile")
    return redirect("/account/login")


@bp.route("/login")
def login_page():
    nxt = _safe_next_url(request.args.get("next", ""), "/account/profile")
    gate = (request.args.get("gate") or "").strip().lower()
    if _current_session_user():
        return redirect(nxt)
    return render_template("account_auth.html", mode="login", next_url=nxt, gate_mode=gate)


@bp.route("/register")
def register_page():
    nxt = _safe_next_url(request.args.get("next", ""), "/account/profile")
    gate = (request.args.get("gate") or "").strip().lower()
    if _current_session_user():
        return redirect(nxt)
    return render_template("account_auth.html", mode="register", next_url=nxt, gate_mode=gate)


@bp.route("/profile")
def profile_page():
    user = _current_session_user()
    if not user:
        return redirect("/account/login?next=/account/profile")
    return render_template("account_profile.html", user=public_user_dict(user), avatar_colors=AVATAR_COLORS)


@bp.route("/avatar/<user_id>")
def serve_avatar(user_id: str):
    user = get_user_by_id(user_id)
    if not user or not user.get("avatar_file"):
        return ("", 404)
    target = (AVATARS_DIR / user["avatar_file"]).resolve()
    if not str(target).startswith(str(AVATARS_DIR.resolve())) or not target.is_file():
        return ("", 404)
    return send_file(target, max_age=300)


# ---------- JSON APIs ----------


@bp.route("/api/me")
def api_me():
    user_row = _current_session_user()
    user_pub = public_user_dict(user_row)
    is_admin = bool(session.get("admin"))
    active_uid = user_pub["user_id"] if user_pub else (f"admin_{session.get('admin')}" if is_admin else session.get("sentinel_user_id", ""))
    plans = get_user_plan_status(active_uid or "guest_preview", is_admin=is_admin, is_local=_is_local_request())
    return jsonify({
        "authenticated": bool(user_pub),
        "is_admin": is_admin,
        "user": user_pub,
        "plans": {
            "plan_id": plans["plan_id"],
            "plan_name": plans["plan_name"],
            "cloner_plan_id": plans["cloner_plan_id"],
            "cloner_plan_name": plans["cloner_plan_name"],
            "bundle_id": plans["bundle_id"],
        },
    })


@bp.route("/api/register", methods=["POST"])
def api_register():
    init_account_tables()
    data = request.get_json(silent=True) or {}
    email = _normalize_email(data.get("email", ""))
    raw_username = data.get("username") or ""
    username = _normalize_username(raw_username) if raw_username else ""
    display_name = (data.get("display_name") or data.get("name") or "").strip()[:80]
    password = data.get("password") or ""
    company = (data.get("company") or "").strip()[:80]
    try:
        website = _validate_website(data.get("website", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if not display_name and not username:
        return jsonify({"error": "Veuillez indiquer votre nom."}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"error": "Adresse e-mail invalide."}), 400
    if username and (not USERNAME_RE.match(username) or username in RESERVED_USERNAMES):
        return jsonify({
            "error": "Nom d'utilisateur invalide (3 à 32 caractères alphanumériques, tirets ou points)."
        }), 400
    if len(password) < MIN_PASSWORD_LEN:
        return jsonify({"error": f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LEN} caractères."}), 400

    user_id = f"u_{uuid.uuid4().hex[:12]}"
    now = _now_iso()
    pw_hash = generate_password_hash(password)

    conn = get_connection()
    try:
        if not username:
            username = _generate_unique_username(conn, display_name, email)
        if not display_name:
            display_name = username

        existing = conn.execute(
            "SELECT email, username FROM users WHERE email = ? OR username = ?",
            (email, username),
        ).fetchone()
        if existing:
            if existing["email"] == email:
                return jsonify({"error": "Un compte existe déjà avec cette adresse e-mail. Connectez-vous."}), 409
            return jsonify({"error": "Ce nom d'utilisateur est déjà pris."}), 409

        color = AVATAR_COLORS[sum(ord(ch) for ch in username) % len(AVATAR_COLORS)]
        conn.execute(
            """
            INSERT INTO users (
                user_id, email, username, display_name, password_hash,
                company, website, avatar_color, created_at, last_login_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, email, username, display_name, pw_hash, company, website, color, now, now),
        )
        conn.commit()
    finally:
        conn.close()

    guest_uid = session.get("sentinel_user_id", "")
    _migrate_guest_session(guest_uid, user_id, email)

    session["user_id"] = user_id
    session["sentinel_user_id"] = user_id
    session["user_email"] = email

    try:
        log_event("ACCOUNT_CREATED", "INFO", "ACCOUNTS", f"Nouveau compte créé : {username} ({email})")
    except Exception:
        pass

    user = public_user_dict(get_user_by_id(user_id))
    return jsonify({
        "success": True,
        "user": user,
        "redirect": _safe_next_url(data.get("next", ""), "/account/profile"),
    }), 201


@bp.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr or "local"
    if _check_login_locked(ip):
        return jsonify({"error": "Trop de tentatives. Réessayez dans quelques minutes."}), 429

    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or data.get("email") or "").strip()
    password = data.get("password") or ""

    if not identifier or not password:
        return jsonify({"error": "Identifiant et mot de passe requis."}), 400

    user = get_user_by_identifier(identifier)
    if not user or not check_password_hash(user["password_hash"], password):
        _record_login_fail(ip)
        return jsonify({"error": "Identifiants incorrects."}), 401

    _login_attempts.pop(ip, None)
    now = _now_iso()
    conn = get_connection()
    try:
        conn.execute("UPDATE users SET last_login_at = ? WHERE user_id = ?", (now, user["user_id"]))
        conn.commit()
    finally:
        conn.close()

    session["user_id"] = user["user_id"]
    session["sentinel_user_id"] = user["user_id"]
    session["user_email"] = user["email"]

    fresh = public_user_dict(get_user_by_id(user["user_id"]))
    return jsonify({
        "success": True,
        "user": fresh,
        "redirect": _safe_next_url(data.get("next", ""), "/account/profile"),
    })


@bp.route("/api/logout", methods=["POST"])
def api_logout():
    for key in ("user_id", "user", "user_email", "sentinel_user_id"):
        session.pop(key, None)
    return jsonify({"success": True, "redirect": "/__sc/home"})


@bp.route("/api/profile", methods=["POST"])
def api_update_profile():
    user = _current_session_user()
    if not user:
        return jsonify({"error": "Connexion requise."}), 401

    data = request.get_json(silent=True) or {}
    display_name = (data.get("display_name") if "display_name" in data else user["display_name"]).strip()[:80]
    username = _normalize_username(data.get("username") if "username" in data else user["username"])
    bio = (data.get("bio") if "bio" in data else user["bio"]).strip()[:400]
    company = (data.get("company") if "company" in data else user["company"]).strip()[:80]
    avatar_color = (data.get("avatar_color") if "avatar_color" in data else user["avatar_color"]).strip()
    try:
        website = _validate_website(data.get("website") if "website" in data else user["website"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if not display_name:
        return jsonify({"error": "Le nom affiché ne peut pas être vide."}), 400
    if not USERNAME_RE.match(username) or username in RESERVED_USERNAMES:
        return jsonify({"error": "Nom d'utilisateur invalide (3 à 32 caractères)."}), 400
    if not HEX_COLOR_RE.match(avatar_color):
        avatar_color = user["avatar_color"] or "#6366f1"

    conn = get_connection()
    try:
        clash = conn.execute(
            "SELECT user_id FROM users WHERE username = ? AND user_id <> ?",
            (username, user["user_id"]),
        ).fetchone()
        if clash:
            return jsonify({"error": "Ce nom d'utilisateur est déjà utilisé."}), 409

        conn.execute(
            """
            UPDATE users
            SET display_name = ?, username = ?, bio = ?, company = ?, website = ?, avatar_color = ?
            WHERE user_id = ?
            """,
            (display_name, username, bio, company, website, avatar_color, user["user_id"]),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "user": public_user_dict(get_user_by_id(user["user_id"]))})


@bp.route("/api/password", methods=["POST"])
def api_change_password():
    user = _current_session_user()
    if not user:
        return jsonify({"error": "Connexion requise."}), 401

    data = request.get_json(silent=True) or {}
    current_pw = data.get("current_password") or ""
    new_pw = data.get("new_password") or ""
    confirm_pw = data.get("confirm_password") or ""

    if not check_password_hash(user["password_hash"], current_pw):
        return jsonify({"error": "Mot de passe actuel incorrect."}), 400
    if len(new_pw) < MIN_PASSWORD_LEN:
        return jsonify({"error": f"Le nouveau mot de passe doit contenir au moins {MIN_PASSWORD_LEN} caractères."}), 400
    if confirm_pw and new_pw != confirm_pw:
        return jsonify({"error": "La confirmation ne correspond pas au nouveau mot de passe."}), 400

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE user_id = ?",
            (generate_password_hash(new_pw), user["user_id"]),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": "Mot de passe mis à jour."})


@bp.route("/api/avatar", methods=["POST", "DELETE"])
def api_avatar():
    user = _current_session_user()
    if not user:
        return jsonify({"error": "Connexion requise."}), 401

    AVATARS_DIR.mkdir(parents=True, exist_ok=True)
    if request.method == "DELETE":
        old_file = (user.get("avatar_file") or "").strip()
        if old_file and (AVATARS_DIR / old_file).is_file():
            (AVATARS_DIR / old_file).unlink(missing_ok=True)
        conn = get_connection()
        try:
            conn.execute("UPDATE users SET avatar_file = '' WHERE user_id = ?", (user["user_id"],))
            conn.commit()
        finally:
            conn.close()
        return jsonify({"success": True, "user": public_user_dict(get_user_by_id(user["user_id"]))})

    f = request.files.get("avatar")
    if not f:
        return jsonify({"error": "Fichier image requis."}), 400
    raw = f.read(MAX_AVATAR_BYTES + 1)
    if not raw:
        return jsonify({"error": "Fichier vide."}), 400
    if len(raw) > MAX_AVATAR_BYTES:
        return jsonify({"error": "Image trop volumineuse (max 2 Mo)."}), 400
    ext = _detect_image_ext(raw)
    if not ext:
        return jsonify({"error": "Format non supporté (PNG, JPG ou WebP uniquement)."}), 400

    old_file = (user.get("avatar_file") or "").strip()
    if old_file and (AVATARS_DIR / old_file).is_file():
        (AVATARS_DIR / old_file).unlink(missing_ok=True)

    filename = f"{user['user_id']}_{int(time.time())}.{ext}"
    (AVATARS_DIR / filename).write_bytes(raw)
    conn = get_connection()
    try:
        conn.execute("UPDATE users SET avatar_file = ? WHERE user_id = ?", (filename, user["user_id"]))
        conn.commit()
    finally:
        conn.close()

    fresh = public_user_dict(get_user_by_id(user["user_id"]))
    return jsonify({"success": True, "user": fresh})


@bp.route("/api/activity")
def api_activity():
    user = _current_session_user()
    if not user:
        return jsonify({"error": "Connexion requise."}), 401

    uid = user["user_id"]
    email = user["email"]
    is_admin = bool(session.get("admin"))
    plans = get_user_plan_status(uid, is_admin=is_admin, is_local=_is_local_request())

    month_key = datetime.now(timezone.utc).strftime("%Y-%m")
    conn = get_connection()
    try:
        clones_month = [
            dict(r)
            for r in conn.execute(
                "SELECT site_host, clone_count, first_clone_at FROM monthly_clone_usage "
                "WHERE user_id = ? AND month_key = ? ORDER BY first_clone_at DESC",
                (uid, month_key),
            ).fetchall()
        ]
        audits_month = [
            dict(r)
            for r in conn.execute(
                "SELECT site_host, scan_count, first_scan_at FROM monthly_audit_usage "
                "WHERE user_id = ? AND month_key = ? ORDER BY first_scan_at DESC",
                (uid, month_key),
            ).fetchall()
        ]
        llm_connections: List[Dict[str, Any]] = []
        has_llm = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sentinel_user_llm_connections'"
        ).fetchone()
        if has_llm:
            llm_connections = [
                dict(r)
                for r in conn.execute(
                    "SELECT provider_id, selected_model, connection_status, usage_count, connected_at "
                    "FROM sentinel_user_llm_connections WHERE user_id = ? ORDER BY connected_at DESC",
                    (uid,),
                ).fetchall()
            ]
    finally:
        conn.close()

    marketplace_products: List[Dict[str, Any]] = []
    marketplace_orders: List[Dict[str, Any]] = []
    if SHOP_DB.is_file():
        sc = sqlite3.connect(SHOP_DB)
        sc.row_factory = sqlite3.Row
        try:
            cols = {r["name"] for r in sc.execute("PRAGMA table_info(products)")}
            if "owner_user_id" in cols:
                rows = sc.execute(
                    "SELECT id, slug, title, category, price_cents, published, submission_status, views, created_at "
                    "FROM products WHERE owner_user_id = ? OR LOWER(author_email) = LOWER(?) ORDER BY created_at DESC LIMIT 30",
                    (uid, email),
                ).fetchall()
            else:
                rows = sc.execute(
                    "SELECT id, slug, title, category, price_cents, published, submission_status, views, created_at "
                    "FROM products WHERE LOWER(author_email) = LOWER(?) ORDER BY created_at DESC LIMIT 30",
                    (email,),
                ).fetchall()
            marketplace_products = [dict(r) for r in rows]

            orders = sc.execute(
                """
                SELECT o.id, o.product_id, p.title AS product_title, p.slug AS product_slug,
                       o.amount_cents, o.currency, o.status, o.created_at, o.paid_at
                FROM orders o
                LEFT JOIN products p ON p.id = o.product_id
                WHERE LOWER(o.email) = LOWER(?)
                ORDER BY o.created_at DESC LIMIT 30
                """,
                (email,),
            ).fetchall()
            marketplace_orders = [dict(r) for r in orders]
        finally:
            sc.close()

    return jsonify({
        "user": public_user_dict(user),
        "plans": {
            "plan_id": plans["plan_id"],
            "plan_name": plans["plan_name"],
            "price_label": plans["price_label"],
            "sites_used": plans["sites_used"],
            "sites_limit": plans["sites_limit"],
            "cloner_plan_id": plans["cloner_plan_id"],
            "cloner_plan_name": plans["cloner_plan_name"],
            "cloner_price_label": plans["cloner_price_label"],
            "clones_used": plans["clones_used"],
            "clones_limit": plans["clones_limit"],
            "cloner_max_pages": plans["cloner_max_pages"],
            "bundle_id": plans["bundle_id"],
            "rea_mode": plans["rea_mode"],
            "sentinel_full_access": plans["sentinel_full_access"],
        },
        "clones_month": clones_month,
        "audits_month": audits_month,
        "llm_connections": llm_connections,
        "marketplace_products": marketplace_products,
        "marketplace_orders": marketplace_orders,
    })


def _seller_base_url() -> str:
    return (os.environ.get("PUBLIC_URL", "").strip().rstrip("/")) or request.host_url.rstrip("/")


def _refresh_connect_account(user: Dict[str, Any]) -> Dict[str, Any]:
    """Syncs Stripe Connect Express capabilities from Stripe into SQLite when configured."""
    acct_id = (user.get("stripe_account_id") or "").strip()
    sk = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not acct_id or not sk:
        return user
    try:
        import stripe
        stripe.api_key = sk
        acct = stripe.Account.retrieve(acct_id)
        onboarded = 1 if getattr(acct, "details_submitted", False) else 0
        charges = 1 if getattr(acct, "charges_enabled", False) else 0
        payouts = 1 if getattr(acct, "payouts_enabled", False) else 0
        conn = get_connection()
        try:
            conn.execute(
                """
                UPDATE users
                SET stripe_onboarding_complete = ?, stripe_charges_enabled = ?, stripe_payouts_enabled = ?
                WHERE user_id = ?
                """,
                (onboarded, charges, payouts, user["user_id"]),
            )
            conn.commit()
        finally:
            conn.close()
        return get_user_by_id(user["user_id"]) or user
    except Exception:
        return user


def _seller_payout_summary(user: Dict[str, Any], refresh_stripe: bool = False) -> Dict[str, Any]:
    """Builds seller payout status (Stripe Connect Express) and 99%/1% net earnings summary."""
    if refresh_stripe:
        user = _refresh_connect_account(user)
    acct_id = (user.get("stripe_account_id") or "").strip()
    charges = bool(user.get("stripe_charges_enabled"))
    payouts = bool(user.get("stripe_payouts_enabled"))
    onboarded = bool(user.get("stripe_onboarding_complete"))

    sales_count = 0
    gross_cents = 0
    platform_fee_cents = 0
    seller_net_cents = 0
    recent_sales: List[Dict[str, Any]] = []

    if SHOP_DB.is_file():
        sc = sqlite3.connect(SHOP_DB)
        sc.row_factory = sqlite3.Row
        try:
            ocols = {r["name"] for r in sc.execute("PRAGMA table_info(orders)").fetchall()}
            pcols = {r["name"] for r in sc.execute("PRAGMA table_info(products)").fetchall()}
            if "seller_user_id" in ocols and "owner_user_id" in pcols:
                rows = sc.execute(
                    """
                    SELECT o.id, o.product_id, p.title AS product_title, o.amount_cents,
                           o.platform_fee_cents, o.seller_payout_cents, o.currency, o.paid_at, o.created_at
                    FROM orders o
                    LEFT JOIN products p ON p.id = o.product_id
                    WHERE o.status = 'paid' AND (o.seller_user_id = ? OR p.owner_user_id = ?)
                    ORDER BY COALESCE(o.paid_at, o.created_at) DESC LIMIT 40
                    """,
                    (user["user_id"], user["user_id"]),
                ).fetchall()
                for r in rows:
                    amt = int(r["amount_cents"] or 0)
                    fee = int(r["platform_fee_cents"] or (max(1, round(amt * 0.01)) if amt > 0 else 0))
                    net = int(r["seller_payout_cents"] or max(0, amt - fee))
                    sales_count += 1
                    gross_cents += amt
                    platform_fee_cents += fee
                    seller_net_cents += net
                    recent_sales.append({
                        "id": r["id"],
                        "product_title": r["product_title"] or f"Produit #{r['product_id']}",
                        "amount_cents": amt,
                        "platform_fee_cents": fee,
                        "seller_payout_cents": net,
                        "currency": (r["currency"] or "eur").upper(),
                        "paid_at": r["paid_at"] or r["created_at"],
                    })
        finally:
            sc.close()

    return {
        "stripe_ready": bool(os.environ.get("STRIPE_SECRET_KEY")),
        "connected": bool(acct_id),
        "stripe_account_id": acct_id,
        "onboarding_complete": onboarded,
        "charges_enabled": charges,
        "payouts_enabled": payouts,
        "ready_to_sell_paid": bool(acct_id and charges and payouts),
        "platform_fee_pct": 1,
        "seller_share_pct": 99,
        "sales_count": sales_count,
        "gross_cents": gross_cents,
        "platform_fee_cents": platform_fee_cents,
        "seller_net_cents": seller_net_cents,
        "recent_sales": recent_sales,
    }


@bp.route("/api/payouts/status")
def api_payouts_status():
    user = _current_session_user()
    if not user:
        return jsonify({"error": "Connexion requise."}), 401
    refresh = request.args.get("refresh") == "1"
    return jsonify(_seller_payout_summary(user, refresh_stripe=refresh))


@bp.route("/api/payouts/connect", methods=["POST"])
def api_payouts_connect():
    user = _current_session_user()
    if not user:
        return jsonify({"error": "Connexion requise."}), 401
    sk = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not sk:
        return jsonify({
            "error": "Stripe n'est pas configuré sur ce serveur (variable STRIPE_SECRET_KEY manquante)."
        }), 503

    import stripe
    stripe.api_key = sk
    acct_id = (user.get("stripe_account_id") or "").strip()
    try:
        if not acct_id:
            acct = stripe.Account.create(
                type="express",
                email=user["email"],
                capabilities={
                    "card_payments": {"requested": True},
                    "transfers": {"requested": True},
                },
                business_profile={"name": (user.get("display_name") or user.get("username") or "Créateur")[:80]},
                metadata={"user_id": user["user_id"]},
            )
            acct_id = acct.id
            conn = get_connection()
            try:
                conn.execute(
                    "UPDATE users SET stripe_account_id = ? WHERE user_id = ?",
                    (acct_id, user["user_id"]),
                )
                conn.commit()
            finally:
                conn.close()

        base = _seller_base_url()
        link = stripe.AccountLink.create(
            account=acct_id,
            refresh_url=f"{base}/account/profile?tab=payouts&payout=refresh",
            return_url=f"{base}/account/payouts/return",
            type="account_onboarding",
        )
        return jsonify({
            "success": True,
            "stripe_account_id": acct_id,
            "onboarding_url": link.url,
        })
    except Exception as exc:
        return jsonify({"error": f"Erreur Stripe Connect : {exc}"}), 400


@bp.route("/payouts/return")
def payouts_return_page():
    user = _current_session_user()
    if not user:
        return redirect("/account/login?next=/account/profile%3Ftab%3Dpayouts")
    _refresh_connect_account(user)
    return redirect("/account/profile?tab=payouts&payout=done")


@bp.route("/api/payouts/dashboard", methods=["POST"])
def api_payouts_dashboard():
    user = _current_session_user()
    if not user:
        return jsonify({"error": "Connexion requise."}), 401
    acct_id = (user.get("stripe_account_id") or "").strip()
    sk = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not acct_id or not sk:
        return jsonify({"error": "Compte Stripe Connect non connecté."}), 400
    try:
        import stripe
        stripe.api_key = sk
        login_link = stripe.Account.create_login_link(acct_id)
        return jsonify({"success": True, "url": login_link.url})
    except Exception as exc:
        return jsonify({"error": f"Impossible d'ouvrir le tableau Stripe : {exc}"}), 400


def init_accounts(app) -> None:
    """Initializes SQLite tables and registers the /account blueprint."""
    init_account_tables()
    app.register_blueprint(bp)
