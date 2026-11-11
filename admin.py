#!/usr/bin/env python3
"""
admin.py - Admin dashboard (authentication + site/job management) for SiteCloner SaaS.
Mounted at /admin by app.py through init_admin().
"""

import json
import os
import secrets
import shutil
import time
from functools import wraps
from pathlib import Path

from flask import (Blueprint, abort, jsonify, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

DATA_DIR = Path(os.environ.get("DATA_DIR") or (Path(__file__).resolve().parent / "data"))
ADMIN_FILE = DATA_DIR / "admin.json"
SECRET_FILE = DATA_DIR / "secret_key"
INITIAL_PW_FILE = DATA_DIR / "admin_initial_password.txt"

MAX_ATTEMPTS = 5
LOCK_SECONDS = 300
_attempts = {}  # ip -> (count, first_attempt_ts)

bp = Blueprint("admin", __name__, url_prefix="/admin")
_ctx = {}


# ---------- credentials storage ----------

def load_secret_key():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SECRET_FILE.exists():
        SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
    return SECRET_FILE.read_text(encoding="utf-8").strip()


def _read_admin():
    try:
        return json.loads(ADMIN_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_admin(username, password):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ADMIN_FILE.write_text(json.dumps({
        "username": username,
        "password_hash": generate_password_hash(password),
    }), encoding="utf-8")


def ensure_admin():
    """First run: create the admin account. ADMIN_PASSWORD env wins, otherwise a random
    password is generated and written to data/admin_initial_password.txt (not in git)."""
    if _read_admin():
        return
    username = os.environ.get("ADMIN_USER", "admin")
    password = os.environ.get("ADMIN_PASSWORD")
    generated = not password
    if generated:
        password = secrets.token_urlsafe(12)
    _write_admin(username, password)
    if generated:
        INITIAL_PW_FILE.write_text(
            f"username: {username}\npassword: {password}\n"
            "Change it from the admin dashboard, then delete this file.\n", encoding="utf-8")
        print(f"[admin] Account created. Initial credentials saved in {INITIAL_PW_FILE}")
    else:
        print(f"[admin] Account '{username}' created from ADMIN_PASSWORD.")


# ---------- auth helpers ----------

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def _check_csrf():
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf", "")
    if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
        abort(403)


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("admin"):
            if request.path.startswith("/admin/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("admin.login", next=request.path))
        if request.method not in ("GET", "HEAD"):
            _check_csrf()
        return view(*a, **kw)
    return wrapped


def _locked(ip):
    rec = _attempts.get(ip)
    if not rec:
        return False
    count, first = rec
    if time.time() - first > LOCK_SECONDS:
        _attempts.pop(ip, None)
        return False
    return count >= MAX_ATTEMPTS


def _fail(ip):
    count, first = _attempts.get(ip, (0, time.time()))
    _attempts[ip] = (count + 1, first)


# ---------- pages ----------

@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    ip = request.remote_addr or "?"
    if request.method == "POST":
        if _locked(ip):
            error = "Trop de tentatives. Réessaie dans quelques minutes."
        else:
            adm = _read_admin() or {}
            user_ok = secrets.compare_digest(request.form.get("username", ""), adm.get("username", ""))
            pw_ok = check_password_hash(adm.get("password_hash", ""), request.form.get("password", ""))
            if user_ok and pw_ok:
                _attempts.pop(ip, None)
                session.clear()
                session["admin"] = True
                csrf_token()
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/admin") else url_for("admin.dashboard"))
            _fail(ip)
            error = "Identifiants incorrects."
    return render_template("admin_login.html", error=error)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("admin.login"))


@bp.route("/")
@login_required
def dashboard():
    return render_template("admin_dashboard.html", csrf=csrf_token(),
                           username=(_read_admin() or {}).get("username", "admin"))


# ---------- API ----------

def _dir_size(path):
    return sum(f.stat().st_size for f in Path(path).rglob("*") if f.is_file())


@bp.route("/api/overview")
@login_required
def overview():
    manifest = _ctx["load_manifest"]()
    jobs = list(_ctx["jobs"].values())
    cloned = _ctx["CLONED_DIR"]
    disk = shutil.disk_usage(cloned)
    return jsonify({
        "sites": len(manifest),
        "total_size": sum(m.get("total_size", 0) for m in manifest.values()),
        "total_pages": sum(m.get("total_pages", 0) for m in manifest.values()),
        "jobs_running": sum(1 for j in jobs if j["status"] == "running"),
        "jobs_failed": sum(1 for j in jobs if j["status"] == "failed"),
        "jobs_completed": sum(1 for j in jobs if j["status"] == "completed"),
        "active_previews": len(_ctx["active_servers"]),
        "disk_free": disk.free,
        "disk_total": disk.total,
    })


@bp.route("/api/sites")
@login_required
def sites():
    manifest = _ctx["load_manifest"]()
    active = _ctx["active_servers"]
    out = []
    for m in manifest.values():
        item = dict(m)
        item["active_port"] = active[m["id"]]["port"] if m["id"] in active else None
        out.append(item)
    out.sort(key=lambda s: s.get("date", ""), reverse=True)
    return jsonify({"sites": out})


@bp.route("/api/sites/<site_id>", methods=["DELETE"])
@login_required
def delete_site(site_id):
    resp = _ctx["delete_site"](site_id)
    return resp


@bp.route("/api/sites/<site_id>/stop", methods=["POST"])
@login_required
def stop_site(site_id):
    return _ctx["stop_serve"](site_id)


@bp.route("/api/jobs")
@login_required
def jobs():
    out = [{
        "job_id": j["job_id"], "site_id": j["site_id"], "url": j["url"],
        "status": j["status"], "error": j.get("error"),
        "message": (j.get("progress") or {}).get("message", ""),
    } for j in _ctx["jobs"].values()]
    return jsonify({"jobs": out[::-1]})


@bp.route("/api/jobs/<job_id>", methods=["DELETE"])
@login_required
def clear_job(job_id):
    job = _ctx["jobs"].get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] == "running":
        return jsonify({"error": "Job en cours"}), 409
    del _ctx["jobs"][job_id]
    return jsonify({"status": "cleared"})


@bp.route("/api/platform-overview")
@login_required
def platform_overview():
    """Unified platform telemetry across Cloner, Shop orders, Security, Plans, and LLM."""
    shop_orders = []
    try:
        from shop import db as shop_db
        with shop_db() as conn:
            shop_orders = [dict(r) for r in conn.execute("SELECT created_at, status, amount_cents FROM orders ORDER BY id DESC LIMIT 1000").fetchall()]
    except Exception:
        shop_orders = []

    from security.admin_overview import build_platform_admin_overview
    manifest = _ctx["load_manifest"]()
    data = build_platform_admin_overview(
        manifest=manifest,
        jobs=_ctx["jobs"],
        active_servers=_ctx["active_servers"],
        shop_orders=shop_orders,
    )
    return jsonify(data)


@bp.route("/api/platform/assign-plan", methods=["POST"])
@login_required
def platform_assign_plan():
    """Allows SaaS admins to upgrade or downgrade a user's Ultron, Cloner, or Suite offer from /admin."""
    data = request.get_json(silent=True) or {}
    user_id = (data.get("user_id") or "").strip()
    plan_id = (data.get("plan_id") or "").strip().lower()
    scope = (data.get("scope") or "").strip().lower() or None
    email = (data.get("email") or "").strip()
    if not user_id or not plan_id:
        return jsonify({"error": "user_id et plan_id sont requis."}), 400
    from security.plans import set_user_plan
    try:
        sub = set_user_plan(user_id, plan_id, source="admin_dashboard", email=email, scope=scope)
        return jsonify({"success": True, "subscription": sub})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@bp.route("/api/password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json() or {}
    adm = _read_admin() or {}
    if not check_password_hash(adm.get("password_hash", ""), data.get("current", "")):
        return jsonify({"error": "Mot de passe actuel incorrect."}), 403
    new = data.get("new", "")
    if len(new) < 10:
        return jsonify({"error": "10 caractères minimum."}), 400
    _write_admin(adm["username"], new)
    INITIAL_PW_FILE.unlink(missing_ok=True)
    return jsonify({"status": "updated"})


def init_admin(app, **ctx):
    """ctx: load_manifest, jobs, active_servers, CLONED_DIR, delete_site, stop_serve."""
    _ctx.update(ctx)
    app.secret_key = load_secret_key()
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_NAME="sc_admin")
    ensure_admin()
    app.register_blueprint(bp)
