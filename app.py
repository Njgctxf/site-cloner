#!/usr/bin/env python3
"""
app.py - Flask Web Backend for SiteCloner SaaS
Handles REST API endpoints, background worker jobs, local live preview servers, and site management.
"""

import sys
import os
import re
import json
import uuid
import shutil
import socket
import threading
import urllib.parse
from datetime import datetime
from pathlib import Path
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import hmac
from flask import Flask, request, jsonify, render_template, send_file, send_from_directory, Response, redirect

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from cloner import clone_site
from site_server import resolve, resolve_post, make_server
from admin import init_admin
from shop import init_shop

app = Flask(__name__, template_folder="templates")

BASE_DIR = Path(__file__).resolve().parent
CLONED_DIR = BASE_DIR / "cloned_sites"
MANIFEST_FILE = CLONED_DIR / "manifest.json"

CLONED_DIR.mkdir(parents=True, exist_ok=True)

# Online mode (Render): password protection + previews served by Flask itself
ONLINE = bool(os.environ.get("RENDER") or os.environ.get("APP_PASSWORD"))
APP_USER = os.environ.get("APP_USER", "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

@app.before_request
def require_auth():
    if not ONLINE:
        return None
    if not APP_PASSWORD:
        return None  # No password configured -> open access
    auth = request.authorization
    ok = bool(
        auth and auth.password
        and hmac.compare_digest(auth.username or "", APP_USER)
        and hmac.compare_digest(auth.password, APP_PASSWORD)
    )
    if not ok:
        return Response("Authentification requise", 401, {"WWW-Authenticate": 'Basic realm="SiteCloner"'})
    return None

# In-memory tracking
jobs = {}
active_servers = {}  # site_id -> {"port": port, "httpd": server_instance, "thread": thread}

def load_manifest():
    manifest = {}
    if MANIFEST_FILE.exists():
        try:
            with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            manifest = {}

    changed = False
    cleaned = {k: v for k, v in manifest.items() if (CLONED_DIR / k).is_dir()}
    if len(cleaned) != len(manifest):
        changed = True
        manifest = cleaned

    for d in CLONED_DIR.iterdir():
        if not d.is_dir():
            continue
        sid = d.name
        if sid not in manifest:
            rep_file = d / "_clone-report.txt"
            url = ""
            pages = 1
            files = 0
            if rep_file.exists():
                txt = rep_file.read_text("utf-8", errors="ignore")
                m_src = re.search(r"Source\s*:\s*(.+)", txt)
                if m_src:
                    url = m_src.group(1).strip()
                m_p = re.search(r"Pages\s*:\s*(\d+)", txt)
                if m_p:
                    pages = int(m_p.group(1))
                m_f = re.search(r"Fichiers\s*:\s*(\d+)", txt)
                if m_f:
                    files = int(m_f.group(1))
            all_files = [f for f in d.rglob("*") if f.is_file()]
            size = sum(f.stat().st_size for f in all_files)
            if not files:
                files = len(all_files)
            title = sid.replace("_", " ").title()
            manifest[sid] = {
                "id": sid,
                "title": title,
                "url": url or ("https://" + sid.split("_")[0]),
                "date": datetime.fromtimestamp(d.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                "total_pages": pages,
                "total_files": files,
                "total_size": size,
                "folder": str(d)
            }
            changed = True

    if changed:
        save_manifest(manifest)

    return manifest

def save_manifest(data):
    try:
        with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving manifest: {e}")

def find_free_port(start_port=4000, end_port=4999):
    for port in range(start_port, end_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return port
    return 4050

SITE_COOKIE = "sc_site"


@app.before_request
def serve_active_clone():
    """While a clone is open (cookie), the whole origin belongs to it: root-absolute paths
    and client-side routers (Next.js, Framer, Astro...) then work exactly as on the real site."""
    if request.path.startswith(("/__sc/", "/preview/", "/admin", "/shop")):
        return None
    sid = request.cookies.get(SITE_COOKIE)
    if not sid or not (CLONED_DIR / sid).is_dir():
        return redirect("/__sc/") if request.path == "/" else None
    if request.method not in ("GET", "HEAD"):
        res = resolve_post(CLONED_DIR / sid, request.full_path.rstrip("?"), request.get_data())
        if res:  # recorded data request (GraphQL, JSON API)
            return send_file(str(res[1]), mimetype=res[2])
        return Response(status=204)  # analytics beacons, forms: no backend offline
    out = _send_resolved(CLONED_DIR / sid, request.full_path.rstrip("?"))
    return out if out is not None else (jsonify({"error": "Not found"}), 404)


@app.route("/__sc/")
def index():
    resp = Response(render_template("index.html"), mimetype="text/html")
    resp.delete_cookie(SITE_COOKIE, path="/")
    return resp

@app.route("/__sc/api/clone", methods=["POST"])
def start_clone():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    crawl_all_pages = bool(data.get("crawl_all_pages", True))
    max_pages = min(int(data.get("max_pages", 15)), 30)  # hard cap: 30 pages max

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    job_id = str(uuid.uuid4())[:8]
    domain = urllib.parse.urlparse(url).netloc.replace(":", "_").replace(".", "_")
    site_id = f"{domain}_{job_id}"
    dest_dir = CLONED_DIR / site_id

    jobs[job_id] = {
        "job_id": job_id,
        "site_id": site_id,
        "url": url,
        "status": "running",
        "progress": {"current": 0, "total": 10, "message": "Initialisation du pipeline de clonage..."},
        "result": None,
        "error": None
    }

    def worker():
        def update_progress(current, total, message):
            if job_id in jobs:
                jobs[job_id]["progress"] = {
                    "current": current,
                    "total": total,
                    "message": message
                }

        try:
            res = clone_site(url, dest_dir, crawl_all_pages=crawl_all_pages, max_pages=max_pages, progress_callback=update_progress)
            if res.get("success"):
                manifest = load_manifest()
                manifest[site_id] = {
                    "id": site_id,
                    "title": res.get("title") or domain,
                    "url": url,
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "total_pages": res.get("total_pages", 1),
                    "total_files": res.get("total_files", 0),
                    "total_size": res.get("total_size", 0),
                    "folder": str(dest_dir)
                }
                save_manifest(manifest)
                jobs[job_id]["status"] = "completed"
                jobs[job_id]["result"] = res
            else:
                jobs[job_id]["status"] = "failed"
                jobs[job_id]["error"] = res.get("error", "Unknown error")
        except Exception as e:
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = str(e)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "started", "site_id": site_id})

@app.route("/__sc/api/status/<job_id>", methods=["GET"])
def get_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

@app.route("/__sc/api/sites", methods=["GET"])
def list_sites():
    manifest = load_manifest()
    sites = [m for m in manifest.values() if (CLONED_DIR / m.get("id", "")).is_dir()]
    # Add active server port if running
    for s in sites:
        sid = s.get("id")
        if sid in active_servers:
            s["active_port"] = active_servers[sid]["port"]
        else:
            s["active_port"] = None
    return jsonify({"sites": sites})

def _send_resolved(dest_dir, raw_path):
    res = resolve(dest_dir, raw_path)
    if res is None:
        return None
    if res[0] == "redirect":
        return Response(status=302, headers={"Location": res[1]})
    _, f, ctype = res
    if "text/html" in ctype and ONLINE:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if "</body>" in content and "/__sc/" not in content:
                badge = (
                    '<div style="position:fixed;bottom:16px;left:16px;z-index:999999;'
                    'background:rgba(9,10,15,0.88);backdrop-filter:blur(10px);border:1px solid rgba(99,102,241,0.5);'
                    'padding:8px 16px;border-radius:24px;font-family:sans-serif;font-size:12px;box-shadow:0 6px 20px rgba(0,0,0,0.6);">'
                    '<a href="/__sc/" style="color:#818cf8;text-decoration:none;font-weight:700;display:flex;align-items:center;gap:6px;">'
                    '⚡ SiteCloner &bull; <span style="color:#f8fafc;font-weight:500;">&larr; Tableau de bord</span></a></div>'
                )
                content = content.replace("</body>", f"{badge}</body>", 1)
                resp = Response(content, mimetype="text/html")
                resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
                return resp
        except Exception:
            pass
    max_age = 0 if "text/html" in ctype else 31536000
    resp = send_file(str(f), mimetype=ctype.split(";")[0], conditional=True, max_age=max_age)
    resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    return resp

@app.route("/preview/<site_id>/", defaults={"filename": ""})
@app.route("/preview/<site_id>/<path:filename>")
def preview_site(site_id, filename):
    if not (CLONED_DIR / site_id).is_dir():
        return jsonify({"error": "Site not found"}), 404
    target = "/" + filename
    if request.query_string:
        target += "?" + request.query_string.decode("utf-8", "ignore")
    resp = redirect(target)
    is_https = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
    resp.set_cookie(SITE_COOKIE, site_id, path="/", samesite="Lax", secure=is_https)
    return resp

@app.route("/__sc/api/sites/<site_id>/serve", methods=["POST"])
def serve_site(site_id):
    dest_dir = CLONED_DIR / site_id
    if not dest_dir.exists():
        return jsonify({"error": "Site directory not found"}), 404

    if ONLINE:
        return jsonify({"url": f"/preview/{site_id}/"})

    # Already running?
    if site_id in active_servers:
        port = active_servers[site_id]["port"]
        return jsonify({"port": port, "url": f"http://localhost:{port}"})

    port = find_free_port()

    try:
        httpd = make_server(dest_dir, port)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        active_servers[site_id] = {
            "port": port,
            "httpd": httpd,
            "thread": thread
        }
        return jsonify({"port": port, "url": f"http://localhost:{port}"})
    except Exception as e:
        return jsonify({"error": f"Failed to start server: {str(e)}"}), 500

@app.route("/__sc/api/sites/<site_id>/stop", methods=["POST"])
def stop_serve(site_id):
    if site_id in active_servers:
        srv = active_servers.pop(site_id)
        try:
            srv["httpd"].shutdown()
        except Exception:
            pass
        return jsonify({"status": "stopped"})
    return jsonify({"status": "not_running"})

@app.route("/__sc/api/sites/<site_id>/download", methods=["GET"])
def download_zip(site_id):
    dest_dir = CLONED_DIR / site_id
    if not dest_dir.exists():
        return jsonify({"error": "Site not found"}), 404

    zip_path = CLONED_DIR / f"{site_id}"
    shutil.make_archive(str(zip_path), "zip", str(dest_dir))
    final_zip = CLONED_DIR / f"{site_id}.zip"
    return send_file(final_zip, as_attachment=True, download_name=f"{site_id}.zip")

@app.route("/__sc/api/sites/<site_id>", methods=["DELETE"])
def delete_site(site_id):
    # Stop if running
    if site_id in active_servers:
        stop_serve(site_id)

    dest_dir = CLONED_DIR / site_id
    if dest_dir.exists():
        try:
            shutil.rmtree(dest_dir)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    zip_file = CLONED_DIR / f"{site_id}.zip"
    if zip_file.exists():
        zip_file.unlink(missing_ok=True)

    manifest = load_manifest()
    if site_id in manifest:
        del manifest[site_id]
        save_manifest(manifest)

    return jsonify({"status": "deleted"})

@app.route("/__sc/api/sites/<site_id>/publish", methods=["POST"])
def publish_github(site_id):
    dest_dir = CLONED_DIR / site_id
    if not dest_dir.exists():
        return jsonify({"error": "Site directory not found"}), 404

    data = request.get_json() or {}
    repo_name = data.get("repo_name", site_id).replace("_", "-")

    try:
        import subprocess
        # Initialize git if needed
        subprocess.run(["git", "init"], cwd=str(dest_dir), check=False)
        subprocess.run(["git", "branch", "-M", "main"], cwd=str(dest_dir), check=False)
        subprocess.run(["git", "add", "."], cwd=str(dest_dir), check=False)
        subprocess.run(["git", "commit", "-m", f"Publish {repo_name}"], cwd=str(dest_dir), check=False)

        # Create repo and push via gh cli
        gh = shutil.which("gh") or "C:\\Program Files\\GitHub CLI\\gh.exe"
        if not shutil.which("gh") and not os.path.exists(gh):
            return jsonify({"error": "GitHub CLI indisponible sur ce serveur : utilise le bouton ZIP."}), 501
        cmd = [gh, "repo", "create", repo_name, "--public", "--source=.", "--remote=origin", "--push", "--confirm"]
        res = subprocess.run(cmd, cwd=str(dest_dir), capture_output=True, text=True)
        if res.returncode != 0 and "already exists" not in res.stderr:
            return jsonify({"error": res.stderr or res.stdout or "Erreur lors de la création GitHub"}), 500

        # Retrieve repo URL
        view_cmd = [gh, "repo", "view", repo_name, "--json", "url", "-q", ".url"]
        view_res = subprocess.run(view_cmd, cwd=str(dest_dir), capture_output=True, text=True)
        repo_url = view_res.stdout.strip() or f"https://github.com/{repo_name}"
        return jsonify({"success": True, "repo_url": repo_url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

init_admin(app, load_manifest=load_manifest, jobs=jobs, active_servers=active_servers,
           CLONED_DIR=CLONED_DIR, delete_site=delete_site, stop_serve=stop_serve)
init_shop(app)
if ONLINE:
    app.config["SESSION_COOKIE_SECURE"] = True

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 0))
    if not port:
        for p in (5050, 5000, 5500, 8080):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("0.0.0.0", p))
                    port = p
                    break
            except Exception:
                continue
        if not port:
            port = find_free_port(5000, 6000)

    print(f"[SiteCloner SaaS v2] starting on http://localhost:{port} ...")
    app.run(host="0.0.0.0", port=port, debug=False)
