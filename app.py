#!/usr/bin/env python3
"""
app.py - Flask Web Backend for SiteCloner SaaS
Handles REST API endpoints, background worker jobs, local live preview servers, and site management.
"""

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
from flask import Flask, request, jsonify, render_template, send_file, send_from_directory, Response

from cloner import clone_site
from site_server import resolve, make_server

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
    auth = request.authorization
    ok = bool(
        APP_PASSWORD and auth and auth.password
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
    if MANIFEST_FILE.exists():
        try:
            with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

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

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/clone", methods=["POST"])
def start_clone():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    crawl_all_pages = bool(data.get("crawl_all_pages", True))
    max_pages = int(data.get("max_pages", 40))

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

@app.route("/api/status/<job_id>", methods=["GET"])
def get_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

@app.route("/api/sites", methods=["GET"])
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
    resp = send_file(str(f), mimetype=ctype.split(";")[0], conditional=True, max_age=0)
    resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    return resp

@app.route("/preview/<site_id>/", defaults={"filename": ""})
@app.route("/preview/<site_id>/<path:filename>")
def preview_site(site_id, filename):
    dest_dir = CLONED_DIR / site_id
    if not dest_dir.is_dir():
        return jsonify({"error": "Site not found"}), 404
    raw = "/" + filename
    if request.query_string:
        raw += "?" + request.query_string.decode("utf-8", "ignore")
    out = _send_resolved(dest_dir, raw)
    return out if out is not None else (jsonify({"error": "Not found"}), 404)

@app.errorhandler(404)
def root_path_fallback(_e):
    """Clones use root-absolute paths (/_next/..., /assets/...): resolve them via the page that asked for them."""
    ref = request.headers.get("Referer", "")
    m = re.search(r"/preview/([^/?#]+)/", ref)
    if m and (CLONED_DIR / m.group(1)).is_dir() and not request.path.startswith(("/api/", "/preview/")):
        out = _send_resolved(CLONED_DIR / m.group(1), request.full_path.rstrip("?"))
        if out is not None:
            return out
    return jsonify({"error": "Not found"}), 404

@app.route("/api/sites/<site_id>/serve", methods=["POST"])
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

@app.route("/api/sites/<site_id>/stop", methods=["POST"])
def stop_serve(site_id):
    if site_id in active_servers:
        srv = active_servers.pop(site_id)
        try:
            srv["httpd"].shutdown()
        except Exception:
            pass
        return jsonify({"status": "stopped"})
    return jsonify({"status": "not_running"})

@app.route("/api/sites/<site_id>/download", methods=["GET"])
def download_zip(site_id):
    dest_dir = CLONED_DIR / site_id
    if not dest_dir.exists():
        return jsonify({"error": "Site not found"}), 404

    zip_path = CLONED_DIR / f"{site_id}"
    shutil.make_archive(str(zip_path), "zip", str(dest_dir))
    final_zip = CLONED_DIR / f"{site_id}.zip"
    return send_file(final_zip, as_attachment=True, download_name=f"{site_id}.zip")

@app.route("/api/sites/<site_id>", methods=["DELETE"])
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

@app.route("/api/sites/<site_id>/publish", methods=["POST"])
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
        cmd = [gh, "repo", "create", f"Njgctxf/{repo_name}", "--public", "--source=.", "--remote=origin", "--push", "--confirm"]
        res = subprocess.run(cmd, cwd=str(dest_dir), capture_output=True, text=True)

        repo_url = f"https://github.com/Njgctxf/{repo_name}"
        return jsonify({"success": True, "repo_url": repo_url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 SiteCloner SaaS starting on http://localhost:{port} ...")
    app.run(host="0.0.0.0", port=port, debug=False)
