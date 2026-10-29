#!/usr/bin/env python3
"""
site_server.py - Resolves a request path inside a cloned site folder.

Every clone carries a `_map.json` ("url path[?query]" -> file / content-type / redirect) written by cloner.py,
so query-string variants, extension-less endpoints and redirects behave offline like they did online.
Used by both the Flask preview routes and the dedicated per-site HTTP servers.
"""

import base64
import hashlib
import html as _html
import json
import mimetypes
import os
import re
import shutil
import threading
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

_cache = {}
_lock = threading.Lock()


def _load(root: Path):
    mp = root / "_map.json"
    if not mp.exists():
        return {}, {}
    mtime = mp.stat().st_mtime
    with _lock:
        hit = _cache.get(str(root))
        if hit and hit[0] == mtime:
            return hit[1], hit[2]
        try:
            data = json.loads(mp.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        by_path = {}
        for k, v in data.items():
            by_path.setdefault(k.split("?", 1)[0], v)
        _cache[str(root)] = (mtime, data, by_path)
        return data, by_path


def _safe(root: Path, rel: str):
    p = (root / rel.lstrip("/")).resolve()
    try:
        p.relative_to(root.resolve())
    except ValueError:
        return None
    return p if p.is_file() else None


def resolve(root, raw_path: str):
    """Returns ("redirect", location) | ("file", Path, content_type) | None."""
    root = Path(root)
    parsed = urllib.parse.urlsplit(raw_path)
    path = urllib.parse.unquote(parsed.path) or "/"
    query = urllib.parse.unquote(parsed.query)
    data, by_path = _load(root)

    keys = []
    if query:
        keys.append(path + "?" + query)
    keys += [path, path.rstrip("/") or "/", path.rstrip("/") + "/"]
    for k in keys:
        e = data.get(k)
        if e is None:
            continue
        if "r" in e:
            return ("redirect", e["r"])
        f = _safe(root, e["f"])
        if f:
            return ("file", f, e.get("t") or mimetypes.guess_type(str(f))[0] or "application/octet-stream")
    e = by_path.get(path)
    if e and "f" in e:
        f = _safe(root, e["f"])
        if f:
            return ("file", f, e.get("t") or mimetypes.guess_type(str(f))[0] or "application/octet-stream")

    # Next.js image optimizer: serve the original file
    if path == "/_next/image" and query:
        src = urllib.parse.parse_qs(query).get("url", [""])[0]
        if src:
            return resolve(root, urllib.parse.unquote(src))

    # Plain static fallbacks (files copied in by hand, older clones)
    for rel in (path, path + ".html", path.rstrip("/") + "/index.html"):
        f = _safe(root, rel)
        if f:
            return ("file", f, mimetypes.guess_type(str(f))[0] or "application/octet-stream")

    # Clones whose start page isn't "/" (e.g. a site that begins at /en): send the root to the shallowest page
    if path == "/":
        pages = sorted((k for k, e in data.items() if "html" in e.get("t", "") and "?" not in k
                        and not k.startswith(("POST ", "/_ext/"))), key=lambda k: (k.rstrip("/").count("/"), k))
        if pages:
            return ("redirect", pages[0])

    # Unknown extension-less route of a client-side app: serve the entry page
    if not os.path.splitext(path)[1]:
        f = _safe(root, "index.html")
        if f:
            return ("file", f, "text/html")
    return None


# ---------- in-place editor (editor.js is injected into pages opened with ?__edit=1) ----------
EDITOR_JS = Path(__file__).with_name("editor.js")
# Studio inspector: overrides runtime + bridge, injected into pages opened with ?__inspect=1
INSPECTOR_FILES = (Path(__file__).with_name("sc_overrides.js"), Path(__file__).with_name("inspector.js"))
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".avif"}
MAX_UPLOAD = 40 * 1024 * 1024

_MASK_RE = re.compile(r"<!--.*?-->|<(script|style)\b[^>]*>.*?</\1\s*>", re.S | re.I)
_TAG_RE = re.compile(r"<!--.*?-->|<(script|style)\b[^>]*>.*?</\1\s*>|<[^>]+>", re.S | re.I)
_IMG_RE = re.compile(r"<img\b[^>]*>", re.I | re.S)


def _body_start(src):
    m = re.search(r"<body\b[^>]*>", src, re.I)
    return m.end() if m else 0


def _text_segments(src):
    """(start, end) of every run of text in <body>, outside tags, scripts, styles and comments."""
    segs, last = [], _body_start(src)
    for m in _TAG_RE.finditer(src, last):
        if m.start() > last:
            segs.append((last, m.start()))
        last = m.end()
    if last < len(src):
        segs.append((last, len(src)))
    return segs


def _attr_re(name):
    return re.compile(r"""(\s%s\s*=\s*)("[^"]*"|'[^']*'|[^\s>"']+)""" % name, re.I)


def _attr_val(tag, name):
    m = _attr_re(name).search(tag)
    if not m:
        return None
    v = m.group(2)
    if v[:1] in "\"'":
        v = v[1:-1]
    return _html.unescape(v)


def _edit_text(src, ch):
    key = (ch.get("old") or "").strip()
    if not key:
        return None, "texte vide"
    idx, n = int(ch.get("idx") or 0), 0
    for s, e in _text_segments(src):
        seg = src[s:e]
        if _html.unescape(seg).strip() == key:
            if n == idx:
                lead = seg[:len(seg) - len(seg.lstrip())]
                trail = seg[len(seg.rstrip()):]
                new = _html.escape((ch.get("new") or "").strip(), quote=False)
                return src[:s] + lead + new + trail + src[e:], None
            n += 1
    return None, "texte introuvable dans le fichier (probablement généré par JavaScript)"


def _edit_img(src, ch, new_src):
    old = ch.get("old")
    idx, n = int(ch.get("idx") or 0), 0
    masked = [(m.start(), m.end()) for m in _MASK_RE.finditer(src)]
    for m in _IMG_RE.finditer(src, _body_start(src)):
        if any(a <= m.start() < b for a, b in masked):
            continue
        tag = m.group(0)
        if _attr_val(tag, "src") != old:
            continue
        if n < idx:
            n += 1
            continue
        tag2 = _attr_re("src").sub(lambda mm: mm.group(1) + '"' + new_src + '"', tag, 1)
        tag2 = _attr_re("srcset").sub("", tag2)
        tag2 = _attr_re("sizes").sub("", tag2)
        start = m.start()
        pic = src.rfind("<picture", 0, start)
        if pic != -1 and src.find("</picture", pic, start) == -1:
            before = re.sub(r"<source\b[^>]*>", "", src[pic:start], flags=re.I)
            return src[:pic] + before + tag2 + src[m.end():], None
        return src[:start] + tag2 + src[m.end():], None
    return None, "image introuvable dans le fichier (src modifié par JavaScript ?)"


def _save_image(root, ch):
    name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(ch.get("name") or "image"))
    ext = os.path.splitext(name)[1].lower()
    if ext not in IMG_EXT:
        raise ValueError("format d'image non pris en charge")
    data = base64.b64decode(ch.get("data") or "")
    if not data or len(data) > MAX_UPLOAD:
        raise ValueError("image vide ou trop lourde")
    out_dir = Path(root) / "_edited"
    out_dir.mkdir(exist_ok=True)
    fname = hashlib.md5(data).hexdigest()[:8] + "_" + name
    (out_dir / fname).write_bytes(data)
    return "/_edited/" + fname


def apply_edits(root, page, changes):
    root = Path(root)
    res = resolve(root, page)
    if not res or res[0] != "file" or "html" not in res[2]:
        return {"error": "page introuvable"}
    f = res[1]
    backup = root / "_edited" / "_backup" / (f.relative_to(root.resolve()).as_posix().replace("/", "__") + ".orig")
    if not backup.exists():
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, backup)
    src = f.read_text(encoding="utf-8")
    results = []
    for ch in changes:
        try:
            if ch.get("type") == "text":
                new, err = _edit_text(src, ch)
                new_src = None
            elif ch.get("type") == "img":
                new_src = _save_image(root, ch)
                new, err = _edit_img(src, ch, new_src)
            else:
                new, err = None, "type de modification inconnu"
        except Exception as e:
            new, err, new_src = None, str(e), None
        if err:
            results.append({"ok": False, "msg": err})
        else:
            src = new
            results.append({"ok": True, "src": new_src})
    if any(r["ok"] for r in results):
        f.write_text(src, encoding="utf-8")
    return {"results": results}


def list_pages(root):
    data, _ = _load(Path(root))
    pages = []
    for k, v in data.items():
        if "f" in v and "html" in (v.get("t") or "") and not k.startswith("/_ext/") and "?" not in k:
            pages.append(k)
    return sorted(set(pages), key=lambda p: (p.count("/"), p)) or ["/"]


def resolve_post(root, raw_path: str, body: bytes):
    """Recorded answer to a data POST (same URL, same payload first, then same URL)."""
    import hashlib
    root = Path(root)
    parsed = urllib.parse.urlsplit(raw_path)
    path = urllib.parse.unquote(parsed.path) or "/"
    query = urllib.parse.unquote(parsed.query)
    key = path + ("?" + query if query else "")
    data, _ = _load(root)
    h = hashlib.md5(body or b"").hexdigest()
    for k in (f"POST {key}#{h}", f"POST {key}", f"POST {path}"):
        e = data.get(k)
        if e and "f" in e:
            f = _safe(root, e["f"])
            if f:
                return ("file", f, e.get("t") or "application/json")
    return None


class _Handler(BaseHTTPRequestHandler):
    root = None
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send_bytes(self, status, ctype, body, head_only=False):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if "text/html" in ctype:
            self.send_header("Cache-Control", "no-cache")
        else:
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _send(self, head_only=False):
        sp = urllib.parse.urlsplit(self.path)
        if sp.path == "/__editor.js" and EDITOR_JS.exists():
            return self._send_bytes(200, "text/javascript; charset=utf-8", EDITOR_JS.read_bytes(), head_only)
        if sp.path == "/__inspector.js" and all(f.exists() for f in INSPECTOR_FILES):
            return self._send_bytes(200, "text/javascript; charset=utf-8",
                                    b"\n".join(f.read_bytes() for f in INSPECTOR_FILES), head_only)
        if sp.path == "/__pages":
            return self._send_bytes(200, "application/json", json.dumps(list_pages(self.root)).encode(), head_only)
        res = resolve(self.root, self.path)
        if res is None:
            if self.server.misses is not None:
                self.server.misses.add(self.path)  # lets the cloner's self-healing see every miss (workers included)
            body = b"Not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head_only:
                self.wfile.write(body)
            return
        if res[0] == "redirect":
            self.send_response(302)
            self.send_header("Location", res[1])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        _, f, ctype = res
        if "text/html" in ctype and urllib.parse.parse_qs(sp.query).get("__inspect") == ["1"]:
            raw = f.read_bytes()
            tag = b'<script src="/__inspector.js"></script>'
            i = raw.lower().rfind(b"</body>")
            body = raw[:i] + tag + raw[i:] if i >= 0 else raw + tag
            return self._send_bytes(200, "text/html; charset=utf-8", body, head_only)
        if "text/html" in ctype and urllib.parse.parse_qs(sp.query).get("__edit") == ["1"]:
            raw = f.read_bytes()
            tag = b'<script src="/__editor.js"></script>'
            i = raw.lower().rfind(b"</body>")
            body = raw[:i] + tag + raw[i:] if i >= 0 else raw + tag
            return self._send_bytes(200, "text/html; charset=utf-8", body, head_only)
        size = f.stat().st_size
        start, end, status = 0, size - 1, 200
        rng = self.headers.get("Range")
        if rng:
            m = re.match(r"bytes=(\d*)-(\d*)", rng)
            if m and (m.group(1) or m.group(2)):
                if m.group(1):
                    start = int(m.group(1))
                    end = int(m.group(2)) if m.group(2) else size - 1
                else:
                    start = max(0, size - int(m.group(2)))
                end = min(end, size - 1)
                if start <= end:
                    status = 206
        self.send_response(status)
        if "text/" in ctype or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8" if "charset" not in ctype else ""
        self.send_header("Content-Type", ctype)
        self.send_header("Accept-Ranges", "bytes")
        # pages, the inspector's edits and 3D models (replaceable in the Studio) must never be served stale
        if "text/html" in ctype or "_edited" in f.parts or f.suffix.lower() in (".glb", ".gltf", ".usdz", ".fbx", ".obj"):
            self.send_header("Cache-Control", "no-cache")
        else:
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        length = end - start + 1
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        if head_only:
            return
        try:
            with open(f, "rb") as fh:
                fh.seek(start)
                left = length
                while left > 0:
                    chunk = fh.read(min(65536, left))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    left -= len(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def do_GET(self):
        self._send()

    def do_HEAD(self):
        self._send(head_only=True)

    def _save(self, n):
        # The custom header forces a CORS preflight, so other websites cannot write into a clone.
        origin = self.headers.get("Origin")
        if self.headers.get("X-SiteCloner-Editor") != "1" or (origin and urllib.parse.urlsplit(origin).netloc != self.headers.get("Host")):
            return self._send_bytes(403, "application/json", b'{"error":"forbidden"}')
        if n <= 0 or n > MAX_UPLOAD * 2:
            return self._send_bytes(413, "application/json", b'{"error":"requete trop grande"}')
        try:
            req = json.loads(self.rfile.read(n).decode("utf-8"))
            out = apply_edits(self.root, req.get("page") or "/", req.get("changes") or [])
        except Exception as e:
            return self._send_bytes(400, "application/json", json.dumps({"error": str(e)}).encode())
        self._send_bytes(400 if "error" in out else 200, "application/json", json.dumps(out).encode())

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if urllib.parse.urlsplit(self.path).path == "/__save":
            return self._save(n)
        body = self.rfile.read(n) if n else b""
        res = resolve_post(self.root, self.path, body)
        if res:
            data = res[1].read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", res[2])
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        # Beacons / analytics have no backend offline
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # browsers abort connections all the time (cancelled video ranges...)


def make_server(root, port, record_misses=False):
    handler = type("SiteHandler", (_Handler,), {"root": Path(root)})
    srv = _QuietServer(("127.0.0.1", port), handler)
    srv.misses = set() if record_misses else None
    return srv
