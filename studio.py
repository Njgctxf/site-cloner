"""
studio.py - the Studio of a clone: a visual board of every cloned page, page and section export,
and the site's design system (colors, typography, radii, shadows) as reusable tokens.

Everything the Studio produces lives in <clone>/_studio/ (thumbnails, sections, design.json), so the clone
itself is never modified.
"""

import hashlib
import io
import json
import os
import re
import shutil
import threading
import time
import urllib.parse
import zipfile
from collections import Counter
from pathlib import Path

from flask import Blueprint, abort, jsonify, render_template, request, send_file

from site_server import make_server, resolve

bp = Blueprint("studio", __name__)
_cfg = {}
_jobs = {}            # site_id -> {"kind", "state", "done", "total", "error", "started"}
_jobs_lock = threading.Lock()

VIEWPORT = {"width": 1440, "height": 900}
SETTLE_MS = 3500      # time given to intros, fonts and WebGL before a screenshot


def init_studio(app, CLONED_DIR, find_free_port):
    _cfg.update(dir=Path(CLONED_DIR), free_port=find_free_port)
    app.register_blueprint(bp)


# ---------------------------------------------------------------- helpers

def _site(site_id):
    if not re.fullmatch(r"[\w.-]+", site_id or ""):
        abort(404)
    d = _cfg["dir"] / site_id
    if not d.is_dir():
        abort(404)
    return d


def _pid(key):
    return hashlib.md5(key.encode("utf-8")).hexdigest()[:12]


def _studio_dir(site_dir):
    d = site_dir / "_studio"
    d.mkdir(exist_ok=True)
    return d


def _pages(site_dir):
    """Every cloned HTML page, one entry per file (the same page can be reachable under several keys)."""
    try:
        m = json.loads((site_dir / "_map.json").read_text(encoding="utf-8"))
    except Exception:
        m = {}
    seen, out = set(), []
    for key, e in m.items():
        if "f" not in e or "html" not in e.get("t", "") or key.startswith(("POST ", "/_ext/")) or "?" in key:
            continue
        if e["f"] in seen:
            continue
        seen.add(e["f"])
        title = ""
        try:
            head = (site_dir / e["f"]).read_text(encoding="utf-8", errors="ignore")[:200000]
            mt = re.search(r"<title[^>]*>(.*?)</title>", head, re.S | re.I)
            title = " ".join(re.sub(r"<[^>]+>", "", mt.group(1)).split())[:120] if mt else ""
        except OSError:
            pass
        pid = _pid(key)
        out.append({"key": key, "file": e["f"], "title": title, "id": pid,
                    "thumb": (site_dir / "_studio" / "thumbs" / f"{pid}.jpg").exists()})
    out.sort(key=lambda p: (p["key"].rstrip("/").count("/"), p["key"]))
    return out


def _job(site_id):
    with _jobs_lock:
        return dict(_jobs.get(site_id) or {})


def _start(site_id, kind, target, *args):
    with _jobs_lock:
        j = _jobs.get(site_id)
        if j and j.get("state") == "running":
            return False
        _jobs[site_id] = {"kind": kind, "state": "running", "done": 0, "total": 0, "error": "", "started": time.time()}

    def run():
        try:
            target(site_id, *args)
            with _jobs_lock:
                _jobs[site_id]["state"] = "done"
        except Exception as e:  # reported to the board
            with _jobs_lock:
                _jobs[site_id].update(state="error", error=str(e)[:300])

    threading.Thread(target=run, daemon=True).start()
    return True


def _progress(site_id, done=None, total=None):
    with _jobs_lock:
        j = _jobs.get(site_id, {})
        if done is not None:
            j["done"] = done
        if total is not None:
            j["total"] = total


class _Browser:
    """A local server for the clone plus a headless Chrome pointed at it."""

    def __init__(self, site_dir):
        self.site_dir = site_dir

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        from cloner import launch
        self.port = _cfg["free_port"](4600, 4999)
        self.httpd = make_server(self.site_dir, self.port)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.pw = sync_playwright().start()
        self.browser = launch(self.pw, [])
        self.ctx = self.browser.new_context(viewport=VIEWPORT, device_scale_factor=0.5, service_workers="block")
        self.page = self.ctx.new_page()
        self.base = f"http://127.0.0.1:{self.port}"
        return self

    def open(self, key):
        try:
            self.page.goto(self.base + key, wait_until="load", timeout=45000)
        except Exception:
            pass  # a slow asset should not block the screenshot of what did load
        self.page.wait_for_timeout(SETTLE_MS)

    def __exit__(self, *exc):
        for step in (lambda: self.browser.close(), lambda: self.pw.stop(), lambda: self.httpd.shutdown()):
            try:
                step()
            except Exception:
                pass


# ---------------------------------------------------------------- thumbnails + design tokens

DESIGN_JS = r"""() => {
  const add = (o, k, n = 1) => { if (k) o[k] = (o[k] || 0) + n; };
  const r = {text: {}, bg: {}, border: {}, fonts: {}, sizes: {}, radii: {}, shadows: {}, weights: {}};
  const els = [...document.querySelectorAll('body *')].slice(0, 5000);
  for (const e of els) {
    const b = e.getBoundingClientRect();
    if (!b.width || !b.height) continue;
    const s = getComputedStyle(e);
    if (s.visibility === 'hidden' || s.opacity === '0') continue;
    const hasText = [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim().length > 1);
    if (hasText) {
      add(r.text, s.color);
      add(r.fonts, s.fontFamily.split(',')[0].replace(/["']/g, '').trim());
      add(r.sizes, s.fontSize);
      add(r.weights, s.fontWeight);
    }
    if (s.backgroundColor && s.backgroundColor !== 'rgba(0, 0, 0, 0)') add(r.bg, s.backgroundColor, Math.max(1, Math.round(b.width * b.height / 20000)));
    if (s.borderTopWidth !== '0px' && s.borderTopStyle !== 'none') add(r.border, s.borderTopColor);
    if (s.borderTopLeftRadius !== '0px') add(r.radii, s.borderTopLeftRadius);
    if (s.boxShadow && s.boxShadow !== 'none') add(r.shadows, s.boxShadow);
  }
  return r;
}"""


def _thumbs_job(site_id, force=False):
    site_dir = _cfg["dir"] / site_id
    tdir = _studio_dir(site_dir) / "thumbs"
    tdir.mkdir(exist_ok=True)
    pages = _pages(site_dir)
    todo = [p for p in pages if force or not p["thumb"]]
    _progress(site_id, 0, len(todo))
    design = {}
    dpath = site_dir / "_studio" / "design_raw.json"
    if dpath.exists() and not force:
        try:
            design = json.loads(dpath.read_text(encoding="utf-8"))
        except Exception:
            design = {}
    if not todo:
        return
    with _Browser(site_dir) as b:
        def shoot(p):
            b.open(p["key"])
            try:
                b.page.screenshot(path=str(tdir / f"{p['id']}.jpg"), type="jpeg", quality=72, timeout=20000)
            except Exception:
                pass
            try:
                design[p["id"]] = b.page.evaluate(DESIGN_JS)
            except Exception:
                pass

        for i, p in enumerate(todo, 1):
            shoot(p)
            _progress(site_id, i)
        # heavy pages (WebGL, big media) can miss the first try while Chrome is still warming up
        for p in todo:
            if not (tdir / f"{p['id']}.jpg").exists():
                shoot(p)
    dpath.write_text(json.dumps(design), encoding="utf-8")


# ---------------------------------------------------------------- design system

def _hex(c):
    """rgb()/rgba() from getComputedStyle -> #rrggbb (or #rrggbbaa when translucent)."""
    m = re.match(r"rgba?\(\s*([\d.]+)[ ,]+([\d.]+)[ ,]+([\d.]+)(?:\s*[,/]\s*([\d.]+%?))?\s*\)", c or "")
    if not m:
        return None
    r, g, b = (max(0, min(255, round(float(x)))) for x in m.groups()[:3])
    a = m.group(4)
    alpha = 1.0
    if a is not None:
        alpha = float(a[:-1]) / 100 if a.endswith("%") else float(a)
    if alpha <= 0.02:
        return None
    h = f"#{r:02x}{g:02x}{b:02x}"
    return h if alpha >= 0.99 else h + f"{round(alpha * 255):02x}"


def _css_texts(site_dir):
    for p in site_dir.rglob("*.css"):
        if "_studio" in p.parts:
            continue
        try:
            yield p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass


def _design(site_dir):
    raw = {}
    dpath = site_dir / "_studio" / "design_raw.json"
    if dpath.exists():
        try:
            raw = json.loads(dpath.read_text(encoding="utf-8"))
        except Exception:
            raw = {}
    agg = {k: Counter() for k in ("text", "bg", "border", "fonts", "sizes", "radii", "shadows", "weights")}
    for page in raw.values():
        for k, d in page.items():
            if k in agg:
                for v, n in d.items():
                    agg[k][v] += n

    def colors(counter, limit):
        out = Counter()
        for v, n in counter.items():
            h = _hex(v)
            if h:
                out[h] += n
        return [{"value": h, "count": n} for h, n in out.most_common(limit)]

    # CSS custom properties the site defines itself are often its real tokens
    var_counter, font_faces = Counter(), Counter()
    for t in _css_texts(site_dir):
        for name, val in re.findall(r"(--[\w-]{2,60})\s*:\s*([^;}{]{1,120})", t):
            var_counter[(name, val.strip())] += 1
        for fam in re.findall(r"@font-face\s*{[^}]*?font-family\s*:\s*['\"]?([^;'\"}]+)", t, re.I):
            font_faces[fam.strip()] += 1
    color_re = re.compile(r"^(#[0-9a-fA-F]{3,8}|rgba?\([^)]*\)|hsla?\([^)]*\))$")
    variables = [{"name": n, "value": v} for (n, v), _ in var_counter.most_common(400) if color_re.match(v)][:40]

    def px_sort(items):
        def key(x):
            m = re.match(r"([\d.]+)px", x["value"])
            return float(m.group(1)) if m else 1e9
        return sorted(items, key=key)

    tokens = {
        "colors": {
            "text": colors(agg["text"], 10),
            "background": colors(agg["bg"], 12),
            "border": colors(agg["border"], 6),
        },
        "fonts": [{"value": f, "count": n} for f, n in agg["fonts"].most_common(6)],
        "font_faces": [f for f, _ in font_faces.most_common(12)],
        "font_sizes": px_sort([{"value": v, "count": n} for v, n in agg["sizes"].most_common(12)]),
        "font_weights": sorted({v for v, _ in agg["weights"].most_common(8)}, key=lambda w: int(w) if w.isdigit() else 0),
        "radii": px_sort([{"value": v, "count": n} for v, n in agg["radii"].most_common(8)]),
        "shadows": [{"value": v, "count": n} for v, n in agg["shadows"].most_common(6)],
        "css_variables": variables,
        "measured_pages": len(raw),
    }
    tokens["css"] = _tokens_css(tokens)
    tokens["tailwind"] = _tokens_tailwind(tokens)
    return tokens


def _uniq_colors(tokens):
    seen, out = set(), []
    for group in ("background", "text", "border"):
        for c in tokens["colors"][group]:
            if c["value"] not in seen:
                seen.add(c["value"])
                out.append((group, c["value"]))
    return out


def _tokens_css(t):
    lines = [":root {"]
    counters = Counter()
    for group, v in _uniq_colors(t):
        counters[group] += 1
        lines.append(f"  --color-{group}-{counters[group]}: {v};")
    for i, f in enumerate(t["fonts"], 1):
        lines.append(f"  --font-{i}: \"{f['value']}\", sans-serif;")
    for i, s in enumerate(t["font_sizes"], 1):
        lines.append(f"  --text-{i}: {s['value']};")
    for i, r in enumerate(t["radii"], 1):
        lines.append(f"  --radius-{i}: {r['value']};")
    for i, s in enumerate(t["shadows"], 1):
        lines.append(f"  --shadow-{i}: {s['value']};")
    lines.append("}")
    return "\n".join(lines)


def _tokens_tailwind(t):
    counters = Counter()
    colors = {}
    for group, v in _uniq_colors(t):
        counters[group] += 1
        colors[f"{group}-{counters[group]}"] = v
    cfg = {
        "theme": {"extend": {
            "colors": colors,
            "fontFamily": {f"brand{i}": [f["value"], "sans-serif"] for i, f in enumerate(t["fonts"], 1)},
            "fontSize": {f"t{i}": s["value"] for i, s in enumerate(t["font_sizes"], 1)},
            "borderRadius": {f"r{i}": r["value"] for i, r in enumerate(t["radii"], 1)},
            "boxShadow": {f"s{i}": s["value"] for i, s in enumerate(t["shadows"], 1)},
        }}
    }
    return "/** @type {import('tailwindcss').Config} */\nmodule.exports = " + json.dumps(cfg, indent=2, ensure_ascii=False) + ";"


# ---------------------------------------------------------------- sections

BLOCKS_JS = r"""() => { window.__scBlocks = () => {
  const vw = innerWidth;
  const visible = e => { const s = getComputedStyle(e); const r = e.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && r.height >= 40 && r.width > 0; };
  // walk down wrapper elements (a single big child) until the level where the page splits into blocks
  let root = document.body;
  for (let i = 0; i < 10; i++) {
    const kids = [...root.children].filter(visible);
    const h = root.getBoundingClientRect().height || 1;
    const big = kids.filter(e => e.getBoundingClientRect().height >= h * 0.8);
    if (kids.length === 1) { root = kids[0]; continue; }
    if (big.length === 1 && kids.length <= 4 && !['HEADER','NAV','FOOTER'].includes(big[0].tagName)) { root = big[0]; continue; }
    break;
  }
  // empty layers (fixed overlays, page-transition curtains) are not sections
  const solid = e => { const s = getComputedStyle(e);
    if (s.position === 'fixed' && !['HEADER', 'NAV'].includes(e.tagName)) return false;
    return e.innerText.trim().length > 0 || !!e.querySelector('img,svg,video,canvas,picture,iframe'); };
  // a block much taller than the screen that splits into several blocks is a wrapper: use its children
  const expand = (e, depth) => {
    const r = e.getBoundingClientRect();
    if (depth > 4 || ['HEADER', 'NAV', 'FOOTER'].includes(e.tagName) || r.height < innerHeight * 1.6) return [e];
    const kids = [...e.children].filter(k => visible(k) && solid(k) && k.getBoundingClientRect().height >= 60);
    if (kids.length === 1) { const inner = expand(kids[0], depth + 1); return inner.length > 1 ? inner : [e]; }
    return kids.length >= 2 ? kids.flatMap(k => expand(k, depth + 1)) : [e];
  };
  const blocks = [...root.children].filter(e => visible(e) && solid(e)).flatMap(e => expand(e, 0))
    .sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top);
  const out = [];
  for (const e of blocks) {
    const r = e.getBoundingClientRect();
    if (r.height < 60 || r.width < vw * 0.5) continue;
    const label = (e.querySelector('h1,h2,h3')?.innerText || e.getAttribute('aria-label') || '').trim().slice(0, 80);
    const tag = e.tagName.toLowerCase();
    const kind = tag === 'header' || tag === 'nav' ? 'en-tête' : tag === 'footer' ? 'pied de page' :
                 !out.some(o => o.kind === 'hero' || o.kind === 'section') && r.top + scrollY < innerHeight ? 'hero' : 'section';
    out.push({e, tag, kind, label});
    if (out.length >= 40) break;
  }
  return out;

}; return true; }"""

SECTIONS_JS = r"""() => window.__scBlocks().map(b => { const r = b.e.getBoundingClientRect();
  return {tag: b.tag, kind: b.kind, label: b.label, x: Math.max(0, r.left + scrollX), y: Math.max(0, r.top + scrollY),
          w: Math.min(r.width, innerWidth), h: r.height, html: b.e.outerHTML.length < 600000 ? b.e.outerHTML : ''}; })"""

HEAD_JS = r"""() => [...document.querySelectorAll('link[rel~=stylesheet], style, link[rel=preload][as=font]')]
  .map(e => e.outerHTML).join('\n')"""

SCROLL_JS = r"""async () => {
  const H = document.documentElement.scrollHeight;
  for (let y = 0; y < H; y += 700) { scrollTo(0, y); await new Promise(r => setTimeout(r, 120)); }
  scrollTo(0, 0); await new Promise(r => setTimeout(r, 600));
}"""


def _sections_job(site_id, key):
    site_dir = _cfg["dir"] / site_id
    pid = _pid(key)
    sdir = _studio_dir(site_dir) / "sections" / pid
    if sdir.exists():
        shutil.rmtree(sdir)
    sdir.mkdir(parents=True)
    _progress(site_id, 0, 1)
    with _Browser(site_dir) as b:
        b.open(key)
        try:
            b.page.evaluate(SCROLL_JS)
        except Exception:
            pass
        b.page.evaluate(BLOCKS_JS)
        found = b.page.evaluate(SECTIONS_JS) or []
        head = b.page.evaluate(HEAD_JS) or ""
        lang = b.page.evaluate("() => document.documentElement.lang || 'en'")
        origin = b.base
        _progress(site_id, 0, len(found))
        meta = []
        for i, s in enumerate(found):
            h = min(s["h"], 2400)
            try:
                b.page.screenshot(path=str(sdir / f"{i}.jpg"), type="jpeg", quality=72, full_page=True,
                                  clip={"x": s["x"], "y": s["y"], "width": max(1, s["w"]), "height": max(1, h)})
            except Exception:
                pass
            doc = ("<!doctype html>\n<html lang=\"" + lang + "\">\n<head>\n<meta charset=\"utf-8\">\n"
                   "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                   f"<title>{s['kind']} {i + 1}</title>\n" + head + "\n</head>\n<body>\n" + s["html"] + "\n</body>\n</html>\n")
            (sdir / f"{i}.html").write_text(doc.replace(origin, ""), encoding="utf-8")
            meta.append({"n": i, "kind": s["kind"], "label": s["label"], "tag": s["tag"],
                         "w": round(s["w"]), "h": round(s["h"]), "has_html": bool(s["html"])})
            _progress(site_id, i + 1)
    (sdir / "sections.json").write_text(json.dumps({"key": key, "sections": meta}, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------- export

REF_ATTR = re.compile(r"""(?:\s(?:src|href|poster|data-src)\s*=\s*)(["'])([^"']+)\1""", re.I)
SRCSET = re.compile(r"""\s(?:srcset|data-srcset)\s*=\s*(["'])([^"']+)\1""", re.I)
CSS_URL = re.compile(r"""url\(\s*(['"]?)([^'")]+)\1\s*\)""", re.I)


def _local_ref(r):
    return r and not r.startswith(("data:", "#", "mailto:", "tel:", "javascript:", "blob:", "//", "http://", "https://", "{"))


class _Bundle:
    """Collects the files a static document uses (stylesheets, fonts, images) from the clone and rewrites their
    references to relative paths, so the result opens from disk or from any server.
    files: zip path -> bytes. Links to other pages are left untouched."""

    def __init__(self, site_dir):
        self.site_dir = site_dir
        self.files = {}
        self._done = {}

    def _file_for(self, key):
        res = resolve(self.site_dir, key)
        if res and res[0] == "file" and res[1].suffix.lower() not in (".html", ".htm"):
            return res[1]
        return None

    def add(self, key, from_dir=""):
        """Store the file behind `key` (a root-relative URL); return its path relative to `from_dir`."""
        path_only = key.split("#")[0]
        if path_only in self._done:
            target = self._done[path_only]
        else:
            f = self._file_for(path_only)
            if not f:
                return None
            target = f.relative_to(self.site_dir).as_posix()
            self._done[path_only] = target
            if f.suffix.lower() == ".css":
                self.files[target] = self.css(f.read_text(encoding="utf-8", errors="ignore"),
                                              os.path.dirname(target), "/" + target).encode("utf-8")
            else:
                self.files[target] = f.read_bytes()
        return os.path.relpath(target, from_dir or ".").replace("\\", "/")

    def css(self, text, from_dir="", base="/"):
        def sub(m):
            u = m.group(2).strip()
            if not _local_ref(u) and not u.startswith("/"):
                return m.group(0)
            if u.startswith("//"):
                return m.group(0)
            sp = urllib.parse.urlsplit(urllib.parse.urljoin(base, u))
            rel = self.add(sp.path + (("?" + sp.query) if sp.query else ""), from_dir)
            return f'url("{rel}")' if rel else m.group(0)
        return CSS_URL.sub(sub, text)

    def html(self, text):
        def attr_sub(m):
            q, u = m.group(1), m.group(2)
            if not u.startswith("/") or u.startswith("//"):
                return m.group(0)
            rel = self.add(u, "")
            return m.group(0).replace(q + u + q, q + rel + q) if rel else m.group(0)

        def srcset_sub(m):
            q, v = m.group(1), m.group(2)
            parts = []
            for c in v.split(","):
                c = c.strip()
                u, _, d = c.partition(" ")
                rel = self.add(u, "") if u.startswith("/") and not u.startswith("//") else None
                parts.append((rel or u) + (" " + d if d else ""))
            return m.group(0).replace(q + v + q, q + ", ".join(parts) + q)

        text = REF_ATTR.sub(attr_sub, text)
        text = SRCSET.sub(srcset_sub, text)
        return self.css(text)


def _bundle_static(site_dir, html_text, out):
    b = _Bundle(site_dir)
    text = b.html(html_text)
    out.update(b.files)
    return text


def _readme(kind, items):
    return (f"Export SiteCloner Studio — {kind}\n\n" + "\n".join(f"- {i}" for i in items) + "\n\n"
            "Les pages complètes gardent le comportement du site (scripts, animations) : lancez `python serve.py` dans ce dossier,\n"
            "puis ouvrez http://localhost:8080 . Les sections sont des captures statiques du rendu (HTML + CSS + images) :\n"
            "ouvrez directement section.html ou copiez son code dans votre projet.\n\n"
            "Rappel : utilisez ces éléments comme base d'inspiration ou sur des sites dont vous avez les droits.\n")


SERVE_PY = '''"""Serve this export locally: python serve.py  ->  http://localhost:8080"""
import sys, threading, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from site_server import make_server
srv = make_server(Path(__file__).parent, 8080)
print("http://localhost:8080")
srv.serve_forever()
'''


@bp.route("/__sc/studio/<site_id>")
def studio_page(site_id):
    site_dir = _site(site_id)
    return render_template("studio.html", site_id=site_id, site_name=site_dir.name)


@bp.route("/__sc/api/studio/<site_id>/pages")
def api_pages(site_id):
    site_dir = _site(site_id)
    return jsonify({"pages": _pages(site_dir), "job": _job(site_id)})


@bp.route("/__sc/api/studio/<site_id>/job")
def api_job(site_id):
    _site(site_id)
    return jsonify(_job(site_id))


@bp.route("/__sc/api/studio/<site_id>/thumbs", methods=["POST"])
def api_thumbs(site_id):
    _site(site_id)
    force = bool((request.get_json(silent=True) or {}).get("force"))
    ok = _start(site_id, "thumbs", _thumbs_job, force)
    return jsonify({"started": ok, "job": _job(site_id)}), (202 if ok else 409)


@bp.route("/__sc/studio/<site_id>/thumb/<pid>.jpg")
def thumb(site_id, pid):
    site_dir = _site(site_id)
    if not re.fullmatch(r"[0-9a-f]{12}", pid):
        abort(404)
    f = site_dir / "_studio" / "thumbs" / f"{pid}.jpg"
    if not f.exists():
        abort(404)
    return send_file(str(f), mimetype="image/jpeg", max_age=0)


@bp.route("/__sc/studio/<site_id>/cover.jpg")
def cover(site_id):
    """Preview of the site for the dashboard cards: the home page thumbnail, else the shallowest page that has one."""
    site_dir = _site(site_id)
    tdir = site_dir / "_studio" / "thumbs"
    f = next((tdir / f"{p['id']}.jpg" for p in _pages(site_dir) if p["thumb"]), None) if tdir.is_dir() else None
    if not f:
        abort(404)
    return send_file(str(f), mimetype="image/jpeg", max_age=0)


@bp.route("/__sc/api/studio/<site_id>/design")
def api_design(site_id):
    return jsonify(_design(_site(site_id)))


@bp.route("/__sc/api/studio/<site_id>/sections", methods=["GET", "POST"])
def api_sections(site_id):
    site_dir = _site(site_id)
    key = (request.get_json(silent=True) or {}).get("key") if request.method == "POST" else request.args.get("key", "")
    if not key or key not in {p["key"] for p in _pages(site_dir)}:
        return jsonify({"error": "Page inconnue"}), 404
    if request.method == "POST":
        ok = _start(site_id, "sections", _sections_job, key)
        return jsonify({"started": ok, "job": _job(site_id)}), (202 if ok else 409)
    f = site_dir / "_studio" / "sections" / _pid(key) / "sections.json"
    if not f.exists():
        return jsonify({"sections": None, "pid": _pid(key)})
    data = json.loads(f.read_text(encoding="utf-8"))
    data["pid"] = _pid(key)
    return jsonify(data)


@bp.route("/__sc/studio/<site_id>/section/<pid>/<int:n>.jpg")
def section_img(site_id, pid, n):
    site_dir = _site(site_id)
    if not re.fullmatch(r"[0-9a-f]{12}", pid):
        abort(404)
    f = site_dir / "_studio" / "sections" / pid / f"{n}.jpg"
    if not f.exists():
        abort(404)
    return send_file(str(f), mimetype="image/jpeg", max_age=0)


@bp.route("/__sc/api/studio/<site_id>/section/<pid>/<int:n>/export")
def section_export(site_id, pid, n):
    site_dir = _site(site_id)
    if not re.fullmatch(r"[0-9a-f]{12}", pid):
        abort(404)
    f = site_dir / "_studio" / "sections" / pid / f"{n}.html"
    if not f.exists():
        abort(404)
    files = {}
    html_out = _bundle_static(site_dir, f.read_text(encoding="utf-8"), files)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("section.html", html_out)
        for path, data in files.items():
            z.writestr(path, data)
        z.writestr("LISEZMOI.txt", _readme("section", [f"section {n + 1} ({len(files)} fichiers)"]))
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{site_id}-section-{n + 1}.zip")


@bp.route("/__sc/api/studio/<site_id>/export", methods=["POST"])
def export_pages(site_id):
    """The chosen pages with every non-page file of the clone (scripts load chunks the HTML never names, so the
    asset set is kept whole), plus a small server so routing and recorded data keep working."""
    site_dir = _site(site_id)
    wanted = set((request.get_json(silent=True) or {}).get("pages") or [])
    pages = [p for p in _pages(site_dir) if p["key"] in wanted]
    if not pages:
        return jsonify({"error": "Aucune page sélectionnée"}), 400
    page_files = {p["file"] for p in _pages(site_dir)}
    keep = {p["file"] for p in pages}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in site_dir.rglob("*"):
            if not f.is_file():
                continue
            rel = f.relative_to(site_dir).as_posix()
            if rel.startswith("_studio/") or rel.endswith(".zip") or rel == "_clone-report.txt":
                continue
            if rel in page_files and rel not in keep:
                continue
            z.write(f, rel)
        z.write(Path(__file__).with_name("site_server.py"), "site_server.py")
        z.writestr("serve.py", SERVE_PY)
        z.writestr("LISEZMOI.txt", _readme("pages", [p["key"] for p in pages]))
    buf.seek(0)
    name = f"{site_id}-{len(pages)}-page{'s' if len(pages) > 1 else ''}.zip"
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=name)


def _clean_readme(name, title, files_count):
    return (f"Export « code propre » SiteCloner Studio — {title}\n\n"
            "Contenu :\n"
            "- index.html + styles.css : la page ou la section en HTML lisible, avec uniquement les règles CSS qui\n"
            "  s'y appliquent (polices, animations et variables comprises). Ouvrez index.html directement.\n"
            f"- react/{name}.jsx + react/styles.css : le même contenu en composant React.\n"
            "  Copiez les deux fichiers dans src/ et les dossiers d'images/polices de cette archive dans public/.\n"
            "- tailwind.config.js : les tokens du design system du site (couleurs, polices, tailles, arrondis, ombres).\n"
            f"- {files_count} fichiers d'images et de polices, avec des chemins relatifs.\n\n"
            "Le HTML est un instantané du rendu : les scripts du site ne sont pas repris. Les animations pilotées par\n"
            "JavaScript et le contenu chargé à la demande sont à recréer dans votre projet.\n\n"
            "Rappel : utilisez ces éléments comme base d'inspiration ou sur des sites dont vous avez les droits.\n")


@bp.route("/__sc/api/studio/<site_id>/clean", methods=["POST"])
def clean_code(site_id):
    from clean_export import CLEAN_JS, component_name, pretty_html, react_component
    site_dir = _site(site_id)
    data = request.get_json(silent=True) or {}
    key, n = data.get("key"), data.get("section")
    if key not in {p["key"] for p in _pages(site_dir)}:
        return jsonify({"error": "Page inconnue"}), 404
    if n is not None and not isinstance(n, int):
        return jsonify({"error": "Section invalide"}), 400
    with _Browser(site_dir) as b:
        b.open(key)
        try:
            b.page.evaluate(SCROLL_JS)
        except Exception:
            pass
        b.page.evaluate(BLOCKS_JS)
        r = b.page.evaluate(CLEAN_JS, n)
        origin = b.base
    if not r:
        return jsonify({"error": "Section introuvable"}), 404
    bundle = _Bundle(site_dir)
    markup = bundle.html(r["html"].replace(origin, ""))
    css = bundle.css(r["css"].replace(origin, ""), "", "/")
    title = r["title"] or key
    label = (data.get("label") or "").strip()
    name = component_name(label or ("Section " + str(n + 1) if n is not None else title), "Section" if n is not None else "Page")
    body_class = f' class="{r["bodyClass"]}"' if r.get("bodyClass") else ""
    doc = ("<!doctype html>\n"
           f"<html lang=\"{r['lang']}\">\n<head>\n  <meta charset=\"utf-8\">\n"
           "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
           f"  <title>{title}</title>\n  <link rel=\"stylesheet\" href=\"styles.css\">\n</head>\n"
           f"<body{body_class}>\n{pretty_html(markup, 1)}\n</body>\n</html>\n")
    css_react = re.sub(r'url\("(?![a-z][\w+.-]*:|/|#)([^"]+)"\)', r'url("/\1")', css)
    tokens = _design(site_dir)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.html", doc)
        z.writestr("styles.css", css)
        z.writestr(f"react/{name}.jsx", react_component(name, markup))
        z.writestr("react/styles.css", css_react)
        z.writestr("tailwind.config.js", tokens["tailwind"])
        for path, blob in bundle.files.items():
            if path.endswith(".css"):
                continue  # their rules are already in styles.css
            z.writestr(path, blob)
        z.writestr("LISEZMOI.txt", _clean_readme(name, title, len([p for p in bundle.files if not p.endswith(".css")])))
    buf.seek(0)
    suffix = f"section-{n + 1}" if n is not None else "page"
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{site_id}-{suffix}-code.zip")


# ---------------------------------------------------------------- inspector (component tree + live edits)

OVERRIDE_TAG = '<script src="/_edited/overrides.js" data-sc-overrides></script>'
OP_ACTS = {"text", "img", "video", "link", "src", "hide", "dup", "embed"}
UPLOAD_EXT = {"img": {".png", ".jpg", ".jpeg", ".webp", ".avif", ".gif", ".svg"},
              "video": {".mp4", ".webm", ".mov"},
              "model": {".glb", ".gltf", ".usdz", ".fbx", ".obj"}}
MAX_INSPECT_UPLOAD = 120 * 1024 * 1024


def _norm_page(p):
    p = re.sub(r"/index\.html?$", "/", p or "/", flags=re.I)
    return (p.rstrip("/") or "/") if p != "/" else "/"


def _ovr_file(site_dir):
    return site_dir / "_edited" / "overrides.json"


def _load_ovr(site_dir):
    try:
        data = json.loads(_ovr_file(site_dir).read_text(encoding="utf-8"))
        return data if isinstance(data.get("pages"), dict) else {"pages": {}}
    except Exception:
        return {"pages": {}}


def _publish_ovr(site_dir, data):
    """overrides.js = the edits + the runtime; every page of the clone loads it once."""
    ed = site_dir / "_edited"
    ed.mkdir(exist_ok=True)
    runtime = Path(__file__).with_name("sc_overrides.js").read_text(encoding="utf-8")
    (ed / "overrides.js").write_text("window.__SC_OVERRIDES = " + json.dumps(data, ensure_ascii=False) + ";\n" + runtime,
                                     encoding="utf-8")
    for p in _pages(site_dir):
        f = site_dir / p["file"]
        try:
            t = f.read_text(encoding="utf-8")
        except OSError:
            continue
        if "data-sc-overrides" in t:
            continue
        i = t.lower().rfind("</body>")
        f.write_text((t[:i] + OVERRIDE_TAG + t[i:]) if i >= 0 else (t + OVERRIDE_TAG), encoding="utf-8")


def _save_ovr(site_dir, data):
    ed = site_dir / "_edited"
    (ed / "history").mkdir(parents=True, exist_ok=True)
    cur = _ovr_file(site_dir)
    if cur.exists():
        shutil.copy2(cur, ed / "history" / f"{int(time.time() * 1000)}.json")
    cur.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    _publish_ovr(site_dir, data)


def _clean_ops(ops):
    out = []
    for op in ops if isinstance(ops, list) else []:
        if not isinstance(op, dict) or op.get("act") not in OP_ACTS or not isinstance(op.get("sel"), str):
            continue
        clean = {"act": op["act"], "sel": op["sel"][:600]}
        for k in ("value", "src", "href", "text", "html", "label"):
            if isinstance(op.get(k), str):
                clean[k] = op[k][:20000]
        out.append(clean)
    return out[:2000]


@bp.route("/__sc/studio/<site_id>/inspect")
def inspect_page(site_id):
    site_dir = _site(site_id)
    pages = _pages(site_dir)
    key = request.args.get("key") or (pages[0]["key"] if pages else "/")
    return render_template("inspect.html", site_id=site_id, site_name=site_dir.name, key=key,
                           pages=[{"key": p["key"], "title": p["title"]} for p in pages])


@bp.route("/__sc/api/studio/<site_id>/inspect/ops")
def inspect_ops(site_id):
    site_dir = _site(site_id)
    data = _load_ovr(site_dir)
    hist = site_dir / "_edited" / "history"
    return jsonify({"ops": data["pages"].get(_norm_page(request.args.get("key", "/")), []),
                    "history": len(list(hist.glob("*.json"))) if hist.exists() else 0})


@bp.route("/__sc/api/studio/<site_id>/inspect/save", methods=["POST"])
def inspect_save(site_id):
    site_dir = _site(site_id)
    body = request.get_json(silent=True) or {}
    page = _norm_page(body.get("key", "/"))
    data = _load_ovr(site_dir)
    ops = _clean_ops(body.get("ops"))
    if ops:
        data["pages"][page] = ops
    else:
        data["pages"].pop(page, None)
    _save_ovr(site_dir, data)
    return jsonify({"ok": True, "count": len(ops)})


@bp.route("/__sc/api/studio/<site_id>/inspect/undo", methods=["POST"])
def inspect_undo(site_id):
    site_dir = _site(site_id)
    hist = sorted((site_dir / "_edited" / "history").glob("*.json")) if (site_dir / "_edited" / "history").exists() else []
    if not hist:
        return jsonify({"error": "Aucune sauvegarde précédente"}), 409
    last = hist[-1]
    data = json.loads(last.read_text(encoding="utf-8"))
    _ovr_file(site_dir).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    last.unlink()
    _publish_ovr(site_dir, data)
    return jsonify({"ok": True})


@bp.route("/__sc/api/studio/<site_id>/inspect/upload", methods=["POST"])
def inspect_upload(site_id):
    site_dir = _site(site_id)
    kind = request.form.get("kind", "")
    f = request.files.get("file")
    if kind not in UPLOAD_EXT or not f or not f.filename:
        return jsonify({"error": "Fichier manquant"}), 400
    name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(f.filename))[-80:]
    ext = os.path.splitext(name)[1].lower()
    if ext not in UPLOAD_EXT[kind]:
        return jsonify({"error": f"Format non pris en charge ({ext or 'inconnu'})"}), 400
    data = f.read(MAX_INSPECT_UPLOAD + 1)
    if not data or len(data) > MAX_INSPECT_UPLOAD:
        return jsonify({"error": "Fichier vide ou trop lourd (120 Mo maximum)"}), 400
    if kind != "model":
        out = site_dir / "_edited"
        out.mkdir(exist_ok=True)
        fname = hashlib.md5(data).hexdigest()[:8] + "_" + name
        (out / fname).write_bytes(data)
        return jsonify({"src": "/_edited/" + fname})
    # a 3D model replaces the file the page already loads: the site's code keeps working with it
    if ext == ".glb" and data[:4] != b"glTF":
        return jsonify({"error": "Ce fichier n'est pas un modèle .glb valide"}), 400
    target = urllib.parse.urlsplit(request.form.get("target", ""))
    key = target.path + (("?" + target.query) if target.query else "")
    res = resolve(site_dir, key)
    if not res or res[0] != "file":
        return jsonify({"error": "Modèle d'origine introuvable dans le clone"}), 404
    dest = res[1]
    rel = dest.relative_to(site_dir).as_posix()
    backup = site_dir / "_edited" / "_backup_assets" / (rel + ".orig")
    if not backup.exists():
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dest, backup)
    dest.write_bytes(data)
    return jsonify({"ok": True, "replaced": rel})


@bp.route("/__sc/api/studio/<site_id>/inspect/model-restore", methods=["POST"])
def inspect_model_restore(site_id):
    site_dir = _site(site_id)
    target = urllib.parse.urlsplit((request.get_json(silent=True) or {}).get("target", ""))
    res = resolve(site_dir, target.path + (("?" + target.query) if target.query else ""))
    if not res or res[0] != "file":
        return jsonify({"error": "Modèle introuvable"}), 404
    rel = res[1].relative_to(site_dir).as_posix()
    backup = site_dir / "_edited" / "_backup_assets" / (rel + ".orig")
    if not backup.exists():
        return jsonify({"error": "Ce modèle n'a pas été remplacé"}), 409
    shutil.copy2(backup, res[1])
    backup.unlink()
    return jsonify({"ok": True})
