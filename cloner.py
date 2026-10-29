#!/usr/bin/env python3
"""
cloner.py - Browser-based core engine for SiteCloner SaaS.

Loads every page in headless Chromium (so JavaScript-rendered sites, WebGL / 3D, lazy loading and
client-side routing are captured), records every network response, crawls all internal pages,
then rewrites the result so the clone is fully self-contained:

  * same-origin files keep their path, third-party files go to /_ext/<host>/...
  * every absolute URL to the original site / CDNs inside HTML, CSS, JS and JSON is rewritten
  * a tiny runtime shim re-routes URLs built at runtime (fetch, XHR, <img>, <script>, workers...)
  * trackers / analytics are removed
  * a _map.json lets site_server.py replay query-string variants, redirects and odd content types

The clone no longer talks to the original website.
"""

import hashlib
import json
import mimetypes
import os
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from curl_cffi import requests

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/128.0.0.0 Safari/537.36")

BLOCKED = re.compile(
    r"googletagmanager|google-analytics|googleadservices|doubleclick|googlesyndication|"
    r"connect\.facebook|facebook\.net|facebook\.com/tr|hotjar|clarity\.ms|segment\.(?:io|com)|"
    r"mixpanel|sentry\.io|sentry-cdn|plausible\.io|/_vercel/(?:insights|speed-insights)|fullstory|"
    r"intercom|hs-scripts|hs-analytics|events\.framer\.com|tiktok\.com/i18n|snap\.licdn|"
    r"analytics\.|/gtag/|/gtm\.js|cloudflareinsights|static\.cloudflareinsights|matomo|posthog|amplitude\.com",
    re.I)

PAGE_SKIP_EXT = {
    ".pdf", ".zip", ".rar", ".gz", ".exe", ".dmg", ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".png", ".jpg",
    ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".css", ".js", ".mjs", ".json", ".xml", ".txt",
    ".woff", ".woff2", ".ttf", ".otf", ".glb", ".gltf", ".drc", ".ktx2", ".wasm", ".bin", ".hdr", ".exr",
}

TEXT_EXT = {".html", ".htm", ".css", ".js", ".mjs", ".json", ".svg", ".xml", ".txt", ".webmanifest", ".map"}
TEXT_TYPES = ("text/", "application/javascript", "application/x-javascript", "application/json",
              "application/xml", "image/svg+xml", "application/manifest+json", "application/ld+json")

DEEP_SCAN_RE = re.compile(
    r"""["'`]([^"'`\s\\<>(){}]{1,300}?\.(?:glb|gltf|drc|ktx2|exr|hdr|wasm|riv|basis|bin|mp3|mp4|webm|ogg|wav|"""
    r"""woff2?|ttf|otf|png|jpe?g|webp|avif|gif|svg|json|css|mjs|js|ico))(?:\?[^"'`\s\\<>]*)?["'`]""",
    re.I)

SCROLL_JS = """async () => {
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  let y = 0;
  while (y < document.documentElement.scrollHeight && y < 40000) {
    window.scrollTo(0, y); y += 500; await sleep(110);
  }
  window.scrollTo(0, document.documentElement.scrollHeight); await sleep(300);
  window.scrollTo(0, 0);
}"""

# Hard guarantee of separation: no script may load from, and no request may be sent to, another host.
CSP = ("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; "
       "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' data: blob:; "
       "connect-src 'self' data: blob:\">")

SHIM = """<script>(function(){var M=%(ext)s,O=%(orig)s;
var B=/googletagmanager|google-analytics|googleadservices|doubleclick|facebook\\.net|hotjar|clarity\\.ms|sentry\\.io|mixpanel/i;
function fix(u){if(u instanceof URL)u=u.href;if(typeof u!=='string')return u;if(B.test(u)&&/^(?:https?:)?\\/\\//i.test(u))return 'data:text/javascript,';u=u.replace(/^https?:\\/*(?=_ext\\/)/i,location.origin+'/');var m=u.match(/^(?:https?:)?\\/\\/([^\\/:?#]+)(?::\\d+)?([\\/?#][\\s\\S]*)?$/i);
if(!m)return u;var h=m[1].toLowerCase();if(h===location.hostname)return u;var r=m[2]||'/';if(r.charAt(0)!=='/')r='/'+r;
if(O[h])return location.origin+r;if(M[h])return location.origin+M[h]+r;return u;}
try{var f=window.fetch;if(f)window.fetch=function(a,b){if(typeof a==='string'||a instanceof URL)a=fix(a);else if(a&&a.url){var n=fix(a.url);if(n!==a.url)a=new Request(n,a);}return f.call(this,a,b);};}catch(e){}
try{var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=fix(String(u));return xo.apply(this,arguments);};}catch(e){}
try{var sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){var k=typeof n==='string'?n.toLowerCase():n;if((k==='srcset'||k==='imagesrcset')&&typeof v==='string')v=fixSet(v);else if((k==='src'||k==='href'||k==='poster'||k==='data')&&typeof v==='string'&&this.tagName!=='A'&&this.tagName!=='AREA')v=fix(v);return sa.call(this,n,v);};}catch(e){}
try{var sn=Element.prototype.setAttributeNS;Element.prototype.setAttributeNS=function(ns,n,v){var k=typeof n==='string'?n.toLowerCase():n;if((k==='srcset'||k==='imagesrcset')&&typeof v==='string')v=fixSet(v);else if((k==='src'||k==='poster')&&typeof v==='string'&&this.tagName!=='A'&&this.tagName!=='AREA')v=fix(v);return sn.call(this,ns,n,v);};}catch(e){}
function P(C,p){try{var d=Object.getOwnPropertyDescriptor(C.prototype,p);if(d&&d.set)Object.defineProperty(C.prototype,p,{get:d.get,set:function(v){d.set.call(this,fix(v));},configurable:true,enumerable:d.enumerable});}catch(e){}}
function fixSet(v){return String(v).split(',').map(function(c){c=c.trim();var i=c.indexOf(' ');return i<0?fix(c):fix(c.slice(0,i))+c.slice(i);}).join(', ');}
try{['HTMLImageElement','HTMLSourceElement'].forEach(function(n){var C=window[n],d=Object.getOwnPropertyDescriptor(C.prototype,'srcset');if(d&&d.set)Object.defineProperty(C.prototype,'srcset',{get:d.get,set:function(v){d.set.call(this,fixSet(v));},configurable:true});});}catch(e){}
P(HTMLImageElement,'src');P(HTMLScriptElement,'src');P(HTMLLinkElement,'href');P(HTMLMediaElement,'src');
P(HTMLSourceElement,'src');P(HTMLIFrameElement,'src');P(HTMLVideoElement,'poster');
try{var W=window.Worker;if(W)window.Worker=function(u,o){return new W(fix(String(u)),o);};window.Worker.prototype=W.prototype;}catch(e){}
function abs(d,n){if(typeof d==='string')return d.indexOf('/_ext/')===0?location.origin+d:d;if(n>4||!d||typeof d!=='object')return d;
if(Array.isArray(d))return d.map(function(x){return abs(x,n+1);});if(Object.getPrototypeOf(d)!==Object.prototype)return d;var o={};for(var k in d)o[k]=abs(d[k],n+1);return o;}
try{var wp=Worker.prototype.postMessage;Worker.prototype.postMessage=function(d){arguments[0]=abs(d,0);return wp.apply(this,arguments);};}catch(e){}
try{navigator.sendBeacon=function(){return true;};}catch(e){}
})();</script>"""


ENTER_JS = r"""() => {
  const re = /^(enter|enter site|enter experience|start|start experience|explore|discover|begin|continue|skip|skip intro|play|go|let'?s go|sound on|sound off|with sound|without sound|enable sound|turn on sound|mute|unmute|accept|ok|got it|entrer|commencer|d[ée]couvrir|explorer|continuer|passer|avec son|sans son)$/i;
  const els = [...document.querySelectorAll('button, a, [role=button], div, span')].filter(e => {
    const t = (e.innerText || e.getAttribute('aria-label') || '').trim();
    if (!t || t.length > 30 || !re.test(t)) return false;
    const href = e.tagName === 'A' && e.getAttribute('href');
    if (href && !/^(#|javascript:)/i.test(href)) return false;  // never leave the page
    const r = e.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden';
  });
  els.slice(0, 2).forEach(e => { try { e.click(); } catch (_) {} });
  return els.length;
}"""

HOVER_JS = """() => {
  const els = [...document.querySelectorAll('a, button, [data-hover], [class*=hover], [class*=card], [class*=project], li')]
    .filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.top < innerHeight && r.bottom > 0; });
  return els.slice(0, 40).map(e => { const r = e.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; });
}"""


def interact(page, long=False, calm=0.8):
    """Behave like a visitor of an Awwwards-style site so every asset gets requested.
    Timeouts are short for cloud deployments – sufficient for 95%+ of sites."""
    last = [time.time()]
    bump = lambda *_: last.__setitem__(0, time.time())
    page.on("request", bump)

    def idle(ms, calm=calm):
        """Wait until no request has started for `calm` seconds (or `ms` elapsed)."""
        end = time.time() + ms / 1000
        while time.time() < end and time.time() - last[0] < calm:
            page.wait_for_timeout(150)
    try:
        # Was 20000/8000 ms → now 5000/2500 ms
        idle(5000 if long else 2500)
        for _ in range(2):  # preloader then intro screen
            if page.evaluate(ENTER_JS):
                page.wait_for_timeout(1000)
                idle(3000 if long else 1500)
        for x, y in [(200, 200), (1200, 250), (720, 450)]:
            page.mouse.move(x, y, steps=4)
        page.mouse.move(720, 450)
        # Was 90/25 steps → now 20/8 steps
        steps = 20 if long else 8
        prev = -1
        stuck = 0
        for i in range(steps):
            page.mouse.wheel(0, 600)
            page.wait_for_timeout(80)
            if i % 5 == 4:
                for x, y in (page.evaluate(HOVER_JS) or [])[:4]:
                    page.mouse.move(x, y, steps=2)
                    page.wait_for_timeout(30)
                page.mouse.move(720, 450)
            pos = page.evaluate("() => Math.round(window.scrollY + document.documentElement.scrollTop)")
            stuck = stuck + 1 if pos == prev else 0
            prev = pos
            if stuck > 6 and i > 10:
                break
        page.evaluate(SCROLL_JS)
        for _ in range(5):
            page.mouse.wheel(0, -1500)
            page.wait_for_timeout(30)
        page.evaluate("() => document.querySelectorAll('video,audio').forEach(m => { m.preload='auto'; try{m.load(); m.play().catch(()=>{});}catch(e){} })")
        # Was 2500/1200 ms → now 600/300 ms
        page.wait_for_timeout(600 if long else 300)
        idle(3000 if long else 1200)
    except Exception:
        pass
    try:
        page.remove_listener("request", bump)
    except Exception:
        pass


def free_memory_mb():
    """Available RAM in MB (None if unknown): each Chrome needs ~600-800 MB, too many at once makes everything crawl."""
    try:
        if os.name == "nt":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong), ("tp", ctypes.c_ulonglong),
                            ("ap", ctypes.c_ulonglong), ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong),
                            ("tx", ctypes.c_ulonglong), ("ax", ctypes.c_ulonglong), ("ae", ctypes.c_ulonglong)]
            m = MS()
            m.l = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return m.ap // (1024 * 1024)
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return None


def default_workers():
    env = os.environ.get("CLONER_WORKERS")
    if env:
        return max(1, int(env))
    if os.environ.get("RENDER"):
        return 1
    mem = free_memory_mb()
    return 2 if mem is None else max(1, min(3, mem // 900))


def launch(pw, extra):
    """Installed Google Chrome renders WebGL on the machine's GPU (far faster than CPU rendering), with its own
    throw-away profile. Without it (servers) the bundled Chromium is used and falls back to SwiftShader."""
    args = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu-sandbox",
        "--ignore-gpu-blocklist",
        "--enable-gpu-rasterization",
        "--enable-unsafe-swiftshader"
    ] + extra

    errors = []
    for channel in ("chrome", "chromium", None):
        try:
            if channel:
                return pw.chromium.launch(channel=channel, headless=True, args=args)
            else:
                return pw.chromium.launch(headless=True, args=args)
        except Exception as e:
            errors.append(f"{channel or 'bundled'}: {e}")
            continue

    # On cloud servers / containers: try on-the-fly playwright chromium install if missing
    try:
        import subprocess, sys
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=False, timeout=180)
        return pw.chromium.launch(headless=True, args=args)
    except Exception as e:
        errors.append(f"auto_install: {e}")

    err_msg = "; ".join(errors)
    raise RuntimeError(f"Aucun navigateur Chromium disponible: {err_msg}")


def norm_host(h):
    h = (h or "").lower()
    return h[4:] if h.startswith("www.") else h


def safe_segment(seg):
    seg = re.sub(r'[<>:"|?*\\\x00-\x1f]', "_", seg).rstrip(" .")
    if len(seg) > 90:
        base, ext = os.path.splitext(seg)
        seg = base[:60] + "_" + hashlib.md5(seg.encode()).hexdigest()[:8] + ext[:10]
    return seg or "_"


class Cloner:
    def __init__(self, url, dest_dir, max_pages=60, progress_callback=None):
        self.start_url = urllib.parse.urldefrag(url)[0]
        self.dest = Path(dest_dir)
        self.max_pages = max_pages
        self.cb = progress_callback or (lambda *a: None)
        self.origin = norm_host(urllib.parse.urlparse(self.start_url).netloc)
        self.map = {}            # key -> {"f","t"} | {"r"}
        self.captured = {}       # absolute url -> relative file
        self.hosts = set()       # exact third-party hosts seen
        self.pages = {}          # page url -> relative file
        self.title = self.origin
        self.errors = []
        self.partial = set()
        self.fresh = set()
        self._lock = threading.Lock()
        self.total_bytes = 0
        self.session = requests.Session(impersonate="chrome124")
        self.session.headers.update({"Referer": self.start_url})

    # ---------- path / key helpers ----------
    def is_origin(self, netloc):
        return norm_host(netloc.split(":")[0]) == self.origin

    def key_of(self, url):
        p = urllib.parse.urlparse(url)
        path = urllib.parse.unquote(p.path) or "/"
        q = ("?" + urllib.parse.unquote(p.query)) if p.query else ""
        if self.is_origin(p.netloc):
            return path + q
        return f"/_ext/{safe_segment(p.netloc.lower())}{path}{q}"

    def rel_path(self, url, ctype):
        p = urllib.parse.urlparse(url)
        path = urllib.parse.unquote(p.path)
        is_html = "html" in ctype
        if is_html:
            if not path.lower().endswith((".html", ".htm")):
                path = path.rstrip("/") + "/index.html"
        elif path.endswith("/") or not path:
            path += "index"
        segs = [safe_segment(s) for s in path.split("/") if s not in ("", ".", "..")]
        if not segs:
            segs = ["index.html"]
        if p.query:
            base, ext = os.path.splitext(segs[-1])
            segs[-1] = f"{base}__{hashlib.md5(p.query.encode()).hexdigest()[:8]}{ext}"
        rel = "/".join(segs)
        if not self.is_origin(p.netloc):
            rel = "_ext/" + safe_segment(p.netloc.lower()) + "/" + rel
        return rel

    def save(self, url, ctype, body):
        url = urllib.parse.urldefrag(url)[0]
        ctype = (ctype or "").split(";")[0].strip().lower()
        if not ctype:
            ctype = mimetypes.guess_type(urllib.parse.urlparse(url).path)[0] or "application/octet-stream"
        rel = self.rel_path(url, ctype)
        target = self.dest / rel
        try:
            with self._lock:  # several browsers capture in parallel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
        except OSError:
            rel = "_misc/" + hashlib.md5(url.encode()).hexdigest() + os.path.splitext(rel)[1][:8]
            target = self.dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        if url not in self.captured:
            self.total_bytes += len(body)
        self.captured[url] = rel
        self.fresh.add(rel)
        key = self.key_of(url)
        self.map[key] = {"f": rel, "t": ctype}
        host = urllib.parse.urlparse(url).netloc.lower()
        if not self.is_origin(host):
            self.hosts.add(host)
        return rel

    # ---------- network capture ----------
    def on_response(self, resp):
        try:
            req = resp.request
            if req.method == "POST":
                self.on_post(req, resp)
                return
            if req.method != "GET":
                return
            url = resp.url
            if not url.startswith(("http://", "https://")) or BLOCKED.search(url):
                return
            status = resp.status
            if 300 <= status < 400:
                loc = resp.headers.get("location")
                if loc:
                    target = urllib.parse.urljoin(url, loc)
                    tp = urllib.parse.urlparse(target)
                    dest_key = self.key_of(target)
                    if self.key_of(url) != dest_key:
                        self.map[self.key_of(url)] = {"r": dest_key}
                return
            if status == 404 and req.resource_type == "document" and self.is_origin(urllib.parse.urlparse(url).netloc):
                # the site's own "not found" page (client routers link to it): keep it, it is part of the site
                if "html" in resp.headers.get("content-type", ""):
                    self.save(url, "text/html", resp.body())
                return
            if status not in (200, 206):
                return
            if status == 206:
                self.partial.add(url)
                return
            ctype = resp.headers.get("content-type", "")
            if "html" in ctype and not self.is_origin(urllib.parse.urlparse(url).netloc):
                return  # third-party pages (editor links, embeds) are not part of the clone
            body = resp.body()
            self.save(url, ctype, body)
            if req.resource_type == "document" and "html" in ctype:
                self.pages[urllib.parse.urldefrag(url)[0]] = self.captured[urllib.parse.urldefrag(url)[0]]
        except Exception:
            pass

    def on_post(self, req, resp):
        """Data requests the page needs to render (GraphQL, JSON APIs): keep the answer so the clone can replay it."""
        url = resp.url
        if resp.status != 200 or BLOCKED.search(url) or not url.startswith(("http://", "https://")):
            return
        ctype = resp.headers.get("content-type", "")
        if "json" not in ctype and "graphql" not in ctype:
            return
        body = resp.body()
        sent = req.post_data_buffer or b""
        h = hashlib.md5(sent).hexdigest()
        key = self.key_of(url)
        rel = f"_post/{hashlib.md5((key + h).encode()).hexdigest()[:20]}.json"
        with self._lock:
            (self.dest / "_post").mkdir(parents=True, exist_ok=True)
            (self.dest / rel).write_bytes(body)
        entry = {"f": rel, "t": ctype.split(";")[0].strip()}
        self.map[f"POST {key}#{h}"] = entry
        self.map.setdefault(f"POST {key}", entry)
        host = urllib.parse.urlparse(url).netloc.lower()
        if not self.is_origin(host):
            self.hosts.add(host)

    # ---------- crawling ----------
    def norm_page(self, url):
        url = urllib.parse.urldefrag(url)[0]
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https") or not self.is_origin(p.netloc):
            return None
        ext = os.path.splitext(p.path)[1].lower()
        if ext in PAGE_SKIP_EXT:
            return None
        q = [kv for kv in urllib.parse.parse_qsl(p.query) if not kv[0].lower().startswith(("utm_", "fbclid", "gclid"))]
        path = p.path or "/"
        return urllib.parse.urlunparse((p.scheme, p.netloc, path, "", urllib.parse.urlencode(q), ""))

    def sitemap_urls(self):
        out = []
        base = urllib.parse.urlparse(self.start_url)
        root = f"{base.scheme}://{base.netloc}"
        try:
            r = self.session.get(root + "/sitemap.xml", timeout=15)
            if r.status_code == 200 and "<loc>" in r.text:
                locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text)
                for loc in locs:
                    if loc.endswith(".xml") and len(out) < 5:
                        try:
                            r2 = self.session.get(loc, timeout=15)
                            out += re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r2.text)
                        except Exception:
                            pass
                    else:
                        out.append(loc)
        except Exception:
            pass
        return out

    def _open(self, pw):
        browser = launch(pw, [
            "--enable-webgl", "--autoplay-policy=no-user-gesture-required", "--mute-audio",
            "--disable-features=PreloadMediaEngagementData,MediaEngagementBypassAutoplayPolicies"])
        context = browser.new_context(user_agent=UA, viewport={"width": 1440, "height": 900},
                                      service_workers="block", ignore_https_errors=True)
        context.route("**/*", lambda r: r.abort() if BLOCKED.search(r.request.url) else r.continue_())
        context.on("response", self.on_response)
        return browser, context

    def _visit(self, context, url, long=False):
        """Open one page like a visitor; returns (final url, title, links)."""
        page = context.new_page()
        final, title, hrefs = url, None, []
        try:
            try:
                page.goto(url, wait_until="load", timeout=60000)
            except Exception:
                pass
            interact(page, long=long)
            final = page.url
            title = page.title()
            hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        except Exception as e:
            self.errors.append(f"{url}: {e}")
        finally:
            try:
                page.close()
            except Exception:
                pass
        return final, title, hrefs

    def crawl(self, pw, workers=None):
        import threading
        from playwright.sync_api import sync_playwright

        if workers is None:  # one browser on small cloud instances, a few in parallel when RAM allows
            workers = default_workers()

        # 1. home page alone: resolves redirects (www, other host), title, sitemap
        browser, context = self._open(pw)
        start = self.norm_page(self.start_url)
        self.cb(1, self.max_pages, "Page 1 : /")
        final, title, hrefs = self._visit(context, start, long=True)
        if self.norm_page(final) is None and final.startswith("http"):
            self.origin = norm_host(urllib.parse.urlparse(final).netloc)
        if title:
            self.title = title.strip() or self.origin
        seen = {start, self.norm_page(final)}
        queue = []
        lock = threading.Lock()
        state = {"count": 1, "active": 0}

        def enqueue(urls):
            with lock:
                for h in urls:
                    n = self.norm_page(h)
                    if n and n not in seen and len(seen) < self.max_pages * 3:
                        seen.add(n)
                        queue.append(n)
        enqueue(hrefs)
        enqueue(self.sitemap_urls())

        # 2. the other pages, several browsers in parallel
        def worker():
            with sync_playwright() as pw2:
                b, ctx = self._open(pw2)
                try:
                    while True:
                        with lock:
                            if queue and state["count"] < self.max_pages:
                                url = queue.pop(0)
                                state["count"] += 1
                                state["active"] += 1
                                n = state["count"]
                            elif state["active"] == 0 or state["count"] >= self.max_pages:
                                break
                            else:
                                url = None
                        if url is None:
                            time.sleep(0.5)
                            continue
                        self.cb(n, self.max_pages, f"Page {n} : {urllib.parse.urlparse(url).path or '/'}")
                        _, _, links = self._visit(ctx, url)
                        enqueue(links)
                        with lock:
                            state["active"] -= 1
                finally:
                    ctx.close()
                    b.close()
        # no extra browser when there is nothing left to crawl (single page / page limit reached)
        n_workers = min(workers, self.max_pages - 1) if queue else 0
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(n_workers)]
        for t in threads:
            t.start()
        # closing Chrome takes ~2 s: do it while the workers already crawl
        context.close()
        browser.close()
        for t in threads:
            t.join()

    # ---------- completing the capture ----------
    def refetch_partial(self):
        def get(u):
            try:
                r = self.session.get(u, timeout=60)
                if r.status_code == 200:
                    self.save(u, r.headers.get("content-type", ""), r.content)
            except Exception:
                self.errors.append(u)
        with ThreadPoolExecutor(8) as ex:
            list(ex.map(get, [u for u in self.partial if u not in self.captured]))

    def deep_scan(self):
        """Find asset URLs hidden in JS/CSS/JSON strings (3D models, textures, wasm...) that were never requested."""
        origin_root = f"{urllib.parse.urlparse(self.start_url).scheme}://{urllib.parse.urlparse(self.start_url).netloc}/"
        # code first: every module that is fetched can reveal more modules/assets, so keep going until nothing new
        # shows up (a fixed 2 passes x 500 candidates silently dropped lazily imported page chunks on big sites)
        for _ in range(8):
            cands = {}
            for url, rel in list(self.captured.items()):
                if os.path.splitext(rel)[1].lower() not in (".js", ".mjs", ".css", ".json", ".html"):
                    continue
                try:
                    text = (self.dest / rel).read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for m in DEEP_SCAN_RE.finditer(text):
                    raw = m.group(0)[1:-1]
                    if "${" in raw or raw.startswith(("data:", "blob:")) or BLOCKED.search(raw):
                        continue
                    options = []
                    if raw.startswith(("http://", "https://")):
                        options.append(raw)
                    elif raw.startswith("//"):
                        options.append("https:" + raw)
                    elif raw.startswith("/"):
                        options.append(urllib.parse.urljoin(origin_root, raw))
                    else:
                        options.append(urllib.parse.urljoin(url, raw))
                        options.append(urllib.parse.urljoin(origin_root, raw))
                        if raw.startswith("static/"):
                            options.append(urllib.parse.urljoin(origin_root, "_next/" + raw))
                    cands.setdefault(options[0], options)
            todo = [(k, o) for k, o in cands.items() if not any(x in self.captured for x in o)]
            if not todo:
                break
            todo.sort(key=lambda kv: 0 if os.path.splitext(urllib.parse.urlparse(kv[0]).path)[1].lower() in (".mjs", ".js", ".json", ".css") else 1)
            todo = todo[:800]

            def fetch(item):
                for u in item[1]:
                    if u in self.captured:
                        return False
                    try:
                        r = self.session.get(u, timeout=30)
                    except Exception:
                        continue
                    ct = r.headers.get("content-type", "")
                    if r.status_code == 200 and "text/html" not in ct and r.content:
                        self.save(u, ct, r.content)
                        return True
                return False
            with ThreadPoolExecutor(16) as ex:
                if not any(ex.map(fetch, todo)):
                    break

    # ---------- making the clone self-contained ----------
    def rewrite(self):
        ext_hosts = sorted(self.hosts, key=len, reverse=True)
        o = re.escape(self.origin)
        lb = r"(?<![\w.:/\\-])"
        # Origin URLs are only rewritten when followed by a path; bare "https://site.com" stays valid for new URL(...)
        # and is re-routed at runtime by the shim. JS needs an explicit scheme (protocol-relative strings are built at runtime).
        origin_html = re.compile(lb + r"(?:https?:)?(?:\\?/){2}(?:www\.)?" + o + r"(?::\d+)?(?=\\?/)", re.I)
        origin_js = re.compile(lb + r"https?:(?:\\?/){2}(?:www\.)?" + o + r"(?::\d+)?(?=\\?/)", re.I)
        ext_html = ext_js = None
        prefixes = set()
        for u in self.captured:
            pu = urllib.parse.urlparse(u)
            full = pu.netloc.lower() + urllib.parse.unquote(pu.path)
            for i, ch in enumerate(full):
                if ch == "/":
                    prefixes.add(full[:i + 1])
            prefixes.add(full)
        if ext_hosts:
            alt = "|".join(re.escape(h) for h in ext_hosts)
            ext_html = re.compile(lb + r"(?:https?:)?(?:\\?/){2}(" + alt + r")(?![\w.-])", re.I)
            ext_js = re.compile(lb + r"https?:(?:\\?/){2}(" + alt + r")((?:\\?/)[^\s\"'`\\)<>?#]*)?", re.I)

        def ext_sub(m):
            esc = "\\" in m.group(0)
            h = safe_segment(m.group(1).lower())
            return ("\\/_ext\\/" if esc else "/_ext/") + h

        def ext_sub_js(m):
            path = m.group(2)
            if not path:
                return m.group(0)  # bare host: leave it, the shim re-routes the final URL at runtime
            if "\\" not in m.group(0) and (m.group(1).lower() + urllib.parse.unquote(path)) not in prefixes:
                return m.group(0)  # a page / API we never captured (e.g. a vimeo.com link): keep it as it was
            return ext_sub(m) + path

        imports = {f"https://{h}/": "/_ext/" + safe_segment(h) + "/" for h in ext_hosts}
        imports.update({f"http://{h}/": "/_ext/" + safe_segment(h) + "/" for h in ext_hosts})
        for h in (self.origin, "www." + self.origin):
            imports[f"https://{h}/"] = "/"
            imports[f"http://{h}/"] = "/"
        importmap = '<script type="importmap">' + json.dumps({"imports": imports}) + "</script>"
        hide = ("<style>#__framer-badge-container,.w-webflow-badge,a[href*='framer.com/?via'],"
                "a[href*='webflow.com?utm_campaign=brandjs']{display:none!important}</style>")
        shim = SHIM % {
            "ext": json.dumps({h.split(":")[0]: "/_ext/" + safe_segment(h) for h in ext_hosts}),
            "orig": json.dumps({self.origin: 1, "www." + self.origin: 1}),
        }
        # only the tracker loaders themselves: a script that merely mentions dataLayer/gtag can also hold the site's
        # config (e.g. Salesforce Commerce's window.SFRA.Constants) and the runtime shim blocks tracker requests anyway
        sc_inline = re.compile(
            r"<script\b(?![^>]*\bsrc=)[^>]*>(?:(?!</script>).)*?"
            r"(?:googletagmanager\.com|connect\.facebook\.net|fbq\(\s*['\"]init|clarity\.ms|static\.hotjar\.com|js\.hs-scripts\.com)"
            r"(?:(?!</script>).)*</script>", re.I | re.S)
        sc_src = re.compile(r"<script\b[^>]*\bsrc=[\"'][^\"']*(?:" + BLOCKED.pattern + r")[^\"']*[\"'][^>]*>\s*</script>", re.I)
        link_blocked = re.compile(r"<link\b[^>]*\bhref=[\"'][^\"']*(?:" + BLOCKED.pattern + r")[^\"']*[\"'][^>]*>", re.I)
        noscript_iframe = re.compile(r"<noscript>\s*<iframe[^>]*googletagmanager[^>]*></iframe>\s*</noscript>", re.I)

        todo, self.fresh = set(self.fresh), set()
        self._rel_key = {v["f"]: k for k, v in self.map.items() if "f" in v}
        for rel in todo:
            f = self.dest / rel
            ctype = self.map.get(self._key_for_rel(rel), {}).get("t", "")
            if not (os.path.splitext(rel)[1].lower() in TEXT_EXT or ctype.startswith(TEXT_TYPES)) or rel.endswith(".map"):
                continue
            try:
                text = f.read_text(encoding="utf-8")
            except Exception:
                continue
            is_html = "html" in ctype or rel.lower().endswith((".html", ".htm"))
            is_js = os.path.splitext(rel)[1].lower() in (".js", ".mjs")
            if is_js or rel.lower().endswith(".json"):
                continue  # code/data stay byte-identical; requests are re-routed at runtime (import map + shim)
            elif is_html:
                new = origin_html.sub("", text)
                if ext_html:  # leave <a> tags alone: links to third-party pages stay real links
                    new = "".join(p if p.lower().startswith("<a ") else ext_html.sub(ext_sub, p)
                                  for p in re.split(r"(<a\s[^>]*>)", new, flags=re.I))
            else:
                new = origin_html.sub("", text)
                if ext_html:
                    new = ext_html.sub(ext_sub, new)
            if is_html:
                new = sc_src.sub("", new)
                # Next.js flight data (self.__next_f.push) carries the layout tree, GTM tags included: dropping one
                # chunk breaks the whole stream ("This page couldn't load"); the runtime shim blocks the tracker itself
                new = sc_inline.sub(lambda m: m.group(0) if "__next_f" in m.group(0)[:160] or len(m.group(0)) > 3000 else "", new)
                new = noscript_iframe.sub("", new)
                new = link_blocked.sub("", new)
                new = re.sub(r"\s+integrity=(\"[^\"]*\"|'[^']*')", "", new, flags=re.I)
                new = re.sub(r"\s+crossorigin(=(\"[^\"]*\"|'[^']*'))?", "", new, flags=re.I)
                new = re.sub(r"<base\b[^>]*>", "", new, flags=re.I)
                new = re.sub(r"<link\b[^>]*rel=[\"'](?:canonical|preconnect|dns-prefetch)[\"'][^>]*>", "", new, flags=re.I)
                m = re.search(r"<head[^>]*>", new, re.I)
                new = (new[:m.end()] + CSP + importmap + shim + hide + new[m.end():]) if m else (CSP + importmap + shim + hide + new)
            if new != text:
                f.write_text(new, encoding="utf-8")


    def _nav_probe(self, p, base, page_url, probed, deadline, max_links=14):
        """Click internal links like a visitor: client-side routers (Framer, Next.js) then request the page
        chunks and CMS ranges that a direct load of each page never asks for. `probed` is shared between pages
        so header/footer links are clicked once; `deadline` keeps the total cost bounded."""
        pu = urllib.parse.urlparse(page_url)
        start = base + (pu.path or "/") + (("?" + pu.query) if pu.query else "")
        try:
            hrefs = p.evaluate("() => [...new Set([...document.querySelectorAll('a[href]')].map(a => a.href)"
                               ".map(h => h.split('#')[0]).filter(h => h.startsWith(location.origin) && h !== location.href.split('#')[0]))]")
        except Exception:
            return
        todo = [h for h in hrefs if h not in probed][:max_links]
        probed.update(todo)
        for h in todo:
            if time.time() > deadline:
                return
            try:
                p.goto(start, wait_until="load", timeout=30000)
                p.wait_for_timeout(300)
                path = urllib.parse.urlparse(h).path
                el = p.query_selector("a[href$=\"%s\"]" % path)
                if not el:
                    continue
                el.click(force=True, timeout=3000)
                p.wait_for_timeout(1200)
            except Exception:
                continue

    # ---------- self-healing: replay the clone offline and fetch whatever it asks for but does not have ----------
    def heal(self, rounds=3, max_visit=6):
        from playwright.sync_api import sync_playwright
        from site_server import make_server
        import threading
        probed = set()  # links already clicked by the navigation probe
        nav_deadline = time.time() + 90
        origin_root = f"{urllib.parse.urlparse(self.start_url).scheme}://{urllib.parse.urlparse(self.start_url).netloc}"
        dirty = set()
        with sync_playwright() as pw:
            # one browser for every round: closing/launching Chrome costs ~3 s each time
            b = launch(pw, ["--ignore-gpu-blocklist", "--autoplay-policy=no-user-gesture-required", "--mute-audio"])
            try:
                for rnd in range(rounds):
                    (self.dest / "_map.json").write_text(json.dumps(self.map, ensure_ascii=False), encoding="utf-8")
                    httpd = make_server(self.dest, 0, record_misses=True)
                    port = httpd.server_address[1]
                    threading.Thread(target=httpd.serve_forever, daemon=True).start()
                    base = f"http://127.0.0.1:{port}"
                    missing = set()
                    try:
                        ctx = b.new_context(service_workers="block", viewport={"width": 1440, "height": 900})
                        ctx.route("**/*", lambda r: r.continue_() if r.request.url.startswith((base, "data:", "blob:")) else r.abort())
                        pages = sorted(self.pages.keys(), key=lambda u: (urllib.parse.urlparse(u).path.count("/"), u))[:max_visit] or [self.start_url]
                        if rnd and dirty:
                            pages = [u for u in pages if u in dirty]
                        dirty = set()
                        for u in pages:
                            before = len(httpd.misses)
                            p = ctx.new_page()
                            p.on("response", lambda r: missing.add(r.url) if r.status == 404 and r.url.startswith(base) else None)
                            try:
                                pu = urllib.parse.urlparse(u)
                                p.goto(base + (pu.path or "/") + (("?" + pu.query) if pu.query else ""), wait_until="load", timeout=45000)
                                # local server answers in ms: a short quiet window is enough to see every miss
                                interact(p, long=False, calm=0.35)
                                p.wait_for_timeout(150)
                                if rnd == 0:
                                    self._nav_probe(p, base, u, probed, nav_deadline)
                            except Exception:
                                pass
                            p.close()
                            if len(httpd.misses) > before:
                                dirty.add(u)
                        ctx.close()
                    finally:
                        httpd.shutdown()
                    missing |= {base + p for p in httpd.misses}
                    fetched = 0
                    for murl in missing:
                        mp = urllib.parse.urlparse(murl)
                        path = mp.path
                        if path in ("/", "") or os.path.splitext(path)[1].lower() in (".html", ".htm") or path.startswith("/preview/"):
                            continue
                        m = re.match(r"^/_ext/([^/]+)(/.*)?$", urllib.parse.unquote(path))
                        if m:
                            target = f"https://{m.group(1)}{m.group(2) or '/'}"
                        else:
                            target = origin_root + path
                        if mp.query:
                            target += "?" + mp.query
                        try:
                            r = self.session.get(target, timeout=60)
                        except Exception:
                            continue
                        ct = r.headers.get("content-type", "")
                        if r.status_code == 200 and r.content and "text/html" not in ct:
                            self.save(target, ct, r.content)
                            fetched += 1
                    self.cb(3, 4, f"Réparation {rnd + 1} : {fetched} fichiers manquants récupérés")
                    self.rewrite()
                    if not fetched:
                        break
            finally:
                b.close()


    @classmethod
    def resume(cls, dest, start_url, progress_callback=None):
        """Re-open an existing clone (from its _map.json) so heal() can keep completing it."""
        c = cls(start_url, dest, progress_callback=progress_callback)
        p = urllib.parse.urlparse(c.start_url)
        root = f"{p.scheme}://{p.netloc}"
        data = json.loads((Path(dest) / "_map.json").read_text(encoding="utf-8"))
        for key, e in data.items():
            c.map[key] = e
            if "f" not in e:
                continue
            if key.startswith("/_ext/"):
                host, _, rest = key[6:].partition("/")
                url = f"https://{host}/{rest}"
                c.hosts.add(host)
            else:
                url = root + key
                if "html" in e.get("t", ""):
                    c.pages[url] = e["f"]
            c.captured[url] = e["f"]
        return c

    # ---- completion passes (run after heal): what a headless visit at one viewport can never see ----
    IMG_REF = re.compile(r"/_ext/([A-Za-z0-9.-]+)/([^\s\"'<>(),?]+\.(?:png|jpe?g|webp|avif|gif|svg))(?![?\w])", re.I)

    def fetch_missing_images(self):
        """Responsive images (srcset widths, high-DPR variants) are referenced by the pages but only the candidate the
        crawl viewport picked was ever downloaded: fetch the others so every screen size and zoom level is complete."""
        want = {}
        for rel in set(self.pages.values()):
            try:
                text = (self.dest / rel).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for m in self.IMG_REF.finditer(text):
                host, path = m.group(1), m.group(2)
                if not (self.dest / "_ext" / host / urllib.parse.unquote(path)).exists():
                    want[f"https://{host}/{path}"] = True

        def get(url):
            try:
                r = self.session.get(url, timeout=30)
                if r.status_code == 200 and r.content:
                    return url, r.headers.get("content-type", ""), r.content
            except Exception:
                pass
            return url, None, None

        got = 0
        with ThreadPoolExecutor(6) as ex:
            for url, ctype, body in ex.map(get, list(want)):
                if body:
                    self.save(url, ctype, body)
                    got += 1
        return got

    ASSET_REF = re.compile(
        r"(?<![\w.:/])(/(?!/)[^\s\"'<>()\\,]+?\.(?:css|js|mjs|woff2?|ttf|otf|png|jpe?g|webp|avif|gif|svg|ico|mp4|webm)"
        r"(?:\?[^\s\"'<>()\\,]*)?)(?=[\s\"'<>()\\,]|$)", re.I)
    CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]+?)['\"]?\s*\)", re.I)
    # assets named in scripts, often built at runtime (`${base}glb/model.glb`): a quoted or template-literal path
    JS_REF = re.compile(
        r"(?:[\"'`]|\})((?:\./|/)?[\w@%+~-]+(?:/[\w@%+~.-]+)*\."
        r"(?:glb|gltf|bin|hdr|exr|ktx2|basis|wasm|drc|mp3|m4a|ogg|wav|mp4|webm|png|jpe?g|webp|avif|gif|svg|woff2?))(?=[\"'`?#])", re.I)
    # three.js decoders: only the folder is in the code, the loader appends its standard file names
    DECODER_PATH = re.compile(r"set(Decoder|Transcoder)Path\(\s*[\"'`]([^\"'`]+)[\"'`]")
    DECODER_FILES = {"Decoder": ("draco_decoder.js", "draco_decoder.wasm", "draco_wasm_wrapper.js"),
                     "Transcoder": ("basis_transcoder.js", "basis_transcoder.wasm")}

    def fetch_missing_assets(self, rounds=3, limit=4000):
        """Stylesheets, scripts, fonts and images that the pages (or the saved stylesheets) reference but that never
        reached the clone, e.g. a page discovered late in the crawl whose sub-resources the browser never loaded, or
        requests a bot manager answered with a challenge. They are plain static files: fetch them directly."""
        sp = urllib.parse.urlparse(self.start_url)
        root = f"{sp.scheme}://{sp.netloc}"
        by_rel = {rel: url for url, rel in self.captured.items()}
        tried, got = set(), 0
        for _ in range(rounds):
            want = []
            for rel in sorted({v["f"] for v in self.map.values() if "f" in v}):
                low = rel.lower()
                is_js = low.endswith((".js", ".mjs"))
                if not (low.endswith((".html", ".htm", ".css")) or is_js):
                    continue
                try:
                    text = (self.dest / rel).read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                refs = [m.group(1) for m in self.ASSET_REF.finditer(text)]
                if is_js:  # relative names are resolved from the site root, where such bundles point their base
                    refs += ["/" + m.group(1).lstrip("./") if not m.group(1).startswith("/") else m.group(1)
                             for m in self.JS_REF.finditer(text) if "/" in m.group(1).lstrip("./")]
                    for m in self.DECODER_PATH.finditer(text):
                        folder = m.group(2) if m.group(2).endswith("/") else m.group(2) + "/"
                        if folder.startswith(("http://", "https://", "/")):
                            refs += [folder + f for f in self.DECODER_FILES[m.group(1)]]
                        else:
                            refs += ["/" + folder.lstrip("./") + f for f in self.DECODER_FILES[m.group(1)]]
                if low.endswith(".css") and rel in by_rel:  # url(...) relative to the stylesheet's own address
                    refs += [urllib.parse.urljoin(by_rel[rel], u) for u in self.CSS_URL.findall(text)
                             if not u.startswith(("data:", "#"))]
                for r in refs:
                    if r.startswith("/_ext/"):
                        host, _, rest = r[6:].partition("/")
                        url = f"https://{host}/{rest}"
                    elif r.startswith("/"):
                        url = root + r
                    elif r.startswith(("http://", "https://")):
                        url = r
                    else:
                        continue
                    url = urllib.parse.urldefrag(url)[0]  # font#iefix and the like: save() stores it without
                    if url in tried or url in self.captured or self.key_of(url) in self.map:
                        continue
                    tried.add(url)
                    want.append(url)
            # what breaks a page first: stylesheets, scripts and fonts, then images
            order = (".css", ".js", ".mjs", ".woff2", ".woff", ".ttf", ".otf")
            want.sort(key=lambda u: next((i for i, e in enumerate(order) if urllib.parse.urlparse(u).path.lower().endswith(e)), len(order)))
            want = want[:max(0, limit - got)]
            if not want:
                break

            def get(url):
                try:
                    video = urllib.parse.urlparse(url).path.lower().endswith((".mp4", ".webm"))
                    r = self.session.get(url, timeout=180 if video else 30)
                    ctype = r.headers.get("content-type", "")
                    if r.status_code == 200 and r.content and "text/html" not in ctype:
                        return url, ctype, r.content
                except Exception:
                    pass
                return url, None, None

            new = 0
            with ThreadPoolExecutor(6) as ex:
                for url, ctype, body in ex.map(get, want):
                    if body:
                        self.save(url, ctype, body)
                        by_rel[self.captured[url]] = url
                        new += 1
            got += new
            if not new:
                break
        return got

    def refetch_binary_served_as_text(self):
        """A server that labels binary files as text/plain (3D models, audio, wasm...) gets them decoded by the browser:
        the body Playwright hands back is that text re-encoded in UTF-8, so the saved file is corrupt. Download every
        such file again over plain HTTP, byte for byte."""
        todo = []
        for key, e in self.map.items():
            if "f" not in e or not e.get("t", "").startswith("text/"):
                continue
            ext = os.path.splitext(e["f"].split("__")[0] if "__" in e["f"] else e["f"])[1].lower()
            if ext and ext not in TEXT_EXT and ext not in (".htm", ".csv", ".md", ".vtt", ".srt", ".glsl", ".frag", ".vert"):
                todo.append(key)
        sp = urllib.parse.urlparse(self.start_url)

        def get(key):
            if key.startswith("/_ext/"):
                host, _, rest = key[6:].partition("/")
                url = f"https://{host}/{urllib.parse.quote(rest, safe='/?=&%:@+,;~')}"
            else:
                url = f"{sp.scheme}://{sp.netloc}{urllib.parse.quote(key, safe='/?=&%:@+,;~')}"
            try:
                r = self.session.get(url, timeout=120)
                if r.status_code == 200 and r.content:
                    return key, r.content
            except Exception:
                pass
            return key, None

        fixed = 0
        with ThreadPoolExecutor(6) as ex:
            for key, body in ex.map(get, todo):
                if body:
                    (self.dest / self.map[key]["f"]).write_bytes(body)
                    fixed += 1
        return fixed

    def framer_cms_static(self):
        """Framer reads its CMS through `file.framercms?range=a-b,c-d` and expects exactly those bytes (status 200). That
        only works with the origin's server. Store the complete files (10-40 KB) at their plain paths and make the CMS
        loader download them whole and cut the ranges itself: the clone then works on any static host."""
        keys = [k for k in self.map if k.startswith("/_ext/") and ".framercms" in k]
        if not keys:
            return 0
        bases = {k.split("?")[0] for k in keys}
        for b in list(bases):
            for kind in ("indexes", "chunk"):
                bases.add(re.sub(r"-(?:indexes|chunk)-default-0", f"-{kind}-default-0", b))
        got = 0
        for b in sorted(bases):
            host, _, rest = b[6:].partition("/")
            try:
                r = self.session.get(f"https://{host}/{rest}", timeout=30)
            except Exception:
                continue
            if r.status_code == 200 and r.content:
                self.save(f"https://{host}/{rest}", "application/octet-stream", r.content)
                got += 1
        old = set()
        for k in keys:
            e = self.map.get(k.split("?")[0])
            if e and "f" in e and k in self.map and self.map[k].get("f") != e["f"]:
                if "f" in self.map[k]:
                    old.add(self.map[k]["f"])
                self.map[k] = dict(e)
        for rel in old:
            if rel not in {v.get("f") for v in self.map.values()}:
                try:
                    (self.dest / rel).unlink()
                except OSError:
                    pass
        BT, DL = chr(96), chr(36)
        loader = re.compile(
            r"let (\w+)=new URL\((\w+)\),(\w+)=(\w+)\.join\(" + BT + "," + BT + r"\);\1\.searchParams\.set\(" + BT + "range" + BT + r",\3\);"
            r"let (\w+)=await (\w+)\(\1\);if\(\5\.status!==200\)throw Error\(" + BT + r"Request failed: \$\{\5\.status\} \$\{\5\.statusText\}" + BT + r"\);"
            r"let (\w+)=await \5\.arrayBuffer\(\),(\w+)=new Uint8Array\(\7\);if\(\8\.length!==(\w+)\)throw Error\(" + BT + r"Request failed: Unexpected response length" + BT + r"\);")

        def cut(m):
            _u, src, _o, _r, s, W, _c, l, total = m.groups()
            return (f"let {s}=await {W}(new URL({src}+'?v=2'));if({s}.status!==200)throw Error(" + BT + "Request failed: " + DL + "{" + s + ".status} " + DL + "{" + s + ".statusText}" + BT + ");"
                    f"let _f=new Uint8Array(await {s}.arrayBuffer()),{l}=new Uint8Array({total}),_p=0;"
                    f"for(let _e of n){{{l}.set(_f.subarray(_e.from,_e.to),_p);_p+=_e.to-_e.from}}")

        for rel in {v["f"] for v in self.map.values() if "f" in v and v["f"].endswith((".mjs", ".js"))}:
            f = self.dest / rel
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if "Unexpected response length" in text:
                new, n = loader.subn(cut, text)
                if n:
                    f.write_text(new, encoding="utf-8")
        return got

    def complete(self):
        """Last passes of a clone: binary files the browser decoded as text, images the crawl viewport never asked for,
        missing static files, then Framer's CMS for static hosting."""
        try:
            n = self.refetch_binary_served_as_text()
            if n:
                self.cb(0, 1, f"{n} fichiers binaires réparés")
        except Exception as e:
            self.errors.append(f"refetch_binary_served_as_text: {e}")
        try:
            n = self.fetch_missing_images()
            if n:
                self.cb(0, 1, f"{n} images responsives complétées")
        except Exception as e:
            self.errors.append(f"fetch_missing_images: {e}")
        try:
            n = self.fetch_missing_assets()
            if n:
                self.cb(0, 1, f"{n} fichiers manquants récupérés")
        except Exception as e:
            self.errors.append(f"fetch_missing_assets: {e}")
        try:
            self.framer_cms_static()
        except Exception as e:
            self.errors.append(f"framer_cms_static: {e}")

    def heal_existing(self, rounds=12):
        self.heal(rounds=rounds, max_visit=14)
        self.complete()
        (self.dest / "_map.json").write_text(json.dumps(self.map, ensure_ascii=False), encoding="utf-8")

    def _key_for_rel(self, rel):
        if not hasattr(self, "_rel_key"):
            self._rel_key = {v["f"]: k for k, v in self.map.items() if "f" in v}
        return self._rel_key.get(rel, "")

    # Global time budget for a full clone (seconds)
    MAX_RUN_SECONDS = 7 * 60

    def run(self):
        import threading as _th
        from playwright.sync_api import sync_playwright
        start = time.time()
        self.dest.mkdir(parents=True, exist_ok=True)
        self._run_done = False

        # Heartbeat thread: updates progress every 3s so the UI is never frozen
        _PHASES = [
            "Lancement navigateur headless...",
            "Crawl pages en cours...",
            "Récupération médias...",
            "Analyse ressources 3D / wasm...",
            "Réécriture liens hors-ligne...",
            "Réparation fichiers manquants...",
            "Finalisation...",
        ]
        _phase = [0]

        def _heartbeat():
            while not self._run_done:
                elapsed = int(time.time() - start)
                label = _PHASES[min(_phase[0], len(_PHASES) - 1)]
                pct = min(elapsed, self.MAX_RUN_SECONDS - 2)
                self.cb(pct, self.MAX_RUN_SECONDS, f"{label} ({elapsed}s — {len(self.captured)} fichiers)")
                time.sleep(3)

        _th.Thread(target=_heartbeat, daemon=True).start()

        try:
            _phase[0] = 0
            with sync_playwright() as pw:
                self.crawl(pw)

            _phase[0] = 2
            self.refetch_partial()

            _phase[0] = 3
            self.deep_scan()

            _phase[0] = 4
            self._rel_key = {v["f"]: k for k, v in self.map.items() if "f" in v}
            self.rewrite()

            # Skip heal if running low on time
            remaining = self.MAX_RUN_SECONDS - (time.time() - start)
            if remaining > 40:
                _phase[0] = 5
                self.heal()

            _phase[0] = 6
            self.complete()
            (self.dest / "_map.json").write_text(json.dumps(self.map, ensure_ascii=False), encoding="utf-8")
            report = [f"Source : {self.start_url}", f"Pages : {len(self.pages)}", f"Fichiers : {len(self.captured)}",
                      f"Hôtes tiers embarqués : {sorted(self.hosts)}", f"Erreurs : {len(self.errors)}"] + self.errors[:50]
            (self.dest / "_clone-report.txt").write_text("\n".join(report), encoding="utf-8")
        finally:
            self._run_done = True

        duration = round(time.time() - start, 2)
        self.cb(self.MAX_RUN_SECONDS, self.MAX_RUN_SECONDS,
                f"Terminé en {duration}s : {len(self.pages)} pages, {len(self.captured)} fichiers")
        return {
            "success": bool(self.captured),
            "title": self.title,
            "total_pages": len(self.pages),
            "total_files": len(self.captured),
            "total_size": self.total_bytes,
            "errors": len(self.errors),
            "duration": duration,
            "dest_dir": str(self.dest),
        }


def clone_site(url, dest_dir, crawl_all_pages=True, max_pages=15, progress_callback=None):
    cl = Cloner(url, dest_dir, max_pages=max_pages if crawl_all_pages else 1, progress_callback=progress_callback)
    try:
        return cl.run()
    except Exception as e:
        return {"success": False, "error": str(e)}
