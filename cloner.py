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
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

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
function fix(u){if(u instanceof URL)u=u.href;if(typeof u!=='string')return u;if(B.test(u)&&/^(?:https?:)?\\/\\//i.test(u))return 'data:text/javascript,';u=u.replace(/^https?:\\/*(?=_ext\\/)/i,'/');var m=u.match(/^(?:https?:)?\\/\\/([^\\/:?#]+)(?::\\d+)?([\\/?#][\\s\\S]*)?$/i);
if(!m)return u;var h=m[1].toLowerCase();if(h===location.hostname)return u;var r=m[2]||'/';if(r.charAt(0)!=='/')r='/'+r;
if(O[h])return r;if(M[h])return M[h]+r;return u;}
try{var f=window.fetch;if(f)window.fetch=function(a,b){if(typeof a==='string'||a instanceof URL)a=fix(a);else if(a&&a.url){var n=fix(a.url);if(n!==a.url)a=new Request(n,a);}return f.call(this,a,b);};}catch(e){}
try{var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=fix(String(u));return xo.apply(this,arguments);};}catch(e){}
try{var sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){if((n==='src'||n==='href'||n==='poster'||n==='data')&&typeof v==='string'&&this.tagName!=='A'&&this.tagName!=='AREA')v=fix(v);return sa.call(this,n,v);};}catch(e){}
function P(C,p){try{var d=Object.getOwnPropertyDescriptor(C.prototype,p);if(d&&d.set)Object.defineProperty(C.prototype,p,{get:d.get,set:function(v){d.set.call(this,fix(v));},configurable:true,enumerable:d.enumerable});}catch(e){}}
P(HTMLImageElement,'src');P(HTMLScriptElement,'src');P(HTMLLinkElement,'href');P(HTMLMediaElement,'src');
P(HTMLSourceElement,'src');P(HTMLIFrameElement,'src');P(HTMLVideoElement,'poster');
try{var W=window.Worker;if(W)window.Worker=function(u,o){return new W(fix(String(u)),o);};window.Worker.prototype=W.prototype;}catch(e){}
try{navigator.sendBeacon=function(){return true;};}catch(e){}
})();</script>"""


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
        self.total_bytes = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Referer": self.start_url})

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

    def crawl(self, pw):
        browser = pw.chromium.launch(headless=True, args=[
            "--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--ignore-gpu-blocklist",
            "--enable-webgl", "--autoplay-policy=no-user-gesture-required", "--mute-audio",
            "--disable-features=PreloadMediaEngagementData,MediaEngagementBypassAutoplayPolicies"])
        context = browser.new_context(user_agent=UA, viewport={"width": 1440, "height": 900},
                                      service_workers="block", ignore_https_errors=True)

        def route(r):
            if BLOCKED.search(r.request.url):
                r.abort()
            else:
                r.continue_()
        context.route("**/*", route)
        context.on("response", self.on_response)

        queue = [self.norm_page(self.start_url)]
        seen = set(queue)
        first = True
        count = 0
        while queue and count < self.max_pages:
            url = queue.pop(0)
            count += 1
            self.cb(count, self.max_pages, f"Page {count} : {urllib.parse.urlparse(url).path or '/'}")
            page = context.new_page()
            try:
                try:
                    page.goto(url, wait_until="load", timeout=60000)
                except Exception:
                    pass
                try:
                    page.wait_for_load_state("networkidle", timeout=20000)
                except Exception:
                    pass
                try:
                    page.mouse.move(400, 300)
                    page.mouse.move(900, 500, steps=8)
                    page.evaluate(SCROLL_JS)
                except Exception:
                    pass
                page.wait_for_timeout(2500)
                try:
                    page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass
                if first:
                    final = self.norm_page(page.url)
                    if final is None:  # redirected to another host: that host becomes the origin
                        self.origin = norm_host(urllib.parse.urlparse(page.url).netloc)
                        final = self.norm_page(page.url)
                    if final:
                        seen.add(final)
                    try:
                        self.title = (page.title() or self.origin).strip() or self.origin
                    except Exception:
                        pass
                    for u in self.sitemap_urls():
                        n = self.norm_page(u)
                        if n and n not in seen and len(seen) < self.max_pages * 3:
                            seen.add(n)
                            queue.append(n)
                    first = False
                hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for h in hrefs:
                    n = self.norm_page(h)
                    if n and n not in seen:
                        seen.add(n)
                        queue.append(n)
            except Exception as e:
                self.errors.append(f"{url}: {e}")
            finally:
                try:
                    page.close()
                except Exception:
                    pass
        context.close()
        browser.close()

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
        for _ in range(2):
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
            todo = todo[:500]

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

        shim = SHIM % {
            "ext": json.dumps({h.split(":")[0]: "/_ext/" + safe_segment(h) for h in ext_hosts}),
            "orig": json.dumps({self.origin: 1, "www." + self.origin: 1}),
        }
        sc_inline = re.compile(
            r"<script\b(?![^>]*\bsrc=)[^>]*>(?:(?!</script>).)*?(?:googletagmanager|gtag\(|fbq\(|clarity|hotjar|_hsq|dataLayer)"
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
            if is_js:
                new = text  # origin URLs stay as written (new URL("https://site/") must remain valid); the shim re-routes them
                if ext_js:
                    new = ext_js.sub(ext_sub_js, new)
            elif is_html:
                new = origin_html.sub("", text)
                if ext_html:  # leave <a> tags alone: links to third-party pages stay real links
                    new = "".join(p if p.lower().startswith("<a ") else ext_html.sub(ext_sub, p)
                                  for p in re.split(r"(<a\s[^>]*>)", new, flags=re.I))
            else:
                new = text if rel.lower().endswith(".json") else origin_html.sub("", text)
                if ext_html:
                    new = ext_html.sub(ext_sub, new)
            if is_html:
                new = sc_src.sub("", new)
                new = sc_inline.sub("", new)
                new = noscript_iframe.sub("", new)
                new = link_blocked.sub("", new)
                new = re.sub(r"\s+integrity=(\"[^\"]*\"|'[^']*')", "", new, flags=re.I)
                new = re.sub(r"\s+crossorigin(=(\"[^\"]*\"|'[^']*'))?", "", new, flags=re.I)
                new = re.sub(r"<base\b[^>]*>", "", new, flags=re.I)
                new = re.sub(r"<link\b[^>]*rel=[\"'](?:canonical|preconnect|dns-prefetch)[\"'][^>]*>", "", new, flags=re.I)
                m = re.search(r"<head[^>]*>", new, re.I)
                new = (new[:m.end()] + CSP + shim + new[m.end():]) if m else (CSP + shim + new)
            if new != text:
                f.write_text(new, encoding="utf-8")


    # ---------- self-healing: replay the clone offline and fetch whatever it asks for but does not have ----------
    def heal(self, rounds=8, max_visit=10):
        from playwright.sync_api import sync_playwright
        from site_server import make_server
        import threading
        origin_root = f"{urllib.parse.urlparse(self.start_url).scheme}://{urllib.parse.urlparse(self.start_url).netloc}"
        for rnd in range(rounds):
            (self.dest / "_map.json").write_text(json.dumps(self.map, ensure_ascii=False), encoding="utf-8")
            httpd = make_server(self.dest, 0)
            port = httpd.server_address[1]
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{port}"
            missing = set()
            try:
                with sync_playwright() as pw:
                    b = pw.chromium.launch(headless=True, args=["--use-angle=swiftshader", "--enable-unsafe-swiftshader",
                                                              "--ignore-gpu-blocklist", "--autoplay-policy=no-user-gesture-required", "--mute-audio"])
                    ctx = b.new_context(service_workers="block", viewport={"width": 1440, "height": 900})
                    ctx.route("**/*", lambda r: r.continue_() if r.request.url.startswith((base, "data:", "blob:")) else r.abort())
                    pages = sorted(self.pages.keys(), key=lambda u: (urllib.parse.urlparse(u).path.count("/"), u))[:max_visit] or [self.start_url]
                    for u in pages:
                        p = ctx.new_page()
                        p.on("response", lambda r: missing.add(r.url) if r.status == 404 and r.url.startswith(base) else None)
                        try:
                            pu = urllib.parse.urlparse(u)
                            p.goto(base + (pu.path or "/") + (("?" + pu.query) if pu.query else ""), wait_until="load", timeout=45000)
                            try:
                                p.wait_for_load_state("networkidle", timeout=20000)
                            except Exception:
                                pass
                            p.mouse.move(500, 400, steps=6)
                            p.evaluate(SCROLL_JS)
                            p.evaluate("() => document.querySelectorAll('video,audio').forEach(m => { m.preload='auto'; try{m.load(); m.play().catch(()=>{});}catch(e){} })")
                            p.wait_for_timeout(7000)
                        except Exception:
                            pass
                        p.close()
                    b.close()
            finally:
                httpd.shutdown()
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

    def heal_existing(self, rounds=12):
        self.heal(rounds=rounds, max_visit=14)
        (self.dest / "_map.json").write_text(json.dumps(self.map, ensure_ascii=False), encoding="utf-8")

    def _key_for_rel(self, rel):
        if not hasattr(self, "_rel_key"):
            self._rel_key = {v["f"]: k for k, v in self.map.items() if "f" in v}
        return self._rel_key.get(rel, "")

    def run(self):
        from playwright.sync_api import sync_playwright
        start = time.time()
        self.dest.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as pw:
            self.crawl(pw)
        self.cb(1, 4, "Récupération des médias complets...")
        self.refetch_partial()
        self.cb(2, 4, "Recherche des ressources cachées (3D, textures, wasm)...")
        self.deep_scan()
        self.cb(3, 4, "Coupure du lien avec le site d'origine...")
        self._rel_key = {v["f"]: k for k, v in self.map.items() if "f" in v}
        self.rewrite()
        self.cb(3, 4, "Réparation des fichiers manquants...")
        self.heal()
        (self.dest / "_map.json").write_text(json.dumps(self.map, ensure_ascii=False), encoding="utf-8")
        report = [f"Source : {self.start_url}", f"Pages : {len(self.pages)}", f"Fichiers : {len(self.captured)}",
                  f"Hôtes tiers embarqués : {sorted(self.hosts)}", f"Erreurs : {len(self.errors)}"] + self.errors[:50]
        (self.dest / "_clone-report.txt").write_text("\n".join(report), encoding="utf-8")
        self.cb(4, 4, f"Terminé : {len(self.pages)} pages, {len(self.captured)} fichiers")
        return {
            "success": bool(self.captured),
            "title": self.title,
            "total_pages": len(self.pages),
            "total_files": len(self.captured),
            "total_size": self.total_bytes,
            "errors": len(self.errors),
            "duration": round(time.time() - start, 2),
            "dest_dir": str(self.dest),
        }


def clone_site(url, dest_dir, crawl_all_pages=True, max_pages=60, progress_callback=None):
    cl = Cloner(url, dest_dir, max_pages=max_pages if crawl_all_pages else 1, progress_callback=progress_callback)
    try:
        return cl.run()
    except Exception as e:
        return {"success": False, "error": str(e)}
