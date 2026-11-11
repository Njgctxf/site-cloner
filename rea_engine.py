#!/usr/bin/env python3
"""
rea_engine.py - R.E.A. (Reverse Engineer Anything) Engine for SiteCloner SaaS.

Combines passive CDP telemetry, Source Map reconstruction, API/GraphQL discovery,
OpenAPI 3.0 generation, local API mocks, and clean-room blueprint extraction
on top of cloned websites as an advanced Pro/Enterprise capability.
"""

import base64
import hashlib
import io
import json
import os
import re
import urllib.parse
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


REA_DIR_NAME = "_rea"
MAX_SOURCE_FILES = 1500
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_API_ENDPOINTS = 150
MAX_SAMPLE_CHARS = 8000

SOURCE_MAP_RE = re.compile(
    r"(?://[@#]\s*|/\*[@#]\s*)sourceMappingURL\s*=\s*([^\s*'\"]+)",
    re.IGNORECASE,
)

STATIC_ENDPOINT_RE = re.compile(
    r"""["'`]((?:/api/|/graphql\b|/v[1-4]/|https?://[a-z0-9.-]+/api/|https?://[a-z0-9.-]+/graphql)[^"'`\s\\<>]{1,160})["'`]""",
    re.IGNORECASE,
)

IGNORED_ENDPOINTS_RE = re.compile(
    r"googletagmanager|google-analytics|doubleclick|facebook\.net|sentry\.io|clarity\.ms|hotjar|mixpanel",
    re.IGNORECASE,
)

TECH_SIGNATURES: List[Tuple[str, str, re.Pattern]] = [
    ("Next.js", "Framework", re.compile(r"__next_f|__NEXT_DATA__|/_next/static", re.I)),
    ("React", "UI Library", re.compile(r"__reactFiber|react-dom|data-reactroot|react\.production", re.I)),
    ("Vue.js", "Framework", re.compile(r"__vue_app__|data-v-[0-9a-f]{6,}|vue\.runtime", re.I)),
    ("Nuxt", "Framework", re.compile(r"__NUXT__|/_nuxt/", re.I)),
    ("Svelte", "Framework", re.compile(r"__svelte|svelte-[a-z0-9]+", re.I)),
    ("Astro", "Framework", re.compile(r"astro-island|/_astro/", re.I)),
    ("Framer", "Site Builder", re.compile(r"framerusercontent\.com|events\.framer\.com|data-framer-", re.I)),
    ("Webflow", "Site Builder", re.compile(r"data-wf-domain|data-wf-page|webflow\.js", re.I)),
    ("Tailwind CSS", "CSS", re.compile(r"--tw-(?:bg|text|border|ring|shadow)|tailwindcss", re.I)),
    ("Three.js / WebGL", "3D / Graphics", re.compile(r"THREE\.WebGLRenderer|three(?:\.module)?(?:\.min)?\.js|\.glb\b|\.ktx2\b", re.I)),
    ("GSAP", "Animation", re.compile(r"gsap\.registerPlugin|ScrollTrigger|gsap(?:\.min)?\.js", re.I)),
    ("Lottie", "Animation", re.compile(r"lottie-player|bodymovin|lottie(?:\.min)?\.js", re.I)),
    ("Stripe", "Payments", re.compile(r"js\.stripe\.com|Stripe\(", re.I)),
    ("Supabase", "BaaS", re.compile(r"supabase\.co|createClient.*supabase", re.I)),
    ("Firebase", "BaaS", re.compile(r"firebaseio\.com|firebaseapp\.com|initializeApp", re.I)),
    ("GraphQL", "API", re.compile(r"/graphql\b|__typename|ApolloClient", re.I)),
]


def _rea_dir(site_dir: Path) -> Path:
    return Path(site_dir) / REA_DIR_NAME


def _safe_source_rel(raw_path: str, fallback_idx: int) -> str:
    """Normalizes a SourceMap source path into a safe relative file path under _rea/sources/."""
    p = (raw_path or "").strip()
    p = re.sub(r"^(?:webpack://[^/]*/|webpack:///|turbopack:///|vite:///|file:///|https?://[^/]+/)", "", p)
    p = p.split("?", 1)[0].split("#", 1)[0]
    p = p.replace("\\", "/")
    parts = [
        re.sub(r'[<>:"|?*\x00-\x1f]', "_", seg).strip(".")
        for seg in p.split("/")
        if seg and seg not in (".", "..")
    ]
    if not parts:
        return f"module_{fallback_idx}.js"
    # Keep paths concise on Windows while preserving component structure
    if len(parts) > 8:
        parts = parts[-6:]
    joined = "/".join(parts)
    if len(joined) > 160:
        ext = os.path.splitext(joined)[1][:10] or ".js"
        joined = f"deep/{hashlib.md5(joined.encode()).hexdigest()[:12]}{ext}"
    return joined


def collect_cdp_page_runtime(page, context, trace_bucket: Dict[str, Any], lock: Any) -> Optional[Dict[str, Any]]:
    """
    Attaches passive CDP Network listeners on a Playwright page (when supported)
    and returns a cleanup/snapshot callable to call after page interaction settles.
    """
    cdp = None
    page_net: Dict[str, Dict[str, Any]] = {}
    ws_urls: List[str] = []

    try:
        cdp = context.new_cdp_session(page)
        cdp.send("Network.enable")

        def _on_req(ev: Dict[str, Any]):
            req = ev.get("request") or {}
            url = req.get("url") or ""
            if not url.startswith(("http://", "https://")) or IGNORED_ENDPOINTS_RE.search(url):
                return
            rtype = (ev.get("type") or "").upper()
            if rtype in ("XHR", "FETCH", "WEBSOCKET") or "/api/" in url or "graphql" in url.lower():
                rid = ev.get("requestId")
                if rid:
                    page_net[rid] = {
                        "url": url,
                        "method": (req.get("method") or "GET").upper(),
                        "resource_type": rtype,
                        "has_post_data": bool(req.get("hasPostData")),
                        "post_data": (req.get("postData") or "")[:1200] if req.get("postData") else "",
                    }

        def _on_resp(ev: Dict[str, Any]):
            rid = ev.get("requestId")
            if rid not in page_net:
                return
            resp = ev.get("response") or {}
            page_net[rid]["status"] = resp.get("status")
            page_net[rid]["mime_type"] = resp.get("mimeType") or ""

        def _on_ws(ev: Dict[str, Any]):
            url = ev.get("url") or ""
            if url and url not in ws_urls:
                ws_urls.append(url)

        cdp.on("Network.requestWillBeSent", _on_req)
        cdp.on("Network.responseReceived", _on_resp)
        cdp.on("Network.webSocketCreated", _on_ws)
    except Exception:
        cdp = None

    def finish_snapshot():
        runtime_info: Dict[str, Any] = {}
        try:
            runtime_info = page.evaluate(
                """() => {
                    const ls = {}, ss = {};
                    try {
                        for (let i = 0; i < Math.min(localStorage.length, 40); i++) {
                            const k = localStorage.key(i);
                            ls[k] = String(localStorage.getItem(k) || '').slice(0, 240);
                        }
                    } catch (e) {}
                    try {
                        for (let i = 0; i < Math.min(sessionStorage.length, 30); i++) {
                            const k = sessionStorage.key(i);
                            ss[k] = String(sessionStorage.getItem(k) || '').slice(0, 240);
                        }
                    } catch (e) {}
                    return {
                        localStorage: ls,
                        sessionStorage: ss,
                        hasNextData: Boolean(document.getElementById('__NEXT_DATA__')),
                        hasNextFlight: Array.isArray(window.__next_f),
                        hasReactHook: Boolean(window.__REACT_DEVTOOLS_GLOBAL_HOOK__),
                        hasVueApp: Boolean(window.__VUE__ || document.querySelector('[data-v-app]')),
                        scriptsCount: document.scripts ? document.scripts.length : 0,
                        formsCount: document.forms ? document.forms.length : 0,
                    };
                }"""
            ) or {}
        except Exception:
            runtime_info = {}

        with lock:
            if page_net:
                trace_bucket.setdefault("cdp_requests", []).extend(page_net.values())
            if ws_urls:
                existing_ws = set(trace_bucket.setdefault("websockets", []))
                for w in ws_urls:
                    if w not in existing_ws:
                        trace_bucket["websockets"].append(w)
                        existing_ws.add(w)
            if runtime_info:
                ls_all = trace_bucket.setdefault("localStorage", {})
                ls_all.update(runtime_info.get("localStorage") or {})
                ss_all = trace_bucket.setdefault("sessionStorage", {})
                ss_all.update(runtime_info.get("sessionStorage") or {})
                flags = trace_bucket.setdefault("runtime_flags", {})
                for fk in ("hasNextData", "hasNextFlight", "hasReactHook", "hasVueApp"):
                    if runtime_info.get(fk):
                        flags[fk] = True

        if cdp is not None:
            try:
                cdp.detach()
            except Exception:
                pass

    return finish_snapshot


def _decode_inline_sourcemap(ref: str) -> Optional[Dict[str, Any]]:
    if not ref.startswith("data:") or "base64," not in ref:
        return None
    try:
        b64 = ref.split("base64,", 1)[1]
        raw = base64.b64decode(b64)
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _resolve_map_url(asset_rel: str, map_ref: str, map_data: Dict[str, Any], origin_url: str) -> Optional[str]:
    """Builds the original remote URL for a sourceMappingURL referenced by a local cloned file."""
    if map_ref.startswith(("http://", "https://")):
        return map_ref
    if map_ref.startswith("//"):
        scheme = urllib.parse.urlparse(origin_url).scheme or "https"
        return f"{scheme}:{map_ref}"
    # Look up original key in _map.json matching asset_rel
    orig_key = next((k for k, v in map_data.items() if v.get("f") == asset_rel), None)
    base_url = origin_url
    if orig_key:
        if orig_key.startswith("/_ext/"):
            rest = orig_key[len("/_ext/"):]
            host, _, path = rest.partition("/")
            base_url = f"https://{host}/{path}"
        else:
            parsed = urllib.parse.urlparse(origin_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{orig_key}"
    return urllib.parse.urljoin(base_url, map_ref)


def unpack_sourcemaps(
    site_dir: Path,
    map_data: Dict[str, Any],
    origin_url: str = "",
    fetch_url: Optional[Callable[[str], Optional[bytes]]] = None,
) -> Dict[str, Any]:
    """
    Finds inline, local, and (optionally) remote SourceMap v3 files inside site_dir,
    unpacks their `sourcesContent` into `_rea/sources/`, and returns extraction stats.
    """
    site_dir = Path(site_dir)
    sources_dir = _rea_dir(site_dir) / "sources"
    sources_dir.mkdir(parents=True, exist_ok=True)

    maps_found: List[Tuple[str, Dict[str, Any]]] = []
    seen_map_hashes = set()

    def _register_map(label: str, raw_bytes: bytes):
        if not raw_bytes or len(raw_bytes) > 15 * 1024 * 1024:
            return
        try:
            parsed = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        except Exception:
            return
        if not isinstance(parsed, dict) or "sources" not in parsed:
            return
        digest = hashlib.md5(raw_bytes).hexdigest()
        if digest in seen_map_hashes:
            return
        seen_map_hashes.add(digest)
        maps_found.append((label, parsed))

    # 1. Existing .map files already cloned into site_dir
    for fpath in site_dir.rglob("*.map"):
        if REA_DIR_NAME in fpath.parts or "_studio" in fpath.parts:
            continue
        try:
            _register_map(fpath.relative_to(site_dir).as_posix(), fpath.read_bytes())
        except OSError:
            continue

    # 2. Scan JS/MJS/CSS bundles for sourceMappingURL directives (inline or remote)
    scanned_urls = set()
    for fpath in site_dir.rglob("*"):
        if not fpath.is_file() or fpath.suffix.lower() not in (".js", ".mjs", ".css"):
            continue
        if REA_DIR_NAME in fpath.parts or "_studio" in fpath.parts:
            continue
        try:
            size = fpath.stat().st_size
            if size == 0 or size > 8 * 1024 * 1024:
                continue
            head_tail = fpath.read_text(encoding="utf-8", errors="ignore")
            tail = head_tail[-4096:]
        except OSError:
            continue
        matches = SOURCE_MAP_RE.findall(tail) or SOURCE_MAP_RE.findall(head_tail[:4096])
        if not matches:
            continue
        rel = fpath.relative_to(site_dir).as_posix()
        for ref in matches[:2]:
            if ref.startswith("data:"):
                parsed_inline = _decode_inline_sourcemap(ref)
                if parsed_inline and "sources" in parsed_inline:
                    raw = json.dumps(parsed_inline).encode("utf-8")
                    _register_map(f"{rel} (inline)", raw)
                continue
            # Check local sibling .map file first
            local_candidate = (fpath.parent / ref.split("?", 1)[0]).resolve()
            try:
                local_candidate.relative_to(site_dir.resolve())
                if local_candidate.is_file():
                    _register_map(local_candidate.relative_to(site_dir).as_posix(), local_candidate.read_bytes())
                    continue
            except ValueError:
                pass
            # Optionally fetch missing .map if fetch_url callback provided during R.E.A. clone
            if fetch_url and origin_url:
                remote_url = _resolve_map_url(rel, ref, map_data, origin_url)
                if remote_url and remote_url not in scanned_urls and len(scanned_urls) < 40:
                    scanned_urls.add(remote_url)
                    fetched = fetch_url(remote_url)
                    if fetched:
                        _register_map(remote_url, fetched)

    reconstructed_files: List[Dict[str, Any]] = []
    seen_rel_paths = set()
    ext_counts: Counter = Counter()
    total_lines = 0

    for map_label, sm in maps_found:
        srcs = sm.get("sources") or []
        contents = sm.get("sourcesContent") or []
        for idx, src_name in enumerate(srcs):
            if len(reconstructed_files) >= MAX_SOURCE_FILES:
                break
            content = contents[idx] if idx < len(contents) else None
            if not isinstance(content, str) or not content.strip():
                continue
            if len(content.encode("utf-8", errors="ignore")) > MAX_SOURCE_BYTES:
                continue
            rel = _safe_source_rel(src_name, idx)
            # Skip noisy node_modules unless small/no app code exists, mark third-party cleanly
            is_vendor = "node_modules/" in rel
            if rel in seen_rel_paths:
                stem, ext = os.path.splitext(rel)
                rel = f"{stem}_{idx}{ext}"
            seen_rel_paths.add(rel)

            dest = (sources_dir / rel).resolve()
            try:
                dest.relative_to(sources_dir.resolve())
            except ValueError:
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

            lines = content.count("\n") + 1
            total_lines += lines
            ext = os.path.splitext(rel)[1].lower() or ".txt"
            ext_counts[ext] += 1
            reconstructed_files.append({
                "path": rel,
                "lines": lines,
                "bytes": len(content.encode("utf-8", errors="ignore")),
                "ext": ext,
                "vendor": is_vendor,
                "from_map": map_label,
            })

    # Put app source files ahead of node_modules in UI listing
    reconstructed_files.sort(key=lambda x: (x["vendor"], x["path"]))
    return {
        "sourcemaps_count": len(maps_found),
        "maps": [lbl for lbl, _ in maps_found],
        "files_count": len(reconstructed_files),
        "app_files_count": sum(1 for x in reconstructed_files if not x["vendor"]),
        "total_lines": total_lines,
        "languages": dict(ext_counts.most_common(12)),
        "files": reconstructed_files[:300],
    }


def _infer_json_schema(val: Any, depth: int = 0) -> Dict[str, Any]:
    if depth >= 3:
        return {"type": type(val).__name__}
    if val is None:
        return {"type": "null"}
    if isinstance(val, bool):
        return {"type": "boolean"}
    if isinstance(val, int):
        return {"type": "integer"}
    if isinstance(val, float):
        return {"type": "number"}
    if isinstance(val, str):
        return {"type": "string", "example": val[:80]}
    if isinstance(val, list):
        if not val:
            return {"type": "array", "items": {}}
        return {"type": "array", "items": _infer_json_schema(val[0], depth + 1)}
    if isinstance(val, dict):
        props = {}
        for k, v in list(val.items())[:25]:
            props[str(k)] = _infer_json_schema(v, depth + 1)
        return {"type": "object", "properties": props}
    return {"type": "string"}


def _detect_tech_stack(site_dir: Path, runtime_flags: Dict[str, Any]) -> List[Dict[str, str]]:
    """Scans HTML/JS/CSS samples and CDP runtime flags to identify frontend/backend tech stack."""
    found: Dict[str, Dict[str, str]] = {}
    sample_chunks: List[str] = []
    scanned_bytes = 0
    for fpath in site_dir.rglob("*"):
        if not fpath.is_file() or REA_DIR_NAME in fpath.parts or "_studio" in fpath.parts:
            continue
        if fpath.suffix.lower() not in (".html", ".htm", ".js", ".mjs", ".css", ".json"):
            continue
        if scanned_bytes > 2_500_000:
            break
        try:
            txt = fpath.read_text(encoding="utf-8", errors="ignore")[:80_000]
            sample_chunks.append(txt)
            scanned_bytes += len(txt)
        except OSError:
            continue

    blob = "\n".join(sample_chunks)
    for name, category, pattern in TECH_SIGNATURES:
        if pattern.search(blob):
            found[name] = {"name": name, "category": category, "evidence": "static_bundle"}

    if runtime_flags.get("hasNextData") or runtime_flags.get("hasNextFlight"):
        found["Next.js"] = {"name": "Next.js", "category": "Framework", "evidence": "cdp_runtime"}
    if runtime_flags.get("hasReactHook"):
        found["React"] = {"name": "React", "category": "UI Library", "evidence": "cdp_runtime"}
    if runtime_flags.get("hasVueApp"):
        found["Vue.js"] = {"name": "Vue.js", "category": "Framework", "evidence": "cdp_runtime"}

    return list(found.values())


def _build_api_inventory(
    site_dir: Path,
    map_data: Dict[str, Any],
    cdp_requests: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    """
    Discovers all captured and statically-referenced API/GraphQL endpoints,
    generates OpenAPI 3.0 spec + local mock index for site_server.py.
    """
    endpoints: Dict[Tuple[str, str], Dict[str, Any]] = {}
    mocks_dir = _rea_dir(site_dir) / "mocks"
    mocks_dir.mkdir(parents=True, exist_ok=True)
    mock_index: Dict[str, Dict[str, str]] = {}

    def _add_ep(method: str, path: str, ctype: str = "", status: int = 200,
                sample_file: Optional[Path] = None, rel_file: str = "", source: str = "capture"):
        if not path or IGNORED_ENDPOINTS_RE.search(path) or len(endpoints) >= MAX_API_ENDPOINTS:
            return
        clean_path = path.split("#", 1)[0]
        if clean_path.startswith("http"):
            parsed = urllib.parse.urlparse(clean_path)
            ep_path = parsed.path or "/"
            host = parsed.netloc
        else:
            ep_path = clean_path.split("?", 1)[0] or "/"
            host = "origin"
        if not ep_path.startswith("/"):
            ep_path = "/" + ep_path
        key = (method.upper(), ep_path)
        entry = endpoints.setdefault(key, {
            "method": method.upper(),
            "path": ep_path,
            "host": host,
            "content_type": ctype or "application/json",
            "status": status,
            "source": source,
            "has_local_mock": False,
            "schema": None,
            "sample_preview": "",
        })
        if sample_file and sample_file.is_file():
            entry["has_local_mock"] = True
            if rel_file:
                mock_index[f"{method.upper()} {ep_path}"] = {
                    "f": rel_file,
                    "t": entry["content_type"],
                }
            if entry["schema"] is None and ("json" in (entry["content_type"] or "") or sample_file.suffix.lower() == ".json"):
                try:
                    raw = sample_file.read_text(encoding="utf-8", errors="ignore")[:MAX_SAMPLE_CHARS]
                    entry["sample_preview"] = raw[:600]
                    parsed_json = json.loads(raw)
                    entry["schema"] = _infer_json_schema(parsed_json)
                except Exception:
                    pass

    # 1. Endpoints captured in _map.json (POST _post/ and JSON GET endpoints)
    for k, entry in map_data.items():
        if not isinstance(entry, dict) or "f" not in entry:
            continue
        rel = entry["f"]
        ctype = entry.get("t", "")
        fpath = site_dir / rel
        if k.startswith("POST "):
            raw_ep = k[5:].split("#", 1)[0]
            _add_ep("POST", raw_ep, ctype, 200, fpath, rel, source="captured_post")
        elif ("json" in ctype or rel.endswith(".json")) and ("/api/" in k or "graphql" in k.lower() or "/_next/data/" in k):
            _add_ep("GET", k, ctype, 200, fpath, rel, source="captured_get")

    # 2. Passive CDP XHR/Fetch/GraphQL telemetry
    for req in cdp_requests:
        url = req.get("url") or ""
        method = (req.get("method") or "GET").upper()
        mime = req.get("mime_type") or ""
        status = int(req.get("status") or 200)
        parsed = urllib.parse.urlparse(url)
        map_key = parsed.path + (("?" + parsed.query) if parsed.query else "")
        matched_entry = map_data.get(f"{method} {map_key}") or map_data.get(map_key)
        fpath = (site_dir / matched_entry["f"]) if (matched_entry and "f" in matched_entry) else None
        rel = matched_entry["f"] if (matched_entry and "f" in matched_entry) else ""
        _add_ep(method, url, mime or "application/json", status, fpath, rel, source="cdp_network")

    # 3. Static JS discovery for unvisited API endpoints
    scanned = 0
    for fpath in site_dir.rglob("*"):
        if not fpath.is_file() or fpath.suffix.lower() not in (".js", ".mjs"):
            continue
        if REA_DIR_NAME in fpath.parts or "_studio" in fpath.parts or scanned > 1_500_000:
            continue
        try:
            txt = fpath.read_text(encoding="utf-8", errors="ignore")[:120_000]
            scanned += len(txt)
        except OSError:
            continue
        for match in STATIC_ENDPOINT_RE.findall(txt):
            if any(x in match.lower() for x in (".png", ".jpg", ".svg", ".css", ".woff", "schema.org", "w3.org")):
                continue
            _add_ep("GET", match, "application/json", 200, None, "", source="static_js_probe")

    ep_list = sorted(endpoints.values(), key=lambda x: (not x["has_local_mock"], x["path"], x["method"]))

    # OpenAPI 3.0.3 generation
    openapi_paths: Dict[str, Any] = {}
    for ep in ep_list:
        p = ep["path"]
        m = ep["method"].lower()
        op: Dict[str, Any] = {
            "summary": f"Discovered via {ep['source']}",
            "responses": {
                str(ep.get("status") or 200): {
                    "description": "Captured or inferred response",
                }
            },
        }
        if ep.get("schema"):
            op["responses"][str(ep.get("status") or 200)]["content"] = {
                "application/json": {"schema": ep["schema"]}
            }
        openapi_paths.setdefault(p, {})[m] = op

    openapi_doc = {
        "openapi": "3.0.3",
        "info": {
            "title": f"R.E.A. Reconstructed API — {site_dir.name}",
            "version": "1.0.0",
            "description": "Endpoints REST/GraphQL extraits par le moteur R.E.A. de SiteCloner SaaS.",
        },
        "paths": openapi_paths,
    }
    return ep_list, openapi_doc, {"routes": mock_index}


def _assets_breakdown(site_dir: Path) -> Dict[str, int]:
    buckets = Counter()
    ext_map = {
        ".html": "html", ".htm": "html",
        ".js": "js", ".mjs": "js",
        ".css": "css",
        ".png": "images", ".jpg": "images", ".jpeg": "images", ".webp": "images", ".svg": "images", ".avif": "images", ".gif": "images",
        ".woff": "fonts", ".woff2": "fonts", ".ttf": "fonts", ".otf": "fonts",
        ".glb": "3d_wasm", ".gltf": "3d_wasm", ".wasm": "3d_wasm", ".drc": "3d_wasm", ".ktx2": "3d_wasm", ".hdr": "3d_wasm", ".riv": "3d_wasm",
        ".mp4": "media", ".webm": "media", ".mp3": "media", ".wav": "media", ".ogg": "media",
        ".map": "sourcemaps", ".json": "json",
    }
    for fpath in site_dir.rglob("*"):
        if not fpath.is_file() or REA_DIR_NAME in fpath.parts or "_studio" in fpath.parts:
            continue
        buckets[ext_map.get(fpath.suffix.lower(), "other")] += 1
    return dict(buckets)


def _build_clean_room_blueprint(report: Dict[str, Any]) -> str:
    stack_txt = ", ".join(s["name"] for s in report.get("tech_stack", [])) or "HTML/CSS/JS standard"
    sm = report.get("sourcemaps") or {}
    apis = report.get("apis") or []
    storage = report.get("storage") or {}

    lines = [
        f"# R.E.A. Clean-Room Blueprint — {report.get('site_id')}",
        f"- **URL source :** {report.get('origin_url') or 'N/A'}",
        f"- **Généré le :** {report.get('generated_at')}",
        f"- **Stack détectée :** {stack_txt}",
        f"- **Source Maps trouvées :** {sm.get('sourcemaps_count', 0)} ({sm.get('app_files_count', 0)} fichiers app, {sm.get('total_lines', 0)} lignes)",
        f"- **Endpoints API / GraphQL :** {len(apis)} ({sum(1 for a in apis if a.get('has_local_mock'))} avec mock local)",
        f"- **Clés localStorage / sessionStorage :** {len(storage.get('localStorage', {}))} / {len(storage.get('sessionStorage', {}))}",
        "",
        "## 1. Architecture & Arborescence reconstituée",
    ]
    for f in (sm.get("files") or [])[:25]:
        tag = "vendor" if f.get("vendor") else "app"
        lines.append(f"- `sources/{f['path']}` ({f['lines']} lignes · {tag})")
    if not sm.get("files"):
        lines.append("- Aucune source map publique exposée : utilisez l'export **Code Propre** du Studio (HTML -> React/Tailwind).")

    lines += ["", "## 2. Endpoints API identifiés (voir `openapi.json`)"]
    for ep in apis[:25]:
        mock_flag = " [MOCK LOCAL]" if ep.get("has_local_mock") else ""
        lines.append(f"- `{ep['method']} {ep['path']}` ({ep['source']}){mock_flag}")
    if not apis:
        lines.append("- Aucun endpoint XHR/GraphQL dynamique détecté (site principalement statique/SSG).")

    lines += [
        "",
        "## 3. Méthodologie R.E.A. (Inspect -> Understand -> Recreate)",
        "1. Inspecter les tokens visuels du Studio (`/design`) et les composants extraits dans `_rea/sources/`.",
        "2. Importer `_rea/openapi.json` pour recréer les contrats d'API backend.",
        "3. Reconstruire une implémentation propre dans votre stack cible (Next.js / React / Tailwind).",
    ]
    return "\n".join(lines) + "\n"


def analyze_site_rea(
    site_dir: Path,
    origin_url: str = "",
    runtime_trace: Optional[Dict[str, Any]] = None,
    fetch_url: Optional[Callable[[str], Optional[bytes]]] = None,
) -> Dict[str, Any]:
    """
    Runs full R.E.A. (Reverse Engineer Anything) extraction on a cloned site folder
    and writes structured artifacts into `<site_dir>/_rea/`.
    """
    site_dir = Path(site_dir)
    rea_dir = _rea_dir(site_dir)
    rea_dir.mkdir(parents=True, exist_ok=True)

    map_data: Dict[str, Any] = {}
    map_path = site_dir / "_map.json"
    if map_path.is_file():
        try:
            map_data = json.loads(map_path.read_text(encoding="utf-8"))
        except Exception:
            map_data = {}

    if not origin_url:
        rep_txt = site_dir / "_clone-report.txt"
        if rep_txt.is_file():
            m = re.search(r"Source\s*:\s*(\S+)", rep_txt.read_text(encoding="utf-8", errors="ignore"))
            if m:
                origin_url = m.group(1).strip()

    trace = runtime_trace or {}
    sm_report = unpack_sourcemaps(site_dir, map_data, origin_url=origin_url, fetch_url=fetch_url)
    tech_stack = _detect_tech_stack(site_dir, trace.get("runtime_flags") or {})
    apis, openapi_doc, mock_cfg = _build_api_inventory(
        site_dir, map_data, trace.get("cdp_requests") or []
    )

    storage = {
        "localStorage": dict(list((trace.get("localStorage") or {}).items())[:40]),
        "sessionStorage": dict(list((trace.get("sessionStorage") or {}).items())[:30]),
        "websockets": list((trace.get("websockets") or [])[:20]),
        "cdp_captured_requests": len(trace.get("cdp_requests") or []),
    }

    report: Dict[str, Any] = {
        "available": True,
        "engine": "SiteCloner R.E.A. (Reverse Engineer Anything)",
        "site_id": site_dir.name,
        "origin_url": origin_url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tech_stack": tech_stack,
        "sourcemaps": sm_report,
        "apis": apis,
        "apis_count": len(apis),
        "mocks_count": len(mock_cfg.get("routes") or {}),
        "storage": storage,
        "assets_breakdown": _assets_breakdown(site_dir),
    }
    report["clean_room_blueprint"] = _build_clean_room_blueprint(report)

    (rea_dir / "rea-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (rea_dir / "openapi.json").write_text(
        json.dumps(openapi_doc, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (rea_dir / "api-mocks.json").write_text(
        json.dumps(mock_cfg, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (rea_dir / "CLEAN-ROOM-BLUEPRINT.md").write_text(
        report["clean_room_blueprint"], encoding="utf-8"
    )
    return report


def load_rea_report(site_dir: Path) -> Optional[Dict[str, Any]]:
    rp = _rea_dir(Path(site_dir)) / "rea-report.json"
    if not rp.is_file():
        return None
    try:
        return json.loads(rp.read_text(encoding="utf-8"))
    except Exception:
        return None


def read_rea_source_file(site_dir: Path, rel_path: str) -> Optional[str]:
    """Safely reads a reconstructed file from `<site_dir>/_rea/sources/`."""
    sources_root = (_rea_dir(Path(site_dir)) / "sources").resolve()
    if not sources_root.is_dir():
        return None
    clean = (rel_path or "").lstrip("/").replace("\\", "/")
    target = (sources_root / clean).resolve()
    try:
        target.relative_to(sources_root)
    except ValueError:
        return None
    if not target.is_file():
        return None
    return target.read_text(encoding="utf-8", errors="replace")


def build_rea_bundle_zip(site_dir: Path) -> io.BytesIO:
    """Packages all reconstructed source files, OpenAPI spec, and R.E.A. blueprint into a ZIP."""
    site_dir = Path(site_dir)
    rea_dir = _rea_dir(site_dir)
    if not (rea_dir / "rea-report.json").is_file():
        analyze_site_rea(site_dir)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for fname in ("rea-report.json", "openapi.json", "api-mocks.json", "CLEAN-ROOM-BLUEPRINT.md"):
            fp = rea_dir / fname
            if fp.is_file():
                z.write(fp, fname)
        sources_dir = rea_dir / "sources"
        if sources_dir.is_dir():
            for fp in sources_dir.rglob("*"):
                if fp.is_file():
                    z.write(fp, "sources/" + fp.relative_to(sources_dir).as_posix())
    buf.seek(0)
    return buf
