#!/usr/bin/env python3
"""
cloner.py - Multi-Page Core Engine for SiteCloner SaaS
Handles recursive multi-page website cloning, deep asset scanning (3D WebGL, models, textures, audio/video),
tracker stripping, intelligent local relative link rewriting, and offline readiness.
"""

import os
import re
import time
import shutil
import urllib.parse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
}

ASSET_REGEX = re.compile(
    r"""(?P<quote>["'`])(?P<url>(?:https?://[^"'`\s]+|/(?:assets|static|media|vendor|images|img|fonts|gl|models|audio|videos)/[^"'`\s]+|(?:\.{1,2}/)+[^"'`\s]+|[a-zA-Z0-9_\-\./]+\.(?:glb|gltf|drc|ktx2|exr|hdr|wasm|riv|webp|png|jpg|jpeg|svg|mp4|webm|mp3|ogg|wav|woff2|woff|ttf|css|js)))["'`]""",
    re.IGNORECASE
)

EXCLUDED_EXTENSIONS = {
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".exe", ".dmg", ".pkg",
    ".mp4", ".mp3", ".webm", ".ogg", ".wav", ".glb", ".gltf", ".bin"
}

def get_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries, pool_connections=25, pool_maxsize=25)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(HEADERS)
    return session

def strip_trackers(soup):
    """Strip Google Tag Manager, Analytics, and tracking snippets from HTML soup."""
    for script in soup.find_all("script"):
        src = script.get("src", "")
        text = script.string or ""
        if any(tracker in src.lower() for tracker in ["googletagmanager", "google-analytics", "gtag", "facebook", "hotjar", "clarity.ms"]):
            script.decompose()
        elif any(tracker in text.lower() for tracker in ["googletagmanager", "google-analytics", "gtag(", "fbq("]):
            script.decompose()

    for tag in soup.find_all(["script", "link"]):
        if tag.has_attr("integrity"):
            del tag["integrity"]
        if tag.has_attr("crossorigin"):
            del tag["crossorigin"]

def scan_js_for_assets(js_text, base_url):
    """Deep scans javascript content for relative and absolute asset URLs."""
    discovered = set()
    for match in ASSET_REGEX.finditer(js_text):
        raw_path = match.group("url")
        if "${" in raw_path or "}" in raw_path or " " in raw_path:
            continue
        full_url = urllib.parse.urljoin(base_url, raw_path)
        discovered.add((raw_path, full_url))
    return discovered

def download_file(session, url, target_path):
    """Downloads a single file and writes it to target_path."""
    try:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        resp = session.get(url, timeout=15, stream=True)
        if resp.status_code == 200:
            with open(target_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=16384):
                    f.write(chunk)
            return True, os.path.getsize(target_path)
    except Exception:
        pass
    return False, 0

def url_to_local_html_path(page_url):
    """Converts a page URL into a clean local relative HTML file path."""
    parsed = urllib.parse.urlparse(page_url)
    path = parsed.path.strip("/")
    if not path:
        return "index.html"
    if path.endswith(".html") or path.endswith(".htm"):
        return path

    ext = os.path.splitext(path)[1].lower()
    if ext and ext not in [".html", ".htm", ".php", ".asp", ".aspx"]:
        return path

    clean_path = path.rstrip("/")
    return f"{clean_path}.html"

def clone_site(url, dest_dir, crawl_all_pages=True, max_pages=50, progress_callback=None):
    """
    Clones the target website into dest_dir.
    If crawl_all_pages is True, discovers and clones all internal pages up to max_pages.
    Downloads all HTML, CSS, JS, images, fonts, 3D models, audio, videos, and KTX2 textures.
    Rewrites internal links and asset paths to work seamlessly offline.
    """
    start_time = time.time()
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    session = get_session()

    clean_base_url, _ = urllib.parse.urldefrag(url)
    parsed_base = urllib.parse.urlparse(clean_base_url)
    base_netloc = parsed_base.netloc.lower()

    pages_to_crawl = [clean_base_url]
    visited_pages = set()
    crawled_pages_data = {}  # page_url -> {"soup": soup, "local_path": local_path}
    assets_to_download = {}  # full_url -> relative_local_path
    page_title = base_netloc

    def register_asset(link_url, current_page_url):
        if not link_url or link_url.startswith("data:") or link_url.startswith("#") or link_url.startswith("javascript:"):
            return None
        full = urllib.parse.urljoin(current_page_url, link_url)
        parsed = urllib.parse.urlparse(full)
        clean_path = parsed.path.lstrip("/")
        if not clean_path:
            return None
        rel_local = clean_path
        assets_to_download[full] = rel_local
        return rel_local

    # 1. CRAWLING ALL PAGES
    page_count = 0
    while pages_to_crawl and page_count < (max_pages if crawl_all_pages else 1):
        current_url = pages_to_crawl.pop(0)
        clean_current, _ = urllib.parse.urldefrag(current_url)

        if clean_current in visited_pages:
            continue
        visited_pages.add(clean_current)
        page_count += 1

        local_html_path = url_to_local_html_path(clean_current)
        short_label = urllib.parse.urlparse(clean_current).path or "/"

        if progress_callback:
            progress_callback(page_count, max_pages if crawl_all_pages else 1, f"Exploration page {page_count} : {short_label}")

        try:
            resp = session.get(clean_current, timeout=12)
            if resp.status_code != 200 or "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            html_text = resp.text
        except Exception:
            continue

        soup = BeautifulSoup(html_text, "html.parser")
        strip_trackers(soup)

        if clean_current == clean_base_url and soup.title and soup.title.string:
            page_title = soup.title.string.strip()

        # Extract internal links for multi-page crawling
        if crawl_all_pages:
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if not href or href.startswith("data:") or href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:") or href.startswith("javascript:"):
                    continue
                full_link = urllib.parse.urljoin(clean_current, href)
                clean_link, _ = urllib.parse.urldefrag(full_link)
                link_parsed = urllib.parse.urlparse(clean_link)

                # Same domain and not a non-HTML asset
                if link_parsed.netloc.lower() == base_netloc:
                    path_ext = os.path.splitext(link_parsed.path)[1].lower()
                    if path_ext not in EXCLUDED_EXTENSIONS:
                        if clean_link not in visited_pages and clean_link not in pages_to_crawl:
                            if len(visited_pages) + len(pages_to_crawl) < max_pages:
                                pages_to_crawl.append(clean_link)

        # Register all assets referenced on this page
        for link in soup.find_all("link", href=True):
            register_asset(link["href"], clean_current)

        for script in soup.find_all("script", src=True):
            register_asset(script["src"], clean_current)

        for img in soup.find_all(["img", "source"], src=True):
            register_asset(img["src"], clean_current)

        # Handle srcset
        for elem in soup.find_all(srcset=True):
            for candidate in elem["srcset"].split(","):
                cand_url = candidate.strip().split(" ")[0]
                register_asset(cand_url, clean_current)

        for media in soup.find_all(["video", "audio"], src=True):
            register_asset(media["src"], clean_current)

        for style in soup.find_all("style"):
            if style.string:
                for match in re.finditer(r'url\([\'"]?([^\'"\)]+)[\'"]?\)', style.string):
                    register_asset(match.group(1), clean_current)

        crawled_pages_data[clean_current] = {
            "soup": soup,
            "local_path": local_html_path
        }

    total_discovered_pages = len(crawled_pages_data)

    # 2. SCAN JS & CSS FOR HIDDEN 3D/WEBGL ASSETS
    if progress_callback:
        progress_callback(1, 4, f"Deep Scan JS & WebGL sur {len(assets_to_download)} ressources...")

    js_css_urls = [u for u in assets_to_download.keys() if u.endswith(".js") or u.endswith(".css") or ".js?" in u or ".css?" in u]
    for script_url in js_css_urls:
        try:
            r = session.get(script_url, timeout=10)
            if r.status_code == 200:
                discovered = scan_js_for_assets(r.text, script_url)
                for raw, full in discovered:
                    register_asset(full, script_url)
        except Exception:
            pass

    # 3. REWRITE LINKS AND ASSET PATHS FOR COMPLETE OFFLINE BROWSING
    if progress_callback:
        progress_callback(2, 4, f"Réécriture des liens relatifs sur {total_discovered_pages} pages...")

    for page_url, pdata in crawled_pages_data.items():
        soup = pdata["soup"]
        current_local_path = pdata["local_path"]
        current_dir = os.path.dirname(current_local_path)

        def make_rel_path(target_path):
            if current_dir:
                return os.path.relpath(target_path, current_dir).replace("\\", "/")
            return target_path.replace("\\", "/")

        # Rewrite internal <a> navigation links
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if not href or href.startswith("data:") or href.startswith("mailto:") or href.startswith("tel:") or href.startswith("javascript:"):
                continue
            if href.startswith("#"):
                continue

            full_link = urllib.parse.urljoin(page_url, href)
            clean_link, fragment = urllib.parse.urldefrag(full_link)
            link_parsed = urllib.parse.urlparse(clean_link)

            if link_parsed.netloc.lower() == base_netloc:
                target_local_html = url_to_local_html_path(clean_link)
                rel_link = make_rel_path(target_local_html)
                if fragment:
                    rel_link = f"{rel_link}#{fragment}"
                a_tag["href"] = rel_link

        # Rewrite asset references
        for link in soup.find_all("link", href=True):
            full = urllib.parse.urljoin(page_url, link["href"])
            if full in assets_to_download:
                link["href"] = make_rel_path(assets_to_download[full])

        for script in soup.find_all("script", src=True):
            full = urllib.parse.urljoin(page_url, script["src"])
            if full in assets_to_download:
                script["src"] = make_rel_path(assets_to_download[full])

        for img in soup.find_all(["img", "source"], src=True):
            full = urllib.parse.urljoin(page_url, img["src"])
            if full in assets_to_download:
                img["src"] = make_rel_path(assets_to_download[full])

        for media in soup.find_all(["video", "audio"], src=True):
            full = urllib.parse.urljoin(page_url, media["src"])
            if full in assets_to_download:
                media["src"] = make_rel_path(assets_to_download[full])

    # 4. DOWNLOAD ALL ASSETS IN PARALLEL
    total_assets = len(assets_to_download)
    downloaded_count = 0
    total_bytes = 0
    errors = []

    if progress_callback:
        progress_callback(3, 4, f"Téléchargement de {total_assets} assets (images, 3D, vidéos, scripts)...")

    def fetch_worker(item):
        asset_url, rel_path = item
        target_file = dest_dir / rel_path
        success, size = download_file(session, asset_url, target_file)
        return asset_url, rel_path, success, size

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(fetch_worker, item): item for item in assets_to_download.items()}
        for future in as_completed(futures):
            downloaded_count += 1
            a_url, r_path, ok, sz = future.result()
            if ok:
                total_bytes += sz
            else:
                errors.append(a_url)
            if progress_callback and downloaded_count % 5 == 0:
                progress_callback(downloaded_count, total_assets, f"Asset ({downloaded_count}/{total_assets}) : {os.path.basename(r_path)}")

    # 5. WRITE ALL HTML PAGES TO DISK
    if progress_callback:
        progress_callback(4, 4, f"Sauvegarde de {total_discovered_pages} pages HTML...")

    for page_url, pdata in crawled_pages_data.items():
        out_file = dest_dir / pdata["local_path"]
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(str(pdata["soup"]))

    # ----- Domain stripping -----
    def _strip_domain_from_file(file_path: Path, domain: str):
        try:
            text = file_path.read_text(encoding="utf-8")
        except Exception:
            return
        patterns = [
            rf"https?://{re.escape(domain)}",
            rf"//{re.escape(domain)}",
            rf"{re.escape(domain)}"
        ]
        for pat in patterns:
            text = re.sub(pat, "", text, flags=re.IGNORECASE)
        file_path.write_text(text, encoding="utf-8")

    # Apply stripping to relevant files in the cloned site
    for root, _, files in os.walk(dest_dir):
        for name in files:
            if name.lower().endswith((".html", ".htm", ".js", ".css", ".txt", ".json")):
                _strip_domain_from_file(Path(root) / name, base_netloc)

    duration = round(time.time() - start_time, 2)
    return {
        "success": True,
        "title": page_title,
        "total_pages": total_discovered_pages,
        "total_files": downloaded_count + total_discovered_pages,
        "total_size": total_bytes,
        "errors": len(errors),
        "duration": duration,
        "dest_dir": str(dest_dir)
    }
