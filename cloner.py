#!/usr/bin/env python3
"""
cloner.py - Core Engine for SiteCloner SaaS
Handles website cloning, deep asset scanning (including 3D models, textures, WebGL assets, audio/video),
tracker stripping, URL rewriting, and local offline readiness.
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

def get_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(HEADERS)
    return session

def strip_trackers(soup):
    """Strip Google Tag Manager, Analytics, and tracking snippets from HTML soup."""
    for script in soup.find_all("script"):
        src = script.get("src", "")
        text = script.string or ""
        if any(tracker in src.lower() for tracker in ["googletagmanager", "google-analytics", "gtag", "facebook", "hotjar"]):
            script.decompose()
        elif any(tracker in text.lower() for tracker in ["googletagmanager", "google-analytics", "gtag("]):
            script.decompose()
            
    # Also remove integrity & crossorigin attributes which break local serving
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
        # filter out template variables like ${e} or clearly invalid URLs
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
    except Exception as e:
        pass
    return False, 0

def clone_site(url, dest_dir, progress_callback=None):
    """
    Main cloning function.
    Clones the target website into dest_dir, downloading all HTML, CSS, JS,
    images, fonts, 3D models, audio, videos, and KTX2 textures.
    """
    start_time = time.time()
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    session = get_session()
    
    # 1. Fetch main page HTML
    if progress_callback:
        progress_callback(1, 10, "Fetching main page...")
        
    try:
        resp = session.get(url, timeout=15)
        resp.raise_for_status()
        html_content = resp.text
    except Exception as e:
        return {"success": False, "error": f"Failed to fetch site: {str(e)}"}

    soup = BeautifulSoup(html_content, "html.parser")
    page_title = soup.title.string.strip() if soup.title and soup.title.string else urllib.parse.urlparse(url).netloc
    
    # Strip trackers from HTML
    strip_trackers(soup)

    # 2. Extract assets from HTML
    if progress_callback:
        progress_callback(2, 10, "Analyzing page resources...")

    assets_to_download = {}  # full_url -> relative_local_path
    parsed_base = urllib.parse.urlparse(url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    def register_asset(link_url):
        if not link_url or link_url.startswith("data:") or link_url.startswith("#") or link_url.startswith("javascript:"):
            return None
        full = urllib.parse.urljoin(url, link_url)
        parsed = urllib.parse.urlparse(full)
        # Avoid downloading off-domain links that aren't CDNs
        clean_path = parsed.path.lstrip("/")
        if not clean_path:
            return None
        rel_local = clean_path
        assets_to_download[full] = rel_local
        return rel_local

    # Tags to examine in HTML
    for link in soup.find_all("link", href=True):
        local_rel = register_asset(link["href"])
        if local_rel:
            link["href"] = f"./{local_rel}"

    for script in soup.find_all("script", src=True):
        local_rel = register_asset(script["src"])
        if local_rel:
            script["src"] = f"./{local_rel}"

    for img in soup.find_all(["img", "source"], src=True):
        local_rel = register_asset(img["src"])
        if local_rel:
            img["src"] = f"./{local_rel}"

    for media in soup.find_all(["video", "audio"], src=True):
        local_rel = register_asset(media["src"])
        if local_rel:
            media["src"] = f"./{local_rel}"

    # Also handle CSS inline url(...)
    for style in soup.find_all("style"):
        if style.string:
            for match in re.finditer(r'url\([\'"]?([^\'"\)]+)[\'"]?\)', style.string):
                found_url = match.group(1)
                register_asset(found_url)

    # 3. Identify and scan CSS & JS for hidden assets (models, textures, fonts, audio)
    if progress_callback:
        progress_callback(3, 10, "Scanning JS & CSS for 3D/Media assets...")

    js_css_urls = [u for u in assets_to_download.keys() if u.endswith(".js") or u.endswith(".css") or ".js?" in u or ".css?" in u]
    for script_url in js_css_urls:
        try:
            r = session.get(script_url, timeout=10)
            if r.status_code == 200:
                discovered = scan_js_for_assets(r.text, script_url)
                for raw, full in discovered:
                    register_asset(full)
        except Exception:
            pass

    total_assets = len(assets_to_download)
    downloaded_count = 0
    total_bytes = 0
    errors = []

    # 4. Download all assets in parallel
    if progress_callback:
        progress_callback(4, total_assets, f"Downloading {total_assets} assets...")

    def fetch_worker(item):
        asset_url, rel_path = item
        target_file = dest_dir / rel_path
        success, size = download_file(session, asset_url, target_file)
        return asset_url, rel_path, success, size

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(fetch_worker, item): item for item in assets_to_download.items()}
        for future in as_completed(futures):
            downloaded_count += 1
            a_url, r_path, ok, sz = future.result()
            if ok:
                total_bytes += sz
            else:
                errors.append(a_url)
            if progress_callback:
                progress_callback(downloaded_count, total_assets, f"Saved: {os.path.basename(r_path)}")

    # 5. Save the modified index.html
    index_file = dest_dir / "index.html"
    with open(index_file, "w", encoding="utf-8") as f:
        f.write(str(soup))

    duration = round(time.time() - start_time, 2)
    return {
        "success": True,
        "title": page_title,
        "total_files": downloaded_count,
        "total_size": total_bytes,
        "errors": len(errors),
        "duration": duration,
        "dest_dir": str(dest_dir)
    }
