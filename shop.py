#!/usr/bin/env python3
"""
shop.py - Marketplace for SiteCloner SaaS: site designs, templates, prompts, skills, software and 3D assets.
Public catalog (search, categories, favorites, preview), free downloads, Stripe Checkout and secure download links
for paid products, plus the admin API to manage products, their media and orders. Mounted by app.py (init_shop).

Env: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, PUBLIC_URL (e.g. https://mysite.com),
     SHOP_CURRENCY (default eur), optional SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASSWORD/SMTP_FROM.
"""

import json
import os
import re
import secrets
import shutil
import smtplib
import sqlite3
import time
import urllib.parse
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

from flask import (Blueprint, abort, jsonify, render_template, request, send_file)
from werkzeug.utils import secure_filename

from admin import DATA_DIR, login_required

DB_FILE = DATA_DIR / "shop.db"
PRODUCTS_DIR = DATA_DIR / "products"
CLONED_DIR = Path(os.environ.get("CLONED_DIR") or (Path(__file__).resolve().parent / "cloned_sites"))

LINK_TTL = 7 * 24 * 3600
MAX_DOWNLOADS = 5
PLATFORM_FEE_RATE = 0.01
COVER_EXT = {".png", ".jpg", ".jpeg", ".webp"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".avif"}
VIDEO_EXT = {".mp4", ".webm", ".mov"}
FILE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".pdf", ".apk", ".exe", ".msi", ".dmg", ".appimage", ".deb",
            ".json", ".md", ".txt", ".csv", ".fig", ".sketch", ".xd", ".psd", ".ai", ".svg",
            ".glb", ".gltf", ".fbx", ".obj", ".blend", ".usdz", ".html", ".css", ".js", ".py"}
CATEGORIES = {
    "design": "Sites & designs web",
    "software": "Logiciels & applications",
    "skill": "Skills & agents IA",
    "template": "Templates & composants",
    "prompt": "Prompts",
    "asset": "Assets 3D & graphiques",
    "other": "Autres produits digitaux",
}
CATEGORY_CONFIG = {
    "design": {
        "label": "Sites & designs web",
        "short": "Site web / Design",
        "hint": "Ideal pour un site complet, une landing page ou une maquette web interactive.",
        "title_ph": "Ex. Landing Page SaaS « Orion »",
        "tagline_ph": "Architecture moderne, responsive et prête à déployer",
        "desc_ph": "Nombre de pages, animations, polices, compatibilité mobile et instructions d'installation…",
        "show_demo": True,
        "demo_label": "URL de démo / prévisualisation live",
        "demo_ph": "https://demo.exemple.com ou /preview/mon-site/",
        "show_preview": False,
        "preview_label": "Extrait HTML / CSS (optionnel)",
        "preview_ph": "",
        "file_label": "Archive du site ou maquette (.zip, .fig, .html…)",
        "file_accept": ".zip,.rar,.7z,.fig,.sketch,.xd,.html,.css,.pdf",
        "file_hint": "Formats recommandés : ZIP du site statique, fichier Figma/Sketch ou PDF.",
        "media_label": "Captures d'écran & vidéos de démo (recommandé)",
        "specs": [
            {"key": "stack", "label": "Technologies / Stack", "placeholder": "HTML/CSS/JS, Framer, React, Tailwind"},
            {"key": "pages", "label": "Pages & Responsive", "placeholder": "5 pages · Desktop, Tablette, Mobile"},
        ],
    },
    "software": {
        "label": "Logiciels & applications",
        "short": "Logiciel / App",
        "hint": "Pour un exécutable desktop, une application mobile, un outil CLI ou un script prêt à tourner.",
        "title_ph": "Ex. Scanner SEO CLI ou App Desktop Facturation",
        "tagline_ph": "Automatisez vos tâches sans configuration complexe",
        "desc_ph": "Fonctionnalités principales, prérequis système, installation et licence d'utilisation…",
        "show_demo": True,
        "demo_label": "Site officiel / documentation / vidéo (optionnel)",
        "demo_ph": "https://docs.mon-outil.com",
        "show_preview": True,
        "preview_label": "Commande d'installation / Quickstart (optionnel)",
        "preview_ph": "pip install mon-outil\nmon-outil --help",
        "file_label": "Installeur, binaire ou code source (.zip, .exe, .dmg, .apk, .py…)",
        "file_accept": ".zip,.rar,.7z,.tar,.gz,.exe,.msi,.dmg,.appimage,.deb,.apk,.py,.js,.json,.md",
        "file_hint": "Joignez l'exécutable (.exe, .dmg, .apk), l'archive source (.zip) ou le script.",
        "media_label": "Captures de l'interface / vidéo de démonstration",
        "specs": [
            {"key": "platforms", "label": "Systèmes compatibles", "placeholder": "Windows, macOS, Linux, Android, Web"},
            {"key": "version", "label": "Version & licence", "placeholder": "v1.0 · Licence mono-utilisateur"},
        ],
    },
    "skill": {
        "label": "Skills & agents IA",
        "short": "Skill / Agent IA",
        "hint": "Pour un fichier SKILL.md, un agent autonome, un serveur MCP ou un workflow IA.",
        "title_ph": "Ex. Skill Audit Cybersécurité ou Agent Support Client",
        "tagline_ph": "Étendez votre assistant IA avec des capacités prêtes à l'emploi",
        "desc_ph": "Cas d'usage, outils ou MCP requis, instructions d'intégration et résultats attendus…",
        "show_demo": True,
        "demo_label": "Lien dépôt / documentation (optionnel)",
        "demo_ph": "https://github.com/...",
        "show_preview": True,
        "preview_label": "Contenu SKILL.md / instructions de l'agent",
        "preview_ph": "# Mon Skill IA\n\n## Rôle\nTu assistes l'utilisateur sur...",
        "file_label": "Package du skill ou scripts (.md, .json, .zip, .py)",
        "file_accept": ".md,.json,.zip,.py,.txt,.tar,.gz",
        "file_hint": "Facultatif si votre SKILL.md complet est collé ci-dessus (un fichier .md sera généré automatiquement).",
        "media_label": "Captures d'exécution ou résultats (optionnel)",
        "specs": [
            {"key": "compatibility", "label": "Plateformes IA compatibles", "placeholder": "Claude Code, Antigravity, Cursor, OpenAI"},
            {"key": "runtime", "label": "Runtime / Dépendances", "placeholder": "Markdown SKILL.md, Python 3.11, MCP"},
        ],
    },
    "template": {
        "label": "Templates & composants",
        "short": "Template / UI",
        "hint": "Pour un kit UI, des composants réutilisables, un thème ou une base de projet.",
        "title_ph": "Ex. Kit UI Dashboard SaaS Tailwind & React",
        "tagline_ph": "35 composants prêts pour la production en mode sombre et clair",
        "desc_ph": "Composants inclus, dépendances, structure des dossiers et guide d'intégration…",
        "show_demo": True,
        "demo_label": "Aperçu interactif / Storybook (optionnel)",
        "demo_ph": "https://ui.exemple.com",
        "show_preview": True,
        "preview_label": "Extrait de code / installation (optionnel)",
        "preview_ph": "npm install\nnpm run dev",
        "file_label": "Archive du template ou fichier design (.zip, .fig, .html, .css, .js)",
        "file_accept": ".zip,.rar,.7z,.fig,.sketch,.xd,.html,.css,.js,.json,.md",
        "file_hint": "Joignez l'archive du projet (.zip) ou la maquette source (.fig).",
        "media_label": "Aperçus visuels des écrans et composants",
        "specs": [
            {"key": "framework", "label": "Framework / Format", "placeholder": "React, Next.js, Tailwind CSS, HTML, Figma"},
            {"key": "license", "label": "Licence & inclus", "placeholder": "Usage commercial · Dark + Light"},
        ],
    },
    "prompt": {
        "label": "Prompts",
        "short": "Prompt IA",
        "hint": "Renseignez votre prompt structuré, l'IA cible et des exemples de rendu — aucun ZIP obligatoire.",
        "title_ph": "Ex. Pack 15 Prompts Copywriting B2B Haute Conversion",
        "tagline_ph": "Prompts testés pour générer des séquences de vente prêtes à envoyer",
        "desc_ph": "Objectif du prompt, variables à personnaliser et conseils pour obtenir le meilleur rendu…",
        "show_demo": False,
        "demo_label": "Lien d'exemple (optionnel)",
        "demo_ph": "",
        "show_preview": True,
        "preview_label": "Prompt complet ou extrait (affiché avec bouton Copier & livré en .md)",
        "preview_ph": "Tu es un expert en...\n\nContexte : {{secteur}}\nObjectif : ...",
        "file_label": "Pack PDF, Markdown ou TXT (optionnel si prompt saisi ci-dessus)",
        "file_accept": ".md,.txt,.pdf,.json,.zip",
        "file_hint": "Si aucun fichier n'est joint, un fichier .md téléchargeable est généré à partir du texte du prompt.",
        "media_label": "Exemples de résultats générés (captures optionnelles)",
        "specs": [
            {"key": "ai_model", "label": "IA / Modèle cible", "placeholder": "ChatGPT GPT-4o, Claude 3.7, Midjourney v6, Gemini"},
            {"key": "prompt_format", "label": "Type de prompt", "placeholder": "Prompt système, Workflow multi-étapes, Image"},
        ],
    },
    "asset": {
        "label": "Assets 3D & graphiques",
        "short": "Asset 3D / Graphique",
        "hint": "Pour des modèles 3D, textures PBR, icônes vectorielles, illustrations ou PSD.",
        "title_ph": "Ex. Pack 40 Icônes 3D Glassmorphism (.glb + .png)",
        "tagline_ph": "Rendu studio haute résolution prêt pour le web et la 3D",
        "desc_ph": "Formats fournis, résolution, maillage/textures PBR, logiciels compatibles et droits d'usage…",
        "show_demo": False,
        "demo_label": "Lien aperçu 3D / portfolio (optionnel)",
        "demo_ph": "",
        "show_preview": False,
        "preview_label": "Notes techniques (optionnel)",
        "preview_ph": "",
        "file_label": "Archive ou fichier source 3D/graphique (.glb, .gltf, .fbx, .obj, .blend, .svg, .zip)",
        "file_accept": ".glb,.gltf,.fbx,.obj,.blend,.usdz,.svg,.psd,.ai,.zip,.rar,.7z",
        "file_hint": "Formats acceptés : GLB, GLTF, FBX, OBJ, BLEND, USDZ, SVG, PSD, AI ou ZIP.",
        "media_label": "Rendus visuels ou vidéo turntable (recommandé)",
        "specs": [
            {"key": "formats", "label": "Formats inclus", "placeholder": "GLB, FBX, BLEND, SVG, PNG 4K"},
            {"key": "resolution", "label": "Résolution / Polycount", "placeholder": "4K PBR · Low-poly web-ready"},
        ],
    },
    "other": {
        "label": "Autres produits digitaux",
        "short": "Autre produit",
        "hint": "E-books, datasets, automatisations n8n/Make, fichiers Notion ou ressources sur mesure.",
        "title_ph": "Ex. Template Notion CRM Freelance ou Workflow n8n",
        "tagline_ph": "Ressource digitale prête à utiliser en quelques minutes",
        "desc_ph": "Contenu détaillé du pack, prérequis, guide d'utilisation et support inclus…",
        "show_demo": True,
        "demo_label": "Lien de démonstration ou documentation (optionnel)",
        "demo_ph": "https://…",
        "show_preview": True,
        "preview_label": "Extrait texte / JSON / documentation (optionnel)",
        "preview_ph": "",
        "file_label": "Fichier ou archive à livrer (.zip, .pdf, .json, .csv, .md…)",
        "file_accept": ".zip,.rar,.7z,.pdf,.json,.md,.txt,.csv,.py,.js",
        "file_hint": "Joignez l'archive ou le document que l'acheteur recevra après paiement/téléchargement.",
        "media_label": "Captures ou vidéo de présentation (optionnel)",
        "specs": [
            {"key": "format", "label": "Format principal", "placeholder": "PDF, Notion, JSON n8n, CSV"},
            {"key": "requirements", "label": "Prérequis / Usage", "placeholder": "Aucun prérequis · Usage commercial"},
        ],
    },
}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

shop = Blueprint("shop", __name__, url_prefix="/shop")
shop_admin = Blueprint("shop_admin", __name__, url_prefix="/admin/api/shop")


# ---------- storage ----------

def db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    PRODUCTS_DIR.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            price_cents INTEGER NOT NULL,
            demo_url TEXT NOT NULL DEFAULT '',
            cover TEXT NOT NULL DEFAULT '',
            file TEXT NOT NULL DEFAULT '',
            published INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            amount_cents INTEGER NOT NULL,
            currency TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            stripe_session TEXT UNIQUE,
            token TEXT UNIQUE,
            token_expires INTEGER,
            downloads INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            paid_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            file TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0
        );
        """)
        cols = {r["name"] for r in c.execute("PRAGMA table_info(products)")}
        for name, ddl in (("category", "TEXT NOT NULL DEFAULT 'design'"), ("tagline", "TEXT NOT NULL DEFAULT ''"),
                          ("tags", "TEXT NOT NULL DEFAULT ''"), ("preview_text", "TEXT NOT NULL DEFAULT ''"),
                          ("featured", "INTEGER NOT NULL DEFAULT 0"), ("views", "INTEGER NOT NULL DEFAULT 0"),
                          ("free_downloads", "INTEGER NOT NULL DEFAULT 0"), ("updated_at", "INTEGER NOT NULL DEFAULT 0"),
                          ("clone_id", "TEXT NOT NULL DEFAULT ''"), ("author_name", "TEXT NOT NULL DEFAULT ''"),
                          ("author_email", "TEXT NOT NULL DEFAULT ''"),
                          ("owner_user_id", "TEXT NOT NULL DEFAULT ''"),
                          ("submission_status", "TEXT NOT NULL DEFAULT 'approved'"),
                          ("specs", "TEXT NOT NULL DEFAULT '{}'"),):
            if name not in cols:
                c.execute(f"ALTER TABLE products ADD COLUMN {name} {ddl}")
        ocols = {r["name"] for r in c.execute("PRAGMA table_info(orders)")}
        for name, ddl in (
            ("seller_user_id", "TEXT NOT NULL DEFAULT ''"),
            ("platform_fee_cents", "INTEGER NOT NULL DEFAULT 0"),
            ("seller_payout_cents", "INTEGER NOT NULL DEFAULT 0"),
            ("stripe_account_id", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in ocols:
                c.execute(f"ALTER TABLE orders ADD COLUMN {name} {ddl}")


def compute_split_cents(amount_cents):
    """Returns (platform_fee_cents, seller_payout_cents) using a 1% platform commission."""
    amt = max(0, int(amount_cents or 0))
    if amt <= 0:
        return 0, 0
    fee = max(1, round(amt * PLATFORM_FEE_RATE))
    return fee, max(0, amt - fee)


def _get_seller_connect_account(owner_user_id):
    """Reads a seller's Stripe Connect Express account status from users DB."""
    uid = (owner_user_id or "").strip()
    if not uid:
        return {"user_id": "", "stripe_account_id": "", "ready": False}
    try:
        from security.database import get_connection
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT stripe_account_id, stripe_charges_enabled, stripe_payouts_enabled FROM users WHERE user_id = ? AND is_active = 1",
                (uid,),
            ).fetchone()
        finally:
            conn.close()
    except Exception:
        return {"user_id": uid, "stripe_account_id": "", "ready": False}
    if not row:
        return {"user_id": uid, "stripe_account_id": "", "ready": False}
    acct_id = (row["stripe_account_id"] or "").strip()
    ready = bool(acct_id and row["stripe_charges_enabled"] and row["stripe_payouts_enabled"])
    return {"user_id": uid, "stripe_account_id": acct_id, "ready": ready}


def currency():
    return os.environ.get("SHOP_CURRENCY", "eur").lower()


def slugify(text):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "projet"


def public_url():
    return os.environ.get("PUBLIC_URL", "").rstrip("/") or request.host_url.rstrip("/")


def stripe_ready():
    return bool(os.environ.get("STRIPE_SECRET_KEY"))


def format_price(cents, cur=None):
    cur = (cur or currency()).upper()
    sym = {"EUR": "€", "USD": "$", "GBP": "£"}.get(cur)
    val = f"{cents / 100:.2f}".replace(".", ",") if cur == "EUR" else f"{cents / 100:.2f}"
    return f"{val} {sym}" if sym and cur == "EUR" else (f"{sym}{val}" if sym else f"{val} {cur}")


def send_mail(to, subject, body):
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
    try:
        msg = EmailMessage()
        msg["From"] = os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USER", "")
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=15) as s:
            s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"[shop] email failed: {e}")
        return False


def fulfill(session_id):
    """Mark an order as paid and create its download link (idempotent)."""
    with db() as c:
        order = c.execute("SELECT * FROM orders WHERE stripe_session=?", (session_id,)).fetchone()
        if not order:
            return None
        if order["status"] == "paid":
            return order
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        c.execute("UPDATE orders SET status='paid', token=?, token_expires=?, paid_at=? WHERE id=?",
                  (token, now + LINK_TTL, now, order["id"]))
        order = c.execute("SELECT * FROM orders WHERE id=?", (order["id"],)).fetchone()
        product = c.execute("SELECT title FROM products WHERE id=?", (order["product_id"],)).fetchone()
    link = f"{os.environ.get('PUBLIC_URL', '').rstrip('/')}/shop/download/{token}"
    send_mail(order["email"], f"Ton achat : {product['title'] if product else 'projet'}",
              f"Merci pour ton achat !\n\nTélécharge ton projet ici (valable 7 jours, {MAX_DOWNLOADS} téléchargements) :\n{link}\n")
    return order


# ---------- public pages ----------

@shop.app_template_global()
def price(cents):
    return format_price(cents)


def _clone_media(clone_id):
    """Return studio preview images for a cloned site without duplicating files."""
    if not clone_id:
        return []
    tdir = CLONED_DIR / clone_id / "_studio" / "thumbs"
    if not tdir.is_dir():
        return []
    thumbs = sorted(p.name for p in tdir.glob("*.jpg") if re.fullmatch(r"[0-9a-f]{12}", p.stem))
    if not thumbs:
        return []
    items = [{"id": 0, "kind": "image", "url": f"/__sc/studio/{clone_id}/cover.jpg"}]
    for fn in thumbs[:5]:
        items.append({"id": 0, "kind": "image", "url": f"/__sc/studio/{clone_id}/thumb/{fn}"})
    return items


def _clean_clone_title(cid, raw_title, url):
    host = urllib.parse.urlparse(url or "").netloc.split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    if host and "." in host:
        return host
    cleaned = re.sub(r"[\s_]+[0-9a-fA-F]{6,}$", "", raw_title or cid).strip(" -_")
    return cleaned or cid


def sync_cloned_sites():
    """Ensure every completed cloned site in cloned_sites/ is listed in the Marketplace catalog."""
    manifest_file = CLONED_DIR / "manifest.json"
    if not manifest_file.exists():
        return 0
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception:
        return 0
    if not isinstance(manifest, dict):
        return 0

    added = 0
    now = int(time.time())
    entries = sorted(manifest.items(), key=lambda kv: str(kv[1].get("date", "")), reverse=True)
    with db() as c:
        existing = {r[0] for r in c.execute("SELECT clone_id FROM products WHERE clone_id <> ''") if r[0]}
        has_featured = bool(c.execute("SELECT 1 FROM products WHERE published=1 AND featured=1").fetchone())
        for sid, m in entries:
            if not sid or sid in existing:
                continue
            sdir = CLONED_DIR / sid
            tdir = sdir / "_studio" / "thumbs"
            if not sdir.is_dir() or not (sdir / "_map.json").exists():
                continue
            if not tdir.is_dir() or not any(tdir.glob("*.jpg")):
                continue
            url = (m.get("url") or "").strip()
            title = _clean_clone_title(sid, m.get("title", ""), url)
            pages = int(m.get("total_pages") or 1)
            files = int(m.get("total_files") or 0)
            size_mb = round((m.get("total_size") or 0) / (1024 * 1024), 1)
            tagline = f"{pages} page{'s' if pages > 1 else ''} · {files} fichiers · {size_mb} Mo"
            desc = (
                f"Design web capturé depuis {url or title}.\n\n"
                f"Inclut {pages} page(s) HTML complète(s) et {files} fichiers locaux "
                f"(styles, médias, polices et scripts), prêt à être édité dans le Studio ou téléchargé en archive ZIP."
            )
            tags = ["site-web", "clone"]
            if pages > 1:
                tags.append("multi-pages")
            if "framer" in url.lower() or "framer" in sid.lower():
                tags.append("framer")
            if (m.get("total_size") or 0) > 25 * 1024 * 1024:
                tags.append("3d")
            try:
                created_at = int(datetime.strptime(m.get("date", ""), "%Y-%m-%d %H:%M").timestamp())
            except Exception:
                created_at = now
            base_slug = slugify(title)
            slug, n = base_slug, 1
            while c.execute("SELECT 1 FROM products WHERE slug=?", (slug,)).fetchone():
                n += 1
                slug = f"{base_slug}-{n}"
            featured = 0
            if not has_featured and pages >= 3:
                featured = 1
                has_featured = True
            c.execute(
                """INSERT INTO products
                   (slug, title, description, price_cents, demo_url, cover, file, published,
                    category, tagline, tags, preview_text, featured, created_at, updated_at, clone_id)
                   VALUES (?,?,?,0,?,'','',1,'design',?,?,?, ?,?,?,?)""",
                (slug, title[:200], desc[:8000], f"/preview/{sid}/", tagline[:160],
                 ",".join(tags), "", featured, created_at, now, sid),
            )
            added += 1
    return added


def _media_for(c, pids):
    out = {}
    if not pids:
        return out
    q = ",".join("?" * len(pids))
    for m in c.execute(f"SELECT * FROM media WHERE product_id IN ({q}) ORDER BY position, id", list(pids)):
        out.setdefault(m["product_id"], []).append({"id": m["id"], "kind": m["kind"], "url": f"/shop/media/{m['id']}"})
    return out


def _decode_specs(raw_specs, category):
    """Decodes stored JSON specs and maps labels cleanly according to CATEGORY_CONFIG."""
    try:
        parsed = json.loads(raw_specs or "{}")
        if not isinstance(parsed, dict):
            parsed = {}
    except Exception:
        parsed = {}
    cleaned = {str(k): str(v).strip() for k, v in parsed.items() if str(v).strip()}
    cfg = CATEGORY_CONFIG.get(category, CATEGORY_CONFIG["other"])
    label_map = {item["key"]: item["label"] for item in cfg.get("specs", [])}
    specs_list = [{"key": k, "label": label_map.get(k, k), "value": v} for k, v in cleaned.items()]
    return cleaned, specs_list


def _card(r, media):
    """What the catalog and the product page need about a product (also used as JSON)."""
    keys = r.keys()
    cat = r["category"] if "category" in keys else "design"
    clone_id = r["clone_id"] if "clone_id" in keys else ""
    items = media.get(r["id"], []) or (_clone_media(clone_id) if clone_id else [])
    cover = next((m["url"] for m in items if m["kind"] == "image"), None) or (f"/shop/cover/{r['id']}" if r["cover"] else None)
    has_file = bool(r["file"]) or bool(clone_id and (CLONED_DIR / clone_id).is_dir())
    specs_dict, specs_list = _decode_specs(r["specs"] if "specs" in keys else "{}", cat)
    return {
        "id": r["id"], "slug": r["slug"], "title": r["title"], "tagline": r["tagline"] if "tagline" in keys else "",
        "description": r["description"], "category": cat,
        "category_label": CATEGORIES.get(cat, "Autres"),
        "tags": [x.strip() for x in (r["tags"] or "").split(",") if x.strip()] if "tags" in keys else [],
        "price_cents": r["price_cents"], "free": r["price_cents"] == 0,
        "price": "Gratuit" if r["price_cents"] == 0 else format_price(r["price_cents"]),
        "cover": cover, "media": items, "has_video": any(m["kind"] == "video" for m in items),
        "demo_url": r["demo_url"], "preview_text": r["preview_text"] if "preview_text" in keys else "",
        "specs": specs_dict, "specs_list": specs_list,
        "featured": bool(r["featured"]) if "featured" in keys else False,
        "views": r["views"] if "views" in keys else 0, "downloads": r["free_downloads"] if "free_downloads" in keys else 0,
        "has_file": has_file, "clone_id": clone_id, "created_at": r["created_at"],
        "author_name": r["author_name"] if "author_name" in keys else "",
    }


@shop.route("/")
def catalog():
    sync_cloned_sites()
    with db() as c:
        rows = c.execute("SELECT * FROM products WHERE published=1 ORDER BY featured DESC, created_at DESC").fetchall()
        media = _media_for(c, [r["id"] for r in rows])
    items = [_card(r, media) for r in rows]
    used = sorted({i["category"] for i in items}, key=list(CATEGORIES).index)
    return render_template(
        "market_index.html",
        items=items,
        categories=CATEGORIES,
        category_config=CATEGORY_CONFIG,
        used_categories=used,
    )


@shop.route("/api/submit", methods=["POST"])
def submit_user_product():
    """Allows platform users to submit digital products, software, skills, sites, or apps for admin review."""
    try:
        from flask import session
        f = _parse_form(is_public=True)
        owner_uid = str(session.get("user_id") or "").strip()
        if f["price_cents"] > 0 and not owner_uid and not session.get("admin"):
            from accounts import account_gate_url
            return jsonify({
                "error": "Créez votre compte gratuit pour publier un produit payant et recevoir vos paiements (99 %).",
                "error_code": "ACCOUNT_REQUIRED",
                "redirect": account_gate_url("market", "/shop/#soumettre"),
            }), 401

        with db() as c:
            slug, n = slugify(f["title"]), 1
            while c.execute("SELECT 1 FROM products WHERE slug=?", (slug,)).fetchone():
                n += 1
                slug = f"{slugify(f['title'])}-{n}"
            now = int(time.time())
            cur = c.execute(
                f"INSERT INTO products (slug,{','.join(FIELDS)},created_at,updated_at) VALUES (?{',?' * len(FIELDS)},?,?)",
                (slug, *[f[k] for k in FIELDS], now, now),
            )
            pid = cur.lastrowid
            if owner_uid:
                c.execute("UPDATE products SET owner_user_id=? WHERE id=?", (owner_uid, pid))
            _save_files(c, pid, parsed=f, slug=slug)
        try:
            from security.database import log_event
            log_event("MARKET_SUBMISSION", "INFO", "MARKETPLACE", f"Nouveau produit soumis par {f['author_name']} : {f['title']} (en attente de validation)")
        except Exception:
            pass
        payout_required = False
        if f["price_cents"] > 0 and owner_uid:
            payout_required = not _get_seller_connect_account(owner_uid)["ready"]
        msg = "Produit envoyé ! Il sera visible sur la Marketplace après validation par l'administrateur."
        if payout_required:
            msg += " Pensez à connecter votre compte Stripe Express (onglet Paiements & Revenus) pour encaisser vos ventes directement (99 % pour vous, 1 % commission plateforme)."
        return jsonify({
            "success": True,
            "id": pid,
            "slug": slug,
            "submission_status": "pending",
            "payout_setup_required": payout_required,
            "payout_setup_url": "/account/profile?tab=payouts",
            "platform_fee_pct": 1,
            "seller_share_pct": 99,
            "message": msg,
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@shop.route("/p/<slug>")
def product(slug):
    with db() as c:
        p = c.execute("SELECT * FROM products WHERE slug=? AND published=1", (slug,)).fetchone()
        if not p:
            abort(404)
        c.execute("UPDATE products SET views=views+1 WHERE id=?", (p["id"],))
        related = c.execute("SELECT * FROM products WHERE published=1 AND id<>? AND category=? ORDER BY featured DESC, created_at DESC LIMIT 4",
                            (p["id"], p["category"])).fetchall()
        media = _media_for(c, [p["id"]] + [r["id"] for r in related])
    item = _card(p, media)
    owner_uid = (p["owner_user_id"] if "owner_user_id" in p.keys() else "") or ""
    seller_ready = True if not owner_uid else _get_seller_connect_account(owner_uid)["ready"]
    can_pay = stripe_ready() and bool(p["file"] or p["clone_id"]) and seller_ready
    seller_payout_missing = bool(p["price_cents"] > 0 and owner_uid and not seller_ready)
    return render_template("market_product.html", p=item, related=[_card(r, media) for r in related],
                           can_pay=can_pay, seller_payout_missing=seller_payout_missing,
                           error=request.args.get("error"))


@shop.route("/media/<int:mid>")
def media_file(mid):
    with db() as c:
        m = c.execute("SELECT m.*, p.published FROM media m JOIN products p ON p.id=m.product_id WHERE m.id=?", (mid,)).fetchone()
    if not m or (not m["published"] and not _is_admin()):
        abort(404)
    return send_file(PRODUCTS_DIR / str(m["product_id"]) / "media" / m["file"], max_age=3600, conditional=True)


@shop.route("/p/<slug>/get")
def free_download(slug):
    """Free products: the file or cloned site archive is downloaded directly, no checkout."""
    with db() as c:
        p = c.execute("SELECT * FROM products WHERE slug=? AND published=1", (slug,)).fetchone()
        if not p or p["price_cents"] != 0:
            abort(404)
        cid = p["clone_id"] if "clone_id" in p.keys() else ""
        if p["file"]:
            target = PRODUCTS_DIR / str(p["id"]) / p["file"]
            dl_name = p["file"]
        elif cid and (CLONED_DIR / cid).is_dir():
            zfile = CLONED_DIR / f"{cid}.zip"
            if not zfile.exists():
                shutil.make_archive(str(CLONED_DIR / cid), "zip", str(CLONED_DIR / cid))
            target = zfile
            dl_name = f"{p['slug']}.zip"
        else:
            abort(404)
        c.execute("UPDATE products SET free_downloads=free_downloads+1 WHERE id=?", (p["id"],))
    return send_file(target, as_attachment=True, download_name=dl_name)


@shop.route("/cover/<int:pid>")
def cover(pid):
    with db() as c:
        p = c.execute("SELECT cover, published FROM products WHERE id=?", (pid,)).fetchone()
    if not p or not p["cover"] or not p["published"] and not _is_admin():
        abort(404)
    return send_file(PRODUCTS_DIR / str(pid) / p["cover"], max_age=3600)


def _is_admin():
    from flask import session
    return bool(session.get("admin"))


@shop.route("/p/<slug>/buy", methods=["POST"])
def buy(slug):
    email = request.form.get("email", "").strip()
    with db() as c:
        p = c.execute("SELECT * FROM products WHERE slug=? AND published=1", (slug,)).fetchone()
    if not p:
        abort(404)
    if p["price_cents"] == 0:
        return _redirect(f"/shop/p/{slug}/get")
    back = f"/shop/p/{slug}"
    if not EMAIL_RE.match(email) or len(email) > 200:
        return _redirect(back + "?error=E-mail invalide")
    if not stripe_ready() or not (p["file"] or (p["clone_id"] if "clone_id" in p.keys() else "")):
        return _redirect(back + "?error=Paiement indisponible pour le moment")

    owner_uid = (p["owner_user_id"] if "owner_user_id" in p.keys() else "") or ""
    seller_acct = ""
    fee_cents = 0
    seller_cents = p["price_cents"]
    if owner_uid:
        seller = _get_seller_connect_account(owner_uid)
        if not seller["ready"]:
            return _redirect(back + "?error=Le créateur n'a pas encore activé son compte Stripe Connect")
        seller_acct = seller["stripe_account_id"]
        fee_cents, seller_cents = compute_split_cents(p["price_cents"])

    import stripe
    stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
    base = public_url()
    session_kwargs = {
        "mode": "payment",
        "customer_email": email,
        "line_items": [{"quantity": 1, "price_data": {
            "currency": currency(), "unit_amount": p["price_cents"],
            "product_data": {"name": p["title"]}}}],
        "success_url": base + "/shop/success?session_id={CHECKOUT_SESSION_ID}",
        "cancel_url": base + back,
    }
    if seller_acct:
        session_kwargs["payment_intent_data"] = {
            "application_fee_amount": fee_cents,
            "transfer_data": {"destination": seller_acct},
        }
    try:
        s = stripe.checkout.Session.create(**session_kwargs)
    except Exception as e:
        print(f"[shop] stripe error: {e}")
        return _redirect(back + "?error=Impossible de lancer le paiement")
    with db() as c:
        c.execute(
            """INSERT INTO orders
               (product_id,email,amount_cents,currency,stripe_session,created_at,seller_user_id,platform_fee_cents,seller_payout_cents,stripe_account_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (p["id"], email, p["price_cents"], currency(), s.id, int(time.time()),
             owner_uid, fee_cents, seller_cents, seller_acct),
        )
    return _redirect(s.url)


def _redirect(url):
    from flask import redirect
    return redirect(url, 303)


@shop.route("/webhook", methods=["POST"])
def webhook():
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not secret:
        return jsonify({"error": "webhook not configured"}), 503
    import stripe
    try:
        event = stripe.Webhook.construct_event(request.get_data(), request.headers.get("Stripe-Signature", ""), secret)
    except Exception:
        return jsonify({"error": "invalid signature"}), 400
    if event["type"] in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        obj = event["data"]["object"]
        if getattr(obj, "payment_status", None) == "paid":
            fulfill(obj["id"])
    return jsonify({"received": True})


@shop.route("/success")
def success():
    sid = request.args.get("session_id", "")
    with db() as c:
        order = c.execute("SELECT * FROM orders WHERE stripe_session=?", (sid,)).fetchone() if sid else None
    if not order:
        abort(404)
    if order["status"] != "paid" and stripe_ready():
        # Don't depend on the webhook alone: ask Stripe directly (also makes local dev work)
        try:
            import stripe
            stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
            if stripe.checkout.Session.retrieve(sid).payment_status == "paid":
                order = fulfill(sid) or order
        except Exception as e:
            print(f"[shop] stripe retrieve failed: {e}")
    return render_template("shop_success.html", order=order,
                           link=f"/shop/download/{order['token']}" if order["status"] == "paid" else None)


@shop.route("/download/<token>")
def download(token):
    with db() as c:
        o = c.execute("SELECT * FROM orders WHERE token=? AND status='paid'", (token,)).fetchone()
        if not o:
            abort(404)
        if o["token_expires"] < time.time() or o["downloads"] >= MAX_DOWNLOADS:
            return render_template("shop_success.html", order=o, link=None, expired=True), 410
        p = c.execute("SELECT * FROM products WHERE id=?", (o["product_id"],)).fetchone()
        if not p or not p["file"]:
            abort(404)
        c.execute("UPDATE orders SET downloads=downloads+1 WHERE id=?", (o["id"],))
    return send_file(PRODUCTS_DIR / str(p["id"]) / p["file"], as_attachment=True, download_name=p["file"])


# ---------- admin API ----------

def _product_dict(r, media=None):
    d = dict(r)
    d["price"] = "Gratuit" if r["price_cents"] == 0 else format_price(r["price_cents"])
    d["has_file"] = bool(r["file"]) or bool(d.get("clone_id") and (CLONED_DIR / d["clone_id"]).is_dir())
    d["category_label"] = CATEGORIES.get(r["category"], "Autres")
    d["submission_status"] = d.get("submission_status") or "approved"
    specs_dict, specs_list = _decode_specs(d.get("specs", "{}"), r["category"])
    d["specs"] = specs_dict
    d["specs_list"] = specs_list
    d["media"] = (media or {}).get(r["id"], []) or (_clone_media(d.get("clone_id")) if d.get("clone_id") else [])
    return d


def _save_upload(pid, fs, allowed, prefix):
    ext = Path(fs.filename).suffix.lower()
    if ext not in allowed:
        raise ValueError(f"Extension non autorisée : {ext or '(aucune)'}")
    folder = PRODUCTS_DIR / str(pid)
    folder.mkdir(parents=True, exist_ok=True)
    name = secure_filename(Path(fs.filename).stem) or prefix
    name = f"{name}{ext}" if prefix == "file" else f"cover{ext}"
    fs.save(folder / name)
    return name


def _parse_form(is_public=False):
    title = request.form.get("title", "").strip()
    if not title:
        raise ValueError("Titre requis")
    author_name = request.form.get("author_name", "").strip()[:120]
    author_email = request.form.get("author_email", "").strip()[:200]
    if is_public:
        if not author_name:
            raise ValueError("Nom du créateur / vendeur requis")
        if not EMAIL_RE.match(author_email):
            raise ValueError("E-mail de contact valide requis")
        has_upload = bool(request.files.get("file") and request.files["file"].filename)
        if not has_upload and not request.form.get("demo_url", "").strip() and not request.form.get("preview_text", "").strip():
            raise ValueError("Ajoutez un fichier à livrer, un aperçu texte/code ou une URL de démo.")
    elif author_email and not EMAIL_RE.match(author_email):
        raise ValueError("E-mail créateur invalide")

    if request.form.get("free") == "1":
        price_cents = 0
    else:
        try:
            price_cents = round(float((request.form.get("price") or "").replace(",", ".")) * 100)
        except ValueError:
            raise ValueError("Prix invalide (ou cochez « Gratuit »)")
        if price_cents < 50 or price_cents > 99_999_900:
            raise ValueError("Prix hors limites (0,50 minimum, ou cochez « Gratuit »)")
    demo = request.form.get("demo_url", "").strip()
    if demo and not demo.startswith(("http://", "https://", "/")):
        raise ValueError("L'URL de démo doit commencer par http(s):// ou /")
    category = request.form.get("category", "design")
    if category not in CATEGORIES:
        raise ValueError("Catégorie inconnue")
    tags = ",".join(sorted({x.strip()[:30] for x in request.form.get("tags", "").split(",") if x.strip()}))[:300]
    sub_status = "pending" if is_public else request.form.get("submission_status", "approved")
    if sub_status not in ("pending", "approved", "rejected"):
        sub_status = "approved"
    cfg = CATEGORY_CONFIG.get(category, CATEGORY_CONFIG["other"])
    specs_dict = {}
    for spec in cfg.get("specs", []):
        k = spec["key"]
        val = (request.form.get(f"spec_{k}") or "").strip()[:120]
        if val:
            specs_dict[k] = val
    return {"title": title[:200], "description": request.form.get("description", "").strip()[:8000],
            "price_cents": price_cents, "demo_url": demo[:500], "category": category,
            "tagline": request.form.get("tagline", "").strip()[:160], "tags": tags,
            "preview_text": request.form.get("preview_text", "").strip()[:6000],
            "specs": json.dumps(specs_dict, ensure_ascii=False),
            "featured": 0 if is_public else (1 if request.form.get("featured") == "1" else 0),
            "published": 0 if is_public else (1 if request.form.get("published") == "1" else 0),
            "author_name": author_name, "author_email": author_email,
            "submission_status": sub_status}


FIELDS = ("title", "description", "price_cents", "demo_url", "category", "tagline", "tags",
          "preview_text", "specs", "featured", "published", "author_name", "author_email", "submission_status")


def _save_files(c, pid, parsed=None, slug=""):
    uploaded_file = bool(request.files.get("file") and request.files["file"].filename)
    if uploaded_file:
        c.execute("UPDATE products SET file=? WHERE id=?", (_save_upload(pid, request.files["file"], FILE_EXT, "file"), pid))
    elif parsed and parsed.get("category") in ("prompt", "skill") and parsed.get("preview_text"):
        cur_row = c.execute("SELECT file, clone_id, slug FROM products WHERE id=?", (pid,)).fetchone()
        if cur_row and not cur_row["file"] and not (cur_row["clone_id"] or ""):
            folder = PRODUCTS_DIR / str(pid)
            folder.mkdir(parents=True, exist_ok=True)
            fname = f"{slug or cur_row['slug'] or 'package'}.md"
            _, specs_list = _decode_specs(parsed.get("specs", "{}"), parsed["category"])
            spec_lines = "\n".join(f"- **{s['label']}** : {s['value']}" for s in specs_list)
            md_parts = [f"# {parsed['title']}"]
            if spec_lines:
                md_parts.append(spec_lines)
            if parsed.get("description"):
                md_parts.append(parsed["description"])
            md_parts.append("## Contenu\n\n" + parsed["preview_text"])
            (folder / fname).write_text("\n\n".join(md_parts), encoding="utf-8")
            c.execute("UPDATE products SET file=? WHERE id=?", (fname, pid))
    if request.files.get("cover") and request.files["cover"].filename:
        c.execute("UPDATE products SET cover=? WHERE id=?", (_save_upload(pid, request.files["cover"], COVER_EXT, "cover"), pid))
    _add_media(c, pid, request.files.getlist("media"))


def _add_media(c, pid, files):
    folder = PRODUCTS_DIR / str(pid) / "media"
    pos = c.execute("SELECT COALESCE(MAX(position),0) FROM media WHERE product_id=?", (pid,)).fetchone()[0] or 0
    added = 0
    for fs in files:
        if not fs or not fs.filename:
            continue
        ext = Path(fs.filename).suffix.lower()
        kind = "image" if ext in IMAGE_EXT else "video" if ext in VIDEO_EXT else None
        if not kind:
            raise ValueError(f"Média non pris en charge : {fs.filename} (images : png, jpg, webp, gif, avif ; vidéos : mp4, webm, mov)")
        folder.mkdir(parents=True, exist_ok=True)
        name = f"{secrets.token_hex(4)}_{secure_filename(Path(fs.filename).stem)[:40] or kind}{ext}"
        fs.save(folder / name)
        pos += 1
        c.execute("INSERT INTO media (product_id,kind,file,position) VALUES (?,?,?,?)", (pid, kind, name, pos))
        added += 1
    return added


@shop_admin.route("/products")
@login_required
def list_products():
    sync_cloned_sites()
    with db() as c:
        rows = c.execute("SELECT * FROM products ORDER BY (submission_status = 'pending') DESC, featured DESC, created_at DESC").fetchall()
        media = _media_for(c, [r["id"] for r in rows])
        sales = {r["product_id"]: (r["n"], r["total"]) for r in c.execute(
            "SELECT product_id, COUNT(*) n, COALESCE(SUM(amount_cents),0) total FROM orders WHERE status='paid' GROUP BY product_id")}
    out = []
    pending_count = 0
    for r in rows:
        d = _product_dict(r, media)
        if d["submission_status"] == "pending":
            pending_count += 1
        n, total = sales.get(r["id"], (0, 0))
        d.update(sales=n, revenue=format_price(total))
        out.append(d)
    return jsonify({"products": out, "categories": CATEGORIES, "category_config": CATEGORY_CONFIG,
                    "pending_count": pending_count,
                    "stripe_ready": stripe_ready(), "webhook_ready": bool(os.environ.get("STRIPE_WEBHOOK_SECRET"))})


@shop_admin.route("/products/<int:pid>/review", methods=["POST"])
@login_required
def review_product(pid):
    """Approves (publishes) or rejects a user-submitted Marketplace item."""
    action = (request.get_json(silent=True) or {}).get("action", "").strip().lower()
    if action not in ("approve", "reject"):
        return jsonify({"error": "Action invalide (approve ou reject requis)"}), 400
    status = "approved" if action == "approve" else "rejected"
    pub = 1 if action == "approve" else 0
    with db() as c:
        c.execute("UPDATE products SET submission_status=?, published=?, updated_at=? WHERE id=?",
                  (status, pub, int(time.time()), pid))
        r = c.execute("SELECT id, title, submission_status, published FROM products WHERE id=?", (pid,)).fetchone()
    if not r:
        return jsonify({"error": "Produit introuvable"}), 404
    return jsonify(dict(r))


@shop_admin.route("/products/<int:pid>/download")
@login_required
def admin_inspect_product_file(pid):
    """Lets the SaaS admin download and inspect any submitted product file before approving it."""
    with db() as c:
        p = c.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    if p["file"]:
        target = PRODUCTS_DIR / str(p["id"]) / p["file"]
        if not target.exists():
            abort(404)
        return send_file(target, as_attachment=True, download_name=p["file"])
    cid = p["clone_id"] if "clone_id" in p.keys() else ""
    if cid and (CLONED_DIR / cid).is_dir():
        zfile = CLONED_DIR / f"{cid}.zip"
        if not zfile.exists():
            shutil.make_archive(str(CLONED_DIR / cid), "zip", str(CLONED_DIR / cid))
        return send_file(zfile, as_attachment=True, download_name=f"{p['slug']}.zip")
    abort(404)


@shop_admin.route("/products", methods=["POST"])
@login_required
def create_product():
    try:
        f = _parse_form()
        with db() as c:
            slug, n = slugify(f["title"]), 1
            while c.execute("SELECT 1 FROM products WHERE slug=?", (slug,)).fetchone():
                n += 1
                slug = f"{slugify(f['title'])}-{n}"
            now = int(time.time())
            cur = c.execute(f"INSERT INTO products (slug,{','.join(FIELDS)},created_at,updated_at) VALUES (?{',?' * len(FIELDS)},?,?)",
                            (slug, *[f[k] for k in FIELDS], now, now))
            pid = cur.lastrowid
            _save_files(c, pid, parsed=f, slug=slug)
        return jsonify({"id": pid, "slug": slug}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@shop_admin.route("/products/<int:pid>", methods=["POST"])
@login_required
def update_product(pid):
    try:
        f = _parse_form()
        with db() as c:
            row = c.execute("SELECT slug FROM products WHERE id=?", (pid,)).fetchone()
            if not row:
                return jsonify({"error": "Produit introuvable"}), 404
            c.execute(f"UPDATE products SET {','.join(k + '=?' for k in FIELDS)},updated_at=? WHERE id=?",
                      (*[f[k] for k in FIELDS], int(time.time()), pid))
            _save_files(c, pid, parsed=f, slug=row["slug"])
        return jsonify({"status": "updated"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@shop_admin.route("/products/<int:pid>/toggle", methods=["POST"])
@login_required
def toggle_product(pid):
    field = (request.get_json(silent=True) or {}).get("field")
    if field not in ("published", "featured"):
        return jsonify({"error": "Champ inconnu"}), 400
    with db() as c:
        c.execute(f"UPDATE products SET {field}=1-{field}, updated_at=? WHERE id=?", (int(time.time()), pid))
        r = c.execute(f"SELECT {field} FROM products WHERE id=?", (pid,)).fetchone()
    if not r:
        return jsonify({"error": "Produit introuvable"}), 404
    return jsonify({field: r[0]})


@shop_admin.route("/products/<int:pid>/media", methods=["POST"])
@login_required
def upload_media(pid):
    try:
        with db() as c:
            if not c.execute("SELECT 1 FROM products WHERE id=?", (pid,)).fetchone():
                return jsonify({"error": "Produit introuvable"}), 404
            n = _add_media(c, pid, request.files.getlist("media"))
        return jsonify({"added": n})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@shop_admin.route("/media/<int:mid>", methods=["DELETE"])
@login_required
def delete_media(mid):
    with db() as c:
        m = c.execute("SELECT * FROM media WHERE id=?", (mid,)).fetchone()
        if not m:
            return jsonify({"error": "Média introuvable"}), 404
        c.execute("DELETE FROM media WHERE id=?", (mid,))
    (PRODUCTS_DIR / str(m["product_id"]) / "media" / m["file"]).unlink(missing_ok=True)
    return jsonify({"status": "deleted"})


@shop_admin.route("/media/<int:mid>/move", methods=["POST"])
@login_required
def move_media(mid):
    """Reorder: the first image is the product's cover."""
    step = -1 if (request.get_json(silent=True) or {}).get("dir") == "up" else 1
    with db() as c:
        m = c.execute("SELECT * FROM media WHERE id=?", (mid,)).fetchone()
        if not m:
            return jsonify({"error": "Média introuvable"}), 404
        order = [r["id"] for r in c.execute("SELECT id FROM media WHERE product_id=? ORDER BY position, id", (m["product_id"],))]
        i = order.index(mid)
        j = max(0, min(len(order) - 1, i + step))
        order[i], order[j] = order[j], order[i]
        for pos, x in enumerate(order, 1):
            c.execute("UPDATE media SET position=? WHERE id=?", (pos, x))
    return jsonify({"status": "moved"})


@shop_admin.route("/products/<int:pid>", methods=["DELETE"])
@login_required
def delete_product(pid):
    import shutil
    with db() as c:
        paid = c.execute("SELECT COUNT(*) FROM orders WHERE product_id=? AND status='paid'", (pid,)).fetchone()[0]
        if paid:
            return jsonify({"error": f"{paid} commande(s) payée(s) : dépublie le produit au lieu de le supprimer."}), 409
        c.execute("DELETE FROM orders WHERE product_id=?", (pid,))
        c.execute("DELETE FROM media WHERE product_id=?", (pid,))
        c.execute("DELETE FROM products WHERE id=?", (pid,))
    shutil.rmtree(PRODUCTS_DIR / str(pid), ignore_errors=True)
    return jsonify({"status": "deleted"})


@shop_admin.route("/stats")
@login_required
def market_stats():
    with db() as c:
        row = c.execute("""SELECT COUNT(*) total, SUM(published) published, SUM(price_cents=0) free,
                           COALESCE(SUM(views),0) views, COALESCE(SUM(free_downloads),0) downloads FROM products""").fetchone()
        paid = c.execute("""SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) s,
                            COALESCE(SUM(platform_fee_cents),0) fees,
                            COALESCE(SUM(seller_payout_cents),0) payouts
                            FROM orders WHERE status='paid'""").fetchone()
        by_cat = {r["category"]: r["n"] for r in c.execute("SELECT category, COUNT(*) n FROM products GROUP BY category")}
        top = c.execute("SELECT title, slug, views, free_downloads FROM products ORDER BY views DESC LIMIT 5").fetchall()
    return jsonify({"products": row["total"] or 0, "published": row["published"] or 0, "free": row["free"] or 0,
                    "views": row["views"], "free_downloads": row["downloads"], "sales": paid["n"],
                    "revenue": format_price(paid["s"]),
                    "platform_fees": format_price(paid["fees"]),
                    "seller_payouts": format_price(paid["payouts"]),
                    "by_category": {CATEGORIES.get(k, k): v for k, v in by_cat.items()},
                    "top": [dict(r) for r in top]})


@shop_admin.route("/orders")
@login_required
def list_orders():
    with db() as c:
        rows = c.execute("""SELECT o.id,o.email,o.amount_cents,o.currency,o.status,o.downloads,o.created_at,o.paid_at,
                            o.platform_fee_cents,o.seller_payout_cents,o.seller_user_id,
                            p.title FROM orders o LEFT JOIN products p ON p.id=o.product_id
                            ORDER BY o.created_at DESC LIMIT 500""").fetchall()
        sums = c.execute("""SELECT COALESCE(SUM(amount_cents),0) total,
                            COALESCE(SUM(platform_fee_cents),0) fees,
                            COALESCE(SUM(seller_payout_cents),0) payouts
                            FROM orders WHERE status='paid'""").fetchone()
    return jsonify({
        "orders": [
            dict(
                r,
                amount=format_price(r["amount_cents"], r["currency"]),
                platform_fee=format_price(r["platform_fee_cents"] or 0, r["currency"]),
                seller_payout=format_price(r["seller_payout_cents"] or 0, r["currency"]),
            )
            for r in rows
        ],
        "revenue": format_price(sums["total"]),
        "platform_fees": format_price(sums["fees"]),
        "seller_payouts": format_price(sums["payouts"]),
        "paid_count": sum(1 for r in rows if r["status"] == "paid"),
    })


def init_shop(app):
    init_db()
    sync_cloned_sites()
    app.config.setdefault("MAX_CONTENT_LENGTH", 500 * 1024 * 1024)
    app.register_blueprint(shop)
    app.register_blueprint(shop_admin)
