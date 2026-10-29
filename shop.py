#!/usr/bin/env python3
"""
shop.py - Marketplace for SiteCloner SaaS: site designs, templates, prompts, skills, software and 3D assets.
Public catalog (search, categories, favorites, preview), free downloads, Stripe Checkout and secure download links
for paid products, plus the admin API to manage products, their media and orders. Mounted by app.py (init_shop).

Env: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, PUBLIC_URL (e.g. https://mysite.com),
     SHOP_CURRENCY (default eur), optional SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASSWORD/SMTP_FROM.
"""

import os
import re
import secrets
import smtplib
import sqlite3
import time
from email.message import EmailMessage
from pathlib import Path

from flask import (Blueprint, abort, jsonify, render_template, request, send_file)
from werkzeug.utils import secure_filename

from admin import DATA_DIR, login_required

DB_FILE = DATA_DIR / "shop.db"
PRODUCTS_DIR = DATA_DIR / "products"

LINK_TTL = 7 * 24 * 3600
MAX_DOWNLOADS = 5
COVER_EXT = {".png", ".jpg", ".jpeg", ".webp"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".avif"}
VIDEO_EXT = {".mp4", ".webm", ".mov"}
FILE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".pdf", ".apk", ".exe", ".msi", ".dmg", ".appimage", ".deb",
            ".json", ".md", ".txt", ".csv", ".fig", ".sketch", ".xd", ".psd", ".ai", ".svg",
            ".glb", ".gltf", ".fbx", ".obj", ".blend", ".usdz", ".html", ".css", ".js", ".py"}
CATEGORIES = {
    "design": "Designs de site",
    "template": "Templates & composants",
    "prompt": "Prompts",
    "skill": "Skills & agents IA",
    "software": "Logiciels & apps",
    "asset": "Assets 3D & graphiques",
    "other": "Autres",
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
                          ("free_downloads", "INTEGER NOT NULL DEFAULT 0"), ("updated_at", "INTEGER NOT NULL DEFAULT 0")):
            if name not in cols:
                c.execute(f"ALTER TABLE products ADD COLUMN {name} {ddl}")


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


def _media_for(c, pids):
    out = {}
    if not pids:
        return out
    q = ",".join("?" * len(pids))
    for m in c.execute(f"SELECT * FROM media WHERE product_id IN ({q}) ORDER BY position, id", list(pids)):
        out.setdefault(m["product_id"], []).append({"id": m["id"], "kind": m["kind"], "url": f"/shop/media/{m['id']}"})
    return out


def _card(r, media):
    """What the catalog and the product page need about a product (also used as JSON)."""
    items = media.get(r["id"], [])
    cover = next((m["url"] for m in items if m["kind"] == "image"), None) or (f"/shop/cover/{r['id']}" if r["cover"] else None)
    keys = r.keys()
    return {
        "id": r["id"], "slug": r["slug"], "title": r["title"], "tagline": r["tagline"] if "tagline" in keys else "",
        "description": r["description"], "category": r["category"] if "category" in keys else "design",
        "category_label": CATEGORIES.get(r["category"] if "category" in keys else "design", "Autres"),
        "tags": [x.strip() for x in (r["tags"] or "").split(",") if x.strip()] if "tags" in keys else [],
        "price_cents": r["price_cents"], "free": r["price_cents"] == 0,
        "price": "Gratuit" if r["price_cents"] == 0 else format_price(r["price_cents"]),
        "cover": cover, "media": items, "has_video": any(m["kind"] == "video" for m in items),
        "demo_url": r["demo_url"], "preview_text": r["preview_text"] if "preview_text" in keys else "",
        "featured": bool(r["featured"]) if "featured" in keys else False,
        "views": r["views"] if "views" in keys else 0, "downloads": r["free_downloads"] if "free_downloads" in keys else 0,
        "has_file": bool(r["file"]), "created_at": r["created_at"],
    }


@shop.route("/")
def catalog():
    with db() as c:
        rows = c.execute("SELECT * FROM products WHERE published=1 ORDER BY featured DESC, created_at DESC").fetchall()
        media = _media_for(c, [r["id"] for r in rows])
    items = [_card(r, media) for r in rows]
    used = sorted({i["category"] for i in items}, key=list(CATEGORIES).index)
    return render_template("market_index.html", items=items, categories=CATEGORIES, used_categories=used)


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
    return render_template("market_product.html", p=item, related=[_card(r, media) for r in related],
                           can_pay=stripe_ready() and bool(p["file"]), error=request.args.get("error"))


@shop.route("/media/<int:mid>")
def media_file(mid):
    with db() as c:
        m = c.execute("SELECT m.*, p.published FROM media m JOIN products p ON p.id=m.product_id WHERE m.id=?", (mid,)).fetchone()
    if not m or (not m["published"] and not _is_admin()):
        abort(404)
    return send_file(PRODUCTS_DIR / str(m["product_id"]) / "media" / m["file"], max_age=3600, conditional=True)


@shop.route("/p/<slug>/get")
def free_download(slug):
    """Free products: the file is downloaded directly, no checkout."""
    with db() as c:
        p = c.execute("SELECT * FROM products WHERE slug=? AND published=1", (slug,)).fetchone()
        if not p or p["price_cents"] != 0 or not p["file"]:
            abort(404)
        c.execute("UPDATE products SET free_downloads=free_downloads+1 WHERE id=?", (p["id"],))
    return send_file(PRODUCTS_DIR / str(p["id"]) / p["file"], as_attachment=True, download_name=p["file"])


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
    if not stripe_ready() or not p["file"]:
        return _redirect(back + "?error=Paiement indisponible pour le moment")
    import stripe
    stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
    base = public_url()
    try:
        s = stripe.checkout.Session.create(
            mode="payment",
            customer_email=email,
            line_items=[{"quantity": 1, "price_data": {
                "currency": currency(), "unit_amount": p["price_cents"],
                "product_data": {"name": p["title"]}}}],
            success_url=base + "/shop/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=base + back,
        )
    except Exception as e:
        print(f"[shop] stripe error: {e}")
        return _redirect(back + "?error=Impossible de lancer le paiement")
    with db() as c:
        c.execute("INSERT INTO orders (product_id,email,amount_cents,currency,stripe_session,created_at) VALUES (?,?,?,?,?,?)",
                  (p["id"], email, p["price_cents"], currency(), s.id, int(time.time())))
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
    d["has_file"] = bool(r["file"])
    d["category_label"] = CATEGORIES.get(r["category"], "Autres")
    d["media"] = (media or {}).get(r["id"], [])
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


def _parse_form():
    title = request.form.get("title", "").strip()
    if not title:
        raise ValueError("Titre requis")
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
    return {"title": title[:200], "description": request.form.get("description", "").strip()[:8000],
            "price_cents": price_cents, "demo_url": demo[:500], "category": category,
            "tagline": request.form.get("tagline", "").strip()[:160], "tags": tags,
            "preview_text": request.form.get("preview_text", "").strip()[:6000],
            "featured": 1 if request.form.get("featured") == "1" else 0,
            "published": 1 if request.form.get("published") == "1" else 0}


FIELDS = ("title", "description", "price_cents", "demo_url", "category", "tagline", "tags", "preview_text", "featured", "published")


def _save_files(c, pid):
    if request.files.get("file") and request.files["file"].filename:
        c.execute("UPDATE products SET file=? WHERE id=?", (_save_upload(pid, request.files["file"], FILE_EXT, "file"), pid))
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
    with db() as c:
        rows = c.execute("SELECT * FROM products ORDER BY featured DESC, created_at DESC").fetchall()
        media = _media_for(c, [r["id"] for r in rows])
        sales = {r["product_id"]: (r["n"], r["total"]) for r in c.execute(
            "SELECT product_id, COUNT(*) n, COALESCE(SUM(amount_cents),0) total FROM orders WHERE status='paid' GROUP BY product_id")}
    out = []
    for r in rows:
        d = _product_dict(r, media)
        n, total = sales.get(r["id"], (0, 0))
        d.update(sales=n, revenue=format_price(total))
        out.append(d)
    return jsonify({"products": out, "categories": CATEGORIES, "stripe_ready": stripe_ready(),
                    "webhook_ready": bool(os.environ.get("STRIPE_WEBHOOK_SECRET"))})


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
            _save_files(c, pid)
        return jsonify({"id": pid, "slug": slug}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@shop_admin.route("/products/<int:pid>", methods=["POST"])
@login_required
def update_product(pid):
    try:
        f = _parse_form()
        with db() as c:
            if not c.execute("SELECT 1 FROM products WHERE id=?", (pid,)).fetchone():
                return jsonify({"error": "Produit introuvable"}), 404
            c.execute(f"UPDATE products SET {','.join(k + '=?' for k in FIELDS)},updated_at=? WHERE id=?",
                      (*[f[k] for k in FIELDS], int(time.time()), pid))
            _save_files(c, pid)
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
        paid = c.execute("SELECT COUNT(*) n, COALESCE(SUM(amount_cents),0) s FROM orders WHERE status='paid'").fetchone()
        by_cat = {r["category"]: r["n"] for r in c.execute("SELECT category, COUNT(*) n FROM products GROUP BY category")}
        top = c.execute("SELECT title, slug, views, free_downloads FROM products ORDER BY views DESC LIMIT 5").fetchall()
    return jsonify({"products": row["total"] or 0, "published": row["published"] or 0, "free": row["free"] or 0,
                    "views": row["views"], "free_downloads": row["downloads"], "sales": paid["n"],
                    "revenue": format_price(paid["s"]), "by_category": {CATEGORIES.get(k, k): v for k, v in by_cat.items()},
                    "top": [dict(r) for r in top]})


@shop_admin.route("/orders")
@login_required
def list_orders():
    with db() as c:
        rows = c.execute("""SELECT o.id,o.email,o.amount_cents,o.currency,o.status,o.downloads,o.created_at,o.paid_at,
                            p.title FROM orders o LEFT JOIN products p ON p.id=o.product_id
                            ORDER BY o.created_at DESC LIMIT 500""").fetchall()
        total = c.execute("SELECT COALESCE(SUM(amount_cents),0) FROM orders WHERE status='paid'").fetchone()[0]
    return jsonify({"orders": [dict(r, amount=format_price(r["amount_cents"], r["currency"])) for r in rows],
                    "revenue": format_price(total), "paid_count": sum(1 for r in rows if r["status"] == "paid")})


def init_shop(app):
    init_db()
    app.config.setdefault("MAX_CONTENT_LENGTH", 500 * 1024 * 1024)
    app.register_blueprint(shop)
    app.register_blueprint(shop_admin)
