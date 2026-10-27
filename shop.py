#!/usr/bin/env python3
"""
shop.py - Project shop for SiteCloner SaaS: public catalog, Stripe Checkout, secure download links,
plus the admin API to manage products and orders. Mounted by app.py through init_shop().

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
FILE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".pdf", ".apk", ".exe", ".msi", ".dmg"}
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
        """)


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


@shop.route("/")
def catalog():
    with db() as c:
        products = c.execute("SELECT * FROM products WHERE published=1 ORDER BY created_at DESC").fetchall()
    return render_template("shop_index.html", products=products)


@shop.route("/p/<slug>")
def product(slug):
    with db() as c:
        p = c.execute("SELECT * FROM products WHERE slug=? AND published=1", (slug,)).fetchone()
    if not p:
        abort(404)
    return render_template("shop_product.html", p=p, can_pay=stripe_ready() and bool(p["file"]),
                           error=request.args.get("error"))


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

def _product_dict(r):
    d = dict(r)
    d["price"] = format_price(r["price_cents"])
    d["has_file"] = bool(r["file"])
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


def _parse_form(existing=None):
    title = request.form.get("title", "").strip()
    if not title:
        raise ValueError("Titre requis")
    try:
        price_cents = round(float(request.form.get("price", "").replace(",", ".")) * 100)
    except ValueError:
        raise ValueError("Prix invalide")
    if price_cents < 50 or price_cents > 99_999_900:
        raise ValueError("Prix hors limites (0,50 minimum)")
    demo = request.form.get("demo_url", "").strip()
    if demo and not demo.startswith(("http://", "https://")):
        raise ValueError("L'URL de démo doit commencer par http(s)://")
    return {"title": title[:200], "description": request.form.get("description", "").strip()[:5000],
            "price_cents": price_cents, "demo_url": demo[:500],
            "published": 1 if request.form.get("published") == "1" else 0}


@shop_admin.route("/products")
@login_required
def list_products():
    with db() as c:
        rows = c.execute("SELECT * FROM products ORDER BY created_at DESC").fetchall()
    return jsonify({"products": [_product_dict(r) for r in rows], "stripe_ready": stripe_ready(),
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
            cur = c.execute("INSERT INTO products (slug,title,description,price_cents,demo_url,published,created_at) VALUES (?,?,?,?,?,?,?)",
                            (slug, f["title"], f["description"], f["price_cents"], f["demo_url"], 0, int(time.time())))
            pid = cur.lastrowid
            if request.files.get("file") and request.files["file"].filename:
                c.execute("UPDATE products SET file=? WHERE id=?", (_save_upload(pid, request.files["file"], FILE_EXT, "file"), pid))
            if request.files.get("cover") and request.files["cover"].filename:
                c.execute("UPDATE products SET cover=? WHERE id=?", (_save_upload(pid, request.files["cover"], COVER_EXT, "cover"), pid))
            c.execute("UPDATE products SET published=? WHERE id=?", (f["published"], pid))
        return jsonify({"id": pid}), 201
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
            c.execute("UPDATE products SET title=?,description=?,price_cents=?,demo_url=?,published=? WHERE id=?",
                      (f["title"], f["description"], f["price_cents"], f["demo_url"], f["published"], pid))
            if request.files.get("file") and request.files["file"].filename:
                c.execute("UPDATE products SET file=? WHERE id=?", (_save_upload(pid, request.files["file"], FILE_EXT, "file"), pid))
            if request.files.get("cover") and request.files["cover"].filename:
                c.execute("UPDATE products SET cover=? WHERE id=?", (_save_upload(pid, request.files["cover"], COVER_EXT, "cover"), pid))
        return jsonify({"status": "updated"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@shop_admin.route("/products/<int:pid>", methods=["DELETE"])
@login_required
def delete_product(pid):
    import shutil
    with db() as c:
        paid = c.execute("SELECT COUNT(*) FROM orders WHERE product_id=? AND status='paid'", (pid,)).fetchone()[0]
        if paid:
            return jsonify({"error": f"{paid} commande(s) payée(s) : dépublie le produit au lieu de le supprimer."}), 409
        c.execute("DELETE FROM orders WHERE product_id=?", (pid,))
        c.execute("DELETE FROM products WHERE id=?", (pid,))
    shutil.rmtree(PRODUCTS_DIR / str(pid), ignore_errors=True)
    return jsonify({"status": "deleted"})


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
