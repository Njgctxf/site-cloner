"""Tests for multi-creator Marketplace submissions and Admin moderation."""

import io
import shutil
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app as flask_app
import shop


class MarketplaceSubmissionTests(unittest.TestCase):
    def setUp(self):
        shop.init_db()
        self.created_ids = []

    def tearDown(self):
        if self.created_ids:
            with shop.db() as conn:
                for pid in self.created_ids:
                    conn.execute("DELETE FROM media WHERE product_id=?", (pid,))
                    conn.execute("DELETE FROM products WHERE id=?", (pid,))
                    shutil.rmtree(shop.PRODUCTS_DIR / str(pid), ignore_errors=True)

    def test_user_submission_requires_admin_approval_and_protects_email(self):
        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()
        title = f"Skill Audit IA {uuid.uuid4().hex[:6]}"
        secret_email = "creator-private@example.com"

        res = client.post(
            "/shop/api/submit",
            data={
                "author_name": "Atelier Alpha",
                "author_email": secret_email,
                "title": title,
                "category": "skill",
                "tagline": "Skill automatisé de sécurité",
                "description": "Analyse OWASP en 1 clic.",
                "free": "1",
                "file": (io.BytesIO(b"# SKILL\nAudit rule"), "audit_skill.md"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 201)
        body = res.get_json()
        pid = body["id"]
        slug = body["slug"]
        self.created_ids.append(pid)
        self.assertEqual(body["submission_status"], "pending")

        # Pending submission must NOT be publicly accessible yet
        self.assertEqual(client.get(f"/shop/p/{slug}").status_code, 404)
        self.assertNotIn(title, client.get("/shop/").get_data(as_text=True))

        # Unauthenticated user cannot approve or inspect via admin endpoints
        self.assertEqual(client.post(f"/admin/api/shop/products/{pid}/review", json={"action": "approve"}).status_code, 401)
        self.assertEqual(client.get(f"/admin/api/shop/products/{pid}/download").status_code, 401)

        # Authenticated admin sees pending submission, creator email, and can download/inspect file
        with client.session_transaction() as sess:
            sess["admin"] = "admin"
            sess["csrf"] = "tok_shop_csrf"

        admin_list = client.get("/admin/api/shop/products").get_json()
        self.assertGreaterEqual(admin_list["pending_count"], 1)
        match = next(x for x in admin_list["products"] if x["id"] == pid)
        self.assertEqual(match["submission_status"], "pending")
        self.assertEqual(match["author_name"], "Atelier Alpha")
        self.assertEqual(match["author_email"], secret_email)

        inspect_dl = client.get(f"/admin/api/shop/products/{pid}/download")
        self.assertEqual(inspect_dl.status_code, 200)
        self.assertIn(b"Audit rule", inspect_dl.data)

        # Admin approves -> now published publicly without exposing private email
        approve_res = client.post(
            f"/admin/api/shop/products/{pid}/review",
            headers={"X-CSRF-Token": "tok_shop_csrf"},
            json={"action": "approve"},
        )
        self.assertEqual(approve_res.status_code, 200)
        self.assertEqual(approve_res.get_json()["published"], 1)

        pub_page = client.get(f"/shop/p/{slug}")
        self.assertEqual(pub_page.status_code, 200)
        pub_html = pub_page.get_data(as_text=True)
        self.assertIn(title, pub_html)
        self.assertIn("Atelier Alpha", pub_html)
        self.assertNotIn(secret_email, pub_html)

    def test_paid_marketplace_connect_split_99_1_and_onboarding(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from security.database import get_connection

        self.assertEqual(shop.compute_split_cents(2500), (25, 2475))
        self.assertEqual(shop.compute_split_cents(1000), (10, 990))
        self.assertEqual(shop.compute_split_cents(50), (1, 49))
        self.assertEqual(shop.compute_split_cents(0), (0, 0))

        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()
        seller_email = f"seller_{uuid.uuid4().hex[:8]}@example.com"
        title = f"Pro Connect Tool {uuid.uuid4().hex[:6]}"
        pid = None
        seller_uid = None
        captured_checkout = {}

        try:
            # 1. Anonymous user cannot submit a PAID product
            anon_paid = client.post(
                "/shop/api/submit",
                data={
                    "author_name": "Anon Seller",
                    "author_email": seller_email,
                    "title": title,
                    "category": "software",
                    "price": "25.00",
                    "file": (io.BytesIO(b"PK_BINARY_DATA"), "tool.zip"),
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(anon_paid.status_code, 401)
            self.assertEqual(anon_paid.get_json()["error_code"], "ACCOUNT_REQUIRED")

            # 2. Register seller & connect Stripe Connect Express account
            reg = client.post(
                "/account/api/register",
                json={"display_name": "Vendeur Direct", "email": seller_email, "password": "Password123!"},
            )
            self.assertEqual(reg.status_code, 201)
            seller_uid = reg.get_json()["user"]["user_id"]

            fake_acct = SimpleNamespace(
                id="acct_connect_test_991",
                details_submitted=True,
                charges_enabled=True,
                payouts_enabled=True,
            )
            fake_link = SimpleNamespace(url="https://connect.stripe.test/onboard/123")

            with patch.dict("os.environ", {"STRIPE_SECRET_KEY": "sk_test_fake_key"}, clear=False):
                with patch("stripe.Account.create", return_value=fake_acct) as m_acc, \
                     patch("stripe.AccountLink.create", return_value=fake_link):
                    conn_res = client.post("/account/api/payouts/connect")
                self.assertEqual(conn_res.status_code, 200)
                self.assertEqual(conn_res.get_json()["stripe_account_id"], "acct_connect_test_991")
                self.assertEqual(m_acc.call_args.kwargs["type"], "express")

                # Return from Stripe onboarding updates capabilities
                with patch("stripe.Account.retrieve", return_value=fake_acct):
                    ret_res = client.get("/account/payouts/return")
                self.assertEqual(ret_res.status_code, 302)

                st_res = client.get("/account/api/payouts/status").get_json()
                self.assertTrue(st_res["ready_to_sell_paid"])
                self.assertEqual(st_res["platform_fee_pct"], 1)
                self.assertEqual(st_res["seller_share_pct"], 99)

                # 3. Seller submits paid 25.00 EUR tool -> Admin approves -> Buyer buys with 1% / 99% split
                sub_res = client.post(
                    "/shop/api/submit",
                    data={
                        "author_name": "Vendeur Direct",
                        "author_email": seller_email,
                        "title": title,
                        "category": "software",
                        "price": "25.00",
                        "file": (io.BytesIO(b"PAID_TOOL_BYTES"), "pro_tool.zip"),
                    },
                    content_type="multipart/form-data",
                )
                self.assertEqual(sub_res.status_code, 201)
                sb = sub_res.get_json()
                pid = sb["id"]
                slug = sb["slug"]
                self.created_ids.append(pid)
                self.assertFalse(sb["payout_setup_required"])

                with client.session_transaction() as sess:
                    sess["admin"] = "admin"
                    sess["csrf"] = "tok_shop_connect"
                self.assertEqual(
                    client.post(
                        f"/admin/api/shop/products/{pid}/review",
                        headers={"X-CSRF-Token": "tok_shop_connect"},
                        json={"action": "approve"},
                    ).status_code,
                    200,
                )

                def _fake_checkout_create(**kwargs):
                    captured_checkout.update(kwargs)
                    return SimpleNamespace(id="cs_test_split_991", url="https://checkout.stripe.test/pay/991")

                with patch("stripe.checkout.Session.create", side_effect=_fake_checkout_create):
                    buy_res = client.post(f"/shop/p/{slug}/buy", data={"email": "buyer@example.com"})
                self.assertEqual(buy_res.status_code, 303)
                self.assertEqual(captured_checkout["payment_intent_data"]["application_fee_amount"], 25)
                self.assertEqual(captured_checkout["payment_intent_data"]["transfer_data"]["destination"], "acct_connect_test_991")

                # Mark paid via Stripe success callback check and verify seller & admin totals
                with patch("stripe.checkout.Session.retrieve", return_value=SimpleNamespace(payment_status="paid")):
                    ok_res = client.get("/shop/success?session_id=cs_test_split_991")
                self.assertEqual(ok_res.status_code, 200)

                payouts_after = client.get("/account/api/payouts/status").get_json()
                self.assertEqual(payouts_after["sales_count"], 1)
                self.assertEqual(payouts_after["gross_cents"], 2500)
                self.assertEqual(payouts_after["platform_fee_cents"], 25)
                self.assertEqual(payouts_after["seller_net_cents"], 2475)

                admin_orders = client.get("/admin/api/shop/orders").get_json()
                self.assertIn("0,25", admin_orders["platform_fees"])
        finally:
            if pid is not None:
                with shop.db() as conn:
                    conn.execute("DELETE FROM orders WHERE product_id = ?", (pid,))
                    conn.commit()
            if seller_uid:
                conn = get_connection()
                try:
                    conn.execute("DELETE FROM users WHERE user_id = ?", (seller_uid,))
                    conn.commit()
                finally:
                    conn.close()

    def test_type_adapted_specs_and_prompt_md_generation(self):
        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()
        title = f"Prompt B2B {uuid.uuid4().hex[:6]}"
        res = client.post(
            "/shop/api/submit",
            data={
                "author_name": "Créateur Prompt",
                "author_email": "prompt@example.com",
                "title": title,
                "category": "prompt",
                "free": "1",
                "spec_ai_model": "Claude 3.7 Sonnet",
                "spec_prompt_format": "Workflow multi-étapes",
                "preview_text": "Tu es un copywriter B2B.\nAnalyse {{offre}} et rédige 3 angles.",
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 201, res.get_json())
        sb = res.get_json()
        pid = sb["id"]
        slug = sb["slug"]
        self.created_ids.append(pid)

        with client.session_transaction() as sess:
            sess["admin"] = "admin"
            sess["csrf"] = "tok_specs"
        adm_prods = client.get("/admin/api/shop/products").get_json()
        self.assertIn("prompt", adm_prods.get("category_config", {}))
        client.post(
            f"/admin/api/shop/products/{pid}/review",
            headers={"X-CSRF-Token": "tok_specs"},
            json={"action": "approve"},
        )

        # Specs & auto-generated .md deliverable work cleanly on product page and download
        page = client.get(f"/shop/p/{slug}")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn("Claude 3.7 Sonnet", html)
        self.assertIn("Workflow multi-étapes", html)
        dl = client.get(f"/shop/p/{slug}/get")
        self.assertEqual(dl.status_code, 200)
        self.assertIn("Tu es un copywriter B2B.", dl.get_data(as_text=True))
        dl.close()


if __name__ == "__main__":
    unittest.main()
