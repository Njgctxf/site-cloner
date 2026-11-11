#!/usr/bin/env python3
"""Tests for user accounts, authentication, profile updates, avatar handling, and guest migration."""

import io
import os
import shutil
import unittest
from pathlib import Path

os.environ.setdefault("SENTINEL_DATA_DIR", str(Path(__file__).resolve().parent / "data"))

import app as sc_app
from accounts import init_account_tables
from security.database import get_connection
from security.plans import get_monthly_clone_usage, record_clone_usage, record_scan_usage


# Valid 1x1 transparent PNG bytes
PNG_1X1 = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x02"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


class AccountsAndProfileTests(unittest.TestCase):
    def setUp(self):
        sc_app.app.config["TESTING"] = True
        self.client = sc_app.app.test_client()
        init_account_tables()
        self.tag = f"{os.getpid()}_{id(self)}"
        self.email = f"alex_{self.tag}@example.com"
        self.username = f"alex_{self.tag}".lower()[:28]

    def tearDown(self):
        conn = get_connection()
        try:
            rows = conn.execute("SELECT user_id FROM users WHERE email = ?", (self.email,)).fetchall()
            for r in rows:
                uid = r["user_id"]
                conn.execute("DELETE FROM monthly_clone_usage WHERE user_id = ?", (uid,))
                conn.execute("DELETE FROM monthly_audit_usage WHERE user_id = ?", (uid,))
                conn.execute("DELETE FROM user_subscriptions WHERE user_id = ?", (uid,))
                conn.execute("DELETE FROM users WHERE user_id = ?", (uid,))
            conn.commit()
        finally:
            conn.close()

    def test_register_guest_migration_login_profile_and_avatar(self):
        # 1. Guest records a clone & audit before registering
        guest_uid = f"usr_guest_{os.getpid()}"
        record_clone_usage(guest_uid, "https://guest-site.local")
        record_scan_usage(guest_uid, "https://guest-audit.local")
        with self.client.session_transaction() as sess:
            sess["sentinel_user_id"] = guest_uid

        # Unauthenticated /account/profile redirects to /account/login
        prof_anon = self.client.get("/account/profile")
        self.assertEqual(prof_anon.status_code, 302)
        self.assertIn("/account/login", prof_anon.headers["Location"])

        # 2. Invalid registrations fail with 400
        bad_pw = self.client.post(
            "/account/api/register",
            json={"email": self.email, "username": self.username, "password": "123"},
        )
        self.assertEqual(bad_pw.status_code, 400)

        # 3. Valid registration migrates guest usage and hides password_hash
        reg = self.client.post(
            "/account/api/register",
            json={
                "email": self.email,
                "username": self.username,
                "display_name": "Alex Martin",
                "company": "Studio Nova",
                "password": "Password123!",
            },
        )
        self.assertEqual(reg.status_code, 201)
        rj = reg.get_json()
        self.assertTrue(rj["success"])
        uid = rj["user"]["user_id"]
        self.assertNotIn("password_hash", rj["user"])
        self.assertIn("guest-site.local", get_monthly_clone_usage(uid))

        # Duplicate email fails with 409
        dup = self.client.post(
            "/account/api/register",
            json={"email": self.email, "username": f"other_{self.tag}"[:24], "password": "Password123!"},
        )
        self.assertEqual(dup.status_code, 409)

        # 4. Authenticated profile update + avatar upload + password change
        upd = self.client.post(
            "/account/api/profile",
            json={
                "display_name": "Alex Studio",
                "bio": "Créateur de templates & audits",
                "website": "https://studionova.local",
                "avatar_color": "#10b981",
            },
        )
        self.assertEqual(upd.status_code, 200)
        self.assertEqual(upd.get_json()["user"]["display_name"], "Alex Studio")
        self.assertEqual(upd.get_json()["user"]["avatar_color"], "#10b981")

        # Reject bad website scheme
        bad_web = self.client.post("/account/api/profile", json={"website": "javascript:alert(1)"})
        self.assertEqual(bad_web.status_code, 400)

        # Upload invalid file bytes -> 400
        bad_av = self.client.post(
            "/account/api/avatar",
            data={"avatar": (io.BytesIO(b"not an image"), "bad.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(bad_av.status_code, 400)

        # Upload valid PNG -> 200 and retrievable
        ok_av = self.client.post(
            "/account/api/avatar",
            data={"avatar": (io.BytesIO(PNG_1X1), "avatar.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(ok_av.status_code, 200)
        av_url = ok_av.get_json()["user"]["avatar_url"]
        self.assertTrue(av_url.startswith(f"/account/avatar/{uid}"))
        self.assertEqual(self.client.get(av_url).status_code, 200)

        # Submit a Marketplace tool while authenticated -> appears in /account/api/activity
        sub_res = self.client.post(
            "/shop/api/submit",
            data={
                "author_name": "Alex Studio",
                "author_email": self.email,
                "title": f"Tool {self.tag}",
                "category": "skill",
                "description": "Skill automatisé pour test profil.",
                "free": "1",
                "file": (io.BytesIO(b"# Tool\nDemo"), "tool_demo.md"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(sub_res.status_code, 201)
        pid = sub_res.get_json()["id"]

        act = self.client.get("/account/api/activity")
        self.assertEqual(act.status_code, 200)
        act_json = act.get_json()
        self.assertTrue(any(p["title"] == f"Tool {self.tag}" for p in act_json["marketplace_products"]))
        self.assertEqual(len(act_json["clones_month"]), 1)

        # Admin overview sees registered user account metadata
        admin_client = sc_app.app.test_client()
        with admin_client.session_transaction() as sess:
            sess["admin"] = "admin"
            sess["csrf"] = "tok_acc_csrf"
        ov = admin_client.get("/admin/api/platform-overview").get_json()
        self.assertGreaterEqual(ov["accounts"]["total"], 1)
        self.assertTrue(any(u["user_id"] == uid for u in ov["accounts"]["items"]))

        # Change password -> logout -> login with username & new password
        pw_res = self.client.post(
            "/account/api/password",
            json={"current_password": "Password123!", "new_password": "NewPassword456!", "confirm_password": "NewPassword456!"},
        )
        self.assertEqual(pw_res.status_code, 200)

        self.assertEqual(self.client.post("/account/api/logout").status_code, 200)
        self.assertFalse(self.client.get("/account/api/me").get_json()["authenticated"])

        bad_login = self.client.post("/account/api/login", json={"identifier": self.username, "password": "wrong"})
        self.assertEqual(bad_login.status_code, 401)

        login_ok = self.client.post(
            "/account/api/login",
            json={"identifier": self.username, "password": "NewPassword456!"},
        )
        self.assertEqual(login_ok.status_code, 200)
        self.assertTrue(self.client.get("/account/api/me").get_json()["authenticated"])

        # Remove avatar cleanup
        self.assertEqual(self.client.delete("/account/api/avatar").status_code, 200)

        # Clean up test shop product & files
        import shutil
        import shop
        with sc_app.app.app_context():
            with shop.db() as c:
                c.execute("DELETE FROM media WHERE product_id = ?", (pid,))
                c.execute("DELETE FROM products WHERE id = ?", (pid,))
        shutil.rmtree(shop.PRODUCTS_DIR / str(pid), ignore_errors=True)

    def test_mandatory_account_gate_after_tool_runs(self):
        import shutil
        from unittest.mock import patch

        site_id = f"gate_site_{self.tag}"
        site_dir = sc_app.CLONED_DIR / site_id
        site_dir.mkdir(parents=True, exist_ok=True)
        (site_dir / "index.html").write_text("<html><body><h1>Gate Test</h1></body></html>", encoding="utf-8")
        scan_id = None
        try:
            with self.client.session_transaction() as sess:
                sess["enforce_account_gate"] = True

            # 1. Cloneur/Studio résultats bloqués tant qu'aucun compte n'est créé
            r_studio = self.client.get(f"/__sc/studio/{site_id}")
            self.assertEqual(r_studio.status_code, 302)
            self.assertIn("/account/register?gate=cloner", r_studio.headers["Location"])

            r_prev = self.client.get(f"/preview/{site_id}/")
            self.assertEqual(r_prev.status_code, 302)
            self.assertIn("/account/register?gate=cloner", r_prev.headers["Location"])

            r_serve = self.client.post(f"/__sc/api/sites/{site_id}/serve")
            self.assertEqual(r_serve.status_code, 401)
            self.assertEqual(r_serve.get_json()["error_code"], "ACCOUNT_REQUIRED")
            self.assertIn("/account/register?gate=cloner", r_serve.get_json()["redirect"])

            r_zip = self.client.get(f"/__sc/api/sites/{site_id}/download")
            self.assertEqual(r_zip.status_code, 401)
            self.assertEqual(r_zip.get_json()["error_code"], "ACCOUNT_REQUIRED")

            r_pages = self.client.get(f"/__sc/api/studio/{site_id}/pages")
            self.assertEqual(r_pages.status_code, 401)
            self.assertEqual(r_pages.get_json()["error_code"], "ACCOUNT_REQUIRED")

            # Vignettes de la liste restent accessibles
            r_cov = self.client.get(f"/__sc/studio/{site_id}/cover.jpg")
            self.assertNotEqual(r_cov.status_code, 401)

            # 2. Scan Ultron s'exécute puis masque les résultats derrière la création de compte
            mock_result = {
                "success": True,
                "target_url": "https://innotech-lab.local",
                "timestamp": "2026-11-11 13:30:00",
                "risk_score": 78,
                "grade": "B",
                "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "total": 1},
                "findings": [{"id": "f1", "title": "HSTS manquant", "severity": "high", "status": "fail"}],
                "recommendations": ["Activer HSTS"],
            }
            with patch("security.scan_target", return_value=mock_result):
                r_scan = self.client.post(
                    "/__sc/security/api/scan",
                    json={"target_url": "https://innotech-lab.local"},
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
            self.assertEqual(r_scan.status_code, 200, r_scan.get_json())
            sj = r_scan.get_json()
            self.assertTrue(sj["requires_account"])
            self.assertIn("/account/register?gate=ultron", sj["register_url"])
            self.assertEqual(sj["findings_count"], 1)
            self.assertNotIn("findings", sj)
            self.assertNotIn("risk_score", sj)
            scan_id = sj["id"]

            r_det = self.client.get(f"/__sc/security/api/scans/{scan_id}")
            self.assertEqual(r_det.status_code, 401)
            self.assertEqual(r_det.get_json()["error_code"], "ACCOUNT_REQUIRED")

            r_rep = self.client.get(f"/__sc/security/api/scans/{scan_id}/report")
            self.assertEqual(r_rep.status_code, 302)
            self.assertIn("/account/register?gate=ultron", r_rep.headers["Location"])

            # 3. Création de compte simplifiée (Nom + Email + Mot de passe uniquement) -> débloque Studio & rapport
            reg_page_html = self.client.get("/account/register").get_data(as_text=True)
            self.assertNotIn('href="/admin', reg_page_html)
            for pub_path in ("/__sc/home", "/__sc/", "/shop/", "/__sc/security/"):
                self.assertNotIn('href="/admin', self.client.get(pub_path).get_data(as_text=True), pub_path)

            reg = self.client.post(
                "/account/api/register",
                json={
                    "display_name": "Jean-Luc Émile",
                    "email": self.email,
                    "password": "Pass1234",
                },
            )
            self.assertEqual(reg.status_code, 201, reg.get_json())
            self.assertTrue(reg.get_json()["user"]["username"].startswith("jean-luc"))

            self.assertEqual(self.client.get(f"/__sc/studio/{site_id}").status_code, 200)
            self.assertEqual(self.client.get(f"/__sc/api/studio/{site_id}/pages").status_code, 200)
            unlocked_scan = self.client.get(f"/__sc/security/api/scans/{scan_id}")
            self.assertEqual(unlocked_scan.status_code, 200)
            self.assertEqual(unlocked_scan.get_json()["risk_score"], 78)
            self.assertEqual(len(unlocked_scan.get_json()["findings"]), 1)
        finally:
            shutil.rmtree(site_dir, ignore_errors=True)
            if scan_id is not None:
                conn = get_connection()
                try:
                    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                    conn.commit()
                finally:
                    conn.close()

    def test_login_and_register_not_hijacked_by_active_preview_cookie(self):
        site_id = f"preview_cookie_{self.tag}"
        site_dir = sc_app.CLONED_DIR / site_id
        site_dir.mkdir(parents=True, exist_ok=True)
        (site_dir / "index.html").write_text("<html><body><h1>Cloned</h1></body></html>", encoding="utf-8")
        try:
            # Simule un utilisateur ayant déjà un cookie sc_site actif après un aperçu
            self.client.set_cookie("sc_site", site_id, path="/")

            # Pages d'authentification et APIs /account/* doivent rester accessibles (pas interceptées en 404/204)
            r_login_page = self.client.get("/account/login")
            self.assertEqual(r_login_page.status_code, 200)
            self.assertIn("loginForm", r_login_page.get_data(as_text=True))

            r_reg_page = self.client.get("/account/register")
            self.assertEqual(r_reg_page.status_code, 200)
            self.assertIn("registerForm", r_reg_page.get_data(as_text=True))

            r_reg_api = self.client.post(
                "/account/api/register",
                json={
                    "display_name": "Cookie Test",
                    "email": self.email,
                    "password": "Password123",
                },
            )
            self.assertEqual(r_reg_api.status_code, 201, r_reg_api.get_data(as_text=True))
            self.assertTrue(r_reg_api.get_json()["success"])

            self.client.post("/account/api/logout")

            r_login_api = self.client.post(
                "/account/api/login",
                json={"identifier": self.email, "password": "Password123"},
            )
            self.assertEqual(r_login_api.status_code, 200, r_login_api.get_data(as_text=True))
            self.assertTrue(r_login_api.get_json()["success"])

            r_me = self.client.get("/account/api/me")
            self.assertEqual(r_me.status_code, 200)
            self.assertTrue(r_me.get_json()["authenticated"])
        finally:
            shutil.rmtree(site_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
