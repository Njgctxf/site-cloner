"""Tests for the 3-tier SaaS offer system (Gratuit / Pro / Entreprise)."""

import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app as flask_app
from security import plans


class SecurityPlansTests(unittest.TestCase):
    def setUp(self):
        plans.init_plan_tables()
        self.uid = f"usr_plan_{uuid.uuid4().hex[:10]}"

    def test_catalog_structure_three_offers(self):
        status = plans.get_user_plan_status(self.uid, is_admin=False, is_local=True)
        self.assertEqual(status["plan_id"], "free")
        ids = [p["id"] for p in status["plans"]]
        self.assertEqual(ids, ["free", "pro", "enterprise"])
        self.assertEqual(status["plans"][0]["max_sites_per_month"], 1)
        self.assertEqual(status["plans"][1]["max_sites_per_month"], 10)
        self.assertIsNone(status["plans"][2]["max_sites_per_month"])
        self.assertFalse(status["sentinel_full_access"])

    def test_free_plan_quota_and_module_restrictions(self):
        # 1st site basic audit allowed
        ok1 = plans.check_and_authorize_scan(self.uid, "https://alpha.example", ["headers", "files", "secrets"])
        self.assertTrue(ok1["allowed"])
        plans.record_scan_usage(self.uid, "https://alpha.example")

        # Re-scanning the exact same host in the same month remains allowed
        ok_same = plans.check_and_authorize_scan(self.uid, "https://www.alpha.example/login", ["headers"])
        self.assertTrue(ok_same["allowed"])

        # 2nd distinct site in the same month must be blocked
        blocked_site = plans.check_and_authorize_scan(self.uid, "https://beta.example", ["headers"])
        self.assertFalse(blocked_site["allowed"])
        self.assertEqual(blocked_site["error_code"], "SITE_QUOTA_EXCEEDED")
        self.assertEqual(blocked_site["required_plan"], "pro")

        # Advanced module on free plan must be blocked
        blocked_mod = plans.check_and_authorize_scan(self.uid, "https://alpha.example", ["headers", "active"])
        self.assertFalse(blocked_mod["allowed"])
        self.assertEqual(blocked_mod["error_code"], "PLAN_UPGRADE_REQUIRED")
        self.assertEqual(blocked_mod["required_plan"], "pro")

    def test_pro_plan_limits_and_enterprise_unlocks_everything(self):
        plans.set_user_plan(self.uid, "pro", source="test")
        pro_ok = plans.check_and_authorize_scan(self.uid, "https://s1.example", ["headers", "active", "tls", "cve"])
        self.assertTrue(pro_ok["allowed"])

        pro_blocked_ent = plans.check_and_authorize_scan(self.uid, "https://s1.example", ["pentagi"])
        self.assertFalse(pro_blocked_ent["allowed"])
        self.assertEqual(pro_blocked_ent["required_plan"], "enterprise")

        for i in range(10):
            plans.record_scan_usage(self.uid, f"https://site{i}.example")
        eleventh = plans.check_and_authorize_scan(self.uid, "https://site10.example", ["headers"])
        self.assertFalse(eleventh["allowed"])
        self.assertEqual(eleventh["error_code"], "SITE_QUOTA_EXCEEDED")
        self.assertEqual(eleventh["required_plan"], "enterprise")

        plans.set_user_plan(self.uid, "enterprise", source="test")
        ent_ok = plans.check_and_authorize_scan(self.uid, "https://site10.example", ["pentagi", "active"])
        self.assertTrue(ent_ok["allowed"])
        ent_status = plans.get_user_plan_status(self.uid)
        self.assertTrue(ent_status["sentinel_full_access"])

    def test_flask_api_scan_enforces_free_quota_and_checkout_guards(self):
        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()
        with client.session_transaction() as sess:
            sess["sentinel_user_id"] = self.uid

        # Remote checkout without Stripe cannot bypass payment
        with patch.dict("os.environ", {"STRIPE_SECRET_KEY": ""}, clear=False):
            remote_res = client.post(
                "/__sc/security/api/plans/checkout",
                json={"plan_id": "pro"},
                environ_base={"REMOTE_ADDR": "203.0.113.10"},
            )
            self.assertEqual(remote_res.status_code, 402)
            self.assertTrue(remote_res.get_json()["stripe_required"])

            # Local loopback checkout works in trial mode
            local_res = client.post(
                "/__sc/security/api/plans/checkout",
                json={"plan_id": "free"},
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            )
            self.assertEqual(local_res.status_code, 200)

        # Free user trying an active/pro scan gets 403
        scan_blocked = client.post(
            "/__sc/security/api/scan",
            json={"target_url": "https://innotech-lab.local", "categories": ["active"]},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        self.assertEqual(scan_blocked.status_code, 403)
        self.assertEqual(scan_blocked.get_json()["error_code"], "PLAN_UPGRADE_REQUIRED")

        # Admin plan assignment endpoint requires admin auth
        unauth_admin = client.get("/__sc/security/api/admin/plans")
        self.assertEqual(unauth_admin.status_code, 401)

    def test_feature_locks_and_comparison_matrix_endpoints(self):
        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()
        with client.session_transaction() as sess:
            sess["sentinel_user_id"] = self.uid

        # GET /api/plans includes comparison_rows, cloner_plans, cloner_comparison_rows, suite_bundles
        plans_res = client.get("/__sc/security/api/plans")
        self.assertEqual(plans_res.status_code, 200)
        plans_json = plans_res.get_json()
        self.assertEqual(len(plans_json["comparison_rows"]), 10)
        self.assertEqual(len(plans_json["cloner_plans"]), 3)
        self.assertEqual(len(plans_json["cloner_comparison_rows"]), 7)
        self.assertEqual(len(plans_json["suite_bundles"]), 2)
        self.assertTrue(len(plans_json["plans"][0]["excluded_features"]) >= 3)
        self.assertTrue(len(plans_json["plans"][1]["excluded_features"]) >= 3)
        self.assertEqual(plans_json["plans"][2]["excluded_features"], [])

        # Free user is blocked from Pro patch/report and Copilot drawer chat
        patch_free = client.get("/__sc/security/api/scans/999999/patch")
        self.assertEqual(patch_free.status_code, 403)
        self.assertEqual(patch_free.get_json()["error_code"], "PLAN_UPGRADE_REQUIRED")

        report_free = client.get("/__sc/security/api/scans/999999/report")
        self.assertEqual(report_free.status_code, 403)

        chat_free = client.post(
            "/__sc/security/api/sentinel/chat",
            json={"message": "Comment corriger HSTS ?", "origin": "copilot", "provider": "mock"},
        )
        self.assertEqual(chat_free.status_code, 403)
        self.assertEqual(chat_free.get_json()["error_code"], "PLAN_UPGRADE_REQUIRED")

        # Upgrading to Pro unlocks patch/report routes (404 when scan missing) and Copilot chat (200)
        plans.set_user_plan(self.uid, "pro", source="test")
        patch_pro = client.get("/__sc/security/api/scans/999999/patch")
        self.assertEqual(patch_pro.status_code, 404)
        report_pro = client.get("/__sc/security/api/scans/999999/report")
        self.assertEqual(report_pro.status_code, 404)
        chat_pro = client.post(
            "/__sc/security/api/sentinel/chat",
            json={"message": "Comment corriger HSTS ?", "origin": "copilot", "provider": "mock"},
        )
        self.assertEqual(chat_pro.status_code, 200)
        self.assertTrue(chat_pro.get_json().get("reply"))

    def test_admin_platform_overview_and_plan_assignment(self):
        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()

        # Unauthenticated admin overview request returns 401
        self.assertEqual(client.get("/admin/api/platform-overview").status_code, 401)

        with client.session_transaction() as sess:
            sess["admin"] = "admin"
            sess["csrf"] = "tok_test_csrf"

        ov_res = client.get("/admin/api/platform-overview")
        self.assertEqual(ov_res.status_code, 200)
        ov = ov_res.get_json()
        self.assertEqual(len(ov["timeline_14d"]["days"]), 14)
        self.assertEqual(len(ov["timeline_14d"]["scans"]), 14)
        for key in ("security", "domains", "plans", "shield", "llm", "logs", "cloner"):
            self.assertIn(key, ov)

        assign_res = client.post(
            "/admin/api/platform/assign-plan",
            headers={"X-CSRF-Token": "tok_test_csrf"},
            json={"user_id": self.uid, "plan_id": "pro", "email": "client@example.com"},
        )
        self.assertEqual(assign_res.status_code, 200)
        self.assertEqual(assign_res.get_json()["subscription"]["plan_id"], "pro")

        dash_res = client.get("/admin/")
        self.assertEqual(dash_res.status_code, 200)
        html = dash_res.get_data(as_text=True)
        for marker in ("activity-chart", "plans-donut", "tab-security", "assign-plan-form"):
            self.assertIn(marker, html)


if __name__ == "__main__":
    unittest.main()
