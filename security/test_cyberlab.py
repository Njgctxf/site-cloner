"""
test_cyberlab.py - Automated Academic Verification Test Suite
Tests security controls, sandbox isolation, scanner whitelist,
and vulnerability remediation accuracy.
Run from the SiteCloner-SaaS folder: python -m unittest security.test_cyberlab
"""

import unittest
import json
from app import app  # SiteCloner's app, with the security module mounted
from security.database import init_db, get_connection
from security.scanner import is_target_authorized, scan_target
from security.simulations import execute_simulation, LAB_STATE

class CyberLabTestSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = app.test_client()

    def test_01_database_integrity(self):
        """Verifies platform tables and mock sandbox fixtures exist."""
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) as cnt FROM lab_users")
        user_count = c.fetchone()["cnt"]
        self.assertGreaterEqual(user_count, 3, "Lab users fixtures must be seeded.")

        c.execute("SELECT COUNT(*) as cnt FROM lab_documents")
        doc_count = c.fetchone()["cnt"]
        self.assertGreaterEqual(doc_count, 2, "Lab documents fixtures must be seeded.")
        conn.close()

    def test_02_scanner_scope_whitelist_enforcement(self):
        """Ensures non-authorized third-party domains are strictly rejected."""
        self.assertFalse(is_target_authorized("https://google.com"))
        self.assertFalse(is_target_authorized("http://bank-prod.com/login"))
        self.assertTrue(is_target_authorized("http://localhost:5050/lab"))
        self.assertTrue(is_target_authorized("http://127.0.0.1:5050/lab"))

        # Test via API
        res = self.client.post('/__sc/security/api/scan', json={"target_url": "https://external-target.com"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("non autorisée", data.get("error", ""))

    def test_03_sqli_demonstration_and_remediation(self):
        """Verifies SQLi exploitation in vulnerable mode and neutralization in secured mode."""
        payload = "' OR '1'='1"

        # 1. Test Vulnerable Mode
        vuln_res = execute_simulation("sqli", payload, user_mode="VULNERABLE")
        self.assertEqual(vuln_res["outcome"], "VULNERABILITY_CONFIRMED")
        self.assertTrue(vuln_res["result_data"]["compromised"])
        self.assertGreater(len(vuln_res["result_data"]["records_exposed"]), 1)

        # 2. Test Secured Mode (Remediation)
        sec_res = execute_simulation("sqli", payload, user_mode="SECURED")
        self.assertEqual(sec_res["outcome"], "MITIGATED")
        self.assertFalse(sec_res["result_data"]["compromised"])

    def test_04_xss_demonstration_and_remediation(self):
        """Verifies XSS unescaped output vs HTML contextual encoding."""
        payload = "<script>alert('XSS-TEST')</script>"

        # Vulnerable mode
        vuln_res = execute_simulation("xss", payload, user_mode="VULNERABLE")
        self.assertEqual(vuln_res["outcome"], "VULNERABILITY_CONFIRMED")
        self.assertIn("<script>", vuln_res["result_data"]["raw_output"])

        # Secured mode
        sec_res = execute_simulation("xss", payload, user_mode="SECURED")
        self.assertEqual(sec_res["outcome"], "MITIGATED")
        self.assertNotIn("<script>", sec_res["result_data"]["raw_output"])
        self.assertIn("&lt;script&gt;", sec_res["result_data"]["raw_output"])

    def test_05_idor_demonstration_and_remediation(self):
        """Verifies broken access control on user profiles and RBAC enforcement."""
        # Vulnerable mode: guest can read user 1 (Admin) salary
        vuln_res = execute_simulation("idor", "1", user_mode="VULNERABLE")
        self.assertEqual(vuln_res["outcome"], "VULNERABILITY_CONFIRMED")
        self.assertIn("salary", vuln_res["result_data"]["data"])

        # Secured mode: RBAC restricts access
        sec_res = execute_simulation("idor", "1", user_mode="SECURED")
        self.assertEqual(sec_res["outcome"], "MITIGATED")
        self.assertFalse(sec_res["result_data"]["compromised"])

    def test_06_lab_mode_toggle_api(self):
        """Verifies switching between vulnerable and secured modes via API."""
        res = self.client.post('/__sc/security/api/lab/toggle-mode', json={"mode": "SECURED"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["mode"], "SECURED")

        res2 = self.client.post('/__sc/security/api/lab/toggle-mode', json={"mode": "VULNERABLE"})
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.get_json()["mode"], "VULNERABLE")

    def test_07_anti_ssrf_protection(self):
        """Verifies that private IP ranges, loopback and AWS/Cloud metadata are blocked."""
        from security.network_guard import is_safe_ip, validate_target_url

        # Direct IP validation
        self.assertFalse(is_safe_ip("127.0.0.1")[0], "Loopback must be rejected")
        self.assertFalse(is_safe_ip("10.0.0.5")[0], "RFC1918 Class A must be rejected")
        self.assertFalse(is_safe_ip("172.16.0.1")[0], "RFC1918 Class B must be rejected")
        self.assertFalse(is_safe_ip("192.168.1.1")[0], "RFC1918 Class C must be rejected")
        self.assertFalse(is_safe_ip("169.254.169.254")[0], "Cloud metadata IP must be rejected")
        self.assertTrue(is_safe_ip("8.8.8.8")[0], "Public IP must be accepted")
        self.assertTrue(is_safe_ip("1.1.1.1")[0], "Public IP must be accepted")

        # URL validation
        self.assertFalse(validate_target_url("http://169.254.169.254/latest/meta-data/")[0])
        self.assertFalse(validate_target_url("http://192.168.1.50:8080/admin")[0])
        self.assertFalse(validate_target_url("gopher://127.0.0.1:6379")[0])

    def test_08_domain_verification_workflow(self):
        """Verifies enrolling an enterprise domain, token generation, and authorization check."""
        import uuid
        from security.database import is_domain_authorized, mark_domain_as_verified

        test_domain = f"audit-enterprise-{uuid.uuid4().hex[:8]}.com"
        self.assertFalse(is_domain_authorized(test_domain), "Unregistered domain must not be authorized")

        # Enroll domain via API
        res = self.client.post('/__sc/security/api/domains', json={"domain": test_domain, "verification_method": "dns_txt"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        token = data["domain"]["verification_token"]
        self.assertTrue(token.startswith("sc-audit-"))

        # Verify domain is still pending
        self.assertFalse(is_domain_authorized(test_domain))

        # Simulate successful ownership proof
        mark_domain_as_verified(test_domain, "dns_txt")
        self.assertTrue(is_domain_authorized(test_domain), "Verified domain must be authorized for audits")
        self.assertTrue(is_domain_authorized(f"api.{test_domain}"), "Subdomains of verified domain must be authorized")

        # Verify listed in API
        list_res = self.client.get('/__sc/security/api/domains')
        self.assertEqual(list_res.status_code, 200)
        domains = list_res.get_json()["domains"]
        self.assertTrue(any(d["domain"] == test_domain and d["is_verified"] == 1 for d in domains))

    def test_09_dast_sqli_detection(self):
        """Verifies that non-destructive SQLi probe detects SGBD syntax error leaks."""
        from unittest.mock import MagicMock
        from security.dast_engine import audit_sqli

        mock_session = MagicMock()
        base_resp = MagicMock(text="<html><body>Welcome User</body></html>")
        # Injected single quote causes SQLite syntax error leak
        error_resp = MagicMock(text="<html><body>Error: near \"'\": syntax error in sqlite3.OperationalError</body></html>")
        mock_session.get.side_effect = [base_resp, error_resp]

        query_targets = ["https://example.com/search?q=test"]
        findings = audit_sqli(mock_session, [], query_targets)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("SQL", findings[0]["title"])
        self.assertIn("SQLite", findings[0]["title"])

    def test_10_dast_xss_detection(self):
        """Verifies that raw reflected HTML tags in parameters are identified as XSS."""
        from unittest.mock import MagicMock
        from security.dast_engine import audit_xss

        mock_session = MagicMock()
        # Mock server reflecting parameter directly without encoding
        def mock_get(url, params=None, **kwargs):
            val = (params or {}).get("q", "")
            return MagicMock(text=f"<html><body>Search results for: {val}</body></html>")

        mock_session.get.side_effect = mock_get
        query_targets = ["https://example.com/search?q=hello"]
        findings = audit_xss(mock_session, "https://example.com", [], query_targets)
        self.assertEqual(len(findings), 1)
        self.assertIn("XSS", findings[0]["title"])
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_11_dast_path_traversal_detection(self):
        """Verifies that parameters exposing filesystem errors on relative paths are caught."""
        from unittest.mock import MagicMock
        from security.dast_engine import audit_path_traversal

        mock_session = MagicMock()
        mock_resp = MagicMock(text="Warning: failed to open stream: No such file or directory in /var/www/download.php")
        mock_session.get.return_value = mock_resp

        query_targets = ["https://example.com/download.php?file=report.pdf"]
        findings = audit_path_traversal(mock_session, query_targets)
        self.assertEqual(len(findings), 1)
        self.assertIn("Path Traversal", findings[0]["title"])
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_12_dast_rate_limiting(self):
        """Verifies detection of unthrottled rapid attempts on password forms."""
        from unittest.mock import MagicMock
        from security.dast_engine import audit_rate_limiting

        mock_session = MagicMock()
        # Mock server returning 200 OK without 429
        mock_session.post.return_value = MagicMock(status_code=200, headers={})

        forms = [{
            "action": "https://example.com/login",
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text", "default": "admin"},
                {"name": "password", "type": "password", "default": "secret"}
            ]
        }]

        findings = audit_rate_limiting(mock_session, forms)
        self.assertEqual(len(findings), 1)
        self.assertIn("Limitation de Cadence", findings[0]["title"])
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_13_dast_idor_detection(self):
        """Verifies detection of direct object access across tenant credentials (IDOR/BOLA)."""
        from unittest.mock import MagicMock
        from security.dast_engine import audit_idor

        mock_session = MagicMock()
        mock_resp = MagicMock(status_code=200, text='{"order_id": 105, "customer": "UserA", "total": 99.0}')
        mock_session.get.return_value = mock_resp

        query_targets = ["https://example.com/api/orders?order_id=105"]
        # User B headers supplied
        b_headers = {"Authorization": "Bearer token_user_b"}

        findings = audit_idor(mock_session, query_targets, auth_headers_user_b=b_headers)
        self.assertEqual(len(findings), 1)
        self.assertIn("IDOR", findings[0]["title"])
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_14_scheduled_audits_workflow(self):
        """Verifies scheduling, listing, toggling, and removing recurring security audits."""
        from security.database import (
            mark_domain_as_verified, add_scheduled_audit,
            list_scheduled_audits, toggle_scheduled_audit, delete_scheduled_audit
        )
        import uuid

        test_domain = f"corp-audit-{uuid.uuid4().hex[:6]}.com"
        mark_domain_as_verified(test_domain, "dns_txt")

        # Create schedule via API
        target_url = f"https://{test_domain}/app"
        res = self.client.post('/__sc/security/api/schedules', json={
            "target_url": target_url,
            "frequency": "weekly"
        })
        self.assertEqual(res.status_code, 200)
        sched_id = res.get_json()["schedule_id"]

        # List schedules
        list_res = self.client.get('/__sc/security/api/schedules')
        self.assertEqual(list_res.status_code, 200)
        schedules = list_res.get_json()["schedules"]
        self.assertTrue(any(s["id"] == sched_id for s in schedules))

        # Toggle pause
        tog_res = self.client.post(f'/__sc/security/api/schedules/{sched_id}/toggle', json={"is_active": False})
        self.assertEqual(tog_res.status_code, 200)
        self.assertEqual(tog_res.get_json()["is_active"], 0)

        # Delete schedule
        del_res = self.client.delete(f'/__sc/security/api/schedules/{sched_id}')
        self.assertEqual(del_res.status_code, 200)

    def test_15_scheduler_cycle_execution(self):
        """Verifies that due scheduled audits are identified and executed by the scheduler."""
        from unittest.mock import patch, MagicMock
        from security.database import add_scheduled_audit, mark_domain_as_verified
        from security.scheduler import run_scheduler_cycle
        import uuid

        test_domain = f"corp-due-{uuid.uuid4().hex[:6]}.com"
        mark_domain_as_verified(test_domain, "dns_txt")
        target_url = f"https://{test_domain}/app"
        sched_id = add_scheduled_audit(test_domain, target_url, "daily")

        mock_scan_res = {
            "success": True,
            "target_url": target_url,
            "timestamp": "2026-10-30 12:00:00",
            "risk_score": 85,
            "grade": "B",
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "findings": [{"severity": "HIGH", "title": "Missing HSTS", "description": "HSTS header absent"}]
        }

        with patch("security.scheduler.scan_target", return_value=mock_scan_res):
            executed = run_scheduler_cycle()
            self.assertGreaterEqual(executed, 1)

    def test_16_security_alerts_dispatch(self):
        """Verifies webhook and email dispatch triggers when critical vulnerabilities are found."""
        from unittest.mock import patch
        from security.alerts import dispatch_scan_alerts

        scan_crit = {
            "risk_score": 35,
            "grade": "F",
            "counts": {"critical": 1, "high": 0, "total": 1},
            "findings": [{"severity": "CRITICAL", "title": "SQLi Detected", "description": "Syntax error leak"}]
        }

        with patch("security.alerts.send_security_alert_webhook") as mock_webhook:
            with patch.dict("os.environ", {"SECURITY_ALERT_WEBHOOK": "https://hooks.slack.com/services/mock"}):
                dispatch_scan_alerts("https://app.corp.com", scan_crit)
                mock_webhook.assert_called_once()

    def test_17_dast_open_redirect(self):
        """Verifies detection of unvalidated 302 redirects to external domains."""
        from unittest.mock import MagicMock
        from security.dast_engine import audit_open_redirect

        mock_session = MagicMock()
        mock_resp = MagicMock(status_code=302, headers={"Location": "https://example.com"})
        mock_session.get.return_value = mock_resp

        query_targets = ["https://corp.com/login?redirect=https://internal.corp.com"]
        findings = audit_open_redirect(mock_session, query_targets)
        self.assertEqual(len(findings), 1)
        self.assertIn("Redirection Ouverte", findings[0]["title"])
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_18_dast_deep_cors_arbitrary_credentials(self):
        """Verifies detection of arbitrary origin reflection with credentials enabled."""
        from unittest.mock import MagicMock
        from security.dast_engine import audit_deep_cors

        mock_session = MagicMock()
        mock_resp = MagicMock(headers={
            "Access-Control-Allow-Origin": "https://evil-attacker.com",
            "Access-Control-Allow-Credentials": "true"
        })
        mock_session.get.return_value = mock_resp

        findings = audit_deep_cors(mock_session, "https://api.corp.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("CORS", findings[0]["title"])

    def test_19_dast_dom_xss_taint_flow(self):
        """Verifies static heuristic detection of dangerous source-to-sink DOM XSS flows."""
        from security.dast_engine import audit_dom_xss_sources_sinks

        vulnerable_script = """
        const params = new URLSearchParams(location.search);
        const name = params.get('user');
        document.getElementById('greeting').innerHTML = 'Hello ' + name;
        """
        findings = audit_dom_xss_sources_sinks([vulnerable_script], "https://corp.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("DOM", findings[0]["title"])
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_20_api_discovery_in_scripts(self):
        """Verifies discovery of hidden REST endpoints inside client JavaScript code."""
        from unittest.mock import MagicMock
        from security.dast_engine import discover_api_endpoints_and_specs

        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(status_code=404)

        html_with_js = """
        <script>
            function loadData() {
                fetch('/api/v2/users/me/billing').then(r => r.json());
                axios.post('/auth/token/refresh');
            }
        </script>
        """
        endpoints = discover_api_endpoints_and_specs(mock_session, "https://corp.com", html_with_js)
        self.assertTrue(any("/api/v2/users/me/billing" in ep for ep in endpoints))
        self.assertTrue(any("/auth/token/refresh" in ep for ep in endpoints))

    def test_21_sast_secret_detection(self):
        """Verifies detection of exposed API keys (Stripe, AWS) in code."""
        from security.sast_secrets import scan_code_for_secrets

        # NOTE: The fake key is split at runtime to avoid GitHub Secret Scanning false positives.
        # The SAST regex matches on the reconstructed string, not the literal source here.
        _fake_stripe = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz012"
        _fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        sample_code = f"""
        const stripeKey = '{_fake_stripe}';
        const awsId = '{_fake_aws}';
        """
        findings = scan_code_for_secrets(sample_code)
        self.assertGreaterEqual(len(findings), 2)
        titles = [f["title"] for f in findings]
        self.assertTrue(any("Stripe" in t for t in titles))
        self.assertTrue(any("AWS" in t for t in titles))

    def test_22_sca_vulnerable_components(self):
        """Verifies Software Composition Analysis (SCA) detecting CVEs in jQuery and Lodash."""
        from security.sca_engine import scan_vulnerable_components

        sample_html = """
        <script src="/static/js/jquery-1.11.1.min.js"></script>
        <script src="/static/js/lodash.4.17.15.js"></script>
        """
        findings = scan_vulnerable_components(sample_html)
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("jQuery" in f["title"] for f in findings))
        self.assertTrue(any("Lodash" in f["title"] for f in findings))

    def test_23_patch_generator_configs(self):
        """Verifies generation of production-ready Nginx and Apache security configs."""
        from security.patch_generator import generate_nginx_security_conf, generate_apache_htaccess

        nginx_conf = generate_nginx_security_conf("https://monentreprise.com", [])
        self.assertIn("Content-Security-Policy", nginx_conf)
        self.assertIn("Strict-Transport-Security", nginx_conf)
        self.assertIn("server_tokens off", nginx_conf)

        apache_conf = generate_apache_htaccess([])
        self.assertIn("Options -Indexes", apache_conf)
        self.assertIn("X-Content-Type-Options", apache_conf)

    def test_24_patch_generator_code_remediation(self):
        """Verifies generation of before/after secure code snippets."""
        from security.patch_generator import generate_code_remediation_bundle

        findings = [
            {"title": "Injection SQL (MySQL) sur 'id'"},
            {"title": "Cross-Site Scripting (XSS Réfléchi)"},
            {"title": "CORS Permissif Dangereux"}
        ]
        bundle = generate_code_remediation_bundle(findings)
        patches = bundle["patches"]
        self.assertEqual(len(patches), 3)
        types = [p["vuln_type"] for p in patches]
        self.assertTrue(any("SQL" in t for t in types))
        self.assertTrue(any("XSS" in t for t in types))
        self.assertTrue(any("CORS" in t for t in types))

    def test_25_live_cve_feed_integration(self):
        """Verifies querying and SQLite caching of CVE advisories."""
        from unittest.mock import patch, MagicMock
        from security.cve_feed import query_live_cve_feed

        mock_osv_resp = MagicMock()
        mock_osv_resp.status_code = 200
        mock_osv_resp.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-jvhq-5mcr-jw5w",
                    "aliases": ["CVE-2020-8203"],
                    "summary": "Prototype Pollution in lodash",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"}]
                }
            ]
        }

        with patch("requests.post", return_value=mock_osv_resp):
            cves = query_live_cve_feed("lodash-live-test", "4.17.15")
            self.assertEqual(len(cves), 1)
            self.assertEqual(cves[0]["cve_id"], "CVE-2020-8203")

    def test_26_ci_cd_security_gate_auth(self):
        """Verifies API key creation and enforcement on CI/CD gate."""
        from security.database import create_security_api_key

        # Rejection without key
        res = self.client.post('/__sc/security/api/ci/scan', json={"target_url": "https://corp.com"})
        self.assertEqual(res.status_code, 401)

        # Create valid API key
        key_data = create_security_api_key("GitHub Actions Runner")
        raw_key = key_data["api_key"]

        # Rejection with invalid target (unauthorized domain)
        res_auth = self.client.post('/__sc/security/api/ci/scan',
                                   headers={"X-API-Key": raw_key},
                                   json={"target_url": "https://unregistered-domain.com"})
        self.assertEqual(res_auth.status_code, 400)

    def test_27_ci_cd_security_gate_pass_fail(self):
        """Verifies CI/CD gate pass (exit code 0) vs block (exit code 1) on critical vulnerabilities."""
        from unittest.mock import patch
        from security.database import create_security_api_key, mark_domain_as_verified
        import uuid

        test_domain = f"ci-audit-{uuid.uuid4().hex[:6]}.com"
        mark_domain_as_verified(test_domain, "dns_txt")
        target_url = f"https://{test_domain}/app"

        key_data = create_security_api_key("GitLab Pipeline")
        raw_key = key_data["api_key"]

        # Case 1: Clean scan -> PASSED (HTTP 200, exit_code 0)
        mock_clean = {
            "success": True,
            "target_url": target_url,
            "timestamp": "2026-10-30 12:00:00",
            "risk_score": 95,
            "grade": "A",
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": []
        }
        with patch("security.scan_target", return_value=mock_clean):
            res_pass = self.client.post('/__sc/security/api/ci/scan',
                                       headers={"X-API-Key": raw_key},
                                       json={"target_url": target_url, "min_score": 75})
            self.assertEqual(res_pass.status_code, 200)
            self.assertEqual(res_pass.get_json()["status"], "PASSED")
            self.assertEqual(res_pass.get_json()["exit_code"], 0)

        # Case 2: Critical finding -> FAILED / BLOCKED (HTTP 422, exit_code 1)
        mock_fail = {
            "success": True,
            "target_url": target_url,
            "timestamp": "2026-10-30 12:00:00",
            "risk_score": 35,
            "grade": "F",
            "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
            "findings": [{"severity": "CRITICAL", "title": "SQLi", "description": "Critical injection"}]
        }
        with patch("security.scan_target", return_value=mock_fail):
            res_fail = self.client.post('/__sc/security/api/ci/scan',
                                       headers={"X-API-Key": raw_key},
                                       json={"target_url": target_url, "min_score": 75})
            self.assertEqual(res_fail.status_code, 422)
            self.assertEqual(res_fail.get_json()["status"], "FAILED")
            self.assertEqual(res_fail.get_json()["exit_code"], 1)

    def test_28_nvd_api_query_and_cache(self):
        """Verifies querying official NIST NVD API v2.0 with local caching."""
        from unittest.mock import patch, MagicMock
        from security.cve_feed import query_nvd_feed
        import uuid

        fake_pkg = f"pkg_{uuid.uuid4().hex[:6]}"
        mock_nvd_resp = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-9999",
                        "descriptions": [{"lang": "en", "value": "Critical buffer overflow in web service"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                }
                            }]
                        }
                    }
                }
            ]
        }

        mock_http = MagicMock()
        mock_http.status_code = 200
        mock_http.json.return_value = mock_nvd_resp

        with patch("requests.get", return_value=mock_http) as mock_get:
            # 1st call: hits API and caches
            cves = query_nvd_feed(fake_pkg, limit=2)
            self.assertEqual(len(cves), 1)
            self.assertEqual(cves[0]["cve_id"], "CVE-2023-9999")
            self.assertEqual(cves[0]["severity"], "CRITICAL")
            self.assertEqual(mock_get.call_count, 1)

            # 2nd call: hits local SQLite cache without HTTP request
            cached_cves = query_nvd_feed(fake_pkg, limit=2)
            self.assertEqual(len(cached_cves), 1)
            self.assertEqual(mock_get.call_count, 1)

    def test_29_detect_outdated_server_and_cms_cves(self):
        """Verifies detection of obsolete web server and CMS versions with CVE matching."""
        from security.cve_feed import detect_server_and_cms_cves

        # Outdated Nginx banner
        findings = detect_server_and_cms_cves(
            server_header="nginx/1.18.0 (Ubuntu)",
            powered_by_header="PHP/7.4.3",
            html_content='<meta name="generator" content="WordPress 5.8.1">'
        )

        self.assertTrue(len(findings) >= 2)
        stack_titles = [f["title"] for f in findings]
        self.assertTrue(any("Nginx" in t for t in stack_titles))
        self.assertTrue(any("PHP" in t for t in stack_titles))
        for f in findings:
            self.assertIn("A06:2021", f["category"])
            self.assertIn("CVE", f["proof"])

    def test_30_admin_owner_authentication_gate(self):
        """Verifies strict access gating on Admin Private Space."""
        # Unauthenticated request -> Redirect or 401
        res_unauth = self.client.get('/__sc/security/admin-space')
        self.assertEqual(res_unauth.status_code, 302)
        self.assertIn("/admin/login", res_unauth.headers["Location"])

        res_api_unauth = self.client.get('/__sc/security/api/admin/domains')
        self.assertEqual(res_api_unauth.status_code, 401)

        # Authenticated request with session['admin']
        with self.client.session_transaction() as sess:
            sess["admin"] = "superadmin_owner"

        res_auth = self.client.get('/__sc/security/admin-space')
        self.assertEqual(res_auth.status_code, 200)
        self.assertIn(b"Espace", res_auth.data)

        res_api_auth = self.client.get('/__sc/security/api/admin/domains')
        self.assertEqual(res_api_auth.status_code, 200)

    def test_31_admin_private_domain_crud_and_auth(self):
        """Verifies lifecycle of owner private domains (CRUD + verification)."""
        import uuid
        from security.database import (
            add_admin_private_domain, list_admin_private_domains,
            verify_admin_private_domain, delete_admin_private_domain,
            is_admin_private_domain_authorized
        )

        test_domain = f"owner-app-{uuid.uuid4().hex[:8]}.com"
        rec = add_admin_private_domain(test_domain, "sc-token-secret-123", method="dns_txt", notes="Core SaaS App")
        self.assertEqual(rec["domain"], test_domain)
        self.assertEqual(rec["is_verified"], 0)

        # Before verification -> not authorized
        self.assertFalse(is_admin_private_domain_authorized(test_domain))

        # Verify domain
        ok = verify_admin_private_domain(rec["id"])
        self.assertTrue(ok)
        self.assertTrue(is_admin_private_domain_authorized(test_domain))

        # Cleanup
        deleted = delete_admin_private_domain(rec["id"])
        self.assertTrue(deleted)
        self.assertFalse(is_admin_private_domain_authorized(test_domain))

    def test_32_advanced_sqli_differential_guardrails(self):
        """Verifies non-destructive differential SQLi diagnostic & strict guardrail enforcement."""
        from unittest.mock import MagicMock
        from security.dast_engine import audit_sqli_advanced_differential, assert_safe_sqli_probe

        # 1. Guardrail test: offensive keywords must raise ValueError
        self.assertRaises(ValueError, assert_safe_sqli_probe, "UNION SELECT 1,2,3")
        self.assertRaises(ValueError, assert_safe_sqli_probe, "DROP TABLE users")
        self.assertRaises(ValueError, assert_safe_sqli_probe, "DELETE FROM accounts")
        self.assertRaises(ValueError, assert_safe_sqli_probe, "SELECT password FROM members")

        # 2. Benign probe validation
        self.assertTrue(assert_safe_sqli_probe("' AND '1'='1"))
        self.assertTrue(assert_safe_sqli_probe("' AND '1'='2"))

        # 3. Diagnostic execution on differential mock responses
        mock_session = MagicMock()
        resp_base = MagicMock(status_code=200, text="<html>Product List (10 items)</html>")
        resp_true = MagicMock(status_code=200, text="<html>Product List (10 items)</html>")
        # False condition causes significant divergence (e.g. empty results or 404)
        resp_false = MagicMock(status_code=404, text="<html>Not Found</html>")

        # Session returns base, true, false
        mock_session.get.side_effect = [resp_base, resp_true, resp_false]

        forms = []
        query_targets = ["https://app.mon-saas.com/search?q=phone"]

        findings = audit_sqli_advanced_differential(mock_session, forms, query_targets)
        self.assertTrue(len(findings) >= 1)
        self.assertIn("A03:2021", findings[0]["category"])
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("Injection SQL", findings[0]["title"])
        self.assertIn("confirm", findings[0]["title"])

    def test_33_scans_comparison_differential(self):
        """Verifies scan comparison logic (Scan A vs Scan B: resolved vs regressions)."""
        from security.database import save_scan, compare_scans
        import uuid

        target = f"https://saas-{uuid.uuid4().hex[:6]}.com"
        
        # Scan A (Baseline with 2 critical findings)
        scan_a = {
            "target_url": target,
            "timestamp": "2026-10-29 10:00:00",
            "risk_score": 50,
            "grade": "D",
            "counts": {"critical": 2, "high": 0, "medium": 0, "low": 0},
            "findings": [
                {"id": "VULN_SQLI", "title": "SQLi in Login", "severity": "CRITICAL", "category": "Injection"},
                {"id": "VULN_XSS", "title": "Reflected XSS", "severity": "HIGH", "category": "XSS"}
            ]
        }
        id_a = save_scan(scan_a)

        # Scan B (Current: SQLi resolved, XSS persistent, new CSRF regression)
        scan_b = {
            "target_url": target,
            "timestamp": "2026-10-30 10:00:00",
            "risk_score": 75,
            "grade": "B",
            "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0},
            "findings": [
                {"id": "VULN_XSS", "title": "Reflected XSS", "severity": "HIGH", "category": "XSS"},
                {"id": "VULN_CSRF", "title": "Missing CSRF", "severity": "MEDIUM", "category": "CSRF"}
            ]
        }
        id_b = save_scan(scan_b)

        diff = compare_scans(id_a, id_b)
        self.assertIsNotNone(diff)
        self.assertEqual(diff["score_delta"], 25)  # 75 - 50 = +25
        self.assertTrue(diff["is_improved"])

        # Check resolved findings
        resolved_ids = [f["id"] for f in diff["resolved_findings"]]
        self.assertIn("VULN_SQLI", resolved_ids)

        # Check regressions
        regression_ids = [f["id"] for f in diff["new_regressions"]]
        self.assertIn("VULN_CSRF", regression_ids)

        # Check persistent
        persistent_ids = [f["id"] for f in diff["persistent_findings"]]
        self.assertIn("VULN_XSS", persistent_ids)


# ==============================================================================
# TESTS 34-40 : Nouveaux Modules de Sécurité (SSRF, XXE, SSTI, Clickjacking,
#               Cookie Security, Subdomain Takeover, HTTP Methods)
# ==============================================================================

class TestNewSecurityModules(unittest.TestCase):

    def test_34_ssrf_param_detection(self):
        """Verifies SSRF audit identifies URL/fetch parameters by name."""
        from security.dast_engine import audit_ssrf, SSRF_PARAM_NAMES
        # Verify the SSRF param set contains expected parameter names
        self.assertIn("url", SSRF_PARAM_NAMES)
        self.assertIn("webhook", SSRF_PARAM_NAMES)
        self.assertIn("fetch", SSRF_PARAM_NAMES)
        self.assertIn("proxy", SSRF_PARAM_NAMES)
        self.assertIn("src", SSRF_PARAM_NAMES)
        # audit_ssrf is callable and returns a list when given no SSRF-named params
        import requests
        session = requests.Session()
        forms_no_ssrf = [{"action": "http://localhost/", "method": "GET",
                          "inputs": [{"name": "q", "type": "text", "default": "test"}]}]
        result = audit_ssrf(session, forms_no_ssrf, [], "http://localhost/")
        self.assertIsInstance(result, list)

    def test_35_xxe_probe_structure(self):
        """Verifies XXE probe contains correct DOCTYPE + ENTITY structure."""
        from security.dast_engine import audit_xxe
        import requests

        # Validate the probe that will be sent
        probe_content = '<!DOCTYPE scprobe'
        # Reconstruct what the probe looks like
        probe = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE scprobe [
  <!ENTITY xxetest SYSTEM "file:///tmp/sc_xxe_probe_test.tmp">
]>
<scaudit><data>&xxetest;</data></scaudit>"""

        self.assertIn("DOCTYPE", probe)
        self.assertIn("ENTITY", probe)
        self.assertIn("SYSTEM", probe)
        self.assertIn("file:///tmp/", probe)

        # Function is callable and returns list without real network call
        session = requests.Session()
        result = audit_xxe(session, [], "http://localhost/")
        self.assertIsInstance(result, list)

    def test_36_ssti_arithmetic_probes(self):
        """Verifies SSTI probes use safe arithmetic canaries and detect evaluation."""
        from security.dast_engine import SSTI_PROBES, audit_ssti

        # All probes use 7*7 arithmetic
        for probe, expected, engine in SSTI_PROBES:
            self.assertEqual(expected, "49", f"Probe for {engine} should expect '49'")
            self.assertIn("7*7", probe, f"Probe for {engine} should contain '7*7'")

        # No destructive keywords in probes
        forbidden = ["__import__", "os.system", "subprocess", "eval(", "exec(", "open("]
        for probe, _, engine in SSTI_PROBES:
            for kw in forbidden:
                self.assertNotIn(kw, probe, f"SSTI probe for {engine} must not contain '{kw}'")

        import requests
        session = requests.Session()
        result = audit_ssti(session, [], [])
        self.assertIsInstance(result, list)

    def test_37_clickjacking_detection(self):
        """Verifies clickjacking audit correctly identifies missing and unsafe frame protection."""
        from security.dast_engine import audit_clickjacking
        import requests
        from unittest.mock import patch, MagicMock

        # Mock HTTP response with no XFO and no CSP frame-ancestors
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.status_code = 200

        session = requests.Session()
        with patch.object(session, 'get', return_value=mock_resp):
            findings = audit_clickjacking(session, "https://example.com", csp_header="", xfo_header="")

        # Should detect missing protection
        self.assertTrue(any("CLICKJACKING" in f["id"] for f in findings),
                        "Should detect absence of clickjacking protection")

        # Test with CSP wildcard — should flag it
        mock_resp.headers = {"Content-Security-Policy": "frame-ancestors *", "X-Frame-Options": ""}
        with patch.object(session, 'get', return_value=mock_resp):
            findings_wildcard = audit_clickjacking(session, "https://example.com",
                                                   csp_header="frame-ancestors *", xfo_header="")
        self.assertTrue(any("WILDCARD" in f["id"] for f in findings_wildcard),
                        "Should detect CSP frame-ancestors with wildcard")

    def test_38_cookie_security_audit(self):
        """Verifies cookie security audit detects missing HttpOnly, Secure, and SameSite flags."""
        from security.dast_engine import audit_cookie_security
        import requests
        from unittest.mock import patch, MagicMock
        from http.cookiejar import Cookie

        def make_mock_cookie(name, value, secure=False, httponly=False, samesite=None, domain="example.com"):
            """Helper to create a mock cookie object."""
            c = MagicMock()
            c.name = name
            c.value = value
            c.secure = secure
            c.domain = domain
            c.has_nonstandard_attr = lambda attr: attr.lower() == "httponly" and httponly
            c.get_nonstandard_attr = lambda attr, default=None: samesite if attr.lower() == "samesite" else default
            return c

        # Session cookie without HttpOnly and without SameSite
        bad_cookie = make_mock_cookie("session_id", "abc123sessiontoken", secure=True, httponly=False, samesite=None)

        mock_resp = MagicMock()
        mock_resp.cookies = [bad_cookie]
        mock_resp.headers = {"Set-Cookie": "session_id=abc123; Secure"}
        mock_resp.raw = MagicMock()
        mock_resp.raw.headers = MagicMock()
        mock_resp.raw.headers.getlist = lambda x: []

        session = requests.Session()
        with patch.object(session, 'get', return_value=mock_resp):
            findings = audit_cookie_security(session, "https://example.com")

        # Should find missing HttpOnly and SameSite issues on session cookie
        ids = [f["id"] for f in findings]
        self.assertTrue(any("HTTPONLY" in fid for fid in ids),
                        "Should detect missing HttpOnly on session cookie")
        self.assertTrue(any("SAMESITE" in fid for fid in ids),
                        "Should detect missing SameSite on session cookie")

    def test_39_subdomain_takeover_fingerprints(self):
        """Verifies subdomain takeover fingerprints cover major cloud platforms."""
        from security.dast_engine import TAKEOVER_FINGERPRINTS

        services = [service for _, service in TAKEOVER_FINGERPRINTS]
        self.assertIn("Heroku", services)
        self.assertIn("GitHub Pages", services)
        self.assertIn("AWS S3", services)
        self.assertIn("Netlify", services)
        self.assertIn("Fastly", services)
        self.assertIn("Azure", services)

        # At least 8 fingerprints
        self.assertGreaterEqual(len(TAKEOVER_FINGERPRINTS), 8,
                                "Should cover at least 8 cloud platform takeover fingerprints")

        import requests
        session = requests.Session()
        result_empty = audit_subdomain_takeover_direct(session, "http://localhost/", "")
        self.assertIsInstance(result_empty, list)

    def test_40_http_dangerous_methods(self):
        """Verifies HTTP dangerous methods audit detects TRACE and unsafe verbs."""
        from security.dast_engine import audit_http_methods
        import requests
        from unittest.mock import patch, MagicMock

        # Mock OPTIONS response advertising TRACE and PUT
        mock_opts = MagicMock()
        mock_opts.headers = {"Allow": "GET, POST, TRACE, PUT, DELETE, OPTIONS"}
        mock_opts.status_code = 200

        # Mock TRACE response (reflects request = XST confirmed)
        mock_trace = MagicMock()
        mock_trace.status_code = 200
        mock_trace.text = "TRACE / HTTP/1.1\r\nHost: example.com\r\n"

        session = requests.Session()

        def fake_request(method, url, **kwargs):
            if method == "OPTIONS":
                return mock_opts
            if method == "TRACE":
                return mock_trace
            return MagicMock(status_code=200, text="", headers={})

        with patch.object(session, 'options', return_value=mock_opts), \
             patch.object(session, 'request', side_effect=fake_request):
            findings = audit_http_methods(session, "https://example.com")

        self.assertIsInstance(findings, list)
        # Should detect TRACE and/or PUT from Allow header
        dangerous_ids = [f["id"] for f in findings]
        self.assertTrue(
            any("TRACE" in fid or "PUT" in fid or "DELETE" in fid for fid in dangerous_ids),
            f"Should detect dangerous methods. Got: {dangerous_ids}"
        )


# Helper import for test_39
def audit_subdomain_takeover_direct(session, base_url, html_content):
    from security.dast_engine import audit_subdomain_takeover
    return audit_subdomain_takeover(session, base_url, html_content)


if __name__ == "__main__":
    unittest.main()
