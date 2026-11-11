"""Tests for mcp_server.py and 1-click Claude Desktop / Code MCP setup."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app as flask_app
import mcp_server
from security import mcp_setup


class McpSetupTests(unittest.TestCase):
    def test_mcp_server_exposes_curated_tools_and_skills_search(self):
        health = mcp_setup.test_mcp_server_health()
        self.assertTrue(health["healthy"], health)
        names = {t["name"] for t in health["tools"]}
        expected = {
            "start_clone",
            "get_clone_status",
            "list_cloned_sites",
            "run_passive_security_scan",
            "list_authorized_domains",
            "start_domain_verification",
            "check_domain_verification",
            "list_security_incidents",
            "search_security_skills",
        }
        self.assertTrue(expected.issubset(names), names)

        skills_res = mcp_server.search_security_skills("jwt", limit=3)
        self.assertEqual(skills_res["query"], "jwt")
        self.assertLessEqual(skills_res["count"], 3)
        self.assertIsInstance(skills_res["results"], list)

    def test_build_payload_local_vs_remote_redacts_server_paths(self):
        local_payload = mcp_setup.build_mcp_setup_payload("http://127.0.0.1:5050", is_local=True)
        self.assertTrue(local_payload["is_local"])
        self.assertIn("mcp_server.py", local_payload["server_entry"]["args"][0])
        parsed_local = json.loads(local_payload["claude_desktop_json"])
        self.assertIn("sitecloner", parsed_local["mcpServers"])

        remote_payload = mcp_setup.build_mcp_setup_payload("https://app.example.com", is_local=False)
        self.assertFalse(remote_payload["is_local"])
        self.assertIsNone(remote_payload["desktop_config_path"])
        self.assertEqual(remote_payload["server_entry"]["command"], "python")
        self.assertIn("/chemin/vers/SiteCloner-SaaS/mcp_server.py", remote_payload["server_entry"]["args"][0])

    def test_install_in_claude_desktop_merges_and_preserves_existing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_cfg = Path(tmpdir) / "Claude" / "claude_desktop_config.json"
            fake_cfg.parent.mkdir(parents=True, exist_ok=True)
            fake_cfg.write_text(
                json.dumps({"mcpServers": {"existing": {"command": "node", "args": ["foo.js"]}}, "theme": "dark"}),
                encoding="utf-8",
            )

            with patch.object(mcp_setup, "get_claude_desktop_config_path", return_value=fake_cfg):
                res = mcp_setup.install_in_claude_desktop("http://127.0.0.1:5050")
                self.assertTrue(res["success"], res)
                self.assertTrue(Path(res["backup_path"]).is_file())

                merged = json.loads(fake_cfg.read_text(encoding="utf-8"))
                self.assertEqual(merged["theme"], "dark")
                self.assertIn("existing", merged["mcpServers"])
                self.assertIn("sitecloner", merged["mcpServers"])
                self.assertTrue(mcp_setup._check_local_installation(fake_cfg))

    def test_install_refuses_corrupt_json_without_overwriting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_cfg = Path(tmpdir) / "claude_desktop_config.json"
            fake_cfg.write_text("{corrupt json", encoding="utf-8")

            with patch.object(mcp_setup, "get_claude_desktop_config_path", return_value=fake_cfg):
                res = mcp_setup.install_in_claude_desktop("http://127.0.0.1:5050")
                self.assertFalse(res["success"])
                self.assertEqual(fake_cfg.read_text(encoding="utf-8"), "{corrupt json")

    def test_flask_routes_and_remote_install_guard(self):
        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()

        resp = client.get("/__sc/security/api/mcp/config", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("claude mcp add sitecloner", data["claude_code_command"])

        blocked = client.post(
            "/__sc/security/api/mcp/install-local",
            environ_base={"REMOTE_ADDR": "203.0.113.10"},
        )
        self.assertEqual(blocked.status_code, 403)
        self.assertFalse(blocked.get_json()["success"])

        health_resp = client.post("/__sc/security/api/mcp/test", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(health_resp.status_code, 200)
        self.assertTrue(health_resp.get_json()["healthy"])

    def test_sentinel_hides_admin_tools_for_standard_users(self):
        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()

        free_html = client.get("/__sc/security/sentinel").get_data(as_text=True)
        self.assertIn("sentinelEnterpriseGate", free_html)
        self.assertIn("Guardian", free_html)

        from security.plans import set_user_plan
        with client.session_transaction() as sess:
            sess["sentinel_user_id"] = "usr_enterprise_test"
        set_user_plan("usr_enterprise_test", "enterprise", source="test")

        ent_html = client.get("/__sc/security/sentinel").get_data(as_text=True)
        self.assertIn("Compétences", ent_html)
        self.assertIn("openClaudeMcpBtn", ent_html)
        self.assertNotIn("openShieldBtn", ent_html)
        self.assertNotIn("openKaliBtn", ent_html)
        self.assertNotIn("openPentagiBtn", ent_html)
        self.assertNotIn("openScannersBtn", ent_html)

        with client.session_transaction() as sess:
            sess["admin"] = True
        admin_html = client.get("/__sc/security/sentinel").get_data(as_text=True)
        self.assertIn("openShieldBtn", admin_html)
        self.assertIn("openKaliBtn", admin_html)
        self.assertIn("openPentagiBtn", admin_html)
        self.assertIn("openScannersBtn", admin_html)


if __name__ == "__main__":
    unittest.main()
