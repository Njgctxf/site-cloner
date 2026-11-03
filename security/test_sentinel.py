"""
test_sentinel.py - Comprehensive Unit & Integration Test Suite for Sentinel AI
Tests Multi-LLM adapters, Guardian Zero-Trust policy, Specialized Engines (JWT, Upload, Race, Logic),
Storage persistence, and Web API Endpoints.
"""

import unittest
import json
from unittest.mock import patch, MagicMock

import requests
from flask import Flask

from security.sentinel.models import AgentMessage, AgentResponse, ToolCall
from security.sentinel.providers import get_provider, MockProvider, OpenAICompatibleProvider, GeminiProvider, ClaudeProvider
from security.sentinel.guardian import guardian, SentinelGuardian
from security.sentinel.jwt_engine import audit_jwt, parse_jwt, forge_alg_none_token
from security.sentinel.upload_engine import audit_file_upload_endpoint
from security.sentinel.race_engine import audit_race_condition
from security.sentinel.logic_engine import audit_price_tampering, audit_role_parameter_tampering
from security.sentinel.agent import SentinelAgent
from security.sentinel.storage import (
    init_sentinel_tables, save_sentinel_config, get_sentinel_config,
    create_conversation, get_conversation_messages, save_message, delete_conversation
)
from security import bp, init_security


class SentinelAITestSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import os
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.app = Flask(
            __name__,
            template_folder=os.path.join(base_dir, "templates"),
            static_folder=os.path.join(base_dir, "static")
        )
        cls.app.config["TESTING"] = True
        cls.app.config["SECRET_KEY"] = "test-secret-key-sentinel"
        init_security(cls.app)
        cls.client = cls.app.test_client()

    def setUp(self):
        guardian.reset_kill_switch()

    # ---------------- 1. MULTI-LLM PROVIDERS ----------------

    def test_01_provider_factory_and_mock(self):
        """Verifies get_provider factory instantiates correct providers."""
        mock_p = get_provider("mock")
        self.assertIsInstance(mock_p, MockProvider)

        openai_p = get_provider("openai", api_key="sk-test", model="gpt-4o")
        self.assertIsInstance(openai_p, OpenAICompatibleProvider)
        self.assertEqual(openai_p.model, "gpt-4o")

        gemini_p = get_provider("gemini", api_key="AIzaSyTest", model="gemini-1.5-flash")
        self.assertIsInstance(gemini_p, GeminiProvider)

        claude_p = get_provider("claude", api_key="sk-ant-test", model="claude-3-5-sonnet")
        self.assertIsInstance(claude_p, ClaudeProvider)

    def test_02_mock_provider_reasoning(self):
        """Verifies MockProvider proposes appropriate tool calls based on user intent."""
        p = MockProvider()
        msgs = [AgentMessage(role="user", content="Peux-tu analyser mon token JWT ?")]
        resp = p.chat(msgs)
        self.assertIsInstance(resp, AgentResponse)
        self.assertTrue(len(resp.tool_calls) > 0)
        self.assertEqual(resp.tool_calls[0].name, "audit_jwt_token")

    # ---------------- 2. GUARDIAN ZERO-TRUST POLICY ----------------

    def test_03_guardian_scope_enforcement(self):
        """Verifies Guardian strictly rejects unauthorized third-party targets."""
        ok_lab, _ = guardian.validate_target("https://innotech-lab.local")
        self.assertTrue(ok_lab, "Local lab must be authorized")

        ok_unauth, reason = guardian.validate_target("https://unauthorized-evil-target.xyz")
        self.assertFalse(ok_unauth, "Unauthorized target must be blocked")
        self.assertIn("non autorisé", reason)

    def test_04_guardian_anti_ssrf(self):
        """Verifies Guardian blocks cloud metadata IP 169.254.169.254."""
        ok, reason = guardian.validate_target("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(ok, "Cloud metadata IP must be blocked by Guardian Anti-SSRF")

    def test_05_guardian_destructive_command_blocking(self):
        """Verifies Guardian rejects destructive commands in tool arguments."""
        safe_call, _ = guardian.validate_tool_call("run_target_diagnostic", {"target_url": "https://innotech-lab.local"})
        self.assertTrue(safe_call)

        destructive_call, reason = guardian.validate_tool_call("custom_query", {"query": "DROP TABLE users; --"})
        self.assertFalse(destructive_call)
        self.assertIn("destructeur", reason)

    def test_06_guardian_kill_switch(self):
        """Verifies emergency kill switch halts all actions immediately."""
        guardian.trigger_kill_switch()
        self.assertTrue(guardian.is_kill_switch_active())

        ok, reason = guardian.validate_target("https://innotech-lab.local")
        self.assertFalse(ok)
        self.assertIn("Kill-Switch", reason)

        guardian.reset_kill_switch()
        self.assertFalse(guardian.is_kill_switch_active())

    # ---------------- 3. JWT SECURITY ENGINE ----------------

    def test_07_jwt_weak_secret_and_expiration(self):
        """Verifies JWT engine identifies weak HMAC secret ('secret') and missing exp."""
        # HS256 token signed with 'secret', no exp
        # header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"123","user":"admin"}
        test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJ1c2VyIjoiYWRtaW4ifQ.uP9vjW7Vb5D5rX9u_iX2P_7_cQ2w3pQ0yJ6e5R_a8Zg"
        parsed = parse_jwt(test_token)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["header"]["alg"], "HS256")

        findings = audit_jwt(test_token)
        ids = [f["id"] for f in findings]
        self.assertIn("JWT_NO_EXPIRATION", ids, "Should detect missing expiration claim")

    def test_08_jwt_alg_none_forgery(self):
        """Verifies JWT engine can forge an alg=none token for non-destructive server probe."""
        sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        parsed = parse_jwt(sample_token)
        forged = forge_alg_none_token(parsed)
        self.assertTrue(forged.endswith("."))

        forged_parsed = parse_jwt(forged)
        self.assertEqual(forged_parsed["header"]["alg"], "none")

    # ---------------- 4. FILE UPLOAD ENGINE ----------------

    def test_09_upload_executable_and_svg_detection(self):
        """Verifies upload engine flags executable extension and SVG acceptance."""
        session = requests.Session()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status": "uploaded", "file": "sentinel_probe.php"}'

        with patch.object(session, "post", return_value=mock_resp):
            findings = audit_file_upload_endpoint(session, "https://innotech-lab.local/upload")

        ids = [f["id"] for f in findings]
        self.assertIn("UPLOAD_EXECUTABLE_EXTENSION_ACCEPTED", ids)
        self.assertIn("UPLOAD_SVG_ALLOWED_XSS_RISK", ids)

    # ---------------- 5. RACE CONDITION ENGINE ----------------

    def test_10_race_condition_burst_synchronization(self):
        """Verifies race condition engine detects multiple concurrent 200 OK responses."""
        session = requests.Session()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"coupon": "applied", "discount": 20}'

        with patch.object(session, "post", return_value=mock_resp):
            findings = audit_race_condition(session, "https://innotech-lab.local/api/coupon/apply", concurrency=4)

        self.assertTrue(any("RACE_CONDITION" in f["id"] for f in findings),
                        "Should detect concurrent acceptance of multiple requests")

    # ---------------- 6. BUSINESS LOGIC ENGINE ----------------

    def test_11_business_logic_price_tampering(self):
        """Verifies detection of accepted zero or negative prices."""
        session = requests.Session()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"order_id": 999, "status": "confirmed"}'

        with patch.object(session, "post", return_value=mock_resp):
            findings = audit_price_tampering(session, "https://innotech-lab.local/checkout")

        ids = [f["id"] for f in findings]
        self.assertTrue(any("TAMPERING" in i for i in ids))

    def test_12_business_logic_role_tampering(self):
        """Verifies detection of mass assignment role elevation."""
        session = requests.Session()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"success": true, "user": {"role": "admin"}}'

        with patch.object(session, "post", return_value=mock_resp):
            findings = audit_role_parameter_tampering(session, "https://innotech-lab.local/api/profile")

        ids = [f["id"] for f in findings]
        self.assertIn("MASS_ASSIGNMENT_ROLE_ELEVATION", ids)

    # ---------------- 7. SENTINEL AGENT ORCHESTRATION ----------------

    def test_13_agent_end_to_end_reasoning_and_tool_call(self):
        """Verifies SentinelAgent processes messages, invokes tools via Guardian, and returns reply."""
        provider = MockProvider()
        agent = SentinelAgent(provider=provider)

        user_msg = AgentMessage(role="user", content="Audite mon token JWT s'il te plaît")
        res = agent.process_message([user_msg], max_steps=2)

        self.assertIn("reply", res)
        self.assertIsInstance(res["tools_executed"], list)
        self.assertTrue(len(res["tools_executed"]) > 0)
        self.assertEqual(res["tools_executed"][0]["name"], "audit_jwt_token")

    # ---------------- 8. PERSISTENCE STORAGE ----------------

    def test_14_storage_conversations_and_messages(self):
        """Verifies conversation lifecycle and message saving in SQLite."""
        conv_id = create_conversation(title="Audit E-Commerce Test")
        self.assertIsNotNone(conv_id)

        msg_id = save_message(conv_id, role="user", content="Analyse mon endpoint /checkout")
        self.assertGreater(msg_id, 0)

        history = get_conversation_messages(conv_id)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["content"], "Analyse mon endpoint /checkout")

        delete_conversation(conv_id)
        empty = get_conversation_messages(conv_id)
        self.assertEqual(len(empty), 0)

    def test_15_storage_byok_config(self):
        """Verifies saving and loading BYOK provider settings."""
        save_sentinel_config(active_provider="deepseek", provider_id="deepseek", api_key="sk-dseek-test", model="deepseek-chat")
        cfg = get_sentinel_config()
        self.assertEqual(cfg["active_provider"], "deepseek")
        self.assertEqual(cfg["providers"]["deepseek"]["api_key"], "sk-dseek-test")

    # ---------------- 9. FLASK REST & WEB APIS ----------------

    def test_16_web_page_sentinel_accessible(self):
        """Verifies /__sc/security/sentinel returns HTTP 200 with HTML."""
        resp = self.client.get("/__sc/security/sentinel")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"SENTINEL AI", resp.data)
        self.assertIn(b"Guardian", resp.data)

    def test_17_api_sentinel_config_endpoints(self):
        """Verifies GET and POST on /__sc/security/api/sentinel/config."""
        # GET
        r_get = self.client.get("/__sc/security/api/sentinel/config")
        self.assertEqual(r_get.status_code, 200)
        data = r_get.json
        self.assertIn("active_provider", data)

        # POST
        r_post = self.client.post("/__sc/security/api/sentinel/config", json={
            "active_provider": "gemini",
            "provider_id": "gemini",
            "api_key": "AIzaSyTestKey12345",
            "model": "gemini-1.5-flash"
        })
        self.assertEqual(r_post.status_code, 200)

        # Re-GET masks the API key
        r_check = self.client.get("/__sc/security/api/sentinel/config")
        self.assertTrue(r_check.json["providers"]["gemini"]["has_key"])
        self.assertNotIn("AIzaSyTestKey12345", json.dumps(r_check.json))

    def test_18_api_sentinel_chat_endpoint(self):
        """Verifies POST to /__sc/security/api/sentinel/chat returns agent answer and tool outputs."""
        resp = self.client.post("/__sc/security/api/sentinel/chat", json={
            "message": "Fais un audit de sécurité de mon jeton JWT",
            "provider": "mock"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        self.assertTrue(data.get("success"))
        self.assertIn("conversation_id", data)
        self.assertIn("reply", data)
        self.assertIsInstance(data.get("tools_executed"), list)

    def test_19_api_sentinel_killswitch_toggle(self):
        """Verifies POST /__sc/security/api/sentinel/guardian/killswitch."""
        r_act = self.client.post("/__sc/security/api/sentinel/guardian/killswitch", json={"activate": True})
        self.assertEqual(r_act.status_code, 200)
        self.assertTrue(r_act.json["kill_switch_active"])

        r_deact = self.client.post("/__sc/security/api/sentinel/guardian/killswitch", json={"activate": False})
        self.assertEqual(r_deact.status_code, 200)
        self.assertFalse(r_deact.json["kill_switch_active"])


if __name__ == "__main__":
    unittest.main()
