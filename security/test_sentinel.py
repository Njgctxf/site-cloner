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

    # ---------------- 6. SKILLS REGISTRY & 818 CYBER PROCEDURES ----------------

    def test_20_skills_registry_indexing(self):
        """Verifies skills registry indexes all 818 procedures and extracts categories."""
        from security.sentinel.skills_registry import skills_registry
        self.assertEqual(skills_registry.count(), 818)
        stats = skills_registry.get_stats()
        self.assertEqual(stats["total_skills"], 818)
        self.assertTrue(stats["is_active"])
        self.assertIn("application-security", stats["categories"])

    def test_21_skills_registry_search_and_load(self):
        """Verifies skill keyword search and progressive disclosure loading of SKILL.md."""
        from security.sentinel.skills_registry import skills_registry
        results = skills_registry.search_skills("jwt", limit=5)
        self.assertTrue(len(results) > 0)
        first_skill_name = results[0]["name"]

        skill_obj = skills_registry.get_skill(first_skill_name)
        self.assertIsNotNone(skill_obj)
        content = skill_obj.load_full_content()
        self.assertIn("instructions_markdown", content)
        self.assertIn("description", content)

    def test_22_agent_skills_tool_execution(self):
        """Verifies SentinelAgent autonomously executes search_security_skills and load_skill_detail."""
        agent = SentinelAgent(provider=MockProvider())
        # Search tool
        res_search = agent.execute_tool("search_security_skills", {"query": "race condition", "limit": 3})
        self.assertFalse(res_search.is_error)
        self.assertEqual(res_search.result["total_available"], 818)
        self.assertTrue(len(res_search.result["skills"]) > 0)

        first_name = res_search.result["skills"][0]["name"]
        # Load tool
        res_load = agent.execute_tool("load_skill_detail", {"skill_name": first_name})
        self.assertFalse(res_load.is_error)
        self.assertIn("instructions_markdown", res_load.result)

    def test_23_api_sentinel_skills_endpoints(self):
        """Verifies GET /api/sentinel/skills, search, and detail API endpoints."""
        # Stats
        r_stats = self.client.get("/__sc/security/api/sentinel/skills")
        self.assertEqual(r_stats.status_code, 200)
        self.assertEqual(r_stats.json["total_skills"], 818)

        # Search
        r_search = self.client.get("/__sc/security/api/sentinel/skills/search?q=api&limit=5")
        self.assertEqual(r_search.status_code, 200)
        self.assertTrue(len(r_search.json["results"]) > 0)
        self.assertEqual(r_search.json["total_available"], 818)

        # Detail
        skill_name = r_search.json["results"][0]["name"]
        r_detail = self.client.get(f"/__sc/security/api/sentinel/skills/{skill_name}")
        self.assertEqual(r_detail.status_code, 200)
        self.assertIn("instructions_markdown", r_detail.json)

    def test_24_mock_provider_skills_routing(self):
        """Verifies MockProvider routes skill-related prompts to search_security_skills."""
        p = MockProvider()
        msgs = [AgentMessage(role="user", content="Quelle est la procédure OWASP pour les failles d'upload ?")]
        resp = p.chat(msgs)
        self.assertTrue(len(resp.tool_calls) > 0)
        self.assertEqual(resp.tool_calls[0].name, "search_security_skills")

    # ---------------- 7. UNIVERSAL ASSET & SCOPE AUTHORIZATION ----------------

    def test_25_universal_asset_registration_and_listing(self):
        """Verifies registering heterogeneous assets (Linux server, API, DB) into project."""
        from security.sentinel.asset_registry import create_project, register_asset, list_assets, get_asset
        proj = create_project("Audit Banque Interne", "Banque Nationale", "Audit de sécurité annuel")
        self.assertTrue(proj["id"].startswith("proj_"))

        asset = register_asset(
            name="Serveur API Paiements",
            asset_type="linux_server",
            target="api-payments.corp.internal",
            project_id=proj["id"],
            environment="production",
            metadata={"os": "Debian 12", "criticality": "tier-1"}
        )
        self.assertTrue(asset["id"].startswith("ast_"))
        self.assertEqual(asset["asset_type"], "linux_server")

        fetched = get_asset(asset["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["metadata"]["os"], "Debian 12")

        assets_list = list_assets(project_id=proj["id"])
        self.assertTrue(len(assets_list) >= 1)

    def test_26_formal_authorization_mandate_and_temporal_validity(self):
        """Verifies RoE mandate grants Guardian access, and temporal validity is enforced."""
        from security.sentinel.asset_registry import register_asset, grant_authorization, is_target_in_universal_scope
        from datetime import datetime, timedelta

        asset = register_asset(name="Passerelle Authentification", asset_type="api", target="auth-gateway.corp.internal")
        now = datetime.now()
        yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")

        # Active mandate
        grant_authorization(
            asset_id=asset["id"],
            authorized_by="Chief Information Security Officer",
            mandate_ref="MANDATE-2026-AUTH-01",
            allowed_test_types=["jwt", "dast"],
            valid_from=yesterday,
            valid_until=tomorrow
        )

        # Validated target via Guardian
        ok, msg = guardian.validate_target("https://auth-gateway.corp.internal/v1/token")
        self.assertTrue(ok)
        self.assertIn("MANDATE-2026-AUTH-01", msg)

        # Non-authorized test type
        is_auth, reason, _ = is_target_in_universal_scope("auth-gateway.corp.internal", test_type="upload")
        self.assertFalse(is_auth)

    def test_27_authorization_revocation_immediately_blocks_guardian(self):
        """Verifies revoking a mandate immediately cuts Guardian authorization."""
        from security.sentinel.asset_registry import register_asset, grant_authorization, revoke_authorization
        from datetime import datetime, timedelta

        asset = register_asset(name="Base de Données Client", asset_type="database", target="db-cluster.corp.internal")
        now = datetime.now()
        auth = grant_authorization(
            asset_id=asset["id"],
            authorized_by="SecOps Lead",
            mandate_ref="MANDATE-DB-TEMP",
            allowed_test_types=["dast", "config_audit"],
            valid_from=(now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
            valid_until=(now + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        )

        ok_before, _ = guardian.validate_target("https://db-cluster.corp.internal")
        self.assertTrue(ok_before)

        # Revoke mandate
        revoked = revoke_authorization(auth["id"], reason="Incident de sécurité en cours, gel des audits")
        self.assertTrue(revoked)

        ok_after, reason_after = guardian.validate_target("https://db-cluster.corp.internal")
        self.assertFalse(ok_after)
        self.assertIn("non autorisé", reason_after)

    def test_28_network_cidr_ip_scope_matching(self):
        """Verifies network CIDR mandate authorizes IPs within the subnet and rejects external IPs."""
        from security.sentinel.asset_registry import register_asset, grant_authorization
        from datetime import datetime, timedelta

        asset = register_asset(name="Zone DMZ Corporate", asset_type="network_cidr", target="10.200.50.0/24")
        now = datetime.now()
        grant_authorization(
            asset_id=asset["id"],
            authorized_by="Network Security Admin",
            mandate_ref="MANDATE-CIDR-DMZ",
            allowed_test_types=["all"],
            valid_from=(now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),
            valid_until=(now + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        )

        # IP inside subnet
        ok_in, msg_in = guardian.validate_target("https://10.200.50.15/api")
        self.assertTrue(ok_in)
        self.assertIn("10.200.50.0/24", msg_in)

        # IP outside subnet
        ok_out, _ = guardian.validate_target("https://10.200.99.15/api")
        self.assertFalse(ok_out)

    def test_29_agent_list_authorized_scope_tool(self):
        """Verifies SentinelAgent can autonomously inspect authorized scope assets."""
        agent = SentinelAgent(provider=MockProvider())
        res = agent.execute_tool("list_authorized_scope", {})
        self.assertFalse(res.is_error)
        self.assertIn("authorized_assets", res.result)
        self.assertIsInstance(res.result["authorized_assets"], list)

    def test_30_api_endpoints_assets_and_mandates(self):
        """Verifies REST API endpoints for projects, assets, mandates, and scope verification."""
        # 1. Create project via API
        r_p = self.client.post("/__sc/security/api/sentinel/projects", json={
            "name": "Audit ERP Global",
            "company_name": "InnoTech Industries"
        })
        self.assertEqual(r_p.status_code, 200)
        proj_id = r_p.json["project"]["id"]

        # 2. Register asset via API
        r_a = self.client.post("/__sc/security/api/sentinel/assets", json={
            "project_id": proj_id,
            "name": "ERP SAP Central",
            "asset_type": "windows_server",
            "target": "erp-central.innotech.internal"
        })
        self.assertEqual(r_a.status_code, 200)
        asset_id = r_a.json["asset"]["id"]

        # 3. Grant authorization mandate via API
        from datetime import datetime, timedelta
        now = datetime.now()
        r_auth = self.client.post("/__sc/security/api/sentinel/authorizations", json={
            "asset_id": asset_id,
            "authorized_by": "Direction Sécurité",
            "mandate_ref=":"MANDATE-SAP-2026",
            "valid_from": (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),
            "valid_until": (now + timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S"),
            "allowed_test_types": ["dast", "config_audit"]
        })
        self.assertEqual(r_auth.status_code, 200)

        # 4. Verify scope via API
        r_v = self.client.post("/__sc/security/api/sentinel/scope/verify", json={
            "target": "https://erp-central.innotech.internal:8443/login"
        })
        self.assertEqual(r_v.status_code, 200)
        self.assertTrue(r_v.json["is_authorized"])

    # ---------------- 8. EMERGENCY SHIELD & ACTIVE DEFENSE (4 TIERS) ----------------

    def test_31_emergency_shield_deterministic_tiers_and_transitions(self):
        """Verifies Emergency Shield graduated tiers (NORMAL -> ALERT -> DEFENSIVE -> EMERGENCY)."""
        from security.sentinel.shield import emergency_shield, ShieldTier

        # Reset to NORMAL
        status_norm = emergency_shield.reset_to_normal()
        self.assertEqual(status_norm["tier"], ShieldTier.NORMAL.value)
        self.assertEqual(status_norm["tier_level"], 0)

        # Elevate to ALERT
        st_alert = emergency_shield.set_tier(ShieldTier.ALERT, "Détection de reconnaissance anormale")
        self.assertEqual(st_alert["tier"], ShieldTier.ALERT.value)
        self.assertIn("soc_live_alerts", st_alert["active_mitigations"])

        # Elevate to DEFENSIVE
        st_def = emergency_shield.set_tier(ShieldTier.DEFENSIVE, "Exploitation active détectée")
        self.assertEqual(st_def["tier"], ShieldTier.DEFENSIVE.value)
        self.assertIn("dynamic_ip_blocking", st_def["active_mitigations"])

        # Elevate to EMERGENCY
        st_em = emergency_shield.set_tier(ShieldTier.EMERGENCY, "Tentative de compromission critique")
        self.assertEqual(st_em["tier"], ShieldTier.EMERGENCY.value)
        self.assertIn("strict_ip_isolation", st_em["active_mitigations"])
        self.assertIn("forensic_evidence_snapshot", st_em["active_mitigations"])

    def test_32_forensic_evidence_sha256_snapshot(self):
        """Verifies capturing tamper-evident attack payloads with SHA-256 fingerprint."""
        from security.sentinel.shield import emergency_shield
        import hashlib

        payload = "UNION SELECT username, password_hash FROM admin_users --"
        rec = emergency_shield.record_forensic_evidence(
            target="api.innotech-lab.local",
            source_ip="198.51.100.42",
            attack_type="sql_injection",
            raw_payload=payload
        )
        self.assertIsNotNone(rec["id"])
        expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self.assertEqual(rec["payload_hash"], expected_hash)

        ev_list = emergency_shield.list_forensic_evidence(limit=10)
        self.assertTrue(any(e["payload_hash"] == expected_hash for e in ev_list))

    def test_33_session_revocation_and_invalidation(self):
        """Verifies immediate session revocation and query check."""
        from security.sentinel.shield import emergency_shield
        import uuid

        token = f"sess_secret_{uuid.uuid4().hex}"
        self.assertFalse(emergency_shield.is_session_revoked(token))

        emergency_shield.revoke_session(
            target="app.innotech.internal",
            source_ip="203.0.113.88",
            session_token=token,
            reason="Exfiltration de token détectée"
        )
        self.assertTrue(emergency_shield.is_session_revoked(token))

    def test_34_active_defense_escalation_to_defensive_and_emergency(self):
        """Verifies ingest_request_event automatically drives EmergencyShield state machine."""
        from security.sentinel.shield import emergency_shield, ShieldTier
        from security.sentinel.realtime import ingest_request_event
        import random

        emergency_shield.reset_to_normal()
        rand_ip = f"198.51.100.{random.randint(10, 250)}"

        # Ingest SQL injection attack (HIGH severity)
        directive = ingest_request_event(
            domain="innotech-lab.local",
            source_ip=rand_ip,
            method="GET",
            path="/api/products",
            query_string="id=1' OR '1'='1"
        )
        self.assertTrue(directive["attack_detected"])
        self.assertTrue(directive["block"])
        self.assertIn(directive["shield_tier"], (ShieldTier.DEFENSIVE.value, ShieldTier.EMERGENCY.value))

    def test_35_api_emergency_shield_endpoints(self):
        """Verifies REST API endpoints for Emergency Shield."""
        # 1. Status
        r_st = self.client.get("/__sc/security/api/sentinel/shield/status")
        self.assertEqual(r_st.status_code, 200)
        self.assertIn("tier", r_st.json)
        self.assertIn("active_mitigations", r_st.json)

        # 2. Set Tier
        r_post = self.client.post("/__sc/security/api/sentinel/shield/tier", json={
            "tier": "DEFENSIVE",
            "reason": "Test audit automatique SOC"
        })
        self.assertEqual(r_post.status_code, 200)
        self.assertEqual(r_post.json["shield"]["tier"], "DEFENSIVE")

        # 3. Forensics
        r_f = self.client.get("/__sc/security/api/sentinel/shield/forensics")
        self.assertEqual(r_f.status_code, 200)
        self.assertIn("forensics", r_f.json)

        # 4. Revoke session
        r_rev = self.client.post("/__sc/security/api/sentinel/shield/revoke_session", json={
            "target": "portal.innotech-lab.local",
            "source_ip": "192.0.2.1",
            "session_token": "token_to_kill_xyz",
            "reason": "Suspicion de vol de session"
        })
        self.assertEqual(r_rev.status_code, 200)
        self.assertTrue(r_rev.json["success"])

    def test_36_agent_shield_tools_execution(self):
        """Verifies SentinelAgent executes get_shield_status and trigger_emergency_defenses tools."""
        agent = SentinelAgent(provider=MockProvider())

        # Tool 1: get_shield_status
        res_st = agent.execute_tool("get_shield_status", {})
        self.assertFalse(res_st.is_error)
        self.assertIn("tier", res_st.result)

        # Tool 2: trigger_emergency_defenses
        res_trig = agent.execute_tool("trigger_emergency_defenses", {
            "tier": "EMERGENCY",
            "reason": "Alerte intrusion confirmée par l'agent"
        })
        self.assertFalse(res_trig.is_error)
        self.assertEqual(res_trig.result["state"]["tier"], "EMERGENCY")

    # ---------------- 9. SYSTEM, SERVER & DATABASE AUDIT ENGINES ----------------

    def test_37_linux_server_ssh_hardening_audit(self):
        """Verifies Linux SSH hardening rule checks (PermitRootLogin, Protocol 1, shadow perms)."""
        from security.sentinel.system_engine import audit_linux_server_config

        vulnerable_cfg = """
Port 22
Protocol 1
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
shadow_perms: 0644
"""
        res = audit_linux_server_config("linux-srv1.corp.internal", config_text=vulnerable_cfg)
        self.assertEqual(res["status"], "vulnerable")
        rule_ids = [f["rule_id"] for f in res["findings"]]
        self.assertIn("SSH_ROOT_LOGIN", rule_ids)
        self.assertIn("SSH_PROTOCOL_1", rule_ids)
        self.assertIn("SSH_EMPTY_PASSWORDS", rule_ids)
        self.assertIn("PERM_SHADOW_WORLD_READABLE", rule_ids)

    def test_38_windows_server_hardening_audit(self):
        """Verifies Windows server audit identifies SMBv1, missing NLA, and null sessions."""
        from security.sentinel.system_engine import audit_windows_server_config

        win_cfg = """
SMB1: Enabled
UserAuthentication: 0 (NLA disabled)
NullSessionShares: 1
"""
        res = audit_windows_server_config("win-ad.corp.internal", config_text=win_cfg)
        self.assertEqual(res["status"], "vulnerable")
        rule_ids = [f["rule_id"] for f in res["findings"]]
        self.assertIn("WIN_SMBV1_ENABLED", rule_ids)
        self.assertIn("WIN_RDP_NLA_DISABLED", rule_ids)
        self.assertIn("WIN_NULL_SESSION_SHARES", rule_ids)

    def test_39_database_hardening_audit_redis_and_postgres(self):
        """Verifies database posture assessments for Redis and PostgreSQL."""
        from security.sentinel.system_engine import audit_database_config

        # Redis
        redis_cfg = "bind 0.0.0.0\nprotected-mode no"
        res_redis = audit_database_config("redis", "redis.corp.internal", config_text=redis_cfg)
        self.assertEqual(res_redis["status"], "vulnerable")
        r_ids = [f["rule_id"] for f in res_redis["findings"]]
        self.assertIn("REDIS_PROTECTED_MODE_OFF", r_ids)
        self.assertIn("REDIS_BIND_ALL", r_ids)

        # Postgres
        pg_cfg = "listen_addresses = '*'\nssl = off"
        res_pg = audit_database_config("postgres", "pg.corp.internal", config_text=pg_cfg)
        self.assertEqual(res_pg["status"], "vulnerable")
        pg_ids = [f["rule_id"] for f in res_pg["findings"]]
        self.assertIn("PG_SSL_OFF", pg_ids)

    def test_40_guardian_enforces_scope_on_system_and_db_audits(self):
        """Verifies Guardian strictly blocks system audits on unauthorized targets."""
        agent = SentinelAgent(provider=MockProvider())

        res_blocked = agent.execute_tool("audit_system_configuration", {
            "target": "https://unauthorized-evil-server.com",
            "os_family": "linux"
        })
        self.assertTrue(res_blocked.is_error)
        self.assertIn("Bloqué par le Guardian", res_blocked.result.get("error", ""))

    def test_41_agent_system_and_db_tools_execution(self):
        """Verifies SentinelAgent executes system and DB audit tools on authorized targets."""
        agent = SentinelAgent(provider=MockProvider())

        # Authorized target: local lab
        res_sys = agent.execute_tool("audit_system_configuration", {
            "target": "https://innotech-lab.local",
            "os_family": "linux"
        })
        self.assertFalse(res_sys.is_error)
        self.assertEqual(res_sys.result["os_family"], "linux")

        res_db = agent.execute_tool("audit_database_security", {
            "target": "https://innotech-lab.local",
            "db_type": "redis"
        })
        self.assertFalse(res_db.is_error)
        self.assertEqual(res_db.result["db_type"], "redis")

    def test_42_api_system_and_db_audit_endpoints(self):
        """Verifies REST API endpoints for system and database configuration audits."""
        # Authorized lab target
        r_sys = self.client.post("/__sc/security/api/sentinel/audit/system", json={
            "target": "https://innotech-lab.local",
            "os_family": "linux",
            "config_text": "Port 22\nPermitRootLogin no\nPasswordAuthentication no"
        })
        self.assertEqual(r_sys.status_code, 200)
        self.assertTrue(r_sys.json["success"])

        # Unauthorized target rejected with 403
        r_unauth = self.client.post("/__sc/security/api/sentinel/audit/system", json={
            "target": "https://unauthorized-hacker-target.com",
            "os_family": "linux"
        })
        self.assertEqual(r_unauth.status_code, 403)


if __name__ == "__main__":
    unittest.main()
