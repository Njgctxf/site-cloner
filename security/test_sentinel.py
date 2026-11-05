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
from security.sentinel.pentagi_engine import pentagi_engine, PentAGIIntegrationEngine, PENTAGI_CAPABILITIES


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
        """Verifies /__sc/security/sentinel and /__sc/security/ulton return HTTP 200 with HTML."""
        resp = self.client.get("/__sc/security/sentinel")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"ULTON AI", resp.data)
        self.assertIn(b"Guardian", resp.data)

        # Test new /ulton endpoint
        resp_u = self.client.get("/__sc/security/ulton")
        self.assertEqual(resp_u.status_code, 200)
        self.assertIn(b"ULTON AI", resp_u.data)

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

    # ---------------- 10. REMEDIATION ENGINE & COUNTER-VALIDATION ----------------

    def test_43_remediation_plan_creation_with_unified_diff(self):
        """Verifies creating a remediation plan generates standard unified diff patches."""
        from security.sentinel.remediation import create_remediation_plan, get_remediation

        plan = create_remediation_plan(
            vulnerability_type="sqli",
            target="https://innotech-lab.local/api/users",
            original_code="query = f'SELECT * FROM users WHERE id = {user_id}'",
            fixed_code="query = 'SELECT * FROM users WHERE id = ?'\ncursor.execute(query, (user_id,))"
        )
        self.assertTrue(plan["id"].startswith("rem_"))
        self.assertEqual(plan["status"], "pending")
        self.assertIn("--- a/target_code", plan["patch_diff"])
        self.assertIn("+++ b/target_code", plan["patch_diff"])

        fetched = get_remediation(plan["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["vulnerability_type"], "sqli")

    def test_44_remediation_human_approval_enforcement(self):
        """Verifies applying a patch strictly requires prior human approval."""
        from security.sentinel.remediation import create_remediation_plan, approve_remediation, apply_remediation

        plan = create_remediation_plan(
            vulnerability_type="jwt",
            target="https://innotech-lab.local/api/auth/token"
        )

        # Applying before approval must fail
        with self.assertRaises(ValueError):
            apply_remediation(plan["id"])

        # Approve by security team lead
        app_res = approve_remediation(plan["id"], approved_by="Alice CISO")
        self.assertEqual(app_res["status"], "approved")

        # Now applying succeeds
        res_apply = apply_remediation(plan["id"])
        self.assertEqual(res_apply["status"], "applied")

    def test_45_remediation_rollback_workflow(self):
        """Verifies an applied patch can be safely rolled back."""
        from security.sentinel.remediation import create_remediation_plan, approve_remediation, apply_remediation, rollback_remediation

        plan = create_remediation_plan(vulnerability_type="upload", target="https://innotech-lab.local/upload")
        approve_remediation(plan["id"], approved_by="Bob SecOps")
        apply_remediation(plan["id"])

        res_rb = rollback_remediation(plan["id"], reason="Problème de compatibilité détecté")
        self.assertEqual(res_rb["status"], "rolled_back")

    def test_46_post_fix_counter_validation(self):
        """Verifies running post-fix counter-validation to prove remediation."""
        from security.sentinel.remediation import create_remediation_plan, approve_remediation, apply_remediation, verify_remediation_post_fix

        plan = create_remediation_plan(vulnerability_type="race_condition", target="https://innotech-lab.local/api/coupon")
        approve_remediation(plan["id"], approved_by="Lead Dev")
        apply_remediation(plan["id"])

        res_ver = verify_remediation_post_fix(plan["id"], test_recheck_result={
            "recheck_passed": True,
            "findings_remaining": 0,
            "message": "Aucun double emploi possible après l'application du verrou atomique."
        })
        self.assertEqual(res_ver["post_validation_status"], "verified_fixed")
        self.assertTrue(res_ver["is_fixed"])

    def test_47_agent_remediation_tools_execution(self):
        """Verifies SentinelAgent autonomously generates remediation proposals and checks status."""
        agent = SentinelAgent(provider=MockProvider())

        # Tool 1: generate_vulnerability_remediation
        res_gen = agent.execute_tool("generate_vulnerability_remediation", {
            "vulnerability_type": "sqli",
            "target": "https://innotech-lab.local/search"
        })
        self.assertFalse(res_gen.is_error)
        self.assertTrue(res_gen.result["requires_human_approval"])
        rem_id = res_gen.result["remediation_plan"]["id"]

        # Tool 2: list_remediations
        res_list = agent.execute_tool("list_remediations", {"target": "https://innotech-lab.local/search"})
        self.assertFalse(res_list.is_error)
        self.assertTrue(len(res_list.result["remediations"]) >= 1)

        # Tool 3: verify_remediation_effectiveness
        from security.sentinel.remediation import approve_remediation, apply_remediation
        approve_remediation(rem_id, approved_by="CISO")
        apply_remediation(rem_id)
        res_v = agent.execute_tool("verify_remediation_effectiveness", {"remediation_id": rem_id})
        self.assertFalse(res_v.is_error)
        self.assertEqual(res_v.result["post_validation_status"], "verified_fixed")

    def test_48_api_remediation_endpoints(self):
        """Verifies REST API endpoints for remediation creation, approval, application, and verification."""
        # 1. Create plan via API
        r_c = self.client.post("/__sc/security/api/sentinel/remediations/create", json={
            "vulnerability_type": "jwt",
            "target": "https://innotech-lab.local/api/jwt",
            "title": "Fix JWT Signature bypass"
        })
        self.assertEqual(r_c.status_code, 200)
        rem_id = r_c.json["remediation"]["id"]

        # 2. Approve via API
        r_app = self.client.post("/__sc/security/api/sentinel/remediations/approve", json={
            "remediation_id": rem_id,
            "approved_by": "SecOps Lead"
        })
        self.assertEqual(r_app.status_code, 200)

        # 3. Apply via API
        r_apl = self.client.post("/__sc/security/api/sentinel/remediations/apply", json={
            "remediation_id": rem_id
        })
        self.assertEqual(r_apl.status_code, 200)

        # 4. Verify post-fix via API
        r_v = self.client.post("/__sc/security/api/sentinel/remediations/verify", json={
            "remediation_id": rem_id
        })
        self.assertEqual(r_v.status_code, 200)
        self.assertEqual(r_v.json["verification"]["post_validation_status"], "verified_fixed")

    # ---------------- 11. PROJECT MEMORY & SOC DASHBOARD REPORTING ----------------

    def test_49_audit_memory_sanitization_and_persistence(self):
        """Verifies audit memory sanitizes secrets (passwords, JWTs, keys) before persistence."""
        from security.sentinel.memory import save_audit_memory, get_audit_memory

        raw_findings = [
            {"id": "F1", "title": "SQLi", "detail": "Leak with password='super_secret_123'"},
            {"id": "F2", "title": "Exposed JWT", "detail": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID"}
        ]
        mem = save_audit_memory(
            project_id="proj_test_mem",
            target="https://innotech-lab.local",
            audit_type="full_dast",
            findings_summary=raw_findings,
            risk_score=45,
            grade="C"
        )
        self.assertTrue(mem["id"].startswith("mem_"))

        fetched = get_audit_memory(mem["id"])
        self.assertIsNotNone(fetched)
        detail_str = json.dumps(fetched["findings"])
        self.assertNotIn("super_secret_123", detail_str)
        self.assertIn("[REDACTED]", detail_str)

    def test_50_audit_history_comparison_new_recurring_resolved(self):
        """Verifies delta comparison between audits correctly flags resolved and new vulnerabilities."""
        from security.sentinel.memory import save_audit_memory, compare_audit_snapshots

        audit_1 = save_audit_memory(
            project_id="proj_compare",
            target="https://innotech-lab.local",
            audit_type="dast",
            findings_summary=[
                {"rule_id": "SQLI_LOGIN", "title": "SQLi on login"},
                {"rule_id": "XSS_SEARCH", "title": "Reflected XSS on search"}
            ],
            risk_score=70,
            grade="D"
        )

        audit_2 = save_audit_memory(
            project_id="proj_compare",
            target="https://innotech-lab.local",
            audit_type="dast",
            findings_summary=[
                {"rule_id": "SQLI_LOGIN", "title": "SQLi on login"},
                {"rule_id": "JWT_WEAK", "title": "Weak JWT Secret"}
            ],
            risk_score=40,
            grade="B"
        )

        diff = compare_audit_snapshots(audit_1["id"], audit_2["id"])
        self.assertEqual(diff["summary"]["resolved_count"], 1)  # XSS_SEARCH resolved
        self.assertEqual(diff["summary"]["recurring_count"], 1) # SQLI_LOGIN recurring
        self.assertEqual(diff["summary"]["new_count"], 1)       # JWT_WEAK new
        self.assertEqual(diff["resolved_findings"][0]["rule_id"], "XSS_SEARCH")
        self.assertEqual(diff["new_findings"][0]["rule_id"], "JWT_WEAK")

    def test_51_architecture_knowledge_and_context_injection(self):
        """Verifies architecture components are memorized and served as context."""
        from security.sentinel.memory import record_architecture_knowledge, get_project_knowledge_context

        record_architecture_knowledge(
            project_id="proj_arch_1",
            component_name="API Gateway Kong",
            component_type="reverse_proxy",
            technology_stack="Kong 3.4 / OpenResty",
            observations={"rate_limiting": "active", "tls": "TLS 1.3"}
        )

        ctx = get_project_knowledge_context("proj_arch_1")
        self.assertEqual(ctx["project_id"], "proj_arch_1")
        self.assertTrue(len(ctx["architecture_components"]) >= 1)
        self.assertEqual(ctx["architecture_components"][0]["name"], "API Gateway Kong")

    def test_52_consolidated_soc_report_aggregation(self):
        """Verifies generate_consolidated_soc_report aggregates across all 5 dimensions."""
        from security.sentinel.reporting import generate_consolidated_soc_report

        rep = generate_consolidated_soc_report()
        self.assertIn("global_security_posture", rep)
        self.assertIn("shield", rep)
        self.assertIn("assets_inventory", rep)
        self.assertIn("incidents", rep)
        self.assertIn("remediation_metrics", rep)

    def test_53_executive_html_report_rendering(self):
        """Verifies executive HTML report renders with proper cards and badge."""
        from security.sentinel.reporting import generate_executive_html_report

        html = generate_executive_html_report()
        self.assertIn("ULTON AI", html)
        self.assertIn("Rapport Exécutif SOC", html)
        self.assertIn("SHIELD:", html)

    def test_54_agent_memory_and_reporting_tools(self):
        """Verifies SentinelAgent autonomously queries project memory and generates reports."""
        agent = SentinelAgent(provider=MockProvider())

        # Tool: get_project_memory_context
        res_mem = agent.execute_tool("get_project_memory_context", {"project_id": "proj_demo"})
        self.assertFalse(res_mem.is_error)
        self.assertEqual(res_mem.result["project_id"], "proj_demo")

        # Tool: generate_soc_executive_report
        res_rep = agent.execute_tool("generate_soc_executive_report", {})
        self.assertFalse(res_rep.is_error)
        self.assertIn("global_security_posture", res_rep.result)

    def test_55_api_memory_and_reports_endpoints(self):
        """Verifies REST API endpoints for memory history, compare, and SOC reports."""
        # History
        r_hist = self.client.get("/__sc/security/api/sentinel/memory/history")
        self.assertEqual(r_hist.status_code, 200)
        self.assertIn("history", r_hist.json)

        # SOC Summary JSON
        r_soc = self.client.get("/__sc/security/api/sentinel/reports/soc_summary")
        self.assertEqual(r_soc.status_code, 200)
        self.assertIn("global_security_posture", r_soc.json)

        # Executive HTML Report
        r_html = self.client.get("/__sc/security/api/sentinel/reports/executive_html")
        self.assertEqual(r_html.status_code, 200)
        self.assertIn(b"Rapport Ex\xc3\xa9cutif SOC", r_html.data)

    # ---------------- 12. OFFICIAL KALI LINUX MCP INTEGRATION ----------------

    def test_56_kali_connector_config_and_health_check(self):
        """Verifies KaliMCPConnector configuration management and health check probe."""
        from security.sentinel.kali_connector import kali_connector

        cfg = kali_connector.get_config()
        self.assertIn("server_url", cfg)
        self.assertIn("timeout_seconds", cfg)

        updated = kali_connector.update_config(server_url="http://127.0.0.1:5000", timeout_seconds=45)
        self.assertEqual(updated["server_url"], "http://127.0.0.1:5000")
        self.assertEqual(updated["timeout_seconds"], 45)

        health = kali_connector.health_check()
        self.assertIn("connected", health)
        self.assertIn("message", health)

    def test_57_kali_connector_tool_discovery(self):
        """Verifies Kali tool catalog discovery matches the permitted security tool list."""
        from security.sentinel.kali_connector import kali_connector, PERMITTED_KALI_TOOLS

        disc = kali_connector.discover_tools()
        self.assertIn("tools", disc)
        tool_names = [t["name"] for t in disc["tools"]]
        for expected in ("nmap", "nikto", "whatweb", "sslyze", "sqlmap"):
            self.assertIn(expected, tool_names)

    def test_58_kali_argument_sanitization_and_injection_blocking(self):
        """Verifies argument sanitizer prevents shell injection and disallowed flags."""
        from security.sentinel.kali_connector import kali_connector

        # 1. Shell command injection attempts must be blocked
        malicious_args = ["-sV", "; rm -rf /", "80"]
        ok, clean, reason = kali_connector.sanitize_arguments("nmap", malicious_args)
        self.assertFalse(ok)
        self.assertIn("Injection de commande", reason)

        pipe_args = ["-sV", "| cat /etc/passwd"]
        ok2, clean2, reason2 = kali_connector.sanitize_arguments("nmap", pipe_args)
        self.assertFalse(ok2)
        self.assertIn("Injection de commande", reason2)

        # 2. Weaponized flags must be blocked (e.g. --os-shell for sqlmap)
        bad_sqlmap_args = ["--batch", "--os-shell"]
        ok3, clean3, reason3 = kali_connector.sanitize_arguments("sqlmap", bad_sqlmap_args)
        self.assertFalse(ok3)
        self.assertIn("Option de commande interdite", reason3)

        # 3. Legitimate arguments pass
        safe_args = ["-sV", "--version-light", "-p", "80,443"]
        ok_safe, clean_safe, reason_safe = kali_connector.sanitize_arguments("nmap", safe_args)
        self.assertTrue(ok_safe)
        self.assertEqual(clean_safe, safe_args)

    def test_59_kali_guardian_blocks_unauthorized_target(self):
        """Verifies Guardian rejects Kali tool executions targeting unauthorized hosts."""
        from security.sentinel.kali_connector import kali_connector

        res = kali_connector.execute_tool(
            tool_name="nmap",
            target="https://unauthorized-victim-corporation.com",
            custom_args=["-sV"]
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "blocked_by_guardian")
        self.assertIn("non autoris", res["error"])

    def test_60_kali_execution_on_authorized_target(self):
        """Verifies execution completes cleanly on authorized target (lab host)."""
        from security.sentinel.kali_connector import kali_connector

        res = kali_connector.execute_tool(
            tool_name="whatweb",
            target="https://innotech-lab.local",
            custom_args=["-a", "1"]
        )
        self.assertTrue(res["success"])
        self.assertIn(res["status"], ("completed", "simulated"))
        self.assertIn("innotech-lab.local", res["command"])
        self.assertTrue(len(res["stdout"]) > 0)

        # Verify history is persisted
        hist = kali_connector.list_history(limit=5)
        self.assertTrue(len(hist) > 0)
        self.assertEqual(hist[0]["tool_name"], "whatweb")

    def test_61_sentinel_agent_kali_tools(self):
        """Verifies SentinelAgent integrates get_kali_mcp_status and execute_kali_security_tool."""
        agent = SentinelAgent(provider=MockProvider())

        # 1. get_kali_mcp_status
        res_status = agent.execute_tool("get_kali_mcp_status", {})
        self.assertFalse(res_status.is_error)
        self.assertIn("health", res_status.result)
        self.assertIn("discovery", res_status.result)

        # 2. execute_kali_security_tool on authorized lab
        res_exec = agent.execute_tool("execute_kali_security_tool", {
            "tool_name": "nmap",
            "target": "https://innotech-lab.local",
            "custom_args": ["-sV", "-p", "80,443"]
        })
        self.assertFalse(res_exec.is_error)
        self.assertTrue(res_exec.result["success"])

        # 3. execute_kali_security_tool blocked on unauthorized target by Guardian
        res_blocked = agent.execute_tool("execute_kali_security_tool", {
            "tool_name": "nmap",
            "target": "https://unauthorized-evil-target.com"
        })
        self.assertTrue(res_blocked.is_error)
        self.assertIn("Bloqué par le Guardian", res_blocked.result.get("error", ""))

    def test_62_api_sentinel_kali_endpoints(self):
        """Verifies REST API endpoints for Kali status, config, sync, execute, and history."""
        # 1. Status
        r_stat = self.client.get("/__sc/security/api/sentinel/kali/status")
        self.assertEqual(r_stat.status_code, 200)
        self.assertIn("config", r_stat.json)
        self.assertIn("permitted_tools", r_stat.json)

        # 2. Config update
        r_cfg = self.client.post("/__sc/security/api/sentinel/kali/config", json={
            "server_url": "http://127.0.0.1:5000",
            "timeout_seconds": 50
        })
        self.assertEqual(r_cfg.status_code, 200)
        self.assertTrue(r_cfg.json["success"])

        # 3. Sync
        r_sync = self.client.post("/__sc/security/api/sentinel/kali/sync")
        self.assertEqual(r_sync.status_code, 200)
        self.assertTrue(r_sync.json["success"])
        self.assertIn("tools", r_sync.json["discovery"])

        # 4. Execute on authorized target
        r_exec = self.client.post("/__sc/security/api/sentinel/kali/execute", json={
            "tool": "whatweb",
            "target": "https://innotech-lab.local"
        })
        self.assertEqual(r_exec.status_code, 200)
        self.assertTrue(r_exec.json["success"])

        # 5. Execute rejected on unauthorized target
        r_bad = self.client.post("/__sc/security/api/sentinel/kali/execute", json={
            "tool": "whatweb",
            "target": "https://evil-unauthorized.com"
        })
        self.assertEqual(r_bad.status_code, 400)
        self.assertFalse(r_bad.json["success"])

        # 6. History
        r_hist = self.client.get("/__sc/security/api/sentinel/kali/history")
        self.assertEqual(r_hist.status_code, 200)
        self.assertIn("history", r_hist.json)
        self.assertTrue(len(r_hist.json["history"]) > 0)

    # ---------------- 13. INDIVIDUAL USER LLM ACCOUNT ARCHITECTURE ----------------

    def test_63_user_llm_encryption_at_rest(self):
        """Verifies cryptographic credential encryption, decryption, and secret masking."""
        from security.sentinel.user_llm_manager import encrypt_secret, decrypt_secret, mask_secret

        raw_key = "sk-proj-test1234567890abcdefghijklmnopqrstuvwxyz"
        encrypted = encrypt_secret(raw_key)

        # Encrypted ciphertext must NOT contain raw secret
        self.assertNotEqual(raw_key, encrypted)
        self.assertNotIn(raw_key, encrypted)

        # Decryption must perfectly recover the plaintext
        decrypted = decrypt_secret(encrypted)
        self.assertEqual(raw_key, decrypted)

        # Masking must redact the inner secret
        masked = mask_secret(raw_key)
        self.assertTrue(masked.startswith("sk-p"))
        self.assertTrue(masked.endswith("wxyz"))
        self.assertIn("****", masked)

    def test_64_user_llm_multi_tenant_isolation(self):
        """Verifies complete multi-tenant account isolation between User A and User B."""
        from security.sentinel.user_llm_manager import user_llm_manager

        user_a = "user_alpha_999"
        user_b = "user_beta_888"

        # User A connects OpenAI
        res_a = user_llm_manager.connect_provider(
            user_id=user_a,
            provider_id="openai",
            api_key="sk-alpha-super-secret-key-12345",
            model="gpt-4o"
        )
        self.assertTrue(res_a["success"])

        # User B inspects their own overview
        overview_b = user_llm_manager.get_user_overview(user_id=user_b)
        openai_b = next(p for p in overview_b["providers"] if p["provider_id"] == "openai")

        # User B must NOT see User A's connection, credentials, or status
        self.assertFalse(openai_b["is_connected"])
        self.assertEqual(openai_b["masked_credentials"], "")
        self.assertEqual(openai_b["usage_count"], 0)

        # User A overview contains their masked credentials
        overview_a = user_llm_manager.get_user_overview(user_id=user_a)
        openai_a = next(p for p in overview_a["providers"] if p["provider_id"] == "openai")
        self.assertTrue(openai_a["is_connected"])
        self.assertIn("****", openai_a["masked_credentials"])
        self.assertNotIn("super-secret", openai_a["masked_credentials"])

    def test_65_user_llm_router_resolution_and_usage_tracking(self):
        """Verifies per-user model router decrypts only the caller's key and tracks usage."""
        import uuid
        from security.sentinel.user_llm_manager import user_llm_manager

        user_client = f"client_enterprise_{uuid.uuid4().hex[:8]}"
        user_llm_manager.connect_provider(
            user_id=user_client,
            provider_id="claude",
            api_key="sk-ant-client-key-8888",
            model="claude-3-5-sonnet-20241022"
        )
        user_llm_manager.set_user_active_provider(user_id=user_client, provider_id="claude")

        # Router resolves for user_client
        provider_inst, meta = user_llm_manager.resolve_user_llm_instance(user_id=user_client)
        self.assertTrue(meta["is_user_custom"])
        self.assertEqual(meta["provider_id"], "claude")
        self.assertEqual(provider_inst.api_key, "sk-ant-client-key-8888")

        # Usage tracking
        user_llm_manager.record_usage(user_id=user_client, provider_id="claude")
        user_llm_manager.record_usage(user_id=user_client, provider_id="claude")

        overview = user_llm_manager.get_user_overview(user_id=user_client)
        claude_meta = next(p for p in overview["providers"] if p["provider_id"] == "claude")
        self.assertEqual(claude_meta["usage_count"], 2)

    def test_66_user_llm_disconnect_isolated(self):
        """Verifies disconnecting an account removes it solely for the calling user."""
        from security.sentinel.user_llm_manager import user_llm_manager

        u1 = "user_isolation_1"
        u2 = "user_isolation_2"

        user_llm_manager.connect_provider(user_id=u1, provider_id="mistral", api_key="mis-key-1111")
        user_llm_manager.connect_provider(user_id=u2, provider_id="mistral", api_key="mis-key-2222")

        # Disconnect u1 only
        ok = user_llm_manager.disconnect_provider(user_id=u1, provider_id="mistral")
        self.assertTrue(ok)

        # u1 is disconnected
        ov_u1 = user_llm_manager.get_user_overview(user_id=u1)
        m_u1 = next(p for p in ov_u1["providers"] if p["provider_id"] == "mistral")
        self.assertFalse(m_u1["is_connected"])

        # u2 is completely unaffected
        ov_u2 = user_llm_manager.get_user_overview(user_id=u2)
        m_u2 = next(p for p in ov_u2["providers"] if p["provider_id"] == "mistral")
        self.assertTrue(m_u2["is_connected"])

    def test_67_api_user_llm_endpoints(self):
        """Verifies REST API endpoints for user LLM catalog, connect, active, and test."""
        headers = {"X-Sentinel-User-Id": "api_test_user_777"}

        # 1. Get providers catalog for this user
        r1 = self.client.get("/__sc/security/api/sentinel/user/llm/providers", headers=headers)
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.json["user_id"], "api_test_user_777")
        self.assertTrue(len(r1.json["providers"]) >= 6)

        # 2. Connect a provider
        r2 = self.client.post("/__sc/security/api/sentinel/user/llm/connect", headers=headers, json={
            "provider_id": "deepseek",
            "api_key": "sk-deepseek-test-9999",
            "model": "deepseek-chat"
        })
        self.assertEqual(r2.status_code, 200)
        self.assertTrue(r2.json["success"])
        self.assertIn("****", r2.json["masked_key"])

        # 3. Set active provider
        r3 = self.client.post("/__sc/security/api/sentinel/user/llm/active", headers=headers, json={
            "provider_id": "deepseek"
        })
        self.assertEqual(r3.status_code, 200)
        self.assertEqual(r3.json["active_provider_id"], "deepseek")

        # 4. Test connectivity endpoint with mock provider
        r4 = self.client.post("/__sc/security/api/sentinel/user/llm/test", headers=headers, json={
            "provider_id": "mock"
        })
        self.assertEqual(r4.status_code, 200)
        self.assertTrue(r4.json["healthy"])

        # 5. Disconnect provider
        r5 = self.client.delete("/__sc/security/api/sentinel/user/llm/disconnect/deepseek", headers=headers)
        self.assertEqual(r5.status_code, 200)
        self.assertTrue(r5.json["success"])

    def test_68_admin_telemetry_stats_without_secret_leakage(self):
        """Verifies admin global telemetry stats aggregate metrics without exposing secrets."""
        # 1. Non-admin request rejected
        r_unauth = self.client.get("/__sc/security/api/sentinel/admin/llm-stats")
        self.assertEqual(r_unauth.status_code, 401)

        # 2. Admin authenticated request
        with self.client.session_transaction() as sess:
            sess["admin"] = "admin"

        r_admin = self.client.get("/__sc/security/api/sentinel/admin/llm-stats")
        self.assertEqual(r_admin.status_code, 200)
        stats = r_admin.json
        self.assertIn("total_users_with_llm", stats)
        self.assertIn("providers", stats)

        # Strictly ensure NO credentials / keys exist in admin telemetry
        dump_str = json.dumps(stats).lower()
        self.assertNotIn("api_key", dump_str)
        self.assertNotIn("encrypted_credentials", dump_str)
        self.assertNotIn("password", dump_str)
        self.assertNotIn("super-secret", dump_str)

    # ---------------- 13. PENTAGI AUTONOMOUS ENGINE INTEGRATION ----------------

    def test_69_pentagi_connector_config_and_health(self):
        """Verifies PentAGIIntegrationEngine configuration, update, and health check."""
        cfg = pentagi_engine.get_config()
        self.assertIn("server_url", cfg)
        self.assertTrue(len(cfg["capabilities_catalog"]) >= 5)

        # Update configuration
        updated = pentagi_engine.update_config(
            server_url="http://127.0.0.1:8443",
            api_token="test-pentagi-token-123",
            is_enabled=True,
            timeout_seconds=90
        )
        self.assertEqual(updated["server_url"], "http://127.0.0.1:8443")
        self.assertTrue(updated["has_token"])

        # Health check
        health = pentagi_engine.health_check()
        self.assertIn("is_connected", health)
        self.assertIn("capabilities", health)
        self.assertIn("workers_available", health)

    def test_70_pentagi_guardian_gating_unauthorized_target(self):
        """Verifies Guardian strictly blocks PentAGI campaigns against unauthorized targets."""
        res_blocked = pentagi_engine.create_campaign(
            user_id="test_user_pagi",
            target="http://evil-attacker-site.com",
            goal="Comprehensive security audit"
        )
        self.assertFalse(res_blocked["success"])
        self.assertEqual(res_blocked["status"], "blocked_by_guardian")
        self.assertIn("non autorisé", res_blocked["error"].lower())

    def test_71_pentagi_guardian_permitted_authorized_target(self):
        """Verifies authorized target passes Guardian and executes structured campaign."""
        res_ok = pentagi_engine.create_campaign(
            user_id="test_user_pagi",
            target="https://innotech-lab.local",
            goal="Diagnostic surface d'exposition",
            depth="standard"
        )
        self.assertTrue(res_ok["success"])
        self.assertIn("pagi_camp_", res_ok["campaign_id"])
        self.assertEqual(res_ok["target"], "https://innotech-lab.local")
        self.assertTrue(res_ok["findings_count"] >= 2)

    def test_72_pentagi_campaign_lifecycle_and_stop(self):
        """Verifies retrieving, listing, and stopping PentAGI campaigns."""
        camp_res = pentagi_engine.create_campaign(
            user_id="lifecycle_user",
            target="https://innotech-lab.local",
            goal="Test lifecycle",
            depth="surface"
        )
        c_id = camp_res["campaign_id"]

        # Get details
        details = pentagi_engine.get_campaign(c_id)
        self.assertIsNotNone(details)
        self.assertEqual(details["id"], c_id)
        self.assertEqual(details["user_id"], "lifecycle_user")

        # List campaigns
        c_list = pentagi_engine.list_campaigns(limit=10, user_id="lifecycle_user")
        self.assertTrue(len(c_list) >= 1)
        self.assertEqual(c_list[0]["id"], c_id)

        # Stop campaign
        stop_res = pentagi_engine.stop_campaign(c_id, stopped_by="admin_test")
        self.assertTrue(stop_res["success"])
        self.assertEqual(stop_res["status"], "stopped")

        # Verify status in DB
        stopped_details = pentagi_engine.get_campaign(c_id)
        self.assertEqual(stopped_details["status"], "stopped")

    def test_73_pentagi_remediation_bridge(self):
        """Verifies bridging PentAGI findings into Sentinel's Remediation Engine."""
        camp_res = pentagi_engine.create_campaign(
            user_id="remed_user",
            target="https://innotech-lab.local",
            goal="Remediation bridge test",
            depth="deep"
        )
        c_id = camp_res["campaign_id"]

        bridge_res = pentagi_engine.bridge_to_remediation(c_id)
        self.assertTrue(bridge_res["success"])
        self.assertTrue(bridge_res["remediations_created"] >= 2)
        self.assertTrue(len(bridge_res["plans"]) >= 2)
        # Verify plans contain diff patches
        for plan in bridge_res["plans"]:
            self.assertIn("patch_diff", plan)
            self.assertIn("title", plan)

    def test_74_pentagi_rest_api_endpoints(self):
        """Verifies all REST API endpoints for PentAGI require admin auth and work when authenticated."""
        # 0. Unauthenticated access rejected with 401
        with self.client.session_transaction() as sess:
            sess.pop("admin", None)

        r_unauth_probe = self.client.get("/__sc/security/api/sentinel/pentagi/status")
        self.assertEqual(r_unauth_probe.status_code, 401)

        # Authenticate session as admin owner
        with self.client.session_transaction() as sess:
            sess["admin"] = "admin"

        # 1. Status API
        r_status = self.client.get("/__sc/security/api/sentinel/pentagi/status")
        self.assertEqual(r_status.status_code, 200)
        self.assertIn("config", r_status.json)
        self.assertIn("capabilities", r_status.json)

        # 2. Config API
        r_cfg = self.client.post("/__sc/security/api/sentinel/pentagi/config", json={
            "server_url": "http://127.0.0.1:8443",
            "timeout_seconds": 150
        })
        self.assertEqual(r_cfg.status_code, 200)
        self.assertTrue(r_cfg.json["success"])

        # 3. Campaign Launch - Unauthorized target rejected 403
        r_unauth = self.client.post("/__sc/security/api/sentinel/pentagi/campaigns", json={
            "target": "https://unauthorized-target.org",
            "goal": "Recon"
        })
        self.assertEqual(r_unauth.status_code, 403)
        self.assertEqual(r_unauth.json["status"], "blocked_by_guardian")

        # 4. Campaign Launch - Authorized target 200
        r_launch = self.client.post("/__sc/security/api/sentinel/pentagi/campaigns", json={
            "target": "https://innotech-lab.local",
            "goal": "Audit complet via API",
            "depth": "standard"
        })
        self.assertEqual(r_launch.status_code, 200)
        c_id = r_launch.json["campaign_id"]
        self.assertTrue(r_launch.json["success"])

        # 5. List campaigns
        r_list = self.client.get("/__sc/security/api/sentinel/pentagi/campaigns")
        self.assertEqual(r_list.status_code, 200)
        self.assertTrue(len(r_list.json["campaigns"]) >= 1)

        # 6. Get campaign item
        r_get = self.client.get(f"/__sc/security/api/sentinel/pentagi/campaigns/{c_id}")
        self.assertEqual(r_get.status_code, 200)
        self.assertEqual(r_get.json["campaign"]["id"], c_id)

        # 7. Stop campaign
        r_stop = self.client.post(f"/__sc/security/api/sentinel/pentagi/campaigns/{c_id}/stop")
        self.assertEqual(r_stop.status_code, 200)
        self.assertTrue(r_stop.json["success"])

        # 8. Remediate campaign
        r_remed = self.client.post(f"/__sc/security/api/sentinel/pentagi/campaigns/{c_id}/remediate")
        self.assertEqual(r_remed.status_code, 200)
        self.assertTrue(r_remed.json["success"])
        self.assertTrue(r_remed.json["remediations_created"] >= 1)

    def test_75_agent_pentagi_tools(self):
        """Verifies the autonomous Sentinel agent can invoke PentAGI tools via schema."""
        mock_prov = MockProvider()
        agent = SentinelAgent(provider=mock_prov)

        # 1. Status tool call
        t_status = agent.execute_tool("get_pentagi_status", {})
        self.assertFalse(t_status.is_error)
        self.assertIn("capabilities", t_status.result)

        # 2. Campaign tool call on authorized target
        t_camp = agent.execute_tool("launch_pentagi_campaign", {
            "target": "https://innotech-lab.local",
            "goal": "Test agent invocation",
            "depth": "surface"
        })
        self.assertFalse(t_camp.is_error)
        self.assertTrue(t_camp.result["success"])
        self.assertIn("pagi_camp_", t_camp.result["campaign_id"])


if __name__ == "__main__":
    unittest.main()
