#!/usr/bin/env python3
"""Tests for R.E.A. (Reverse Engineer Anything) engine, local mocks, and Pro/Enterprise plan gating."""

import base64
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

os.environ.setdefault("SENTINEL_DATA_DIR", str(Path(__file__).resolve().parent / "data"))

import app as sc_app
from rea_engine import analyze_site_rea, build_rea_bundle_zip, read_rea_source_file
from security.plans import (
    CLONER_PLANS,
    check_and_authorize_clone,
    check_cloner_plan_requirement,
    check_plan_requirement,
    init_plan_tables,
    record_clone_usage,
    set_user_plan,
)
from site_server import resolve, resolve_post


class TestReaClonerIntegration(unittest.TestCase):
    def setUp(self):
        init_plan_tables()
        self.tmp_root = Path(tempfile.mkdtemp(prefix="test_rea_"))
        self.site_id = f"demo_rea_{os.getpid()}"
        self.site_dir = sc_app.CLONED_DIR / self.site_id
        self.site_dir.mkdir(parents=True, exist_ok=True)
        self._build_sample_clone(self.site_dir)

        sc_app.app.testing = True
        self.client = sc_app.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp_root, ignore_errors=True)
        shutil.rmtree(self.site_dir, ignore_errors=True)

    def _build_sample_clone(self, root: Path):
        (root / "_post").mkdir(parents=True, exist_ok=True)
        (root / "assets").mkdir(parents=True, exist_ok=True)

        # Sample HTML referencing React/Next + Tailwind signatures
        (root / "index.html").write_text(
            '<!doctype html><html><head><script src="/assets/app.js"></script></head>'
            '<body><div id="__next"><script id="__NEXT_DATA__" type="application/json">{}</script></div></body></html>',
            encoding="utf-8",
        )

        # Inline SourceMap v3 with intentional path traversal attempt to verify sanitization
        sm_inline = {
            "version": 3,
            "sources": ["webpack:///../../src/components/HeroCard.tsx", "src/utils/format.ts"],
            "sourcesContent": [
                "export function HeroCard() { return <h1>Hello R.E.A.</h1>; }\n",
                "export const fmt = (n: number) => `${n} EUR`;\n",
            ],
            "mappings": "",
        }
        sm_b64 = base64.b64encode(json.dumps(sm_inline).encode("utf-8")).decode("ascii")
        (root / "assets" / "app.js").write_text(
            "console.log('react-dom __reactFiber --tw-bg');\n"
            "fetch('/api/v1/products');\n"
            f"//# sourceMappingURL=data:application/json;charset=utf-8;base64,{sm_b64}\n",
            encoding="utf-8",
        )

        # Captured API POST + GET JSON payloads
        (root / "_post" / "search.json").write_text(
            json.dumps({"items": [{"id": 1, "name": "Sentinel Pro", "price": 29}], "total": 1}),
            encoding="utf-8",
        )
        (root / "api_products.json").write_text(
            json.dumps({"products": [{"sku": "SKU-1", "active": True}]}),
            encoding="utf-8",
        )

        map_data = {
            "/": {"f": "index.html", "t": "text/html"},
            "/assets/app.js": {"f": "assets/app.js", "t": "application/javascript"},
            "/api/v1/products": {"f": "api_products.json", "t": "application/json"},
            "POST /api/v1/search#abc": {"f": "_post/search.json", "t": "application/json"},
            "POST /api/v1/search": {"f": "_post/search.json", "t": "application/json"},
        }
        (root / "_map.json").write_text(json.dumps(map_data), encoding="utf-8")
        (root / "_clone-report.txt").write_text("Source : https://example.com/\nPages : 1\n", encoding="utf-8")

    def test_rea_engine_extracts_sourcemaps_openapi_and_mocks(self):
        trace = {
            "cdp_requests": [
                {"url": "https://example.com/api/v1/search", "method": "POST", "status": 200, "mime_type": "application/json"},
                {"url": "https://example.com/api/v1/products", "method": "GET", "status": 200, "mime_type": "application/json"},
            ],
            "localStorage": {"theme": "dark"},
            "websockets": ["wss://example.com/ws"],
            "runtime_flags": {"hasNextData": True, "hasReactHook": True},
        }
        rep = analyze_site_rea(self.site_dir, origin_url="https://example.com/", runtime_trace=trace)
        self.assertTrue(rep["available"])
        self.assertEqual(rep["sourcemaps"]["sourcemaps_count"], 1)
        self.assertGreaterEqual(rep["sourcemaps"]["app_files_count"], 2)

        # Path traversal sanitized: HeroCard.tsx lives strictly inside _rea/sources/
        hero = read_rea_source_file(self.site_dir, "src/components/HeroCard.tsx")
        self.assertIn("HeroCard", hero)
        self.assertIsNone(read_rea_source_file(self.site_dir, "../rea-report.json"))

        # Tech stack detection
        names = {t["name"] for t in rep["tech_stack"]}
        self.assertIn("Next.js", names)
        self.assertIn("React", names)

        # OpenAPI 3.0 & Smart Mock resolution in site_server
        openapi = json.loads((self.site_dir / "_rea" / "openapi.json").read_text(encoding="utf-8"))
        self.assertEqual(openapi["openapi"], "3.0.3")
        self.assertIn("/api/v1/search", openapi["paths"])

        # Remove POST key from _map.json temporarily to test _rea/api-mocks.json fallback in site_server
        mp = json.loads((self.site_dir / "_map.json").read_text(encoding="utf-8"))
        mp.pop("POST /api/v1/search", None)
        mp.pop("POST /api/v1/search#abc", None)
        (self.site_dir / "_map.json").write_text(json.dumps(mp), encoding="utf-8")
        mocked = resolve_post(self.site_dir, "/api/v1/search", b"{}")
        self.assertIsNotNone(mocked)
        self.assertEqual(mocked[0], "file")

        # Bundle ZIP packaging
        zbuf = build_rea_bundle_zip(self.site_dir)
        with zipfile.ZipFile(zbuf) as zf:
            names_in_zip = set(zf.namelist())
            self.assertIn("openapi.json", names_in_zip)
            self.assertIn("CLEAN-ROOM-BLUEPRINT.md", names_in_zip)
            self.assertIn("sources/src/components/HeroCard.tsx", names_in_zip)

    def test_plan_gating_on_cloner_and_studio_rea(self):
        self.assertFalse(CLONER_PLANS["free"]["rea_mode"])
        self.assertTrue(CLONER_PLANS["pro"]["rea_mode"])
        self.assertTrue(CLONER_PLANS["agency"]["rea_mode"])

        # Free user cannot launch a clone with rea_mode=True
        free_uid = f"rea_free_{os.getpid()}"
        with self.client.session_transaction() as sess:
            sess["sentinel_user_id"] = free_uid
        r_clone = self.client.post("/__sc/api/clone", json={"url": "https://example.com", "rea_mode": True})
        self.assertEqual(r_clone.status_code, 403)
        self.assertEqual(r_clone.get_json()["error_code"], "PLAN_UPGRADE_REQUIRED")

        # Ultron Security Pro alone does NOT unlock Cloner / R.E.A.
        sec_only_uid = f"sec_only_{os.getpid()}"
        set_user_plan(sec_only_uid, "pro", source="test", scope="security")
        self.assertTrue(check_plan_requirement(sec_only_uid, "pro")["allowed"])
        self.assertFalse(check_cloner_plan_requirement(sec_only_uid, "pro")["allowed"])
        with self.client.session_transaction() as sess:
            sess["sentinel_user_id"] = sec_only_uid
        self.assertEqual(self.client.get(f"/__sc/api/studio/{self.site_id}/rea").status_code, 403)
        self.assertEqual(self.client.post(f"/__sc/api/studio/{self.site_id}/rea/analyze").status_code, 403)

        # Upgrade user to Cloner Pro -> R.E.A. unlocks, while Ultron Security remains Free
        pro_uid = f"rea_pro_{os.getpid()}"
        set_user_plan(pro_uid, "pro", source="test", scope="cloner")
        self.assertTrue(check_cloner_plan_requirement(pro_uid, "pro")["allowed"])
        self.assertFalse(check_plan_requirement(pro_uid, "pro")["allowed"])
        with self.client.session_transaction() as sess:
            sess["sentinel_user_id"] = pro_uid
        r_an = self.client.post(f"/__sc/api/studio/{self.site_id}/rea/analyze")
        self.assertEqual(r_an.status_code, 200)
        data = r_an.get_json()
        self.assertTrue(data["available"])
        self.assertGreaterEqual(data["sourcemaps"]["app_files_count"], 2)

        r_src = self.client.get(f"/__sc/api/studio/{self.site_id}/rea/source?path=src/components/HeroCard.tsx")
        self.assertEqual(r_src.status_code, 200)
        self.assertIn("HeroCard", r_src.get_json()["content"])

        r_oai = self.client.get(f"/__sc/api/studio/{self.site_id}/rea/openapi.json")
        self.assertEqual(r_oai.status_code, 200)
        self.assertEqual(json.loads(r_oai.data.decode("utf-8"))["openapi"], "3.0.3")

        r_zip = self.client.get(f"/__sc/api/studio/{self.site_id}/rea/bundle.zip")
        self.assertEqual(r_zip.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(r_zip.data)) as zf:
            self.assertIn("CLEAN-ROOM-BLUEPRINT.md", zf.namelist())

        # Suite Pro bundle unlocks BOTH Cloner Pro and Ultron Security Pro
        bundle_uid = f"suite_user_{os.getpid()}"
        set_user_plan(bundle_uid, "suite_pro", source="test", scope="bundle")
        self.assertTrue(check_cloner_plan_requirement(bundle_uid, "pro")["allowed"])
        self.assertTrue(check_plan_requirement(bundle_uid, "pro")["allowed"])

    def test_cloner_quotas_depth_zip_github_and_studio_locks(self):
        uid = f"cloner_quota_{os.getpid()}"
        # Free: max 1 distinct site/month and max 5 pages
        self.assertTrue(check_and_authorize_clone(uid, "https://alpha.local", requested_max_pages=5)["allowed"])
        depth_block = check_and_authorize_clone(uid, "https://alpha.local", requested_max_pages=15)
        self.assertFalse(depth_block["allowed"])
        self.assertEqual(depth_block["required_plan"], "pro")

        record_clone_usage(uid, "https://alpha.local")
        self.assertTrue(check_and_authorize_clone(uid, "https://www.alpha.local/about", requested_max_pages=5)["allowed"])
        site_block = check_and_authorize_clone(uid, "https://beta.local", requested_max_pages=5)
        self.assertFalse(site_block["allowed"])
        self.assertEqual(site_block["error_code"], "CLONE_QUOTA_EXCEEDED")

        # HTTP route locks for Free user (ZIP export, GitHub, Studio export & Inspect save)
        with self.client.session_transaction() as sess:
            sess["sentinel_user_id"] = uid
        self.assertEqual(self.client.get(f"/__sc/api/sites/{self.site_id}/download").status_code, 403)
        self.assertEqual(self.client.post(f"/__sc/api/sites/{self.site_id}/publish", json={}).status_code, 403)
        self.assertEqual(self.client.post(f"/__sc/api/studio/{self.site_id}/export", json={"pages": ["/"]}).status_code, 403)
        self.assertEqual(self.client.post(f"/__sc/api/studio/{self.site_id}/inspect/save", json={"key": "/", "ops": []}).status_code, 403)

        # Upgrade to Cloner Pro: 60 pages allowed, 150 pages requires Agency; ZIP & Studio unlocked
        set_user_plan(uid, "pro", source="test", scope="cloner")
        self.assertTrue(check_and_authorize_clone(uid, "https://beta.local", requested_max_pages=60)["allowed"])
        agency_depth = check_and_authorize_clone(uid, "https://beta.local", requested_max_pages=150)
        self.assertFalse(agency_depth["allowed"])
        self.assertEqual(agency_depth["required_plan"], "agency")
        self.assertEqual(self.client.get(f"/__sc/api/sites/{self.site_id}/download").status_code, 200)
        self.assertEqual(self.client.post(f"/__sc/api/studio/{self.site_id}/inspect/save", json={"key": "/", "ops": []}).status_code, 200)

        # Cloner Agency: 150 pages + unlimited sites
        set_user_plan(uid, "agency", source="test", scope="cloner")
        for i in range(12):
            record_clone_usage(uid, f"https://ent{i}.local")
        self.assertTrue(check_and_authorize_clone(uid, "https://ent99.local", requested_max_pages=150)["allowed"])


if __name__ == "__main__":
    unittest.main()
