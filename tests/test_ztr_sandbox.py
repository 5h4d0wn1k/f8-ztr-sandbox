import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from firmware.ztr_sandbox import (  # noqa: E402
    EVIDENCE_LEGACY,
    EVIDENCE_MODERN,
    PILLAR_ORDER,
    PILLARS,
    _default_evidence,
    assess,
    main,
)


class AssessTest(unittest.TestCase):
    def test_modern_passes(self):
        r = assess(EVIDENCE_MODERN)
        self.assertEqual(r["verdict"], "PASS")
        self.assertGreaterEqual(r["overall"], 75)
        self.assertEqual(r["missing_required"], [])

    def test_legacy_fails(self):
        r = assess(EVIDENCE_LEGACY)
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIn("id_mfa", r["missing_required"])  # required, missing
        self.assertLess(r["overall"], 50)

    def test_all_four_pillars_scored(self):
        r = assess(_default_evidence())
        labels = [p["pillar"] for p in r["pillars"]]
        self.assertEqual(labels, PILLAR_ORDER)
        for p in r["pillars"]:
            self.assertGreaterEqual(p["score"], 0.0)
            self.assertLessEqual(p["score"], 100.0)

    def test_evidence_present_in_output(self):
        r = assess(EVIDENCE_MODERN)
        id_pillar = next(p for p in r["pillars"] if p["pillar"] == "identity")
        ctrl = next(c for c in id_pillar["controls"] if c["control"] == "id_mfa")
        self.assertTrue(ctrl["evidence"])  # evidence field is grounded

    def test_partial_verdict_exists(self):
        # craft a bundle that clears 50-75 but misses a required control
        bundle = {
            "org": "half.example",
            "identity": {"id_mfa": {"status": 1, "evidence": "e"},
                         "id_iam": {"status": 1, "evidence": "e"}},
            "device": {"dev_mdm": {"status": 0, "evidence": ""},
                       "dev_patch": {"status": 0, "evidence": ""}},
            "network": {"net_seg": {"status": 0, "evidence": ""}},
            "application": {"app_allowlist": {"status": 1, "evidence": "e"},
                            "app_sec": {"status": 1, "evidence": "e"}},
        }
        r = assess(bundle)
        self.assertIn("dev_mdm", r["missing_required"])  # still not ready
        self.assertTrue(r["verdict"].upper() in ("FAIL", "NOT-READY"))

    def test_no_evidence_means_zero_credit(self):
        r = assess({"org": "none.example"})
        self.assertEqual(r["overall"], 0.0)
        self.assertNotEqual(r["missing_required"], [])


class CliTest(unittest.TestCase):
    def test_demo_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.md")
            code = main(["--report", rp])
            self.assertEqual(code, 0)
            self.assertIn("ZERO-TRUST", open(rp).read())

    def test_fixture_modern_json(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.json")
            code = main(["--fixture", "modern", "--report", rp])
            self.assertEqual(code, 0)
            data = json.loads(open(rp).read())
            self.assertEqual(data["verdict"], "PASS")

    def test_fixture_legacy_strict_exit_one(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.md")
            code = main(["--fixture", "legacy", "--report", rp, "--strict"])
            self.assertEqual(code, 1)

    def test_bundle_file_input(self):
        with tempfile.TemporaryDirectory() as td:
            bp = os.path.join(td, "bundle.json")
            json.dump(EVIDENCE_MODERN, open(bp, "w"))
            rp = os.path.join(td, "r.json")
            code = main(["--bundle", bp, "--report", rp])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(open(rp).read())["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()