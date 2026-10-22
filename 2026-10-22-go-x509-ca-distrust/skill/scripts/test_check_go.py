import csv
import tempfile
import unittest
from pathlib import Path

from check_go import REQUIRED, check, classify


class CheckGoTests(unittest.TestCase):
    def fixture(self, row):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        file = Path(temp.name) / "inventory.csv"
        with file.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=sorted(REQUIRED))
            writer.writeheader()
            writer.writerow(row)
        return file

    def test_supported_branch_boundaries(self):
        for branch, threshold in ((26, 10), (27, 3)):
            self.assertEqual(classify(f"go1.{branch}.{threshold - 1}"), "before_fix_upstream_build")
            self.assertEqual(classify(f"go1.{branch}.{threshold}"), "at_or_above_fix_verify_deployment")
            self.assertEqual(classify(f"go1.{branch}.{threshold + 1}"), "at_or_above_fix_verify_deployment")

    def test_custom_and_other_branches_are_unknown(self):
        for version in ("go1.25.10", "go1.27.3rc1", "go1.27.3-custom", "1.27.3", "go1.28.0", ""):
            self.assertEqual(classify(version), "unknown_or_unsupported_review")

    def test_missing_usage_preserves_gap(self):
        row = {"asset": "a", "service": "api", "build_go_version": "go1.27.2", "build_evidence": "local binary",
               "binary_path": "/app/api", "cert_verify_usage": "unknown", "owner": "ops"}
        result, incomplete = check(self.fixture(row))
        self.assertTrue(incomplete)
        self.assertEqual(result["rows"][0]["version_status"], "before_fix_upstream_build")
        self.assertIn("cert_verify_usage:unconfirmed", result["rows"][0]["evidence_gaps"])

    def test_fixed_build_not_asserted_safe(self):
        row = {"asset": "b", "service": "mtls", "build_go_version": "go1.26.10", "build_evidence": "running path",
               "binary_path": "/app/mtls", "cert_verify_usage": "yes", "owner": "ops"}
        result, incomplete = check(self.fixture(row))
        self.assertFalse(incomplete)
        self.assertEqual(result["rows"][0]["priority"], "review_first")
        self.assertIn("verify_running_binary", result["rows"][0]["scope"])


if __name__ == "__main__":
    unittest.main()
