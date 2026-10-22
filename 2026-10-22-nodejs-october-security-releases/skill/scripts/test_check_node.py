import csv
import tempfile
import unittest
from pathlib import Path

from check_node import REQUIRED, classify, inspect


class InventoryTests(unittest.TestCase):
    def fixture(self, rows):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "asset.csv"
        with path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=sorted(REQUIRED))
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_branch_boundaries_and_cve_scope(self):
        for major, previous, fixed in ((22, "22.23.3", "22.23.4"), (24, "24.22.0", "24.22.1"), (26, "26.12.0", "26.12.1")):
            self.assertEqual(classify("v" + previous), ("below_fixed_upstream_version", major))
            self.assertEqual(classify(fixed), ("at_or_above_fixed_verify_running_build", major))
        row = {"asset": "a", "service": "api", "node_version": "v22.23.3", "version_source": "running process",
               "internet_exposed": "yes", "owner": "team"}
        result, incomplete = inspect(self.fixture([row]))
        self.assertFalse(incomplete)
        self.assertNotIn("CVE-2026-105483", result["rows"][0]["high_cves_for_branch"])
        self.assertEqual(result["rows"][0]["priority"], "review_first")

    def test_unknown_versions_stay_unknown(self):
        for version in ("v20.0.0", "v24.22.1-rc.1", "24.22.1+vendor", "node 24.22.1", "v26.x", ""):
            self.assertEqual(classify(version), ("unknown_or_other_line", None))

    def test_empty_evidence_is_incomplete(self):
        row = {"asset": "b", "service": "worker", "node_version": "", "version_source": "",
               "internet_exposed": "unknown", "owner": "ops"}
        result, incomplete = inspect(self.fixture([row]))
        self.assertTrue(incomplete)
        self.assertEqual(result["rows"][0]["inputs"]["brotli_untrusted"], "unknown")
        self.assertEqual(result["rows"][0]["version_status"], "unknown_or_other_line")

    def test_missing_columns_error(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "bad.csv"
        path.write_text("asset\na\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            inspect(path)


if __name__ == "__main__":
    unittest.main()
