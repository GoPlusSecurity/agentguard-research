import csv
import tempfile
import unittest
from pathlib import Path

from check_php import INVENTORY_COLUMNS, PROCESS_COLUMNS, classify_version, inventory, processes, read_rows


class OfflineEvidenceTests(unittest.TestCase):
    def write_csv(self, columns, rows):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "evidence.csv"
        with path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def test_inventory_marks_fixed_release_number_without_declaring_instance_safe(self):
        columns = sorted(INVENTORY_COLUMNS)
        path = self.write_csv(columns, [{"asset": "a", "service": "web", "php_version": "8.5.999",
                                       "version_source": "node snapshot", "internet_exposed": "yes", "owner": "team"}])
        result, incomplete = inventory(read_rows(path, INVENTORY_COLUMNS))
        self.assertFalse(incomplete)
        self.assertEqual(result["rows"][0]["vulnerability_status"], "at_or_above_fixed_release_verify_build")
        self.assertIn("running_binary_and_vendor_patch_need_verification", result["rows"][0]["version_result_scope"])
        self.assertEqual(result["rows"][0]["priority"], "review_first")

    def test_branch_boundaries_and_unknown_versions(self):
        for (minor, fixed) in ((2, 35), (3, 36), (4, 27), (5, 12)):
            self.assertEqual(classify_version(f"8.{minor}.{fixed-1}"), "affected_upstream_release")
            self.assertEqual(classify_version(f"8.{minor}.{fixed}"), "at_or_above_fixed_release_verify_build")
            self.assertEqual(classify_version(f"8.{minor}.{fixed+1}"), "at_or_above_fixed_release_verify_build")
        for version in ("8.1.99", "7.4.33"):
            self.assertEqual(classify_version(version), "unsupported_review_vendor_backport")
        for version in ("8.5.12-1ubuntu1", "8.6.0RC3", "8.6.0", "8.x", "PHP 8.5.12", ""):
            self.assertEqual(classify_version(version), "unknown_version_or_build")

    def test_unknown_or_invalid_exposure_is_incomplete(self):
        columns = sorted(INVENTORY_COLUMNS)
        path = self.write_csv(columns, [{"asset": "b", "service": "job", "php_version": "",
                                       "version_source": "", "internet_exposed": "perhaps", "owner": "ops"}])
        result, incomplete = inventory(read_rows(path, INVENTORY_COLUMNS))
        self.assertTrue(incomplete)
        self.assertEqual(result["rows"][0]["internet_exposed"], "unknown")

    def test_explicit_unknown_exposure_is_a_gap(self):
        path = self.write_csv(sorted(INVENTORY_COLUMNS), [{"asset": "c", "service": "api", "php_version": "8.x",
                "version_source": "local record", "internet_exposed": "unknown", "owner": "ops"}])
        result, incomplete = inventory(read_rows(path, INVENTORY_COLUMNS))
        self.assertTrue(incomplete)
        self.assertIn("internet_exposed:unconfirmed", result["rows"][0]["missing_evidence"])

    def test_process_path_normalization_and_incomplete_event(self):
        columns = sorted(PROCESS_COLUMNS)
        path = self.write_csv(columns, [
            {"asset": "w", "timestamp": "t1", "parent_image": "C:\\PHP\\php-cgi.exe", "child_image": "C:\\Windows\\System32\\cmd.exe"},
            {"asset": "w", "timestamp": "t2", "parent_image": "/usr/sbin/php-fpm", "child_image": "/usr/bin/convert"},
            {"asset": "w", "timestamp": "", "parent_image": "php", "child_image": "sh"},
        ])
        result, incomplete = processes(read_rows(path, PROCESS_COLUMNS))
        self.assertTrue(incomplete)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["signal"], "shell")

    def test_missing_header_is_error(self):
        path = self.write_csv(["asset"], [{"asset": "a"}])
        with self.assertRaises(ValueError):
            read_rows(path, INVENTORY_COLUMNS)


if __name__ == "__main__":
    unittest.main()
