#!/usr/bin/env python3
"""Read local Node.js asset CSV; no network or runtime execution."""

import argparse
import csv
import json
import re
import sys
from pathlib import Path


REQUIRED = {"asset", "service", "node_version", "version_source", "internet_exposed", "owner"}
INPUTS = ("dns_untrusted", "tls_dynamic_host", "brotli_untrusted")
FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
HIGH = {
    22: ("CVE-2026-105482", "CVE-2026-106069", "CVE-2026-111497"),
    24: ("CVE-2026-105482", "CVE-2026-105483", "CVE-2026-106069", "CVE-2026-111497"),
    26: ("CVE-2026-105482", "CVE-2026-105483", "CVE-2026-106069", "CVE-2026-111497"),
}


def classify(raw):
    match = re.fullmatch(r"v?(22|24|26)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", (raw or "").strip())
    if not match:
        return "unknown_or_other_line", None
    major, minor, patch = map(int, match.groups())
    return ("below_fixed_upstream_version" if (major, minor, patch) < FIXED[major]
            else "at_or_above_fixed_verify_running_build"), major


def tri(raw):
    value = (raw or "").strip().lower()
    return value if value in ("yes", "no", "unknown") else "unknown"


def inspect(path):
    with Path(path).open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        if reader.fieldnames is None or not REQUIRED.issubset(reader.fieldnames):
            raise ValueError("missing CSV columns: " + ", ".join(sorted(REQUIRED - set(reader.fieldnames or []))))
        output = []
        incomplete = False
        for number, row in enumerate(reader, 2):
            if None in row:
                raise ValueError(f"line {number}: extra CSV columns")
            if not any((value or "").strip() for value in row.values()):
                continue
            status, major = classify(row["node_version"])
            missing = sorted(key for key in REQUIRED if not (row[key] or "").strip())
            exposure = tri(row["internet_exposed"])
            if exposure == "unknown":
                missing.append("internet_exposed:unconfirmed")
            if major is None:
                missing.append("node_version:verify_branch_and_vendor_build")
            surfaces = {key: tri(row.get(key)) for key in INPUTS}
            if missing:
                incomplete = True
            output.append({"line": number, "asset": row["asset"], "service": row["service"],
                           "node_version": row["node_version"], "version_source": row["version_source"],
                           "owner": row["owner"], "internet_exposed": exposure, "inputs": surfaces,
                           "version_status": status, "high_cves_for_branch": HIGH.get(major, ()),
                           "priority": "review_first" if exposure == "yes" or "yes" in surfaces.values()
                           else "confirm_exposure" if exposure == "unknown" else "review",
                           "missing_evidence": missing,
                           "scope": "upstream_release_number_only; verify_running_binary_and_vendor_backports"})
    if not output:
        raise ValueError("no asset rows")
    return {"mode": "inventory", "status": "incomplete" if incomplete else "processed", "rows": output}, incomplete


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inventory",))
    parser.add_argument("csv_file")
    args = parser.parse_args(argv)
    try:
        result, incomplete = inspect(args.csv_file)
    except (OSError, UnicodeError, ValueError, csv.Error) as exc:
        result, incomplete = {"mode": args.mode, "status": "error", "reason": str(exc)}, True
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
