#!/usr/bin/env python3
"""Read a local Go build inventory; never execute binaries or connect to hosts."""

import argparse
import csv
import json
import re
import sys
from pathlib import Path


REQUIRED = {"asset", "service", "build_go_version", "build_evidence", "binary_path", "cert_verify_usage", "owner"}
FIXED = {26: 10, 27: 3}


def classify(value):
    match = re.fullmatch(r"go1\.(26|27)\.(0|[1-9][0-9]*)", (value or "").strip())
    if not match:
        return "unknown_or_unsupported_review"
    minor, patch = map(int, match.groups())
    return "before_fix_upstream_build" if patch < FIXED[minor] else "at_or_above_fix_verify_deployment"


def check(path):
    with Path(path).open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or not REQUIRED.issubset(reader.fieldnames):
            raise ValueError("missing required CSV columns: " + ", ".join(sorted(REQUIRED - set(reader.fieldnames or []))))
        rows = []
        incomplete = False
        for line, item in enumerate(reader, 2):
            if None in item:
                raise ValueError(f"line {line}: unexpected extra columns")
            if not any((v or "").strip() for v in item.values()):
                continue
            gaps = sorted(k for k in REQUIRED if not (item[k] or "").strip())
            status = classify(item["build_go_version"])
            if status == "unknown_or_unsupported_review":
                gaps.append("build_go_version:verify_toolchain_or_vendor_backport")
            usage = (item["cert_verify_usage"] or "").strip().lower()
            if usage not in ("yes", "no"):
                usage = "unknown"
                gaps.append("cert_verify_usage:unconfirmed")
            if gaps:
                incomplete = True
            rows.append({"line": line, "asset": item["asset"], "service": item["service"],
                         "binary_path": item["binary_path"], "build_go_version": item["build_go_version"],
                         "build_evidence": item["build_evidence"], "owner": item["owner"],
                         "cert_verify_usage": usage, "version_status": status, "evidence_gaps": gaps,
                         "priority": "review_first" if usage == "yes" else "confirm_usage" if usage == "unknown" else "review",
                         "scope": "upstream_build_number_only; verify_running_binary_and_custom_verifier"})
        if not rows:
            raise ValueError("no evidence rows")
        return {"status": "incomplete" if incomplete else "processed", "rows": rows}, incomplete


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inventory",))
    parser.add_argument("csv_file")
    args = parser.parse_args(argv)
    try:
        result, incomplete = check(args.csv_file)
    except (OSError, ValueError, UnicodeError, csv.Error) as exc:
        result, incomplete = {"status": "error", "reason": str(exc)}, True
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
