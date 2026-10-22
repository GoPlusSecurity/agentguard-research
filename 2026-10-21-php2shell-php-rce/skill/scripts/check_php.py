#!/usr/bin/env python3
"""Read normalized local CSV evidence; never execute PHP or send requests."""

import argparse
import csv
import json
import re
import sys
from pathlib import Path


INVENTORY_COLUMNS = {"asset", "service", "php_version", "version_source", "internet_exposed", "owner"}
PROCESS_COLUMNS = {"asset", "timestamp", "parent_image", "child_image"}
FIXED_PATCH = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
PARENTS = {"php", "php.exe", "php-cgi", "php-cgi.exe", "php-fpm", "php-fpm.exe", "httpd", "httpd.exe", "apache2", "apache2.exe"}
CHILDREN = {
    "sh": "shell", "bash": "shell", "dash": "shell", "cmd.exe": "shell", "powershell.exe": "shell", "pwsh.exe": "shell",
    "python": "interpreter", "python3": "interpreter", "python.exe": "interpreter", "perl": "interpreter", "perl.exe": "interpreter",
    "curl": "download_or_network", "curl.exe": "download_or_network", "wget": "download_or_network", "nc": "download_or_network", "certutil.exe": "download_or_network",
}


def basename(value):
    return (value or "").replace("\\", "/").rsplit("/", 1)[-1].lower().strip()


def classify_version(value):
    """Compare exact upstream stable versions only; never infer vendor patch state."""
    version = (value or "").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        return "unknown_version_or_build"
    major, minor, patch = map(int, version.split("."))
    if (major, minor) in FIXED_PATCH:
        return ("affected_upstream_release" if patch < FIXED_PATCH[major, minor]
                else "at_or_above_fixed_release_verify_build")
    if major < 8 or (major == 8 and minor <= 1):
        return "unsupported_review_vendor_backport"
    return "unknown_version_or_build"


def read_rows(path, required):
    with Path(path).open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
            raise ValueError("missing required CSV columns: " + ", ".join(sorted(required - set(reader.fieldnames or []))))
        rows = []
        for line, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(f"line {line}: unexpected extra columns")
            if any("\x00" in (cell or "") for cell in row.values()):
                raise ValueError(f"line {line}: NUL in field")
            if any((cell or "").strip() for cell in row.values()):
                rows.append((line, row))
        if not rows:
            raise ValueError("no evidence rows")
        return rows


def inventory(rows):
    result = []
    incomplete = False
    for line, row in rows:
        missing = sorted(k for k in INVENTORY_COLUMNS if not (row[k] or "").strip())
        exposed = (row["internet_exposed"] or "").strip().lower()
        if exposed not in ("yes", "no", "unknown"):
            missing.append("internet_exposed:invalid_or_missing")
            exposed = "unknown"
        elif exposed == "unknown":
            missing.append("internet_exposed:unconfirmed")
        version_status = classify_version(row["php_version"])
        if (row["php_version"] or "").strip() and version_status in (
                "unknown_version_or_build", "unsupported_review_vendor_backport"):
            missing.append("version:verify_build_or_vendor_patch")
        if missing:
            incomplete = True
        result.append({"line": line, "asset": row["asset"], "service": row["service"],
                       "php_version_evidence": row["php_version"], "version_source": row["version_source"],
                       "internet_exposed": exposed, "owner": row["owner"], "missing_evidence": missing,
                       "priority": "review_first" if exposed == "yes" else "confirm_exposure" if exposed == "unknown" else "review",
                       "vulnerability_status": version_status,
                       "version_result_scope": "upstream_release_number_only; running_binary_and_vendor_patch_need_verification"})
    return {"mode": "inventory", "status": "incomplete" if incomplete else "processed", "rows": result}, incomplete


def processes(rows):
    findings = []
    incomplete = False
    for line, row in rows:
        if any(not (row[k] or "").strip() for k in PROCESS_COLUMNS):
            incomplete = True
            continue
        parent, child = basename(row["parent_image"]), basename(row["child_image"])
        if parent in PARENTS and child in CHILDREN:
            findings.append({"line": line, "asset": row["asset"], "timestamp": row["timestamp"],
                             "parent": parent, "child": child, "signal": CHILDREN[child],
                             "interpretation": "generic_review_only_not_cve_ioc"})
    return {"mode": "processes", "status": "incomplete" if incomplete else "processed",
            "records_read": len(rows), "findings": findings,
            "conclusion": "no_finding_does_not_exclude_exploitation"}, incomplete


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inventory", "processes"))
    parser.add_argument("csv_file")
    args = parser.parse_args(argv)
    try:
        required = INVENTORY_COLUMNS if args.mode == "inventory" else PROCESS_COLUMNS
        rows = read_rows(args.csv_file, required)
        result, incomplete = inventory(rows) if args.mode == "inventory" else processes(rows)
    except (OSError, UnicodeError, ValueError, csv.Error) as exc:
        result, incomplete = {"mode": args.mode, "status": "error", "reason": str(exc)}, True
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
