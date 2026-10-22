---
name: check-go-x509-ca-distrust
description: Review authorized Go services for CVE-2026-111943 by checking build versions, certificate-chain verification use, and rebuild/redeployment evidence. Use read-only commands and an offline CSV checker for the go1.26.10 and go1.27.3 thresholds; do not probe TLS services.
---

# Go CVE-2026-111943 Build and Certificate Verification Self-Check

## Baseline and Scope

According to [Go issue #82345](https://go.dev/issue/82345) and [Go's release history](https://go.dev/doc/devel/release), Go 1.26.10 and 1.27.3 address trust in specified intermediate CAs during `crypto/x509` verification. The Go issue describes security concerns with the relevant CA's operations; it does not confirm private-key compromise. The issue is on the URGENT track, which is not a CVSS score.

Check the **running binaries** and certificate-verification use of authorized assets. Do not create forged certificates or connect to unauthorized services. The checker reads local CSV only and never executes an asset binary.

## 1. Collect Running-Build Evidence

For each service replica, record the asset, executable path and hash, Go build version, build provenance, certificate-verification use, and owner. Read the process path on the target host and inspect the confirmed binary with trusted tooling:

```bash
ps -eo pid,ppid,user,args | grep -E '[g]o-service-name'
readlink -f /proc/<PID>/exe
go version -m /path/to/confirmed/go-binary
```

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'myservice.exe' } | Select-Object ProcessId,ExecutablePath
go version -m 'C:\path\to\confirmed\myservice.exe'
```

`go version -m` reads build information without executing the target, but the `go` command must come from a trusted installation. Mark uncertain paths or permissions as unresolved. Plain `go version` reports the local toolchain; the `go` directive in `go.mod` does not prove which compiler built a deployed artifact. Retain image digests and vendor build evidence where applicable.

## 2. Offline Inventory

Create a UTF-8 CSV using [references/inventory-schema.md](references/inventory-schema.md):

```bash
python3 scripts/check_go.py inventory /path/to/go-assets.csv
```

The checker compares only stable **go1.26.x and go1.27.x** build versions. It returns `before_fix_upstream_build`, `at_or_above_fix_verify_deployment`, or `unknown_or_unsupported_review`. The last category covers older lines, prereleases, and unrecognized vendor builds; an older version with a vendor backport needs manual review too. A version at the threshold does not prove that all running replicas have been updated. Exit code 0 means the input was processed; 2 means input or evidence is incomplete.

## 3. Review Application Impact and Rollout

- List outbound TLS/HTTPS, mTLS client-certificate checks, internal PKI, certificate-management paths, and calls to `crypto/x509.Certificate.Verify`. Review custom `tls.Config` settings or verification callbacks that replace or bypass standard chain validation; assess custom logic separately.
- **Rebuild, redeploy, and restart** with a trusted Go 1.26.10, 1.27.3, or later supported version containing the fix. Verify the binary used by each process, its build information, image digest, and every node. Updating a developer's toolchain does not alter deployed binaries.
- Correlate existing certificate errors, TLS handshakes, and chain-configuration changes. Check whether a business dependency relies on a filtered intermediate. If a chain fails after updating, obtain a trusted alternative from the service or CA; do not disable certificate verification.
- Report the build version, running file, verification use, vendor backport evidence, log coverage, update and redeployment status, and unresolved items. A lack of error logs does not establish that the service was unaffected.

See [references/validation.md](references/validation.md) for checker limitations and [../case.md](../case.md) for the English analysis.
