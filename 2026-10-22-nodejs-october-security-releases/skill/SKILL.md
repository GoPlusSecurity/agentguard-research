---
name: check-nodejs-october-2026
description: Review authorized Node.js services for the four High and six Medium/Low CVEs fixed in October 2026. Check running versions, DNS/TLS/Brotli input paths, existing logs, and vendor backport evidence with a read-only offline inventory workflow; do not probe vulnerabilities.
---

# Node.js October 2026 Security Self-Check

## Baseline and Boundaries

- Use the [Node.js advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) and release notes for [22.x](https://nodejs.org/en/blog/release/v22.23.4/), [24.x](https://nodejs.org/en/blog/release/v24.22.1/), and [26.x](https://nodejs.org/en/blog/release/v26.12.1/). **The highest severity is High; none is Critical.** The four High issues are CVE-2026-105482 (`dns.resolve` NUL truncation; 22/24/26), CVE-2026-105483 (TLS hostname checking with fullwidth IP digits; 24/26), CVE-2026-106069 (TLS hostname checking with noncanonical IP text; 22/24/26), and CVE-2026-111497 (Brotli out-of-bounds write and potential RCE; 22/24/26).
- Medium issues: CVE-2026-105481 (keep-alive response handling), CVE-2026-106072 (noncanonical IPv4 certificate checking), and CVE-2026-106074 (repeated random values in snapshots/SEAs), all on 22/24/26. Low issues: CVE-2026-106070 (ZIP prefix bytes) and CVE-2026-106071 (Permission Model wildcard over-grant) on 26.x, plus CVE-2026-106073 (`fs.realpathSync` Permission Model bypass) on 22/24/26. See [../case.md](../case.md).
- Review existing evidence only for assets you own or are authorized to assess. Do not send probes, create malicious compressed inputs, disable TLS verification, or run unknown binaries. The checker reads local CSV; it does not connect to the network or run Node.

## 1. Collect Running Versions and Input Paths

For each service, record entry points, asset ID, process/container, actual Node executable and version, image or vendor package provenance, internet exposure, and owner. Review names passed to `dns.resolve`, HTTPS/TLS targets, and untrusted Brotli decoding. Include proxies, webhooks, uploads, queues, and embedded Node runtimes. Establish reachability from the actual data flow rather than merely finding an API name in source code.

```bash
# Linux: existing service/process information; confirm the PID with the service owner
ps -eo pid,ppid,user,args | grep '[n]ode'
readlink -f /proc/<PID>/exe
# Record container versions and image digests; verify every replica has rolled out
kubectl get pods -n <NAMESPACE> -o wide
```

```powershell
# Windows: process and executable paths
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'node.exe' } | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine
```

Production command lines may contain secrets. Restrict their collection and sharing; do not paste raw command lines into shared inventories. A shell's `node -v` may refer to another installation, not the service runtime. Retain the node, collection time, and package or image evidence when an administrator checks a confirmed executable.

## 2. Offline Inventory

Prepare UTF-8 CSV using [references/inventory-schema.md](references/inventory-schema.md). Exclude tokens, full URLs, and sensitive request bodies:

```bash
python3 scripts/check_node.py inventory /path/to/node-assets.csv
```

The checker compares upstream version numbers against the **separate 22.x, 24.x, and 26.x thresholds** and lists applicable High-severity CVEs. `below_fixed_upstream_version` means an upstream release number is below its threshold; a vendor backport requires separate evidence. `at_or_above_fixed_verify_running_build` still requires verification of the running build and every node. `unknown_or_other_line` makes no safety determination. Exit code 0 means CSV processing completed; 2 means input or evidence is incomplete. Neither proves an instance is safe.

The checker enumerates only High-severity CVEs. Review the six Medium/Low issues against their affected lines and actual feature use; absence from checker output is not evidence of non-exposure.

## 3. Review Configuration, Logs, and Priority

- **Brotli:** Identify decoders of externally controlled compressed input in `zlib`, proxies, or dependencies. Correlate existing decoding errors, crashes, worker restarts, unexpected subprocesses, and outbound connections. Do not test production services with crafted compressed samples.
- **TLS:** Review controllable URLs and hostnames, certificate checks, proxies, and certificate alerts. Unusual IP representations matter, but missing targets or successful checks in logs make a negative finding inconclusive.
- **DNS:** Review call paths that accept NUL characters and consider differences hidden by log normalization. Have developers confirm validation/lookup discrepancies through the real data flow.
- **Medium/Low:** Review keep-alive response pairing, noncanonical IPv4 targets, random values in startup snapshots/SEAs, untrusted ZIP handling, and Permission Model use including `fs.realpathSync`. Apply each issue's affected-line scope.
- **Priority:** Address exposed services with untrusted Brotli input or dynamic DNS/TLS targets first. Internal services, queues, and vendor packages still require review. Record separately where Node is installed but not used by the service.

## 4. Update and Report

Upgrade by line to **22.23.4 / 24.22.1 / 26.12.1**, or later supported fixed versions. Verify package provenance, rollout, running processes on all nodes, and rollback plans. Retain advisories and package revisions for vendor backports, and plan migration from EOL lines. Report upstream version classification, running-build evidence, backports, input paths, log coverage, and unresolved items separately. A single DNS anomaly, TLS failure, or decoder error does not prove exploitation; follow the organization's incident process for credible compromise.

See [references/validation.md](references/validation.md) for checker behavior and limitations, and [../case.md](../case.md) for the English analysis and official sources.
