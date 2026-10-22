---
name: check-php2shell-exposure
description: Review authorized PHP services for CVE-2026-109618 and CVE-2026-109619 using runtime version, exposure, and existing process evidence. Check the 8.2.35/8.3.36/8.4.27/8.5.12 thresholds and vendor backports with read-only offline workflows; do not run vulnerability probes.
---

# PHP Critical Vulnerabilities: Version, Exposure, and Evidence Self-Check

## Baseline and Boundaries

- Use the October 21, 2026 [PHP release announcement](https://www.php.net/archive/2026.php#2026-10-21-5) and upstream advisories for [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). Both can cause unauthenticated RCE and have a CVSS v4.0 score of 9.2.
- Upstream fixed thresholds are **8.2.x ≥8.2.35, 8.3.x ≥8.3.36, 8.4.x ≥8.4.27, and 8.5.x ≥8.5.12**. Older upstream releases in those lines require a fix. PHP 8.1 and earlier receive no ordinary upstream security release; minimal **source-backport branches** exist for 7.4/8.0/8.1 but are not fixed release packages. Check distribution backports, custom builds, prereleases, and 8.6 development builds separately. **A version string alone does not prove a deployed instance is fixed.**
- Unauthenticated RCE is confirmed for mod_php. The FPM session-lifecycle path for CVE-2026-109619 is also validated. Source analysis supports CVE-2026-109618 risk in FPM, but the advisory does not report a complete FPM exploit. Review all PHP installations serving web requests. See [../case.md](../case.md) for distinctions.
- Collect existing evidence only on owned or authorized assets. Do not submit test requests or run PoCs. The offline script **does not execute PHP or asset binaries**.

## 1. Inventory Services and Runtimes

For each service record the asset ID, owner, entry point and reachability, node and deployment model, actual runtime path/version, evidence timestamp, package or image source, log retention, and update owner. Confirm exposure from gateway/load-balancer and deployment records. Include FPM, CGI, Apache modules, Windows services, scheduled jobs, containers, and embedded vendor runtimes. Adapt these read-only examples to the environment and permissions:

```bash
# Linux: process and executable paths; /proc reflects a point-in-time view
ps -eo pid,ppid,user,args | grep -E '[p]hp-fpm|[p]hp-cgi|[a]pache2|[h]ttpd'
readlink -f /proc/<PID>/exe
# Package source: use the applicable distribution command and retain backport evidence
dpkg-query -W 'php*' 2>/dev/null
rpm -qa 'php*' 2>/dev/null
# Container orchestration: confirm the namespace and workload from the service inventory
kubectl get pods -n <NAMESPACE> -o wide
```

```powershell
# Windows: read process and service paths with appropriate privileges
Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(php|php-cgi|httpd)\.exe$' } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'php|httpd' } | Select-Object Name,PathName,State
```

In a trusted administrative environment, inspect version or package metadata for the PHP executable **confirmed to belong to the service**; record location and time. A shell's `php -v` may refer to another installation. Image tags, HTTP headers, and Composer dependencies do not establish the worker version. If no binary can be run safely, retain package/image evidence and the vendor advisory, and mark the version unresolved.

## 2. Check the Offline Inventory

Export existing CMDB or manual inventory to UTF-8 CSV using [references/inventory-schema.md](references/inventory-schema.md). Exclude secrets, personal data, and full request content. Leave unavailable fields empty so the checker can report evidence gaps.

```bash
python3 scripts/check_php.py inventory /path/to/inventory.csv
```

The script emits JSON. Plain upstream versions such as `8.5.12` on maintained lines are marked `affected_upstream_release` or `at_or_above_fixed_release_verify_build`; the latter still requires proof of the running build. PHP 8.1 and earlier return `unsupported_review_vendor_backport`; custom, prerelease, or other unknown versions return `unknown_version_or_build`. `priority` helps order review; `internet_exposed=yes` takes precedence and `unknown` requires more evidence. Exit code 0 means processing succeeded, while 2 signals input or evidence gaps. **Neither means the asset is safe.**

## 3. Correlate Existing Process Events

Export normalized process-creation CSV from internal EDR or system audit logs, using the same schema reference. Select **generic investigative leads** where PHP/FPM/CGI/web processes start shells, interpreters, or download tools:

```bash
python3 scripts/check_php.py processes /path/to/process-events.csv
```

Output contains only asset, time, parent/child executable names, and rule tags; it does not echo command lines or request content. Maintenance, plugins, and queue jobs may match, while missing parent names or event gaps can hide relevant behavior. Correlate with internal logs and change records before reviewing detailed process trees, network activity, and file changes. **These rules are not issue-specific IOCs.**

Review reverse-proxy and web/PHP errors, restarts, OOM events, diagnostics before request initialization, and reachable fatal errors alongside process telemetry and unexpected files or tasks. Record each log's source and time range. An HTTP 500, FPM restart, no matching event, or no WAF alert does not establish whether exploitation occurred. Follow the organization's evidence-preservation process for incident investigation.

## 4. Report and Remediate

Report inventory, runtime/build evidence, exposure and privileges, log coverage, correlated leads, and evidence gaps for each service. Prioritize internet-facing mod_php; other exposed PHP services also require a fix. Upgrade within the branch or install a confirmed vendor backport, then verify every node and worker. Migrate PHP 8.1 and older to a supported line. Have maintainers review the official minimal source-backport branches; do not treat them as ready-to-install releases.

If an immediate upgrade is impossible, assess access restrictions, VPN, and network isolation against business impact. Upstream's `memory_limit=-1` reduces only some CVE-2026-109618 paths and may increase resource-exhaustion risk. `session.upload_progress.enabled=0` and, on PHP 8.5, `fatal_error_backtraces=0` reduce validated CVE-2026-109619 paths only if applied before request parsing and followed by worker restarts. **These are not complete mitigations; install fixed releases or patches.** A WAF or absence of alerts is not proof of safety.

See [references/validation.md](references/validation.md) for offline checker validation and limitations.
