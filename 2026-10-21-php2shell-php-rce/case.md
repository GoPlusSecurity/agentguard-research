---
id: GSI-2026-PHP-109618-109619
language: en
title: PHP unauthenticated remote code execution (CVE-2026-109618 / CVE-2026-109619)
date: 2026-10-21
updated: 2026-10-22
as_of: "2026-10-21 PHP release announcement and two php-src security advisories"
status: confirmed
confidence: "High: PHP release announcement and two php-src advisories; the official sources do not confirm exploitation in the wild"
severity: critical
cvss: "Both score 9.2 under CVSS v4.0; CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
cve: [CVE-2026-109618, CVE-2026-109619]
affected_versions: "Maintained upstream branches: 8.2.x before 8.2.35, 8.3.x before 8.3.36, 8.4.x before 8.4.27, and 8.5.x before 8.5.12; evaluate older and vendor builds separately"
fixed_versions: "Upstream releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12; minimal source-backport branches for 7.4/8.0/8.1 are not official release packages"
in_the_wild: "The PHP release announcement and php-src advisories do not confirm exploitation in the wild"
check_skill: ./skill/SKILL.md
references:
  - https://www.php.net/archive/2026.php#2026-10-21-5
  - https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
  - https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
  - https://www.php.net/ChangeLog-8.php#8.5.12
  - https://www.php.net/downloads.php?source=Y
---

# Two PHP Unauthenticated Remote Code Execution Vulnerabilities: Analysis and Security Self-Check

> The [PHP security release announcement](https://www.php.net/archive/2026.php#2026-10-21-5) confirms that CVE-2026-109618 and CVE-2026-109619 can both lead to unauthenticated remote code execution. The fixed releases are 8.2.35, 8.3.36, 8.4.27, and 8.5.12. Their mechanisms and the degree of validation across PHP deployment models differ; consult the PHP announcement and the respective php-src advisories for those distinctions.

## Timeline and Affected Versions

PHP previewed two critical issues rated 9.2 under CVSS v4.0 on October 20. On October 21, it published security releases for four branches and advisories for [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). Both advisories use `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`. The score does not imply reliable exploitation of every site with a single request.

| Maintained upstream branch | Releases requiring a fix | First fixed release | Note |
|---|---|---|---|
| 8.2.x | < 8.2.35 | **8.2.35** | PHP lists 2026-12-31 as the end of support for 8.2 |
| 8.3.x | < 8.3.36 | **8.3.36** | Verify the version used by running workers |
| 8.4.x | < 8.4.27 | **8.4.27** | Verify the version used by running workers |
| 8.5.x | < 8.5.12 | **8.5.12** | Verify the version used by running workers |

These thresholds apply to **upstream PHP releases** and must be compared within each branch. A prerelease, custom build, distribution backport, embedded vendor build, or 8.6 development build requires separate verification of its patch provenance and running binary. PHP 8.1 and earlier no longer receive ordinary upstream security releases. PHP also published minimal **source-backport branches** for [7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619), and [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619); these are not installable official release packages for those versions. Consult the vendor for older branches and plan migration to a supported release rather than assuming a precise exposure boundary that upstream has not established.

PHP calls attention to deployments serving web requests, including PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, and LiteSpeed. **The clearest demonstrated risk is in mod_php:** the official advisories describe HTTP-validated unauthenticated code execution under common prefork multi-worker configurations and default PHP input or memory limits. CVE-2026-109618 can occur before application code runs. Other deployment models also require remediation, but the demonstrated behavior should not be generalized to every SAPI configuration.

## Mechanisms and Exploitability Boundaries

| Issue | Mechanism described by the upstream advisories | What has and has not been demonstrated |
|---|---|---|
| **CVE-2026-109618: state corruption during OOM handling** | An out-of-memory path can exit while request data is incompletely initialized, leaving later cleanup to handle invalid state. The fix changes the OOM exit behavior. | Unauthenticated RCE was demonstrated in mod_php with web-worker privileges. Source analysis supports risk in FPM, but the advisory does not report a complete FPM exploit. FrankenPHP is considered likely affected; the application-specific LSAPI path has not been validated. |
| **CVE-2026-109619: stale global state across requests** | State owned by one request remains referenced after it has been freed. A later request may read it before normal initialization resets the worker, creating a use-after-free condition. The fix improves cross-request cleanup. | The advisories validate mod_php and FPM session-lifecycle paths. An RCE path involving fatal-error backtraces on PHP 8.5 was demonstrated in mod_php. Relevant requests must reach both the stale-state creation and consumption paths on a worker; exploitation is not established for every configuration. |

Code execution would occur with **web-worker privileges**. Access to source code, database credentials, cloud keys, or adjacent systems depends on the environment and its isolation; root privileges are not an inherent outcome. The [8.5.12 changelog](https://www.php.net/ChangeLog-8.php#8.5.12) lists both advisories under Core; other security fixes in that release should not be conflated with these CVEs.

## Security Self-Check and Remediation

1. **Establish the running version.** Record each entry point, service, node/container, PHP SAPI, actual worker path and version, package/image provenance, configuration overrides, and internet exposure. A separate CLI `php -v`, Composer dependency, or HTTP banner does not establish the version used by web workers. Compare each maintained branch against its own threshold; retain vendor advisories and package revisions for distribution backports.
2. **Prioritize upgrades.** Address internet-facing mod_php first, followed by other exposed PHP services and internal services reachable through untrusted requests. Deploy the appropriate fixed release or a verified vendor backport. Perform compatibility checks, backups, rollback planning, restarts of every worker, and version checks on every node. Migrate PHP 8.1 and older to a supported branch; have maintainers review any temporary source backport and build provenance.
3. **Reduce exposure if upgrading is delayed.** Restrict access and review input/upload sizes and request-rate limits. Upstream notes that `memory_limit=-1` reduces only part of the controllable PHP-limit path for CVE-2026-109618; it may increase resource-exhaustion risk, and underlying allocation failures remain possible. Disabling `session.upload_progress.enabled` on all branches and `fatal_error_backtraces` on PHP 8.5 reduces demonstrated paths for CVE-2026-109619 only when configured early enough and followed by worker restarts. **These settings are not a fix; upstream identifies installing the patch as the complete remediation.**
4. **Investigate existing evidence.** Correlate proxy and HTTP requests, PHP/FPM/Apache errors, fatal errors, OOM events, worker restarts, upload-progress settings, unexpected web-worker child processes, network connections, and file changes. Check diagnostics before request initialization and application-reachable fatal errors. A single error, OOM event, or absence of child processes cannot establish whether exploitation occurred. The PHP advisories do not provide a universal request signature or IOC for these issues.
5. **Respond to credible compromise.** Preserve evidence and isolate affected systems before assessing persistence, application code, and exposed credentials under the incident-response process. Upgrading prevents future exploitation of the patched issue but does not remove an existing intrusion.

See [skill/SKILL.md](skill/SKILL.md) for an offline inventory and evidence-review workflow. Its tools do not contact remote targets or execute PHP.
