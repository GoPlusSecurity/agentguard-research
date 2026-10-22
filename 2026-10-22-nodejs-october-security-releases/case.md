---
id: GSI-2026-NODE-OCT
language: en
title: Node.js October 2026 security releases — four high and six medium/low issues, analysis and self-check
date: 2026-10-22
updated: 2026-10-22
as_of: 2026-10-22
status: confirmed
confidence: "High: Node.js advisory and three branch release notes; the advisory does not confirm exploitation in the wild or exploitability for every service"
severity: high
cve: [CVE-2026-105481, CVE-2026-105482, CVE-2026-105483, CVE-2026-106069, CVE-2026-106070, CVE-2026-106071, CVE-2026-106072, CVE-2026-106073, CVE-2026-106074, CVE-2026-111497]
affected_versions: "Pre-fix releases in the affected 22.x, 24.x, and 26.x lines as listed for each CVE; CVE-2026-105483 does not affect 22.x"
fixed_versions: "22.23.4, 24.22.1, and 26.12.1 by branch; assess vendor backports separately"
check_skill: ./skill/SKILL.md
references:
  - https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
  - https://nodejs.org/en/blog/release/v22.23.4/
  - https://nodejs.org/en/blog/release/v24.22.1/
  - https://nodejs.org/en/blog/release/v26.12.1/
---

# Node.js October 2026 Security Releases: Vulnerability Analysis and Self-Check

> On October 21, 2026, Node.js released versions 22.23.4, 24.22.1, and 26.12.1. The **highest severity is High; none of the listed issues is Critical**. One of four High-severity issues is an out-of-bounds write in the Brotli decoder with potential remote code execution. Whether a service exposes a relevant input path depends on how it handles untrusted compressed data.

## Affected and Fixed Versions

| Release line | Fixed version | High-severity issues |
|---|---:|---|
| 22.x | **22.23.4** | CVE-2026-105482, CVE-2026-106069, CVE-2026-111497 |
| 24.x | **24.22.1** | The three above, plus CVE-2026-105483 |
| 26.x | **26.12.1** | All four |

Earlier upstream releases within each affected line require an update. Verify the **actual running process and image/package provenance**. Node.js does not list 22.x as affected by CVE-2026-105483. End-of-life lines, custom or embedded builds, distribution backports, prereleases, and other lines require vendor-specific evidence; the advisory's general warning about EOL versions does not establish which exact CVE affects every older line. The Node.js runtime version is distinct from npm package versions in `package.json` or lockfiles.

## Four High-Severity Issues

| CVE | Description and risk | Lines | Defensive review |
|---|---|---|---|
| [CVE-2026-105482](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases#dnsresolve-truncates-names-containing-nul-char-cve-2026-105482---high) | `dns.resolve` truncates a name containing a NUL character. Where an application accepts an untrusted name, its validation and the actual DNS lookup may disagree. Further outcomes depend on application data flow. | 22/24/26 | Review callers and wrappers of `dns.resolve`, input provenance, name validation, and how the DNS result is used. Review existing logs rather than probing services. |
| [CVE-2026-105483](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases#tls-certificate-hostname-bypass-when-the-ip-is-written-fullwidth-digits-cve-2026-105483---high) | TLS certificate hostname verification may be bypassed when an IP address uses **fullwidth digits**. This concerns outbound client certificate checks, not authentication of every incoming server request. | 24/26 | Inventory HTTPS/TLS targets controlled by users or upstream data; review unusual IP text and certificate-verification settings. |
| [CVE-2026-106069](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases#tls-certificate-hostname-bypass-when-the-host-loosely-resolves-to-an-ip-address-cve-2026-106069---high) | Host text loosely interpreted as an IP address may bypass TLS certificate hostname checks. Exposure depends on target input and connection control; the fix rejects noncanonical IP addresses. | 22/24/26 | Review proxy, webhook, callback, and dynamic API targets alongside host normalization and TLS verification. |
| [CVE-2026-111497](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases#nodejs-brotli-decoder-out-of-bounds-write-permits-remote-code-execution-cve-2026-111497---high) | The Node.js Brotli decoder has an **out-of-bounds write** that may permit RCE. The advisory does not establish an exploitable path for every server; the application must decode attacker-controlled Brotli data. | 22/24/26 | Identify untrusted compressed data passed to `zlib` Brotli decoders, proxies, upload handlers, or dependencies; prioritize externally reachable input paths. |

All four are rated **High**. The [Node.js advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) does not provide a general request-level IOC, a confirmed exploitation rate, or an affirmative claim of exploitation in the wild. The DNS NUL, unusual IP, and Brotli descriptions are input clues, not proof of compromise in access logs. Confirm the relevant APIs and untrusted data flows; input filtering does not replace a runtime update.

## Other Issues in the Same Release

| Severity | CVE | Short description | Lines |
|---|---|---|---|
| Medium | CVE-2026-105481 | A keep-alive socket may process a response written before the request was sent | 22/24/26 |
| Medium | CVE-2026-106072 | Noncanonical IPv4 hostname verification may allow a DNS SAN to authenticate an IP endpoint | 22/24/26 |
| Medium | CVE-2026-106074 | `crypto.randomUUID()` and `randomInt()` entropy caches included in user-land startup snapshots or single executable applications (SEAs) can repeat values across processes | 22/24/26 |
| Low | CVE-2026-106070 | `ZipFile` can return attacker-controlled prefix bytes after failed ZIP-header validation | 26 |
| Low | CVE-2026-106071 | A wildcard radix lookup in the Permission Model can grant excessive filesystem access | 26 |
| Low | CVE-2026-106073 | `fs.realpathSync` can bypass the Permission Model | 22/24/26 |

The titles, severities, and affected lines above follow the [official advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases). Review keep-alive clients, noncanonical IPv4 targets, startup snapshots/SEAs, untrusted ZIP handling, and reliance on the Permission Model as relevant to the application. The security releases also update c-ares, CA certificates, and Undici, plus OpenSSL or SQLite in some lines. Install the **complete fixed Node.js release** rather than treating an npm dependency update as a runtime fix.

## Security Self-Check and Remediation

1. **Inventory running runtimes.** Record the executable, version, path, image/package provenance, startup settings, service, and owner for each process, container, embedded runtime, and vendor product. A shell's `node -v` may refer to a different installation. An updated base image alone does not prove that every workload replica has switched.
2. **Upgrade by release line.** Move 22.x to 22.23.4, 24.x to 24.22.1, and 26.x to 26.12.1, or to later supported fixed versions. Migrate EOL lines and verify vendor backports against vendor advisories and package revisions. Retain image digests and before/after evidence from running processes on all nodes.
3. **Review application data flows.** Prioritize DNS names, TLS targets, and Brotli decoder inputs controlled by requests, webhooks, uploads, queues, or external services. Absence of a reachable input path reduces direct exposure to a particular issue but does not mean an older runtime is fixed.
4. **Review historical evidence.** Correlate existing DNS queries, outbound TLS certificate alerts, Brotli decoding errors, crashes and restarts, unexpected subprocesses, and network connections. These are investigative leads; missing logs or a lack of matches cannot exclude exploitation.
5. **Reduce exposure while updating.** Restrict untrusted compressed input and controllable outbound targets where the application permits, and monitor sensitive destinations. If multiple independent signals indicate compromise, preserve evidence and follow the organization's isolation and credential-review process.

See [skill/SKILL.md](skill/SKILL.md) for the offline inventory checker and self-check procedure.
