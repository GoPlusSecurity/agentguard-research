---
id: GSI-2026-GO-111943
language: en
title: Go crypto/x509 intermediate CA distrust (CVE-2026-111943) — analysis and self-check
date: 2026-10-22
updated: 2026-10-22
as_of: 2026-10-22
status: confirmed
confidence: "High: Go issue, release history, and fix commits; the official materials do not confirm a CA private-key compromise"
severity: "Go labels the issue URGENT; the cited materials do not establish a CVSS score"
cve: [CVE-2026-111943]
affected_versions: "Prioritize Go 1.26.x before 1.26.10 and 1.27.x before 1.27.3 when their binaries perform relevant certificate-chain verification; assess older or custom builds individually"
fixed_versions: "Go 1.26.10 and 1.27.3; verify that later or vendor-specific builds include the fix"
check_skill: ./skill/SKILL.md
references:
  - https://go.dev/issue/82345
  - https://go.dev/doc/devel/release
  - https://github.com/golang/go/commit/90617fb7ceb59cf08bee7826bb51b8c8fb8c11de
  - https://github.com/golang/go/commit/aa64342a9e13affffea3e989d67e574475af5a78
---

# Go Intermediate CA Distrust: Vulnerability Analysis and Security Self-Check

> [Go issue #82345](https://go.dev/issue/82345) identifies this as **CVE-2026-111943** and calls for an urgent upgrade. Go 1.27.3 and 1.26.10 filter verification chains containing specified intermediate certificates in `crypto/x509` because of security concerns regarding the relevant CA's operations. **Existing deployed Go binaries must be rebuilt and redeployed with a fixed toolchain.**

## Confirmed Facts and Boundaries

| Item | Confirmed information | Boundary |
|---|---|---|
| Issue | Go no longer trusts certain intermediate certificates; chains returned by `Certificate.Verify` are filtered accordingly | The Go issue describes security concerns but does not confirm private-key compromise, malicious certificate issuance, or attacks in the wild |
| Identifier and priority | CVE-2026-111943 is on Go's URGENT track, with an explicit recommendation to upgrade promptly | URGENT is a project priority, not a CVSS score or proof that every application can be exploited remotely |
| Fix | [Go's release history](https://go.dev/doc/devel/release) lists **go1.27.3 and go1.26.10, released on 2026-10-19**, with a `crypto/x509` security fix | The release notes do not provide corresponding releases for Go 1.25 and earlier; evaluate custom builds and vendor backports separately |
| Mechanism | The [Go 1.27 fix](https://github.com/golang/go/commit/90617fb7ceb59cf08bee7826bb51b8c8fb8c11de) recognizes intermediate certificates by **SHA-256 SPKI hashes**; the patch contains **eight hash entries** and changes generic as well as Darwin and Windows verification paths | Eight hashes do not establish eight compromised keys or eight revoked roots. This Go verification change does not by itself update the operating system trust store |

## Impact

Exposure arises where a Go program uses `crypto/x509` chain verification and may encounter these intermediate certificates: verifying a remote peer on an outbound TLS connection, validating mTLS client certificates, verifying signatures, or otherwise calling `Certificate.Verify`. Whether an affected chain is encountered depends on trust anchors, chain building, application trust policy, and the peer. **An older build number alone does not prove that the program accepted a malicious certificate.**

A chain previously accepted only through one of the filtered intermediates will be rejected by the fixed verifier. Another valid chain that avoids the filtered intermediates may still succeed. Legitimate connections relying on the affected CA may fail after the update; inventory those dependencies before rollout. Do not restore connectivity by disabling TLS verification, setting `InsecureSkipVerify`, or adding the affected certificates to custom trust roots.

The change is in the Go standard library. Updating `go.mod` dependencies or only the system CA package does not necessarily fix an **existing binary built with an older Go toolchain**. A host can run multiple Go applications built with different toolchains, and a container base-image version does not establish the version embedded in an application binary. Review dynamic linking, vendor packages, and nonstandard verification code separately.

## Self-Check and Remediation

1. **Inventory deployed builds.** Record the service, owner, node/container, path and hash of the running binary, image digest, Go build version, and build time. Include vendor software, helper processes, and statically deployed executables. Use a trusted Go installation to run `go version -m /path/to/binary`; it reads build information without executing the target. Mark unreadable files as unresolved. The `go` directive in `go.mod` is not proof of the compiler used for a deployed binary.
2. **Determine verification use.** Check outbound HTTPS/TLS, mTLS client-certificate verification, signature validation, internal PKI, certificate management, and supplier integrations. Review business certificate chains and verification-failure alerts for dependence on the filtered intermediates. Do not probe endpoints outside your authorization.
3. **Upgrade, rebuild, and redeploy.** Build with Go **1.26.10 / 1.27.3** or a later supported version containing the fix. Deploy the new binary or image, restart workloads, and verify the actual file used by every replica. Obtain patch statements, package versions, and build evidence for vendor products. Plan certificate-compatibility checks and rollback without restoring an uncontrolled old trust policy.
4. **Review historical evidence.** Correlate existing TLS handshakes, certificate errors, CA changes, proxy logs, and client connections with suspicious chains. Missing chain details or an absence of errors does not establish that historical connections were unaffected. Escalate credible evidence through the organization's certificate and key incident process.

The offline inventory checker and evidence format are documented in [skill/SKILL.md](skill/SKILL.md). It compares **Go build-version fields** in a local inventory; it does not connect to TLS services or inspect business certificates.
