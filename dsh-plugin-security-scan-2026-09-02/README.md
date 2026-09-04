# DeepSeek Harness Plugin Ecosystem Security Scan

**Dataset snapshot:** September 2, 2026  
**Scanner:** AgentGuard v1.1.29  
**Ecosystem:** DeepSeek Harness  
**Research team:** AgentGuard Team

## Overview

AgentGuard conducted a sample-based security study of the DeepSeek Harness plugin ecosystem using a September 2, 2026 marketplace snapshot.

The dataset contained:

- **2,916 total plugins**
- **3,885,362 downloads over the previous 30 days**
- **659 sampled plugins**
- **90.0% of 30-day marketplace downloads covered**
- **590 successfully scanned plugins**
- **15 plugins with incomplete scan coverage**
- **54 plugins that could not be scanned**

This was a sample-based ecosystem study, not a complete audit of all 2,916 marketplace plugins.

## Key Findings

### 94.7% of Successful Scans Were High or Critical

Among the **590 successfully scanned plugins**:

| Risk Level | Plugins | Share |
|---|---:|---:|
| Critical | 192 | 32.5% |
| High | 367 | 62.2% |
| Medium | 20 | 3.4% |
| Low | 11 | 1.9% |

High and Critical results accounted for **94.7% of successful scans**.

Risk level reflects capability surface, permission exposure, and potential impact.

It does **not** determine whether a plugin, developer, or maintainer is malicious.

### High-Privilege Capabilities Are Common

Across **605 plugins with successful or partial scan data**, observed capabilities included:

| Capability | Share |
|---|---:|
| File read | 91% |
| Environment-variable access | 81% |
| Network access | 74% |
| Shell execution | 63% |

These capabilities may be legitimate requirements of plugin functionality.

They do, however, expand the possible impact if the plugin itself, its maintainer account, or its distribution path is compromised.

### Long-Tail Exposure

A random long-tail sample included **60 plugins**.

Of those:

- **56 were scanned successfully**
- **50 of 56** were rated High or Critical

This does not mean low-download plugins are inherently more dangerous.

It means low popularity should not be treated as evidence of low security risk.

### AUTO_UPDATE Patterns

AgentGuard identified **32 plugins** containing code patterns that retrieve remote content and automatically install or execute it.

An `AUTO_UPDATE` pattern is not, by itself, evidence of:

- malicious intent;
- compromise;
- credential theft;
- or a confirmed vulnerability.

The supply-chain concern is the additional trust path created when remote content can be retrieved and executed after installation.

## Scan Status

| Status | Count |
|---|---:|
| Successfully scanned | 590 |
| Incomplete coverage | 15 |
| Could not be scanned | 54 |
| **Total sampled** | **659** |

Incomplete scans were handled on a fail-closed basis.

Targets with incomplete coverage were not included in any conclusion that classified them as safe.

## Unsuccessful Targets

Among the **54 targets that could not be scanned**:

- **39** referenced repository subdirectories that no longer existed in the current repository version.
- **15** repositories were unreachable or continued to fail after repeated attempts.

These results should be interpreted as stale or unavailable listings.

They are not evidence of fraud or malicious behavior.

## Dataset

The complete scan dataset is published as:

[`appendix-a-plugins-20260902.csv`](./appendix-a-plugins-20260902.csv)

It contains results for all **659 sampled targets**.

The dataset should be interpreted together with the methodology and limitations documented on this page.

## Verification

Successful and incomplete scan results are tied to the corresponding repository version, commit SHA, artifact SHA-256 hash, dataset snapshot, scanner version, and AgentGuard scan rules where available.

The published dataset is accompanied by:

[`SHA256SUMS.txt`](./SHA256SUMS.txt)

Use the checksum to verify that the published CSV artifact has not changed.

## Methodology and Limitations

The findings reflect:

- the **September 2, 2026** dataset snapshot;
- repository versions available during scanning;
- and the rules in **AgentGuard v1.1.29**.

This research:

- covers **659 sampled targets**, not all 2,916 marketplace listings;
- represents **90.0% of marketplace downloads over the previous 30 days**;
- measures capability surface, permission exposure, and potential impact;
- does not determine whether a plugin or developer is malicious;
- does not indicate that a security incident has occurred;
- and does not guarantee that any plugin is safe.

Results should be treated as a **review-priority map**, not a malicious-plugin list.

Results apply only to the referenced dataset, repository version, commit SHA, artifact SHA-256 hash, and scan rules.

## Scan a DeepSeek Harness Plugin

```bash
agentguard dsh-scan https://github.com/<owner>/<repo>
