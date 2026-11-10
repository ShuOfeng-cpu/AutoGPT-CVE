# GHSA-575v-8hfq-m3mc: Sandbox bind mounts could bypass parent-directory denylist checks

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Sandbox bind mounts could bypass parent-directory denylist checks
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-575v-8hfq-m3mc`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-22` (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) [source: GitHub Repository Advisory]; `CWE-59` (Improper Link Resolution Before File Access ('Link Following')) [source: GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: In affected versions, a lower-trust caller or configured input path could perform actions that should have required a stronger authorization or policy check. It does not change OpenClaw's trusted-operator model: authenticated Gateway operators, installed plugins, and intentional local execution surfaces remain trusted unless a separate policy, approval, allowlist, sandbox, or auth boundary is crossed.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Sandbox bind mounts could bypass parent-directory denylist checks. In affected versions, a lower-trust caller or configured input path could perform actions that should have required a stronger authorization or policy check. This advisory is scoped to the named feature and configuration. It does not change OpenClaw's trusted-operator model: authenticated Gateway operators, installed plugins, and intentional local execution surfaces remain trusted unless a separate policy, approval, allowlist, sandbox, or auth boundary is crossed.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: In affected versions, a lower-trust caller or configured input path could perform actions that should have required a stronger authorization or policy check. When the affected feature is enabled and reachable, this could perform actions that should have required a stronger authorization or policy check.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Repository Advisory CVSS v3.x: **8.4 High** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Repository Advisory CVSS v3.x.
- **12. Direct Impact**: When the affected feature is enabled and reachable, this could perform actions that should have required a stronger authorization or policy check. Practical impact depends on the operator's configuration and whether lower-trust input can reach that path.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Not publicly extractable from a specific fix patch. The advisory may describe the affected flow, but no qualifying removed-code excerpt was available.
- **15. Fix Patch (Commit)**: No specific vulnerability-fixing commit is publicly identified by the advisory.
- **16. Fix Summary**: Upgrade to a patched OpenClaw release when one is listed. Before upgrading, restrict the affected feature to trusted operators or disable it when it is not needed. As general hardening, keep channel and tool allowlists narrow, avoid sharing one Gateway between mutually untrusted users, and disable the affected feature when it is not needed.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `2026.6.6`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `< 2026.6.6`
- **19. Fixed Versions**: `openclaw` (npm): `2026.6.6`
- **20. Disclosure and Fix Dates**: Published: `2026-06-30T00:38:59Z`; last advisory update: `2026-06-30T00:38:59Z`; public npm release time(s): `openclaw@2026.6.6` published 2026-06-12T11:03:39.456Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-575v-8hfq-m3mc)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
  - [CWE-59](https://cwe.mitre.org/data/definitions/59.html)
