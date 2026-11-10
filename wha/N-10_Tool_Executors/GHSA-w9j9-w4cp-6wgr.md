# GHSA-w9j9-w4cp-6wgr: OpenClaw Host-Exec Environment Variable Injection

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: OpenClaw Host-Exec Environment Variable Injection
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-w9j9-w4cp-6wgr`; no confirmed CVE assignment; **source disagreement**: CVE CNA data references this GHSA URL with a non-advisory label `CVE-2026-22177` as `Patch Commit`; the malformed reference is disclosed but is not used as a CVE mapping
- **3. CWE Classification**: `CWE-78` (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: OpenClaw Host-Exec Environment Variable Injection
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **5.9 Medium** (`CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: OpenClaw Host-Exec Environment Variable Injection. Host exec could inherit environment variables that influence interpreters, shells, or build tools. OpenClaw is a user-controlled local assistant. This advisory is scoped to the OpenClaw trust model and does not assume a multi-tenant service boundary.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Not publicly extractable from a specific fix patch. The advisory may describe the affected flow, but no qualifying removed-code excerpt was available.
- **15. Fix Patch (Commit)**: No specific vulnerability-fixing commit is publicly identified by the advisory. Verified fixed tree reference(s): [`d7c3210cd6f5fdfdc1beff4c9541673e814354d5`](https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5). These references confirm a fixed repository state and are not reported here as patch commits.
- **16. Fix Summary**: The issue was fixed on `main` and is available in the patched npm version listed above. The verified fixed tree is commit `d7c3210cd6f5fdfdc1beff4c9541673e814354d5`.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `2026.4.8`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.3.28`
- **19. Fixed Versions**: `openclaw` (npm): `2026.4.8`
- **20. Disclosure and Fix Dates**: Published: `2026-04-08T05:33:48Z`; last advisory update: `2026-04-08T05:33:48Z`; public npm release time(s): `openclaw@2026.4.8` published 2026-04-08T05:18:48.421Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-w9j9-w4cp-6wgr)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-w9j9-w4cp-6wgr)
  - [Commit `d7c3210cd6f5fdfdc1beff4c9541673e814354d5`](https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5)
  - [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
