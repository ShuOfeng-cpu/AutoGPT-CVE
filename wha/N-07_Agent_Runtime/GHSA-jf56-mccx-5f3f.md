# GHSA-jf56-mccx-5f3f: Authenticated `/hooks/wake` and mapped `wake` payloads are promoted into the trusted `System:` prompt channel

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Authenticated `/hooks/wake` and mapped `wake` payloads are promoted into the trusted `System:` prompt channel
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-jf56-mccx-5f3f`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-501` (Trust Boundary Violation) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: Authenticated `/hooks/wake` and mapped `wake` payloads are promoted into the trusted `System:` prompt channel. An authenticated wake hook or mapped wake payload could be promoted into the trusted System prompt channel instead of an untrusted event.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Authenticated `/hooks/wake` and mapped `wake` payloads are promoted into the trusted `System:` prompt channel
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **8.5 High** (`CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: Authenticated `/hooks/wake` and mapped `wake` payloads are promoted into the trusted `System:` prompt channel. An authenticated wake hook or mapped wake payload could be promoted into the trusted System prompt channel instead of an untrusted event. OpenClaw is a user-controlled local assistant. This advisory is scoped to the OpenClaw trust model and does not assume a multi-tenant service boundary.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Not publicly extractable from a specific fix patch. The advisory may describe the affected flow, but no qualifying removed-code excerpt was available.
- **15. Fix Patch (Commit)**: No specific vulnerability-fixing commit is publicly identified by the advisory. Verified fixed tree reference(s): [`d7c3210cd6f5fdfdc1beff4c9541673e814354d5`](https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5). These references confirm a fixed repository state and are not reported here as patch commits.
- **16. Fix Summary**: The issue was fixed on `main` and is available in the patched npm version listed above. The verified fixed tree is commit `d7c3210cd6f5fdfdc1beff4c9541673e814354d5`.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `2026.4.8`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.4.2`
- **19. Fixed Versions**: `openclaw` (npm): `2026.4.8`
- **20. Disclosure and Fix Dates**: Published: `2026-04-08T05:33:37Z`; last advisory update: `2026-04-08T05:33:37Z`; public npm release time(s): `openclaw@2026.4.8` published 2026-04-08T05:18:48.421Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-jf56-mccx-5f3f)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-jf56-mccx-5f3f)
  - [Commit `d7c3210cd6f5fdfdc1beff4c9541673e814354d5`](https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5)
  - [CWE-501](https://cwe.mitre.org/data/definitions/501.html)
