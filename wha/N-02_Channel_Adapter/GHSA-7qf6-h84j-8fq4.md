# GHSA-7qf6-h84j-8fq4: Microsoft Teams media fetch SSRF hardening: unified guarded fetch across Graph and attachment paths

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Microsoft Teams media fetch SSRF hardening: unified guarded fetch across Graph and attachment paths
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-7qf6-h84j-8fq4`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-367` (Time-of-check Time-of-use (TOCTOU) Race Condition) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-918` (Server-Side Request Forgery (SSRF)) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Microsoft Teams media fetch SSRF hardening: unified guarded fetch across Graph and attachment paths
- **7. Technical Root Cause**: The Microsoft Teams attachment/media code previously relied on plugin-local fetch behavior in parts of the flow, instead of uniformly using shared guarded fetch logic with pinned DNS + policy checks. This could allow policy drift and SSRF boundary inconsistency between channel/plugin paths. The fix unifies this path by: routing Microsoft Teams Graph message/hosted-content/attachment fetches through shared SSRF-guarded fetch paths, routing auth-scope fallback attachment downloads through the same guarded policy model, centralizing hostname-suffix allowlist policy helpers in `plugin-sdk` so channel/plugins use the same allowlist normalization and policy construction behavior.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: The Microsoft Teams attachment/media code previously relied on plugin-local fetch behavior in parts of the flow, instead of uniformly using shared guarded fetch logic with pinned DNS + policy checks.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **2.3 Low** (`CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: Microsoft Teams media handling used mixed fetch paths for Graph metadata/content and attachment auth-retry flows. Some paths bypassed the shared SSRF guard model and created inconsistent host/DNS enforcement across redirect/fetch hops.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `extensions/msteams/src/attachments/download.ts` at [`57334cd7d851`](https://github.com/openclaw/openclaw/commit/57334cd7d85174d5f951de01114fd5801b063564):

  ```diff
  -  safeFetch,
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`57334cd7d85174d5f951de01114fd5801b063564`](https://github.com/openclaw/openclaw/commit/57334cd7d85174d5f951de01114fd5801b063564) - [PATCH] refactor: unify channel/plugin ssrf fetch policy and auth fallback.

  Fix excerpt from `extensions/msteams/src/attachments/download.ts`:

  ```diff
  +  resolveMediaSsrfPolicy,
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.26`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.2.25`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.26`
- **20. Disclosure and Fix Dates**: Published: `2026-02-26T22:40:33Z`; last advisory update: `2026-02-26T22:40:33Z`; fix commit authored date(s): `Thu, 26 Feb 2026 16:43:44 +0100`; public npm release time(s): `openclaw@2026.2.26` published 2026-02-26T23:59:10.915Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-7qf6-h84j-8fq4)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-7qf6-h84j-8fq4)
  - [Commit `57334cd7d85174d5f951de01114fd5801b063564`](https://github.com/openclaw/openclaw/commit/57334cd7d85174d5f951de01114fd5801b063564)
  - [CWE-367](https://cwe.mitre.org/data/definitions/367.html)
  - [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
