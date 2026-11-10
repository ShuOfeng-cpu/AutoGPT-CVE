# GHSA-8cp7-rp8r-mg77: SSRF guard bypass via IPv6 transition over ISATAP

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: SSRF guard bypass via IPv6 transition over ISATAP
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-8cp7-rp8r-mg77`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-918` (Server-Side Request Forgery (SSRF)) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: OpenClaw's SSRF hostname/IP guard did not detect ISATAP embedded IPv4 addresses (`...:5efe:w.x.y.z`). A crafted URL containing an ISATAP IPv6 literal could embed a private IPv4 target (for example loopback) and bypass private-address filtering in URL-fetching paths.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.9 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: This can permit SSRF-style access attempts to internal/private network targets through URL ingestion/fetch paths that rely on shared hostname/IP blocking.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `extensions/nostr/src/nostr-profile-http.ts` at [`d51929ecb52f`](https://github.com/openclaw/openclaw/commit/d51929ecb52fe65e90bf36795f4247feb29eb8aa):

  ```diff
  -import { readJsonBodyWithLimit, requestBodyErrorToText } from "openclaw/plugin-sdk";
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`d51929ecb52fe65e90bf36795f4247feb29eb8aa`](https://github.com/openclaw/openclaw/commit/d51929ecb52fe65e90bf36795f4247feb29eb8aa) - [PATCH] fix: block ISATAP SSRF bypass via shared host/ip guard.

  Fix excerpt from `extensions/nostr/src/nostr-profile-http.ts`:

  ```diff
  +import {
  +  isBlockedHostnameOrIp,
  +  readJsonBodyWithLimit,
  +  requestBodyErrorToText,
  +} from "openclaw/plugin-sdk";
  ```
- **16. Fix Summary**: Added RFC 5214 ISATAP embedded-IPv4 detection to the shared SSRF classifier. Centralized hostname/IP blocking through `isBlockedHostnameOrIp` and routed relevant validators to that shared path. Added regression tests for ISATAP private vs public embedded IPv4 handling.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.19`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `>=2026.1.20 <=2026.2.17`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.19`
- **20. Disclosure and Fix Dates**: Published: `2026-02-21T10:34:08Z`; last advisory update: `2026-02-21T10:39:19Z`; fix commit authored date(s): `Thu, 19 Feb 2026 09:59:34 +0100`; public npm release time(s): `openclaw@2026.2.19` published 2026-02-19T16:05:33.610Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-8cp7-rp8r-mg77)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-8cp7-rp8r-mg77)
  - [Commit `d51929ecb52fe65e90bf36795f4247feb29eb8aa`](https://github.com/openclaw/openclaw/commit/d51929ecb52fe65e90bf36795f4247feb29eb8aa)
  - [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
