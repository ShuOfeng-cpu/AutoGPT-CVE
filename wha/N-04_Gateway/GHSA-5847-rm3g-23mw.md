# GHSA-5847-rm3g-23mw: Hook auth rate limiter bypass via IPv4-mapped IPv6 client key variants

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Hook auth rate limiter bypass via IPv4-mapped IPv6 client key variants
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-5847-rm3g-23mw`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-770` (Allocation of Resources Without Limits or Throttling) [source: GitHub Global Advisory]
- **4. Affected Component**: `src/gateway/server-http.ts` `src/gateway/auth-rate-limit.ts`
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: The hook authentication throttle keyed failed attempts by raw socket `remoteAddress` text. IPv4 and IPv4-mapped IPv6 forms of the same client (for example `1.2.3.4` and `::ffff:1.2.3.4`) were treated as different clients, allowing separate rate-limit buckets.
- **7. Technical Root Cause**: `src/gateway/server-http.ts` `src/gateway/auth-rate-limit.ts`
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.9 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: An attacker could split failed hook-auth attempts across both address forms and effectively double the brute-force budget from 20 to 40 attempts per 60-second window.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/gateway/auth-rate-limit.ts` at [`3284d2eb227e`](https://github.com/openclaw/openclaw/commit/3284d2eb227e7b6536d543bcf5c3e320bc9d13c5):

  ```diff
  -import { isLoopbackAddress } from "./net.js";
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`3284d2eb227e7b6536d543bcf5c3e320bc9d13c5`](https://github.com/openclaw/openclaw/commit/3284d2eb227e7b6536d543bcf5c3e320bc9d13c5) - [PATCH] fix(security): normalize hook auth rate-limit client keys.

  Fix excerpt from `src/gateway/auth-rate-limit.ts`:

  ```diff
  +import { isLoopbackAddress, resolveClientIp } from "./net.js";
  ```
- **16. Fix Summary**: Centralize and reuse canonical client-IP normalization for auth rate-limiting, and use that canonical key for hook auth throttling.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.22`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.2.21-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.22`
- **20. Disclosure and Fix Dates**: Published: `2026-02-23T00:52:08Z`; last advisory update: `2026-02-23T00:52:08Z`; fix commit authored date(s): `Sun, 22 Feb 2026 08:40:39 +0100`; public npm release time(s): `openclaw@2026.2.22` published 2026-02-23T00:36:27.582Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-5847-rm3g-23mw)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-5847-rm3g-23mw)
  - [Commit `3284d2eb227e7b6536d543bcf5c3e320bc9d13c5`](https://github.com/openclaw/openclaw/commit/3284d2eb227e7b6536d543bcf5c3e320bc9d13c5)
  - [CWE-770](https://cwe.mitre.org/data/definitions/770.html)
