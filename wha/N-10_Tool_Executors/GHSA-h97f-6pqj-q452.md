# GHSA-h97f-6pqj-q452: IPv6 multicast SSRF classifier bypass

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: IPv6 multicast SSRF classifier bypass
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-h97f-6pqj-q452`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-918` (Server-Side Request Forgery (SSRF)) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: OpenClaw's SSRF IP classifier did not treat IPv6 multicast literals (`ff00::/8`) as blocked/private-internal. This allowed literal multicast hosts to pass SSRF preflight checks.
- **7. Technical Root Cause**: The IPv6 private/internal range set omitted `multicast`, so addresses like `ff02::1` and `ff05::1:3` were not classified as blocked by the shared SSRF classifier.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.3 Medium** (`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Low**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: A bypass in address classification existed for IPv6 multicast literals. OpenClaw's network fetch/navigation paths are constrained to HTTP/HTTPS and this was triaged as low-severity defense-in-depth hardening.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Pre-fix context immediately preceding the added guard in `src/shared/net/ip.ts` at [`baf656bc6fd7`](https://github.com/openclaw/openclaw/commit/baf656bc6fd7f83b6033e6dbc2548ec75028641f):

  ```diff
     "loopback",
     "linkLocal",
     "uniqueLocal",
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`baf656bc6fd7f83b6033e6dbc2548ec75028641f`](https://github.com/openclaw/openclaw/commit/baf656bc6fd7f83b6033e6dbc2548ec75028641f) - [PATCH] fix: block IPv6 multicast SSRF bypass.

  Fix excerpt from `src/shared/net/ip.ts`:

  ```diff
  +  "multicast",
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.25`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.24`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.25`
- **20. Disclosure and Fix Dates**: Published: `2026-02-26T03:58:14Z`; last advisory update: `2026-02-26T03:58:14Z`; fix commit authored date(s): `Thu, 26 Feb 2026 03:34:47 +0100`; public npm release time(s): `openclaw@2026.2.25` published 2026-02-26T04:16:34.010Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-h97f-6pqj-q452)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-h97f-6pqj-q452)
  - [Commit `baf656bc6fd7f83b6033e6dbc2548ec75028641f`](https://github.com/openclaw/openclaw/commit/baf656bc6fd7f83b6033e6dbc2548ec75028641f)
  - [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
