# GHSA-56f2-hvwg-5743: SSRF in Image Tool Remote Fetch

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: SSRF in Image Tool Remote Fetch
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-56f2-hvwg-5743`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-918` (Server-Side Request Forgery (SSRF)) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A server-side request forgery (SSRF) vulnerability in the Image tool allowed attackers to force OpenClaw to make HTTP requests to arbitrary internal or restricted network targets.
- **7. Technical Root Cause**: The Image tool accepts file paths, file:// URLs, data: URLs, and http(s) URLs. In vulnerable versions, http(s) URLs were fetched without SSRF protections, enabling requests to localhost, RFC1918, link-local, and cloud metadata targets. This was fixed by routing remote media fetching through the SSRF guard (private/internal IP + hostname blocking, redirect hardening, DNS pinning).
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **7.6 High** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: A server-side request forgery (SSRF) vulnerability in the Image tool allowed attackers to force OpenClaw to make HTTP requests to arbitrary internal or restricted network targets.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Not publicly extractable from a specific fix patch. The advisory may describe the affected flow, but no qualifying removed-code excerpt was available.
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`81c68f582d4a9a20d9cca9f367d2da9edc5a65ae`](https://github.com/openclaw/openclaw/commit/81c68f582d4a9a20d9cca9f367d2da9edc5a65ae); [`9bd64c8a1f91dda602afc1d5246a2ff2be164647`](https://github.com/openclaw/openclaw/commit/9bd64c8a1f91dda602afc1d5246a2ff2be164647).
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `2026.2.2`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.2.1`
- **19. Fixed Versions**: `openclaw` (npm): `2026.2.2`
- **20. Disclosure and Fix Dates**: Published: `2026-02-14T17:21:19Z`; last advisory update: `2026-02-14T17:21:19Z`; public npm release time(s): `openclaw@2026.2.2` published 2026-02-04T00:56:41.932Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-56f2-hvwg-5743)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-56f2-hvwg-5743)
  - [Commit `81c68f582d4a9a20d9cca9f367d2da9edc5a65ae`](https://github.com/openclaw/openclaw/commit/81c68f582d4a9a20d9cca9f367d2da9edc5a65ae)
  - [Commit `9bd64c8a1f91dda602afc1d5246a2ff2be164647`](https://github.com/openclaw/openclaw/commit/9bd64c8a1f91dda602afc1d5246a2ff2be164647)
  - [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
