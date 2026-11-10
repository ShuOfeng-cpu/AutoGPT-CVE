# GHSA-pfv7-rr5m-qmv6: Auth inconsistency on local Browser Extension Relay /extension endpoint

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Auth inconsistency on local Browser Extension Relay /extension endpoint
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-pfv7-rr5m-qmv6`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-306` (Missing Authentication for Critical Function) [source: GitHub Global Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: When the optional Chrome extension relay is enabled, `/extension` accepted unauthenticated WebSocket upgrades while `/json/*` and `/cdp` required auth.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: When the optional Chrome extension relay is enabled, `/extension` accepted unauthenticated WebSocket upgrades while `/json/*` and `/cdp` required auth.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: When the optional Chrome extension relay is enabled, `/extension` accepted unauthenticated WebSocket upgrades while `/json/*` and `/cdp` required auth. This is a local-only issue on loopback (`127.0.0.1`) and only applies when the extension relay feature is in use.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **5.1 Medium** (`CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: This is a local-only issue on loopback (`127.0.0.1`) and only applies when the extension relay feature is in use. A local process on the same machine could connect to `/extension` without the token and interfere with extension-relay behavior. No remote network exploit path is involved.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/browser/extension-relay.ts` at [`7e54b6c96feb`](https://github.com/openclaw/openclaw/commit/7e54b6c96feb1a5c30884f2b32037b8dadd0e532):

  ```diff
  -import { createHash, randomBytes } from "node:crypto";
  -import { createServer } from "node:http";
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`7e54b6c96feb1a5c30884f2b32037b8dadd0e532`](https://github.com/openclaw/openclaw/commit/7e54b6c96feb1a5c30884f2b32037b8dadd0e532) - [PATCH] fix(browser): unify extension relay auth on gateway token.

  Fix excerpt from `src/browser/extension-relay.ts`:

  ```diff
  +import { createServer } from "node:http";
  ```
- **16. Fix Summary**: Require gateway-token auth on both `/extension` and `/cdp` relay WebSocket endpoints. Keep loopback/origin checks as defense-in-depth, not as authentication. Use one token path in setup: `gateway.auth.token` / `OPENCLAW_GATEWAY_TOKEN`.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.19`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.17`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.19`
- **20. Disclosure and Fix Dates**: Published: `2026-02-21T10:34:07Z`; last advisory update: `2026-02-21T10:39:18Z`; fix commit authored date(s): `Thu, 19 Feb 2026 08:39:34 +0100`; public npm release time(s): `openclaw@2026.2.19` published 2026-02-19T16:05:33.610Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-pfv7-rr5m-qmv6)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-pfv7-rr5m-qmv6)
  - [Commit `7e54b6c96feb1a5c30884f2b32037b8dadd0e532`](https://github.com/openclaw/openclaw/commit/7e54b6c96feb1a5c30884f2b32037b8dadd0e532)
  - [CWE-306](https://cwe.mitre.org/data/definitions/306.html)
