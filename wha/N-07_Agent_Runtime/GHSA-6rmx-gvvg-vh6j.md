# GHSA-6rmx-gvvg-vh6j: hooks count non-POST requests toward auth lockout

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: hooks count non-POST requests toward auth lockout
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-6rmx-gvvg-vh6j`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-307` (Improper Restriction of Excessive Authentication Attempts) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-799` (Improper Control of Interaction Frequency) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: An unauthenticated client could send repeated non-`POST` requests (for example `GET`) with an invalid token to consume the hook auth failure budget and trigger the temporary lockout window for that client key. An unauthenticated network client that could reach `/hooks/*` could temporarily lock out legitimate webhook delivery when requests collapsed to the same hook auth client key, such as shared proxy or NAT topologies.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: hooks count non-POST requests toward auth lockout
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: An unauthenticated network client that could reach `/hooks/*` could temporarily lock out legitimate webhook delivery when requests collapsed to the same hook auth client key, such as shared proxy or NAT topologies.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **5.3 Medium** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: An unauthenticated network client that could reach `/hooks/*` could temporarily lock out legitimate webhook delivery when requests collapsed to the same hook auth client key, such as shared proxy or NAT topologies. Impact is limited to temporary availability loss for hook-triggered wake or automation delivery.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Pre-fix context immediately preceding the added guard in `src/gateway/server-http.ts` at [`44820dceadac`](https://github.com/openclaw/openclaw/commit/44820dceadac65ac7c0ce8fc0ffba8c2bd9fae89):

  ```diff
         return true;
       }
   
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`44820dceadac65ac7c0ce8fc0ffba8c2bd9fae89`](https://github.com/openclaw/openclaw/commit/44820dceadac65ac7c0ce8fc0ffba8c2bd9fae89) - [PATCH] fix(hooks): gate methods before auth lockout accounting.

  Fix excerpt from `src/gateway/server-http.ts`:

  ```diff
  +    if (req.method !== "POST") {
  +      res.statusCode = 405;
  +      res.setHeader("Allow", "POST");
  +      res.setHeader("Content-Type", "text/plain; charset=utf-8");
  +      res.end("Method Not Allowed");
  +      return true;
  +    }
  +
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.3.7`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.3.2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.3.7`
- **20. Disclosure and Fix Dates**: Published: `2026-03-08T14:26:54Z`; last advisory update: `2026-03-08T14:26:54Z`; fix commit authored date(s): `Sat, 7 Mar 2026 18:04:45 +0000`; public npm release time(s): `openclaw@2026.3.7` published 2026-03-08T05:46:01.183Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-6rmx-gvvg-vh6j)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-6rmx-gvvg-vh6j)
  - [Commit `44820dceadac65ac7c0ce8fc0ffba8c2bd9fae89`](https://github.com/openclaw/openclaw/commit/44820dceadac65ac7c0ce8fc0ffba8c2bd9fae89)
  - [CWE-307](https://cwe.mitre.org/data/definitions/307.html)
  - [CWE-799](https://cwe.mitre.org/data/definitions/799.html)
