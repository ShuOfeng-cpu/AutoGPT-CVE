# GHSA-9q2p-vc84-2rwm: system.run allow-always persistence included shell-commented payload tails

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: system.run allow-always persistence included shell-commented payload tails
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-9q2p-vc84-2rwm`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-436` (Interpretation Conflict) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: system.run allow-always persistence included shell-commented payload tails
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: OpenClaw's `system.run` allowlist analysis did not honor POSIX shell comment semantics when deriving `allow-always` persistence entries. A caller in `security=allowlist` mode who received an `allow-always` decision could submit a shell command whose tail was commented out at runtime, for example by using an unquoted `#` before a chained payload.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **5.0 Medium** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: system.run allow-always persistence included shell-commented payload tails
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Pre-fix context immediately preceding the added guard in `src/infra/exec-approvals-analysis.ts` at [`939b18475d73`](https://github.com/openclaw/openclaw/commit/939b18475d734ed75173f59507e3ebbdfe1992b7):

  ```diff
     return next === "\n" || next === "\r";
   }
   
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`939b18475d734ed75173f59507e3ebbdfe1992b7`](https://github.com/openclaw/openclaw/commit/939b18475d734ed75173f59507e3ebbdfe1992b7) - [PATCH] fix(exec): honor shell comments in allow-always analysis. Other advisory commit reference(s), not classified as fix commits: [`939b18475d734ed75173f59507e3ebbdfe1992b7`](https://github.com/openclaw/openclaw/commit/939b18475d734ed75173f59507e3ebbdfe1992b7).

  Fix excerpt from `src/infra/exec-approvals-analysis.ts`:

  ```diff
  +function isShellCommentStart(source: string, index: number): boolean {
  +  if (source[index] !== "#") {
  +    return false;
  +  }
  +  if (index === 0) {
  +    return true;
  +  }
  +  const prev = source[index - 1];
  +  return Boolean(prev && /\s/.test(prev));
  +}
  +
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.3.7`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.3.2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.3.7`
- **20. Disclosure and Fix Dates**: Published: `2026-03-08T14:26:57Z`; last advisory update: `2026-03-08T14:26:57Z`; fix commit authored date(s): `Sat, 7 Mar 2026 23:30:23 +0000`; public npm release time(s): `openclaw@2026.3.7` published 2026-03-08T05:46:01.183Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-9q2p-vc84-2rwm)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-9q2p-vc84-2rwm)
  - [Commit `939b18475d734ed75173f59507e3ebbdfe1992b7`](https://github.com/openclaw/openclaw/commit/939b18475d734ed75173f59507e3ebbdfe1992b7)
  - [CWE-436](https://cwe.mitre.org/data/definitions/436.html)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
