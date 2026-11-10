# GHSA-7ff8-xjh3-mgh6: non-default autoAllowSkills setting could bypass on-miss exec prompt

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: non-default autoAllowSkills setting could bypass on-miss exec prompt
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-7ff8-xjh3-mgh6`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-266` (Incorrect Privilege Assignment) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: `./skill-bin`, `/`, `\\`, `./<skill-bin>`.
- **5. Trust Boundary Crossing**: Official advisory narrative: In affected non-default configurations, approval prompts could be skipped for commands that should have required operator confirmation.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: In `openclaw` versions up to and including `2026.2.22-2`, a non-default exec-approval configuration could allow a skill-name collision to bypass an `ask=on-miss` prompt. When `autoAllowSkills=true`, a path-scoped executable such as `./skill-bin` could resolve to basename `skill-bin`, satisfy the `skills` allowlist segment, and run without prompting for approval.
- **7. Technical Root Cause**: The allowlist evaluator accepted `skills` satisfaction by bin-name match, so `./skill-bin` could match `skillBins.has("skill-bin")` after resolution. The fix hardens skill auto-allow matching by requiring: a pathless invocation token (no `/` or `\\`), and a trusted resolved executable path for that skill bin on the machine where skills run. This preserves normal `skill-bin ...` behavior while preventing `./<skill-bin>` and absolute-path basename collisions from auto-satisfying `skills`.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: When `autoAllowSkills=true`, a path-scoped executable such as `./skill-bin` could resolve to basename `skill-bin`, satisfy the `skills` allowlist segment, and run without prompting for approval. In affected non-default configurations, approval prompts could be skipped for commands that should have required operator confirmation.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **7.3 High** (`CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: In affected non-default configurations, approval prompts could be skipped for commands that should have required operator confirmation.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/infra/exec-approvals-allowlist.ts` at [`ffd63b7a2c4c`](https://github.com/openclaw/openclaw/commit/ffd63b7a2c4c6d5aeb4710ef951d5794ad7ad77b):

  ```diff
  -    skillBins?: Set<string>;
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`ffd63b7a2c4c6d5aeb4710ef951d5794ad7ad77b`](https://github.com/openclaw/openclaw/commit/ffd63b7a2c4c6d5aeb4710ef951d5794ad7ad77b) - [PATCH] fix(security): trust resolved skill-bin paths in allowlist auto-allow.

  Fix excerpt from `src/infra/exec-approvals-allowlist.ts`:

  ```diff
  +    skillBins?: readonly SkillBinTrustEntry[];
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>=2026.2.23`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.2.22-2`
- **19. Fixed Versions**: `openclaw` (npm): `>=2026.2.23`
- **20. Disclosure and Fix Dates**: Published: `2026-02-24T05:27:21Z`; last advisory update: `2026-02-24T05:27:21Z`; fix commit authored date(s): `Tue, 24 Feb 2026 03:12:22 +0000`; public npm release time(s): `openclaw@2026.2.23` published 2026-02-24T05:40:17.896Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-7ff8-xjh3-mgh6)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-7ff8-xjh3-mgh6)
  - [Commit `ffd63b7a2c4c6d5aeb4710ef951d5794ad7ad77b`](https://github.com/openclaw/openclaw/commit/ffd63b7a2c4c6d5aeb4710ef951d5794ad7ad77b)
  - [CWE-266](https://cwe.mitre.org/data/definitions/266.html)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
