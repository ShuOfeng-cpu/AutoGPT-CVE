# GHSA-mmpf-jwf4-h3qv: Option injection in pre-commit hook can stage ignored files

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Option injection in pre-commit hook can stage ignored files
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-mmpf-jwf4-h3qv`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-77` (Improper Neutralization of Special Elements used in a Command ('Command Injection')) [source: GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (other); code paths named by the advisory: `git-hooks/`.
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A maliciously-named file (for example, `--force`) can trigger option injection in the repository's `git-hooks/pre-commit` hook when a contributor uses the built-in git hook setup (`git config core.hooksPath git-hooks`). This can cause unintended staging of ignored files.
- **7. Technical Root Cause**: The hook collected staged filenames and piped them through `xargs` into `git add` without a `--` separator. Filenames beginning with `-` could be interpreted as flags. This issue only affects contributors who: use the repo's `git-hooks/` hook mechanism (not the `pre-commit` framework), and run commits in a working directory that contains sensitive ignored files.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: A maliciously-named file (for example, `--force`) can trigger option injection in the repository's `git-hooks/pre-commit` hook when a contributor uses the built-in git hook setup (`git config core.hooksPath git-hooks`).

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Repository Advisory qualitative severity: **Low**
- **11. Required Attacker Privileges**: Not separately specified by the official advisory.
- **12. Direct Impact**: Under specific circumstances, ignored files (for example `.env`) can be added to git history.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Not publicly extractable from a specific fix patch. The advisory may describe the affected flow, but no qualifying removed-code excerpt was available.
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`b88f37762f5b6d7ec0f589eb761815e466e4ef4b`](https://github.com/openclaw/openclaw/commit/b88f37762f5b6d7ec0f589eb761815e466e4ef4b); [`ba84b1253967143692166023f9e174c149b6f2ed`](https://github.com/openclaw/openclaw/commit/ba84b1253967143692166023f9e174c149b6f2ed).
- **16. Fix Summary**: The hook now: uses NUL-delimited file lists (`git diff ... -z`) to safely handle whitespace, and passes paths to `git add` after `--` to prevent option injection.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (other): `>=2026.2.15`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (other): `<=2026.2.14`
- **19. Fixed Versions**: `openclaw` (other): `>=2026.2.15`
- **20. Disclosure and Fix Dates**: Published: `2026-02-18T03:39:01Z`; last advisory update: `2026-02-21T10:37:07Z`; independent package-registry release time not available for this record.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-mmpf-jwf4-h3qv)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [Commit `b88f37762f5b6d7ec0f589eb761815e466e4ef4b`](https://github.com/openclaw/openclaw/commit/b88f37762f5b6d7ec0f589eb761815e466e4ef4b)
  - [Commit `ba84b1253967143692166023f9e174c149b6f2ed`](https://github.com/openclaw/openclaw/commit/ba84b1253967143692166023f9e174c149b6f2ed)
  - [CWE-77](https://cwe.mitre.org/data/definitions/77.html)
