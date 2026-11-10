# GHSA-9mph-4f7v-fmvh: Agent avatar symlink traversal in gateway session metadata

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Agent avatar symlink traversal in gateway session metadata
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-9mph-4f7v-fmvh`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-59` (Improper Link Resolution Before File Access ('Link Following')) [source: GitHub Global Advisory]
- **4. Affected Component**: `src/gateway/session-utils.ts` (`resolveIdentityAvatarUrl`)
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A crafted local avatar path could follow a symlink outside the agent workspace and return arbitrary file contents as a base64 `data:` URL in gateway responses.
- **7. Technical Root Cause**: `src/gateway/session-utils.ts` (`resolveIdentityAvatarUrl`)
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.9 Medium** (`CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: Confidentiality impact: local file read in the gateway process context. Exfiltration path: `agents.list` can return the resulting `avatarUrl` payload.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/gateway/session-utils.ts` at [`3d0337504349`](https://github.com/openclaw/openclaw/commit/3d0337504349954237d09e4d957df5cb844d5e77):

  ```diff
  -  const workspaceRoot = path.resolve(workspaceDir);
  -  const resolved = path.resolve(workspaceRoot, trimmed);
  -  if (!isPathWithinRoot(workspaceRoot, resolved)) {
  -    const stat = fs.statSync(resolved);
  -    if (!stat.isFile() || stat.size > AVATAR_MAX_BYTES) {
  -    const buffer = fs.readFileSync(resolved);
  -    const mime = resolveAvatarMime(resolved);
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`3d0337504349954237d09e4d957df5cb844d5e77`](https://github.com/openclaw/openclaw/commit/3d0337504349954237d09e4d957df5cb844d5e77) - [PATCH] fix(gateway): block avatar symlink escapes.

  Fix excerpt from `src/gateway/session-utils.ts`:

  ```diff
  +  const workspaceRoot = tryResolveExistingPath(workspaceDir) ?? path.resolve(workspaceDir);
  +  const resolvedCandidate = path.resolve(workspaceRoot, trimmed);
  +  if (!isPathWithinRoot(workspaceRoot, resolvedCandidate)) {
  +  let fd: number | null = null;
  +    const resolvedReal = fs.realpathSync(resolvedCandidate);
  +    if (!isPathWithinRoot(workspaceRoot, resolvedReal)) {
  +      return undefined;
  +    }
  +    const preOpenStat = fs.lstatSync(resolvedReal);
  +    if (!preOpenStat.isFile() || preOpenStat.size > AVATAR_MAX_BYTES) {
  +    const openFlags =
  +      fs.constants.O_RDONLY |
  +      (typeof fs.constants.O_NOFOLLOW === "number" ? fs.constants.O_NOFOLLOW : 0);
  +    fd = fs.openSync(resolvedReal, openFlags);
  +    const openedStat = fs.fstatSync(fd);
  +    if (
  ```
- **16. Fix Summary**: Resolve workspace and avatar paths with `realpath` and enforce realpath containment. Open files with `O_NOFOLLOW` when available. Compare pre-open and opened file identity (`dev`/`ino`) to block swap races. Add regression tests for outside-workspace symlink rejection and in-workspace symlink allowance.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.22`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.21-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.22`
- **20. Disclosure and Fix Dates**: Published: `2026-02-23T00:52:08Z`; last advisory update: `2026-02-23T00:52:08Z`; fix commit authored date(s): `Sun, 22 Feb 2026 08:51:06 +0100`; public npm release time(s): `openclaw@2026.2.22` published 2026-02-23T00:36:27.582Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-9mph-4f7v-fmvh)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-9mph-4f7v-fmvh)
  - [Commit `3d0337504349954237d09e4d957df5cb844d5e77`](https://github.com/openclaw/openclaw/commit/3d0337504349954237d09e4d957df5cb844d5e77)
  - [CWE-59](https://cwe.mitre.org/data/definitions/59.html)
