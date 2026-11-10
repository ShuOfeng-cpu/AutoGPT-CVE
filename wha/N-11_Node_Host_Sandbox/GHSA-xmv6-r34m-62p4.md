# GHSA-xmv6-r34m-62p4: Sandbox media fallback tmp symlink alias bypass allows host file reads outside sandboxRoot

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Sandbox media fallback tmp symlink alias bypass allows host file reads outside sandboxRoot
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-xmv6-r34m-62p4`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-22` (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-59` (Improper Link Resolution Before File Access ('Link Following')) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: `/tmp/openclaw`, `src/infra/tmp-openclaw-dir.ts`, `os.tmpdir()/openclaw-<uid>`, `src/agents/sandbox-paths.ts`.
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A sandbox path validation bypass in `openclaw` allows host file reads outside `sandboxRoot` via the media path fallback tmp flow when the fallback tmp root is a symlink alias.
- **7. Technical Root Cause**: When `/tmp/openclaw` is unavailable or unsafe, `resolvePreferredOpenClawTmpDir()` in `src/infra/tmp-openclaw-dir.ts` fell back to `os.tmpdir()/openclaw-<uid>` without verifying that fallback path was a trusted non-symlink directory. `resolveSandboxedMediaSource()` (`src/agents/sandbox-paths.ts`) allows absolute tmp media paths under the OpenClaw tmp root using lexical containment and alias checks. If the fallback tmp root is a symlink alias (for example to `/`), inputs like `$TMPDIR/openclaw-<uid>/etc/passwd` can pass validation and resolve to host files outside `sandboxRoot`.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: A sandbox path validation bypass in `openclaw` allows host file reads outside `sandboxRoot` via the media path fallback tmp flow when the fallback tmp root is a symlink alias. When `/tmp/openclaw` is unavailable or unsafe, `resolvePreferredOpenClawTmpDir()` in `src/infra/tmp-openclaw-dir.ts` fell back to `os.tmpdir()/openclaw-<uid>` without verifying that fallback path was a trusted non-symlink directory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **7.8 High** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: This can break sandbox media path confinement and permit unauthorized host file reads (confidentiality impact).
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/browser/routes/agent.act.ts` at [`496a76c03ba8`](https://github.com/openclaw/openclaw/commit/496a76c03ba85e15ea715e5a583e498ae04d36e3):

  ```diff
  -  resolvePathWithinRoot,
  -function resolveDownloadPathOrRespond(res: BrowserResponse, requestedPath: string): string | null {
  -  const downloadPathResult = resolvePathWithinRoot({
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`496a76c03ba85e15ea715e5a583e498ae04d36e3`](https://github.com/openclaw/openclaw/commit/496a76c03ba85e15ea715e5a583e498ae04d36e3) - [PATCH] fix(security): harden browser trace/download temp path handling.

  Fix excerpt from `src/browser/routes/agent.act.ts`:

  ```diff
  +  resolveWritablePathWithinRoot,
  +async function resolveDownloadPathOrRespond(
  +  res: BrowserResponse,
  +  requestedPath: string,
  +): Promise<string | null> {
  +  const downloadPathResult = await resolveWritablePathWithinRoot({
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.25`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.24`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.25`
- **20. Disclosure and Fix Dates**: Published: `2026-02-26T03:58:31Z`; last advisory update: `2026-02-26T03:58:31Z`; fix commit authored date(s): `Thu, 26 Feb 2026 01:01:17 +0100`; public npm release time(s): `openclaw@2026.2.25` published 2026-02-26T04:16:34.010Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-xmv6-r34m-62p4)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-xmv6-r34m-62p4)
  - [Commit `496a76c03ba85e15ea715e5a583e498ae04d36e3`](https://github.com/openclaw/openclaw/commit/496a76c03ba85e15ea715e5a583e498ae04d36e3)
  - [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
  - [CWE-59](https://cwe.mitre.org/data/definitions/59.html)
