# GHSA-3h2q-j2v4-6w5r: system.run allowlist approval parsing missed PowerShell encoded-command wrappers

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: system.run allowlist approval parsing missed PowerShell encoded-command wrappers
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-3h2q-j2v4-6w5r`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-184` (Incomplete List of Disallowed Inputs) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: system.run allowlist approval parsing missed PowerShell encoded-command wrappers
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: In `allowlist` mode, a caller with access to `system.run` could invoke `pwsh` or `powershell` using `-EncodedCommand`, `-enc`, or `-e`, and the request would fall back to plain argv analysis instead of the normal shell-wrapper approval path. This could allow a PowerShell inline payload to execute without the approval step that equivalent `-Command` invocations would require.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **5.0 Medium** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: system.run allowlist approval parsing missed PowerShell encoded-command wrappers
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/infra/shell-inline-command.ts` at [`1d1757b16f48`](https://github.com/openclaw/openclaw/commit/1d1757b16f48f1a93cd16ab0ad7e2c3c63ce727d):

  ```diff
  -export const POWERSHELL_INLINE_COMMAND_FLAGS = new Set(["-c", "-command", "--command"]);
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`1d1757b16f48f1a93cd16ab0ad7e2c3c63ce727d`](https://github.com/openclaw/openclaw/commit/1d1757b16f48f1a93cd16ab0ad7e2c3c63ce727d) - [PATCH] fix(exec): recognize PowerShell encoded commands. Other advisory commit reference(s), not classified as fix commits: [`1d1757b16f48f1a93cd16ab0ad7e2c3c63ce727d`](https://github.com/openclaw/openclaw/commit/1d1757b16f48f1a93cd16ab0ad7e2c3c63ce727d).

  Fix excerpt from `src/infra/shell-inline-command.ts`:

  ```diff
  +export const POWERSHELL_INLINE_COMMAND_FLAGS = new Set([
  +  "-c",
  +  "-command",
  +  "--command",
  +  "-encodedcommand",
  +  "-enc",
  +  "-e",
  +]);
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.3.7`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.3.2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.3.7`
- **20. Disclosure and Fix Dates**: Published: `2026-03-08T14:26:58Z`; last advisory update: `2026-03-08T14:26:58Z`; fix commit authored date(s): `Sat, 7 Mar 2026 23:15:37 +0000`; public npm release time(s): `openclaw@2026.3.7` published 2026-03-08T05:46:01.183Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-3h2q-j2v4-6w5r)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-3h2q-j2v4-6w5r)
  - [Commit `1d1757b16f48f1a93cd16ab0ad7e2c3c63ce727d`](https://github.com/openclaw/openclaw/commit/1d1757b16f48f1a93cd16ab0ad7e2c3c63ce727d)
  - [CWE-184](https://cwe.mitre.org/data/definitions/184.html)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
