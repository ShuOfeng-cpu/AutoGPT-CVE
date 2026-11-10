# GHSA-qcc4-p59m-p54m: Sandbox dangling-symlink alias handling could bypass workspace-only write boundary

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Sandbox dangling-symlink alias handling could bypass workspace-only write boundary
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-qcc4-p59m-p54m`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-59` (Improper Link Resolution Before File Access ('Link Following')) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-367` (Time-of-check Time-of-use (TOCTOU) Race Condition) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A sandbox boundary-validation gap in symlink alias handling allowed certain workspace-only write paths to be treated as in-boundary even when they could resolve outside the workspace/sandbox root.
- **7. Technical Root Cause**: In affected versions, dangling symlink hops could be accepted during boundary checks under missing-target conditions. For workspace-only write flows (including `apply_patch`), this could allow writes to resolve outside the configured workspace/sandbox boundary. The fix resolves symlink targets through existing ancestors and fails closed when canonical resolution escapes the configured boundary.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: A sandbox boundary-validation gap in symlink alias handling allowed certain workspace-only write paths to be treated as in-boundary even when they could resolve outside the workspace/sandbox root. For workspace-only write flows (including `apply_patch`), this could allow writes to resolve outside the configured workspace/sandbox boundary.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **7.0 High** (`CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: Boundary-confined write operations could be redirected outside the configured workspace/sandbox root. Primary impact is integrity of host-side files reachable from that path resolution.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Pre-fix context immediately preceding the added guard in `src/agents/apply-patch.test.ts` at [`4fd29a35bb85`](https://github.com/openclaw/openclaw/commit/4fd29a35bb85a1898ebff518364c467058b50e14):

  ```diff
     }
   }
   
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`4fd29a35bb85a1898ebff518364c467058b50e14`](https://github.com/openclaw/openclaw/commit/4fd29a35bb85a1898ebff518364c467058b50e14) - [PATCH] fix: block broken-symlink sandbox path escapes.

  Fix excerpt from `src/agents/apply-patch.test.ts`:

  ```diff
  +async function withWorkspaceTempDir<T>(fn: (dir: string) => Promise<T>) {
  +  const dir = await fs.mkdtemp(path.join(process.cwd(), "openclaw-patch-workspace-"));
  +  try {
  +    return await fn(dir);
  +  } finally {
  +    await fs.rm(dir, { recursive: true, force: true });
  +  }
  +}
  +
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.26`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.2.25`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.26`
- **20. Disclosure and Fix Dates**: Published: `2026-02-26T22:40:37Z`; last advisory update: `2026-02-26T22:40:37Z`; fix commit authored date(s): `Thu, 26 Feb 2026 13:19:48 +0100`; public npm release time(s): `openclaw@2026.2.26` published 2026-02-26T23:59:10.915Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-qcc4-p59m-p54m)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-qcc4-p59m-p54m)
  - [Commit `4fd29a35bb85a1898ebff518364c467058b50e14`](https://github.com/openclaw/openclaw/commit/4fd29a35bb85a1898ebff518364c467058b50e14)
  - [CWE-59](https://cwe.mitre.org/data/definitions/59.html)
  - [CWE-367](https://cwe.mitre.org/data/definitions/367.html)
