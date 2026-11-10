# GHSA-474h-prjg-mmw3: Sandboxed sessions_spawn(runtime="acp") bypassed sandbox inheritance and allowed host ACP initialization

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Sandboxed sessions_spawn(runtime="acp") bypassed sandbox inheritance and allowed host ACP initialization
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-474h-prjg-mmw3`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-269` (Improper Privilege Management) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: The fix now fail-closes ACP spawn from sandboxed requester sessions and rejects `sandbox="require"` for `runtime="acp"`. Fixed behavior: deny ACP spawn when requester runtime is sandboxed deny `sessions_spawn` with `runtime="acp", sandbox="require"` align sandboxed prompt guidance to avoid advertising blocked ACP paths

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Sandboxed `sessions_spawn(runtime="acp")` could bypass sandbox inheritance and initialize host-side ACP runtime. The fix now fail-closes ACP spawn from sandboxed requester sessions and rejects `sandbox="require"` for `runtime="acp"`.
- **7. Technical Root Cause**: Root cause: `runtime="subagent"` enforced sandbox inheritance, while `runtime="acp"` did not enforce equivalent sandbox/runtime checks. Security impact: sandbox-boundary bypass into host-side ACP initialization. Fixed behavior: deny ACP spawn when requester runtime is sandboxed deny `sessions_spawn` with `runtime="acp", sandbox="require"` align sandboxed prompt guidance to avoid advertising blocked ACP paths
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: The fix now fail-closes ACP spawn from sandboxed requester sessions and rejects `sandbox="require"` for `runtime="acp"`. Fixed behavior: deny ACP spawn when requester runtime is sandboxed deny `sessions_spawn` with `runtime="acp", sandbox="require"` align sandboxed prompt guidance to avoid advertising blocked ACP paths

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **8.0 High** (`CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:H` (High), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: Sandboxed `sessions_spawn(runtime="acp")` could bypass sandbox inheritance and initialize host-side ACP runtime. The fix now fail-closes ACP spawn from sandboxed requester sessions and rejects `sandbox="require"` for `runtime="acp"`.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/agents/subagent-spawn.ts` at [`ac11f0af731d`](https://github.com/openclaw/openclaw/commit/ac11f0af731d41743ba02d8595f4d0fe747336e3):

  ```diff
  -    acpEnabled: cfg.acp?.enabled !== false,
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`ac11f0af731d41743ba02d8595f4d0fe747336e3`](https://github.com/openclaw/openclaw/commit/ac11f0af731d41743ba02d8595f4d0fe747336e3) - [PATCH] Security: enforce ACP sandbox inheritance for sessions_spawn (#32254); [`c703aa0fe92df9fb71cf254fc46991e05fba2114`](https://github.com/openclaw/openclaw/commit/c703aa0fe92df9fb71cf254fc46991e05fba2114) - [PATCH] fix(agents): align sandboxed ACP prompt guidance.

  Fix excerpt from `src/agents/subagent-spawn.ts`:

  ```diff
  +    acpEnabled: cfg.acp?.enabled !== false && !childRuntime.sandboxed,
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.3.2`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.3.1`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.3.2`
- **20. Disclosure and Fix Dates**: Published: `2026-03-03T04:14:22Z`; last advisory update: `2026-03-03T04:14:22Z`; fix commit authored date(s): `Mon, 2 Mar 2026 23:50:38 +0100`; `Mon, 2 Mar 2026 23:23:56 +0000`; public npm release time(s): `openclaw@2026.3.2` published 2026-03-03T04:36:54.843Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-474h-prjg-mmw3)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-474h-prjg-mmw3)
  - [Commit `ac11f0af731d41743ba02d8595f4d0fe747336e3`](https://github.com/openclaw/openclaw/commit/ac11f0af731d41743ba02d8595f4d0fe747336e3)
  - [Commit `c703aa0fe92df9fb71cf254fc46991e05fba2114`](https://github.com/openclaw/openclaw/commit/c703aa0fe92df9fb71cf254fc46991e05fba2114)
  - [Pull request #32254](https://github.com/openclaw/openclaw/pull/32254)
  - [CWE-269](https://cwe.mitre.org/data/definitions/269.html)
