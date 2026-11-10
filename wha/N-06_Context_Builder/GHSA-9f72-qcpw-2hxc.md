# GHSA-9f72-qcpw-2hxc: Native prompt image auto-load did not honor tools.fs.workspaceOnly in sandboxed runs

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Native prompt image auto-load did not honor tools.fs.workspaceOnly in sandboxed runs
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-9f72-qcpw-2hxc`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-200` (Exposure of Sensitive Information to an Unauthorized Actor) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-284` (Improper Access Control) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: ` / `.
- **5. Trust Boundary Crossing**: Official advisory narrative: When operators enabled it, prompt text could still reference mounted out-of-workspace image paths (for example `/agent/secret.png`) and load those image bytes for vision-capable model input.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: In sandboxed runs, native prompt image auto-load did not honor `tools.fs.workspaceOnly=true`. This optional hardening setting is **not enabled by default**. When operators enabled it, prompt text could still reference mounted out-of-workspace image paths (for example `/agent/secret.png`) and load those image bytes for vision-capable model input.
- **7. Technical Root Cause**: Native prompt image ingestion (`detectAndLoadPromptImages` / `loadImageFromRef`) resolved and read sandbox paths but did not apply the same workspace-root assertion used by file tools when `tools.fs.workspaceOnly` was set.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: This optional hardening setting is **not enabled by default**. When operators enabled it, prompt text could still reference mounted out-of-workspace image paths (for example `/agent/secret.png`) and load those image bytes for vision-capable model input.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **8.9 High** (`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: In sandboxed runs, native prompt image auto-load did not honor `tools.fs.workspaceOnly=true`. This optional hardening setting is **not enabled by default**. When operators enabled it, prompt text could still reference mounted out-of-workspace image paths (for example `/agent/secret.png`) and load those image bytes for vision-capable model input.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/agents/pi-embedded-runner/run/attempt.ts` at [`370d115549c0`](https://github.com/openclaw/openclaw/commit/370d115549c0dadace0902775eea0d5094aedfdc):

  ```diff
  -import { resolveSessionAgentIds } from "../../agent-scope.js";
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`370d115549c0dadace0902775eea0d5094aedfdc`](https://github.com/openclaw/openclaw/commit/370d115549c0dadace0902775eea0d5094aedfdc) - [PATCH] fix: enforce workspaceOnly for native prompt image autoload.

  Fix excerpt from `src/agents/pi-embedded-runner/run/attempt.ts`:

  ```diff
  +import { resolveAgentConfig, resolveSessionAgentIds } from "../../agent-scope.js";
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.24`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.23`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.24`
- **20. Disclosure and Fix Dates**: Published: `2026-02-25T04:37:41Z`; last advisory update: `2026-02-25T04:37:41Z`; fix commit authored date(s): `Tue, 24 Feb 2026 14:47:22 +0000`; public npm release time(s): `openclaw@2026.2.24` published 2026-02-25T02:50:19.980Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-9f72-qcpw-2hxc)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-9f72-qcpw-2hxc)
  - [Commit `370d115549c0dadace0902775eea0d5094aedfdc`](https://github.com/openclaw/openclaw/commit/370d115549c0dadace0902775eea0d5094aedfdc)
  - [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
  - [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
