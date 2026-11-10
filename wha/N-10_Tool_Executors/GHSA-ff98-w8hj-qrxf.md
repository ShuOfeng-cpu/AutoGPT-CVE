# GHSA-ff98-w8hj-qrxf: Plugin runtime command execution is part of trusted plugin boundary

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Plugin runtime command execution is part of trusted plugin boundary
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-ff98-w8hj-qrxf`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-78` (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: OpenClaw plugins/extensions run in-process and are treated as trusted code. This advisory tracks trust-boundary clarification around plugin runtime command execution (`runtime.system.runCommandWithTimeout`).
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.9 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Low**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: Plugins already execute with the same OS privileges as the OpenClaw process. Exposing runtime command helpers does not cross an additional sandbox boundary.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/plugins/runtime/index.ts` at [`2e421f32dfc5`](https://github.com/openclaw/openclaw/commit/2e421f32dfc589c02706265fd3c3137ffc06c4b1):

  ```diff
  -      runCommandWithTimeout: runtimeCommandExecutionGuarded,
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`2e421f32dfc589c02706265fd3c3137ffc06c4b1`](https://github.com/openclaw/openclaw/commit/2e421f32dfc589c02706265fd3c3137ffc06c4b1) - [PATCH] fix(security): restore trusted plugin runtime exec default.

  Fix excerpt from `src/plugins/runtime/index.ts`:

  ```diff
  +      runCommandWithTimeout,
  ```
- **16. Fix Summary**: Install only trusted plugins. Use `plugins.allow` to pin explicit trusted plugin IDs. SECURITY.md now explicitly documents that plugin runtime helpers are convenience APIs, not a sandbox boundary. Thanks @markmusson for reporting.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.19`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.17`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.19`
- **20. Disclosure and Fix Dates**: Published: `2026-02-21T10:34:13Z`; last advisory update: `2026-02-21T10:39:21Z`; fix commit authored date(s): `Thu, 19 Feb 2026 16:01:22 +0100`; public npm release time(s): `openclaw@2026.2.19` published 2026-02-19T16:05:33.610Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-ff98-w8hj-qrxf)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-ff98-w8hj-qrxf)
  - [Commit `2e421f32dfc589c02706265fd3c3137ffc06c4b1`](https://github.com/openclaw/openclaw/commit/2e421f32dfc589c02706265fd3c3137ffc06c4b1)
  - [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
