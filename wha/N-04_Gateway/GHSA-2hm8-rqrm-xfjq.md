# GHSA-2hm8-rqrm-xfjq: Owner-only gateway tool access checks were incomplete in specific authenticated DM flows

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Owner-only gateway tool access checks were incomplete in specific authenticated DM flows
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-2hm8-rqrm-xfjq`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-269` (Improper Privilege Management) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: In authenticated non-owner DM sessions, a narrow tool-invocation path could reach broader-than-intended owner-only gateway actions. This requires an authenticated non-owner sender in a DM session and a specific tool invocation path.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: In authenticated non-owner DM sessions, a narrow tool-invocation path could reach broader-than-intended owner-only gateway actions.
- **7. Technical Root Cause**: Some gateway call paths were still using broader default scopes instead of method-level least-privilege scopes. Owner-only enforcement depended on tool-name checks and was not consistently metadata-driven across all call paths.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: This requires an authenticated non-owner sender in a DM session and a specific tool invocation path. Some gateway call paths were still using broader default scopes instead of method-level least-privilege scopes.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **4.8 Medium** (`CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Low**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: This requires an authenticated non-owner sender in a DM session and a specific tool invocation path. No unauthenticated access is involved, and this does not provide direct code execution by itself.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/agents/tool-policy.ts` at [`a40c10d3e245`](https://github.com/openclaw/openclaw/commit/a40c10d3e24568b1e2947c104484be74bf66b8d2):

  ```diff
  -const OWNER_ONLY_TOOL_NAMES = new Set<string>(["whatsapp_login"]);
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`a40c10d3e24568b1e2947c104484be74bf66b8d2`](https://github.com/openclaw/openclaw/commit/a40c10d3e24568b1e2947c104484be74bf66b8d2) - [PATCH] fix: harden agent gateway authorization scopes; [`2777d8ad91ef1e8a7c6f5b4b18f8507be7d02914`](https://github.com/openclaw/openclaw/commit/2777d8ad91ef1e8a7c6f5b4b18f8507be7d02914); [`3d7ad1cfca4daaa84cd553e843e0e08fa6201349`](https://github.com/openclaw/openclaw/commit/3d7ad1cfca4daaa84cd553e843e0e08fa6201349) - [PATCH] fix(security): centralize owner-only tool gating and scope maps.

  Fix excerpt from `src/agents/tool-policy.ts`:

  ```diff
  +const OWNER_ONLY_TOOL_NAMES = new Set<string>(["whatsapp_login", "cron", "gateway"]);
  ```
- **16. Fix Summary**: Refactored gateway method scope mapping to a data-driven table and added guard tests to ensure all exposed core gateway methods stay classified. Centralized owner-only enforcement in tool policy wrappers and tool metadata. Marked owner-only tools explicitly (`cron`, `gateway`, `whatsapp_login`) and removed duplicated per-tool owner checks. Refactored gateway call path internals into smaller helpers while preserving behavior and coverage.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.19`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.17`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.19`
- **20. Disclosure and Fix Dates**: Published: `2026-02-21T10:34:15Z`; last advisory update: `2026-02-21T10:40:02Z`; fix commit authored date(s): `Thu, 19 Feb 2026 14:37:56 +0100`; `Thu, 19 Feb 2026 15:27:45 +0100`; public npm release time(s): `openclaw@2026.2.19` published 2026-02-19T16:05:33.610Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-2hm8-rqrm-xfjq)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-2hm8-rqrm-xfjq)
  - [Commit `a40c10d3e24568b1e2947c104484be74bf66b8d2`](https://github.com/openclaw/openclaw/commit/a40c10d3e24568b1e2947c104484be74bf66b8d2)
  - [Commit `2777d8ad91ef1e8a7c6f5b4b18f8507be7d02914`](https://github.com/openclaw/openclaw/commit/2777d8ad91ef1e8a7c6f5b4b18f8507be7d02914)
  - [Commit `3d7ad1cfca4daaa84cd553e843e0e08fa6201349`](https://github.com/openclaw/openclaw/commit/3d7ad1cfca4daaa84cd553e843e0e08fa6201349)
  - [CWE-269](https://cwe.mitre.org/data/definitions/269.html)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
