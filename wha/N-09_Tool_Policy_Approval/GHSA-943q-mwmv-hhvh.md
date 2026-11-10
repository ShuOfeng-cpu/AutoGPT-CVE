# GHSA-943q-mwmv-hhvh: OC-02: Gateway /tools/invoke tool escalation + ACP permission auto-approval

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: OC-02: Gateway /tools/invoke tool escalation + ACP permission auto-approval
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-943q-mwmv-hhvh`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-78` (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: OpenClaw Gateway exposes an authenticated HTTP endpoint (`POST /tools/invoke`) intended for invoking a constrained set of tools.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: OpenClaw Gateway exposes an authenticated HTTP endpoint (`POST /tools/invoke`) intended for invoking a constrained set of tools. Two issues could combine to significantly increase blast radius in misconfigured or exposed deployments: The HTTP gateway layer did not deny high-risk session orchestration tools by default, allowing a caller with Gateway auth to invoke tools like `sessions_spawn` / `sessions_send` and pivot into creating or controlling agent sessions. ACP clients could auto-approve permission requests for risky tools with insufficient user interaction/guardrails, reducing the friction that should normally prevent silent execution or mutation.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Two issues could combine to significantly increase blast radius in misconfigured or exposed deployments: The HTTP gateway layer did not deny high-risk session orchestration tools by default, allowing a caller with Gateway auth to invoke tools like `sessions_spawn` / `sessions_send` and pivot into creating or controlling agent sessions. If the Gateway is reachable by an attacker and they obtain a valid Gateway token, they may be able to: Escalate from single-tool invocation to spawning/controlling sessions and reach command execution capabilities depending on tool policy and runtime environment.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **8.8 High** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: If the Gateway is reachable by an attacker and they obtain a valid Gateway token, they may be able to: Escalate from single-tool invocation to spawning/controlling sessions and reach command execution capabilities depending on tool policy and runtime environment. Perform cross-session message injection via `sessions_send`. In ACP-integrated scenarios, obtain unintended approvals for non-read/search tool permissions.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Not publicly extractable from a specific fix patch. The advisory may describe the affected flow, but no qualifying removed-code excerpt was available.
- **15. Fix Patch (Commit)**: No specific vulnerability-fixing commit is publicly identified by the advisory.
- **16. Fix Summary**: The default behavior is now hardened: PR #15390: deny high-risk tools over HTTP `/tools/invoke` by default (with `gateway.tools.{allow,deny}` overrides) and harden ACP permission handling. Commit `bb1c3dfe1`: ACP clients now prompt for any non-read/search permission request (fail closed for mutating/execution/fetch operations). Commit `539689a2f`: security audit warns when `gateway.tools.allow` re-enables default-denied HTTP tools, since this can increase RCE blast radius if the Gateway is reachable. Commit `153a7644e`: ACP safe-kind inference is stricter to avoid accidental auto-approval due to substring matches (still auto-approves only confident `read/search`).
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>=2026.2.14`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<2026.2.14`
- **19. Fixed Versions**: `openclaw` (npm): `>=2026.2.14`
- **20. Disclosure and Fix Dates**: Published: `2026-02-14T11:55:07Z`; last advisory update: `2026-02-14T12:19:32Z`; public npm release time(s): `openclaw@2026.2.14` published 2026-02-15T02:59:48.267Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-943q-mwmv-hhvh)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-943q-mwmv-hhvh)
  - [Pull request #15390](https://github.com/openclaw/openclaw/pull/15390)
  - [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
