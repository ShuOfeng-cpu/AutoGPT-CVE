# GHSA-j425-whc4-4jgc: `system.run` env override filtering allowed dangerous helper-command pivots

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: `system.run` env override filtering allowed dangerous helper-command pivots
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-j425-whc4-4jgc`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-15` (External Control of System or Configuration Setting) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-639` (Authorization Bypass Through User-Controlled Key) [source: GitHub Global Advisory]; `CWE-693` (Protection Mechanism Failure) [source: GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: `src/infra/host-env-security.ts`, ` / `.
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: `system.run` env override sanitization allowed dangerous override-only helper-command pivots to reach subprocesses. A caller who could invoke `system.run` with `env` overrides could bypass allowlist/approval intent by steering an allowlisted tool through helper-command or config-loading environment variables such as `GIT_SSH_COMMAND`, editor/pager hooks, and `GIT_CONFIG_*` / `NPM_CONFIG_*`.
- **7. Technical Root Cause**: Before the fix, `src/infra/host-env-security.ts` blocked only a narrow set of override-only environment variables. Dangerous request-scoped overrides such as `GIT_SSH_COMMAND` and prefix families such as `GIT_CONFIG_*` and `NPM_CONFIG_*` could still survive `sanitizeSystemRunEnvOverrides(...)` / `sanitizeHostExecEnv(...)` and reach the spawned process. That mattered for `system.run` allowlist and approval flows because approval evaluation was tied to the reviewed binary/argv, while the launched process could still inherit attacker-controlled env overrides that changed helper-command execution or config resolution. For allowlisted tools such as `git`, this allowed behavior outside the reviewed command semantics. The fix extends the shared TypeScript and macOS policy to block dangerous override-only exact keys and prefixes while preserving trusted inherited base-environment behavior.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: This is a real protection-bypass issue, but exploitation requires an already tool-enabled caller who can invoke `system.run` and supply `env` overrides. In affected deployments, that caller could bypass allowlist/approval intent and trigger helper-command execution or config-loading behavior that is not represented by the approved command line.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **6.3 Medium** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: This is a real protection-bypass issue, but exploitation requires an already tool-enabled caller who can invoke `system.run` and supply `env` overrides. In affected deployments, that caller could bypass allowlist/approval intent and trigger helper-command execution or config-loading behavior that is not represented by the approved command line. Maintainer severity is set to medium because the bug still requires that existing execution capability; the vulnerability is the mismatch between reviewed command semantics and the actual spawned-process behavior.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `apps/macos/Sources/OpenClaw/HostEnvSanitizer.swift` at [`e27bbe498243`](https://github.com/openclaw/openclaw/commit/e27bbe4982439da6864160fd1b66445058f74801):

  ```diff
  -            if self.blockedOverrideKeys.contains(upper) { continue }
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`e27bbe4982439da6864160fd1b66445058f74801`](https://github.com/openclaw/openclaw/commit/e27bbe4982439da6864160fd1b66445058f74801) - [PATCH] fix(exec): block dangerous override-only env pivots.

  Fix excerpt from `apps/macos/Sources/OpenClaw/HostEnvSanitizer.swift`:

  ```diff
  +            if self.isBlockedOverride(upper) { continue }
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.3.7`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.3.2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.3.7`
- **20. Disclosure and Fix Dates**: Published: `2026-03-08T14:26:56Z`; last advisory update: `2026-03-08T14:26:56Z`; fix commit authored date(s): `Sat, 7 Mar 2026 19:17:59 +0000`; public npm release time(s): `openclaw@2026.3.7` published 2026-03-08T05:46:01.183Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-j425-whc4-4jgc)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-j425-whc4-4jgc)
  - [Commit `e27bbe4982439da6864160fd1b66445058f74801`](https://github.com/openclaw/openclaw/commit/e27bbe4982439da6864160fd1b66445058f74801)
  - [CWE-15](https://cwe.mitre.org/data/definitions/15.html)
  - [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
  - [CWE-693](https://cwe.mitre.org/data/definitions/693.html)
