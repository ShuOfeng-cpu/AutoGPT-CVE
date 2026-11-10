# GHSA-5h2c-8v84-qpvr: Shell-env fallback trusted startup env and could execute attacker-influenced login-shell paths

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Shell-env fallback trusted startup env and could execute attacker-influenced login-shell paths
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-5h2c-8v84-qpvr`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-15` (External Control of System or Configuration Setting) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-78` (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: `src/infra/shell-env.ts`, `src/config/io.ts`, `src/config/env-vars.ts`.
- **5. Trust Boundary Crossing**: Official advisory narrative: Under OpenClaw trust assumptions (`SECURITY.md`), this is not a public-remote issue and depends on crossing local trusted-operator boundaries.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: OpenClaw shell-env fallback trusted startup environment values and could execute attacker-influenced login-shell startup paths before loading env keys.
- **7. Technical Root Cause**: The vulnerable chain was in the shell-env fallback path: 1. `src/infra/shell-env.ts` `resolveShell(env)` trusted `env.SHELL` when set. `execLoginShellEnvZero(...)` executed `${SHELL} -l -c "env -0"` with inherited runtime env. 2. `src/config/io.ts` Config env values were applied before shell fallback execution. 3. `src/config/env-vars.ts` / env policy coverage `SHELL` handling was hardened, but startup-path selectors (`HOME`, `ZDOTDIR`) still needed explicit blocking in config env ingestion and sanitization for shell fallback execution. With env/config influence, this could trigger unintended command execution in shell startup processing on the OpenClaw host process context.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: `src/infra/shell-env.ts` `resolveShell(env)` trusted `env.SHELL` when set.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **5.3 Medium** (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: Local code-execution risk in environments where attacker-controlled env/config input can reach shell-env fallback. Under OpenClaw trust assumptions (`SECURITY.md`), this is not a public-remote issue and depends on crossing local trusted-operator boundaries.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Not publicly extractable from a specific fix patch. The advisory may describe the affected flow, but no qualifying removed-code excerpt was available.
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`9363c320d8ffe29290906752fab92621da02c3f7`](https://github.com/openclaw/openclaw/commit/9363c320d8ffe29290906752fab92621da02c3f7). Other advisory commit reference(s), not classified as fix commits: [`9363c320d8ffe29290906752fab92621da02c3f7`](https://github.com/openclaw/openclaw/commit/9363c320d8ffe29290906752fab92621da02c3f7).
- **16. Fix Summary**: Mainline hardening now: blocks `SHELL`, `HOME`, and `ZDOTDIR` during config env ingestion used by runtime fallback, sanitizes shell fallback execution env, pinning `HOME` to the real user home and dropping `ZDOTDIR` + dangerous startup vars, adds regression tests for config env ingestion and shell fallback/path-probe sanitization.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.22`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.2.21-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.22`
- **20. Disclosure and Fix Dates**: Published: `2026-02-23T00:52:06Z`; last advisory update: `2026-02-23T00:52:06Z`; public npm release time(s): `openclaw@2026.2.22` published 2026-02-23T00:36:27.582Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-5h2c-8v84-qpvr)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-5h2c-8v84-qpvr)
  - [Commit `9363c320d8ffe29290906752fab92621da02c3f7`](https://github.com/openclaw/openclaw/commit/9363c320d8ffe29290906752fab92621da02c3f7)
  - [CWE-15](https://cwe.mitre.org/data/definitions/15.html)
  - [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
