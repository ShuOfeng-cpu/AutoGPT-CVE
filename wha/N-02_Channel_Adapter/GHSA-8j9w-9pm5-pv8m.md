# GHSA-8j9w-9pm5-pv8m: DUPLICATE of GHSA-3c6h-g97w-fg78: safeBins denied flags can be bypassed via GNU long-option abbreviations

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: DUPLICATE of GHSA-3c6h-g97w-fg78: safeBins denied flags can be bypassed via GNU long-option abbreviations
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-8j9w-9pm5-pv8m`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-184` (Incomplete List of Disallowed Inputs) [source: GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: `src/infra/exec-safe-bin-policy.ts`, `src/infra/exec-approvals-allowlist.ts`.
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: OpenClaw `safeBins` argument validation allowed denied flags to be bypassed via GNU long-option abbreviations. The validator matched denied long flags by exact string and treated unknown long options as allowed, creating a policy/runtime mismatch: commands could be approved as safe-bin usage while runtime behavior reached denied options.
- **7. Technical Root Cause**: Affected paths included safe-bin argv validation and allowlist evaluation: `src/infra/exec-safe-bin-policy.ts` `src/infra/exec-approvals-allowlist.ts`
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Configured safe-bin `sort`: external program invocation via abbreviated `--compress-prog` (runtime resolves to `--compress-program`).

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: Official advisory narrative: Default safe-bin `wc`: unauthorized file-read behavior via abbreviated `--files0-fro` (runtime resolves to `--files0-from`).
- **12. Direct Impact**: Default safe-bin `wc`: unauthorized file-read behavior via abbreviated `--files0-fro` (runtime resolves to `--files0-from`). Configured safe-bin `sort`: external program invocation via abbreviated `--compress-prog` (runtime resolves to `--compress-program`). Additional hardening gap: unknown or ambiguous long options in safe-bin mode were not rejected fail-closed.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/infra/exec-safe-bin-policy.ts` at [`3b8e33037ae2`](https://github.com/openclaw/openclaw/commit/3b8e33037ae2e12af7beb56fcf0346f1f8cbde6f):

  ```diff
  -      "--temporary-directory",
  -      "--random-source",
  -      "-T",
  -    deniedFlags: ["--compress-program", "--files0-from", "--output", "-o"],
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`3b8e33037ae2e12af7beb56fcf0346f1f8cbde6f`](https://github.com/openclaw/openclaw/commit/3b8e33037ae2e12af7beb56fcf0346f1f8cbde6f) - [PATCH] fix(security): harden safeBins long-option validation.

  Fix excerpt from `src/infra/exec-safe-bin-policy.ts`:

  ```diff
  +    // --random-source/--temporary-directory/-T are filesystem-dependent and not stdin-only.
  +    deniedFlags: [
  +      "--compress-program",
  +      "--files0-from",
  +      "--output",
  +      "--random-source",
  +      "--temporary-directory",
  +      "-T",
  +      "-o",
  +    ],
  ```
- **16. Fix Summary**: Canonicalize long options using GNU-style unique-prefix matching. Reject unknown and ambiguous long options in safe-bin mode (fail-closed). Reject inline values for non-value long flags. Deny additional sort filesystem-dependent flags in safe-bin mode: `--random-source`, `--temporary-directory`, `-T`. Add regression tests for denied-flag abbreviations and fail-closed long-option handling.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>=2026.2.23`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.22-2`
- **19. Fixed Versions**: `openclaw` (npm): `>=2026.2.23`
- **20. Disclosure and Fix Dates**: Published: `2026-02-24T05:27:13Z`; last advisory update: `2026-02-24T05:27:13Z`; fix commit authored date(s): `Mon, 23 Feb 2026 23:55:28 +0000`; public npm release time(s): `openclaw@2026.2.23` published 2026-02-24T05:40:17.896Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-8j9w-9pm5-pv8m)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [Commit `3b8e33037ae2e12af7beb56fcf0346f1f8cbde6f`](https://github.com/openclaw/openclaw/commit/3b8e33037ae2e12af7beb56fcf0346f1f8cbde6f)
  - [CWE-184](https://cwe.mitre.org/data/definitions/184.html)
