# GHSA-w9cg-v44m-4qv8: BASH_ENV / ENV startup-file injection into spawned shell commands

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: BASH_ENV / ENV startup-file injection into spawned shell commands
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-w9cg-v44m-4qv8`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-15` (External Control of System or Configuration Setting) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-78` (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: Exploitation requires local/privileged influence over configuration or environment inputs; there is no standalone remote unauthenticated trigger from this issue alone.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: `BASH_ENV` / `ENV` startup-file injection could lead to unintended pre-command shell execution when attacker-controlled environment values were admitted and then inherited by host command execution paths.
- **7. Technical Root Cause**: The fix hardens environment handling across all relevant execution paths: Blocks dangerous startup/runtime env keys and prefixes in shared host env sanitization. Sanitizes inherited ambient environment even when no per-request overrides are provided. Blocks dangerous config-driven env injection before values enter process environment. Uses the same sanitizer in macOS host execution paths. Aligns skill env override sanitization with the shared dangerous-env policy.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: `BASH_ENV` / `ENV` startup-file injection could lead to unintended pre-command shell execution when attacker-controlled environment values were admitted and then inherited by host command execution paths. Sanitizes inherited ambient environment even when no per-request overrides are provided.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **7.3 High** (`CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: Medium. Exploitation requires local/privileged influence over configuration or environment inputs; there is no standalone remote unauthenticated trigger from this issue alone.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `apps/macos/Sources/OpenClaw/ExecApprovalsSocket.swift` at [`2cdbadee1f8f`](https://github.com/openclaw/openclaw/commit/2cdbadee1f8fcaa93302d7debbfc529e19868ea4):

  ```diff
  -    private static func sanitizedEnv(_ overrides: [String: String]?) -> [String: String]? {
  -        guard let overrides else { return nil }
  -        var merged = ProcessInfo.processInfo.environment
  -        for (rawKey, value) in overrides {
  -            let key = rawKey.trimmingCharacters(in: .whitespacesAndNewlines)
  -            guard !key.isEmpty else { continue }
  -            let upper = key.uppercased()
  -            if self.blockedEnvKeys.contains(upper) { continue }
  -            if self.blockedEnvPrefixes.contains(where: { upper.hasPrefix($0) }) { continue }
  -            merged[key] = value
  -        }
  -        return merged
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`2cdbadee1f8fcaa93302d7debbfc529e19868ea4`](https://github.com/openclaw/openclaw/commit/2cdbadee1f8fcaa93302d7debbfc529e19868ea4) - [PATCH] fix(security): block startup-file env injection across host execution paths. Other advisory commit reference(s), not classified as fix commits: [`2cdbadee1f8fcaa93302d7debbfc529e19868ea4`](https://github.com/openclaw/openclaw/commit/2cdbadee1f8fcaa93302d7debbfc529e19868ea4).

  Fix excerpt from `apps/macos/Sources/OpenClaw/ExecApprovalsSocket.swift`:

  ```diff
  +    private static func sanitizedEnv(_ overrides: [String: String]?) -> [String: String] {
  +        HostEnvSanitizer.sanitize(overrides: overrides)
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>=2026.2.21`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.19-2`
- **19. Fixed Versions**: `openclaw` (npm): `>=2026.2.21`
- **20. Disclosure and Fix Dates**: Published: `2026-02-21T18:16:03Z`; last advisory update: `2026-02-21T18:16:03Z`; fix commit authored date(s): `Sat, 21 Feb 2026 11:43:53 +0100`; public npm release time(s): `openclaw@2026.2.21` published 2026-02-21T16:02:01.230Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-w9cg-v44m-4qv8)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-w9cg-v44m-4qv8)
  - [Commit `2cdbadee1f8fcaa93302d7debbfc529e19868ea4`](https://github.com/openclaw/openclaw/commit/2cdbadee1f8fcaa93302d7debbfc529e19868ea4)
  - [CWE-15](https://cwe.mitre.org/data/definitions/15.html)
  - [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
