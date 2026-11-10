# GHSA-8mf7-vv8w-hjr2: tools.exec.safeBins generic fallback allowed interpreter-style inline payload execution in allowlist mode

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: tools.exec.safeBins generic fallback allowed interpreter-style inline payload execution in allowlist mode
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-8mf7-vv8w-hjr2`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-78` (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-693` (Protection Mechanism Failure) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: This requires explicit operator configuration to add such binaries to `safeBins`, so impact is limited to non-default/misconfigured deployments.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: When `tools.exec.safeBins` contained a binary without an explicit safe-bin profile, OpenClaw used a permissive generic fallback profile. In allowlist mode, that could let interpreter-style binaries (for example `python3`, `node`, `ruby`) execute inline payloads via flags like `-c`. This requires explicit operator configuration to add such binaries to `safeBins`, so impact is limited to non-default/misconfigured deployments.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: When `tools.exec.safeBins` contained a binary without an explicit safe-bin profile, OpenClaw used a permissive generic fallback profile. This requires explicit operator configuration to add such binaries to `safeBins`, so impact is limited to non-default/misconfigured deployments.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **2.3 Low** (`CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Low**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: When `tools.exec.safeBins` contained a binary without an explicit safe-bin profile, OpenClaw used a permissive generic fallback profile. In allowlist mode, that could let interpreter-style binaries (for example `python3`, `node`, `ruby`) execute inline payloads via flags like `-c`. This requires explicit operator configuration to add such binaries to `safeBins`, so impact is limited to non-default/misconfigured deployments.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/infra/exec-approvals-allowlist.ts` at [`47c3f742b6c4`](https://github.com/openclaw/openclaw/commit/47c3f742b6c488be26dd7b9636dbbb8676089154):

  ```diff
  -  const genericSafeBinProfile = params.safeBinGenericProfile ?? SAFE_BIN_GENERIC_PROFILE;
  -  const profile = safeBinProfiles[execName] ?? genericSafeBinProfile;
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`47c3f742b6c488be26dd7b9636dbbb8676089154`](https://github.com/openclaw/openclaw/commit/47c3f742b6c488be26dd7b9636dbbb8676089154) - [PATCH] fix(exec): require explicit safe-bin profiles.

  Fix excerpt from `src/infra/exec-approvals-allowlist.ts`:

  ```diff
  +  const profile = safeBinProfiles[execName];
  +  if (!profile) {
  +    return false;
  +  }
  ```
- **16. Fix Summary**: Remove generic safe-bin fallback during allowlist evaluation. Require explicit safe-bin profiles for `safeBins` entries. Add configurable `tools.exec.safeBinProfiles` (global + per-agent) for safe custom binaries. Update docs to clearly separate `safeBins` from command allowlist semantics.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.22`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.21-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.22`
- **20. Disclosure and Fix Dates**: Published: `2026-02-23T00:52:06Z`; last advisory update: `2026-02-23T00:52:06Z`; fix commit authored date(s): `Sun, 22 Feb 2026 12:57:53 +0100`; public npm release time(s): `openclaw@2026.2.22` published 2026-02-23T00:36:27.582Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-8mf7-vv8w-hjr2)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-8mf7-vv8w-hjr2)
  - [Commit `47c3f742b6c488be26dd7b9636dbbb8676089154`](https://github.com/openclaw/openclaw/commit/47c3f742b6c488be26dd7b9636dbbb8676089154)
  - [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
  - [CWE-693](https://cwe.mitre.org/data/definitions/693.html)
