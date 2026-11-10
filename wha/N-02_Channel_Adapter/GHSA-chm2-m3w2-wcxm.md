# GHSA-chm2-m3w2-wcxm: Google Chat spoofing access with allowlist authorized mutable email principal despite sender-ID mismatch

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Google Chat spoofing access with allowlist authorized mutable email principal despite sender-ID mismatch
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-chm2-m3w2-wcxm`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-290` (Authentication Bypass by Spoofing) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm), `clawdbot` (npm); code paths named by the advisory: `extensions/googlechat/src/monitor.ts`, `users/<id>`, `users/<email>`.
- **5. Trust Boundary Crossing**: Official advisory narrative: Google Chat allowlisting supports matching by sender email in addition to immutable sender resource name (`users/<id>`). Affected component: `extensions/googlechat/src/monitor.ts` The `allowFrom` checks accept: Immutable sender id (`users/<id>`) Raw email (`alice@example.com`) for usability Historically, `users/<email>` was also treated as an email allowlist entry.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Google Chat allowlisting supports matching by sender email in addition to immutable sender resource name (`users/<id>`). This weakens identity binding if a deployment assumes allowlists are strictly keyed by immutable principals.
- **7. Technical Root Cause**: Affected component: `extensions/googlechat/src/monitor.ts` The `allowFrom` checks accept: Immutable sender id (`users/<id>`) Raw email (`alice@example.com`) for usability Historically, `users/<email>` was also treated as an email allowlist entry. This is now deprecated because it looks like an immutable ID but is actually a mutable principal.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: This weakens identity binding if a deployment assumes allowlists are strictly keyed by immutable principals.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **2.1 Low** (`CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Low**
- **11. Required Attacker Privileges**: `PR:H` (High), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: Google Chat allowlisting supports matching by sender email in addition to immutable sender resource name (`users/<id>`). This weakens identity binding if a deployment assumes allowlists are strictly keyed by immutable principals.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `extensions/googlechat/src/monitor.ts` at [`c8424bf29a92`](https://github.com/openclaw/openclaw/commit/c8424bf29a921e25663b29f308640b3d91a49432):

  ```diff
  -    if (normalized === normalizedSenderId) {
  -      return true;
  -    }
  -    if (normalizedEmail && normalized === normalizedEmail) {
  -      return true;
  -    }
  -    if (normalizedEmail && normalized.replace(/^users\//i, "") === normalizedEmail) {
  -      return true;
  -    }
  -    if (normalized.replace(/^users\//i, "") === normalizedSenderId) {
  -      return true;
  -    if (normalized.replace(/^(googlechat|google-chat|gchat):/i, "") === normalizedSenderId) {
  -      return true;
  -    return false;
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`c8424bf29a921e25663b29f308640b3d91a49432`](https://github.com/openclaw/openclaw/commit/c8424bf29a921e25663b29f308640b3d91a49432) - [PATCH] fix(googlechat): deprecate users/<email> allowlists (#16243).

  Fix excerpt from `extensions/googlechat/src/monitor.ts`:

  ```diff
  +
  +    // Accept `googlechat:<id>` but treat `users/...` as an *ID* only (deprecated `users/<email>`).
  +    const withoutPrefix = normalized.replace(/^(googlechat|google-chat|gchat):/i, "");
  +    if (withoutPrefix.startsWith("users/")) {
  +      return normalizeUserId(withoutPrefix) === normalizedSenderId;
  +
  +    // Raw email allowlist entries remain supported for usability.
  +    if (normalizedEmail && isEmailLike(withoutPrefix)) {
  +      return withoutPrefix === normalizedEmail;
  +
  +    return withoutPrefix.replace(/^users\//i, "") === normalizedSenderId;
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>=2026.2.14`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.2.13`; `clawdbot` (npm): `<=2026.1.24-3`
- **19. Fixed Versions**: `openclaw` (npm): `>=2026.2.14`
- **20. Disclosure and Fix Dates**: Published: `2026-02-16T00:31:29Z`; last advisory update: `2026-02-21T10:40:48Z`; fix commit authored date(s): `Sat, 14 Feb 2026 15:31:26 +0100`; public npm release time(s): `openclaw@2026.2.14` published 2026-02-15T02:59:48.267Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-chm2-m3w2-wcxm)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-chm2-m3w2-wcxm)
  - [Commit `c8424bf29a921e25663b29f308640b3d91a49432`](https://github.com/openclaw/openclaw/commit/c8424bf29a921e25663b29f308640b3d91a49432)
  - [Pull request #16243](https://github.com/openclaw/openclaw/pull/16243)
  - [CWE-290](https://cwe.mitre.org/data/definitions/290.html)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
