# GHSA-4cqv-h74h-93j4: Discord `allowFrom` slug-collision authorization bypass

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Discord `allowFrom` slug-collision authorization bypass
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-4cqv-h74h-93j4`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-287` (Improper Authentication) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Discord `allowFrom` slug-collision authorization bypass
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: OpenClaw supports Discord allowlists using either user IDs or names/tags.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **6.5 Medium** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: Discord `allowFrom` slug-collision authorization bypass
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/security/audit-channel.ts` at [`f97c45c5b5e0`](https://github.com/openclaw/openclaw/commit/f97c45c5b5e0698b6667bb5f6badc0cac7dabd12):

  ```diff
  -        const guildEntries = (discordCfg.guilds as Record<string, unknown> | undefined) ?? {};
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`f97c45c5b5e0698b6667bb5f6badc0cac7dabd12`](https://github.com/openclaw/openclaw/commit/f97c45c5b5e0698b6667bb5f6badc0cac7dabd12) - [PATCH] fix(security): warn on Discord name-based allowlists in audit; [`747bb581b3f2264495e1fec5a0727d9f2ca1b6f1`](https://github.com/openclaw/openclaw/commit/747bb581b3f2264495e1fec5a0727d9f2ca1b6f1) - [PATCH] fix(discord): canonicalize resolved allowlists to ids.

  Fix excerpt from `src/security/audit-channel.ts`:

  ```diff
  +        const guildEntries = discordGuildEntries;
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.22`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.21-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.22`
- **20. Disclosure and Fix Dates**: Published: `2026-02-23T00:52:17Z`; last advisory update: `2026-02-23T00:52:17Z`; fix commit authored date(s): `Sat, 21 Feb 2026 19:44:58 +0100`; `Sat, 21 Feb 2026 19:53:00 +0100`; public npm release time(s): `openclaw@2026.2.22` published 2026-02-23T00:36:27.582Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-4cqv-h74h-93j4)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-4cqv-h74h-93j4)
  - [Commit `f97c45c5b5e0698b6667bb5f6badc0cac7dabd12`](https://github.com/openclaw/openclaw/commit/f97c45c5b5e0698b6667bb5f6badc0cac7dabd12)
  - [Commit `747bb581b3f2264495e1fec5a0727d9f2ca1b6f1`](https://github.com/openclaw/openclaw/commit/747bb581b3f2264495e1fec5a0727d9f2ca1b6f1)
  - [CWE-287](https://cwe.mitre.org/data/definitions/287.html)
