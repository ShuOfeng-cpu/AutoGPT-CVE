# GHSA-gp3q-wpq4-5c5h: LINE group allowlist scope mismatch with DM pairing-store entries

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: LINE group allowlist scope mismatch with DM pairing-store entries
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-gp3q-wpq4-5c5h`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: In specific LINE configurations, sender IDs approved through DM pairing could also satisfy group allowlist checks when operators expected group sender access to be scoped only to explicit group allowlists. DM pairing-store entries could influence group sender authorization in allowlist mode.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: In specific LINE configurations, sender IDs approved through DM pairing could also satisfy group allowlist checks when operators expected group sender access to be scoped only to explicit group allowlists.
- **7. Technical Root Cause**: Root cause: group allowlist composition inherited pairing-store entries intended for DM approvals. Under default DM pairing policy, a DM-paired sender could match group allowlist checks. Fixes on `main`: isolate group allowlist composition from pairing-store entries centralize shared DM/group allowlist composition to preserve DM-only pairing behavior add regression coverage for LINE and Mattermost policy paths
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: In specific LINE configurations, sender IDs approved through DM pairing could also satisfy group allowlist checks when operators expected group sender access to be scoped only to explicit group allowlists.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **7.1 High** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: This is a group-authorization scope mismatch. DM pairing-store entries could influence group sender authorization in allowlist mode.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `extensions/mattermost/src/mattermost/monitor.ts` at [`8bdda7a651c2`](https://github.com/openclaw/openclaw/commit/8bdda7a651c21e98faccdbbd73081e79cffe8be0):

  ```diff
  -    const configAllowFrom = normalizeAllowList(account.config.allowFrom ?? []);
  -    const configGroupAllowFrom = normalizeAllowList(account.config.groupAllowFrom ?? []);
  -    const effectiveAllowFrom = Array.from(new Set([...configAllowFrom, ...storeAllowFrom]));
  -    const effectiveGroupAllowFrom = Array.from(
  -      new Set([
  -        ...(configGroupAllowFrom.length > 0 ? configGroupAllowFrom : configAllowFrom),
  -        ...storeAllowFrom,
  -      ]),
  -    );
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`8bdda7a651c21e98faccdbbd73081e79cffe8be0`](https://github.com/openclaw/openclaw/commit/8bdda7a651c21e98faccdbbd73081e79cffe8be0) - [PATCH] fix(security): keep DM pairing allowlists out of group auth; [`892a9c24b0f6118729ab5b5f5499b1a7e792dd15`](https://github.com/openclaw/openclaw/commit/892a9c24b0f6118729ab5b5f5499b1a7e792dd15) - [PATCH] refactor(security): centralize channel allowlist auth policy.

  Fix excerpt from `extensions/mattermost/src/mattermost/monitor.ts`:

  ```diff
  +    const { effectiveAllowFrom, effectiveGroupAllowFrom } =
  +      resolveMattermostEffectiveAllowFromLists({
  +        dmPolicy,
  +        allowFrom: account.config.allowFrom,
  +        groupAllowFrom: account.config.groupAllowFrom,
  +        storeAllowFrom,
  +      });
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.26`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.25`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.26`
- **20. Disclosure and Fix Dates**: Published: `2026-02-26T22:40:37Z`; last advisory update: `2026-02-26T22:40:37Z`; fix commit authored date(s): `Thu, 26 Feb 2026 12:58:06 +0100`; `Thu, 26 Feb 2026 13:06:27 +0100`; public npm release time(s): `openclaw@2026.2.26` published 2026-02-26T23:59:10.915Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-gp3q-wpq4-5c5h)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-gp3q-wpq4-5c5h)
  - [Commit `8bdda7a651c21e98faccdbbd73081e79cffe8be0`](https://github.com/openclaw/openclaw/commit/8bdda7a651c21e98faccdbbd73081e79cffe8be0)
  - [Commit `892a9c24b0f6118729ab5b5f5499b1a7e792dd15`](https://github.com/openclaw/openclaw/commit/892a9c24b0f6118729ab5b5f5499b1a7e792dd15)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
