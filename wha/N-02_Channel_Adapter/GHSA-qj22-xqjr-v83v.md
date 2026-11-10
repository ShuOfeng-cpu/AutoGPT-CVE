# GHSA-qj22-xqjr-v83v: Telegram message_reaction authorization bypass allows unauthorized system-event injection

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Telegram message_reaction authorization bypass allows unauthorized system-event injection
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-qj22-xqjr-v83v`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: A missing sender-authorization check in Telegram `message_reaction` handling allowed unauthorized users to trigger reaction-derived system events. When reaction notifications are enabled, unauthorized Telegram senders could inject reaction system events despite configured DM/group authorization controls (`dmPolicy`, `allowFrom`, `groupPolicy`, `groupAllowFrom`).

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Telegram message_reaction authorization bypass allows unauthorized system-event injection
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: When reaction notifications are enabled, unauthorized Telegram senders could inject reaction system events despite configured DM/group authorization controls (`dmPolicy`, `allowFrom`, `groupPolicy`, `groupAllowFrom`).

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **7.1 High** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: When reaction notifications are enabled, unauthorized Telegram senders could inject reaction system events despite configured DM/group authorization controls (`dmPolicy`, `allowFrom`, `groupPolicy`, `groupAllowFrom`).
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/telegram/bot-handlers.ts` at [`e56b0cf1a04f`](https://github.com/openclaw/openclaw/commit/e56b0cf1a04f992ac6ebc775899f48ea31687640):

  ```diff
  -      const senderUsername = user?.username ? `@${user.username}` : undefined;
  -      if (senderName && senderUsername) {
  -        senderLabel = `${senderName} (${senderUsername})`;
  -      } else if (!senderName && senderUsername) {
  -        senderLabel = senderUsername;
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`e56b0cf1a04f992ac6ebc775899f48ea31687640`](https://github.com/openclaw/openclaw/commit/e56b0cf1a04f992ac6ebc775899f48ea31687640) - [PATCH] fix: enforce telegram reaction authorization.

  Fix excerpt from `src/telegram/bot-handlers.ts`:

  ```diff
  +      const senderUsernameLabel = user?.username ? `@${user.username}` : undefined;
  +      if (senderName && senderUsernameLabel) {
  +        senderLabel = `${senderName} (${senderUsernameLabel})`;
  +      } else if (!senderName && senderUsernameLabel) {
  +        senderLabel = senderUsernameLabel;
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.25`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.24`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.25`
- **20. Disclosure and Fix Dates**: Published: `2026-02-26T03:58:21Z`; last advisory update: `2026-02-26T03:58:21Z`; fix commit authored date(s): `Thu, 26 Feb 2026 01:02:36 +0100`; public npm release time(s): `openclaw@2026.2.25` published 2026-02-26T04:16:34.010Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-qj22-xqjr-v83v)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-qj22-xqjr-v83v)
  - [Commit `e56b0cf1a04f992ac6ebc775899f48ea31687640`](https://github.com/openclaw/openclaw/commit/e56b0cf1a04f992ac6ebc775899f48ea31687640)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
