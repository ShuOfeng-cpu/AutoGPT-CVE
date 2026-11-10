# GHSA-f6h3-846h-2r8w: Elevated allowFrom matching tightened for sender-scoped authorization

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Elevated allowFrom matching tightened for sender-scoped authorization
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-f6h3-846h-2r8w`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-639` (Authorization Bypass Through User-Controlled Key) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: The fix tightens matching to sender-scoped identity by default and makes mutable metadata matching explicit. Elevated sender authorization now matches sender-scoped identity values only by default (`SenderId`, `From`, `SenderE164`) and no longer considers recipient routing fields such as `ctx.To`.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: In certain elevated-mode configurations, `tools.elevated.allowFrom` accepted broader identity signals than intended. The fix tightens matching to sender-scoped identity by default and makes mutable metadata matching explicit.
- **7. Technical Root Cause**: Elevated sender authorization now matches sender-scoped identity values only by default (`SenderId`, `From`, `SenderE164`) and no longer considers recipient routing fields such as `ctx.To`. Mutable sender metadata (`SenderName`, `SenderUsername`, `SenderTag`) now requires explicit allowlist prefixes (`name:`, `username:`, `tag:`). Explicit identity prefixes are also supported (`id:`, `from:`, `e164:`).
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Mutable sender metadata (`SenderName`, `SenderUsername`, `SenderTag`) now requires explicit allowlist prefixes (`name:`, `username:`, `tag:`).

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **5.3 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: In certain elevated-mode configurations, `tools.elevated.allowFrom` accepted broader identity signals than intended. The fix tightens matching to sender-scoped identity by default and makes mutable metadata matching explicit.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/auto-reply/reply/reply-elevated.ts` at [`6817c0ec7b4f`](https://github.com/openclaw/openclaw/commit/6817c0ec7b4fa830123d4f5c340f075a4bd04ee2):

  ```diff
  -  const tokens = new Set<string>();
  -  const addToken = (value?: string) => {
  -    if (!value) {
  -      return;
  -    }
  -    const trimmed = value.trim();
  -    if (!trimmed) {
  -      return;
  -    tokens.add(trimmed);
  -    const normalized = normalizeAllowToken(trimmed);
  -    if (normalized) {
  -      tokens.add(normalized);
  -    const slugged = slugAllowToken(trimmed);
  -    if (slugged) {
  -      tokens.add(slugged);
  -  };
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`6817c0ec7b4fa830123d4f5c340f075a4bd04ee2`](https://github.com/openclaw/openclaw/commit/6817c0ec7b4fa830123d4f5c340f075a4bd04ee2) - [PATCH] fix(security): tighten elevated allowFrom sender matching.

  Fix excerpt from `src/auto-reply/reply/reply-elevated.ts`:

  ```diff
  +  const senderIdTokens = new Set<string>();
  +  const senderFromTokens = new Set<string>();
  +  const senderE164Tokens = new Set<string>();
  +
  +  if (params.ctx.SenderId?.trim()) {
  +    addProviderFormattedTokens({
  +      cfg: params.cfg,
  +      provider: params.provider,
  +      accountId: params.ctx.AccountId,
  +      values: [params.ctx.SenderId, stripSenderPrefix(params.ctx.SenderId)].filter(Boolean),
  +      tokens: senderIdTokens,
  +    });
  +  }
  +  if (params.ctx.From?.trim()) {
  +    addProviderFormattedTokens({
  +      cfg: params.cfg,
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.22`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.21-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.22`
- **20. Disclosure and Fix Dates**: Published: `2026-02-23T00:52:03Z`; last advisory update: `2026-02-23T00:52:03Z`; fix commit authored date(s): `Sun, 22 Feb 2026 21:58:40 +0100`; public npm release time(s): `openclaw@2026.2.22` published 2026-02-23T00:36:27.582Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-f6h3-846h-2r8w)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-f6h3-846h-2r8w)
  - [Commit `6817c0ec7b4fa830123d4f5c340f075a4bd04ee2`](https://github.com/openclaw/openclaw/commit/6817c0ec7b4fa830123d4f5c340f075a4bd04ee2)
  - [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
