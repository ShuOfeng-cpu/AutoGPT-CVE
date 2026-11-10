# GHSA-gcj7-r3hg-m7w6: voice-call Twilio replay dedupe now bound to authenticated webhook identity

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: voice-call Twilio replay dedupe now bound to authenticated webhook identity
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-gcj7-r3hg-m7w6`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-294` (Authentication Bypass by Capture-replay) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-345` (Insufficient Verification of Data Authenticity) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: The fix removes unsigned-header trust from Twilio replay/dedupe identity and binds replay/manager dedupe to authenticated request material.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: The voice-call Twilio webhook path accepted replay/dedupe identity from unsigned request metadata (`i-twilio-idempotency-token`), enabling replayed signed requests to bypass replay detection and manager dedupe by mutating only that header.
- **7. Technical Root Cause**: The fix removes unsigned-header trust from Twilio replay/dedupe identity and binds replay/manager dedupe to authenticated request material. It also threads a verified request identity through provider parsing so dedupe uses verification-derived identity rather than mutable headers.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Deployments using the optional `voice-call` Twilio webhook path could accept replayed webhook events as fresh events when an attacker had one valid signed request and changed only the unsigned idempotency header.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **3.7 Low** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`); GitHub Repository Advisory qualitative severity: **Low**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: Deployments using the optional `voice-call` Twilio webhook path could accept replayed webhook events as fresh events when an attacker had one valid signed request and changed only the unsigned idempotency header.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `extensions/voice-call/src/providers/base.ts` at [`1aadf26f9acc`](https://github.com/openclaw/openclaw/commit/1aadf26f9acc399affabd859937a09468a9c5cb4):

  ```diff
  -  parseWebhookEvent(ctx: WebhookContext): ProviderWebhookParseResult;
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`1aadf26f9acc399affabd859937a09468a9c5cb4`](https://github.com/openclaw/openclaw/commit/1aadf26f9acc399affabd859937a09468a9c5cb4) - [PATCH] fix(voice-call): bind webhook dedupe to verified request identity. Other advisory commit reference(s), not classified as fix commits: [`1aadf26f9acc399affabd859937a09468a9c5cb4`](https://github.com/openclaw/openclaw/commit/1aadf26f9acc399affabd859937a09468a9c5cb4).

  Fix excerpt from `extensions/voice-call/src/providers/base.ts`:

  ```diff
  +  parseWebhookEvent(ctx: WebhookContext, options?: WebhookParseOptions): ProviderWebhookParseResult;
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.26`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.2.25`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.26`
- **20. Disclosure and Fix Dates**: Published: `2026-02-26T22:40:32Z`; last advisory update: `2026-02-26T22:40:32Z`; fix commit authored date(s): `Thu, 26 Feb 2026 21:43:42 +0100`; public npm release time(s): `openclaw@2026.2.26` published 2026-02-26T23:59:10.915Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-gcj7-r3hg-m7w6)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-gcj7-r3hg-m7w6)
  - [Commit `1aadf26f9acc399affabd859937a09468a9c5cb4`](https://github.com/openclaw/openclaw/commit/1aadf26f9acc399affabd859937a09468a9c5cb4)
  - [CWE-294](https://cwe.mitre.org/data/definitions/294.html)
  - [CWE-345](https://cwe.mitre.org/data/definitions/345.html)
