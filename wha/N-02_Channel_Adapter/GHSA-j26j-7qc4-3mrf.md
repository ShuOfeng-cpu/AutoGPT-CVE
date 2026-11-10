# GHSA-j26j-7qc4-3mrf: MS Teams fileConsent/invoke missing conversation binding allowed cross-conversation pending-upload consumption

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: MS Teams fileConsent/invoke missing conversation binding allowed cross-conversation pending-upload consumption
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-j26j-7qc4-3mrf`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-639` (Authorization Bypass Through User-Controlled Key) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-862` (Missing Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: In `openclaw` MS Teams file-consent flow, pending uploads were authorized by `uploadId` alone. `fileConsent/invoke` did not verify the invoke conversation against the conversation that created the pending upload.
- **7. Technical Root Cause**: Pending uploads stored `conversationId`, but invoke handling consumed by `uploadId` only. The invoke path did not enforce conversation binding before `uploadToConsentUrl(...)` and pending-upload removal. Fix binds accept/decline handling to normalized conversation id match before consuming pending upload state.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **5.3 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: An attacker who obtained a valid `uploadId` within TTL could trigger cross-conversation upload completion (accept path) or cancel a victim pending upload (decline path).
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `extensions/msteams/src/monitor-handler.ts` at [`347f7b955006`](https://github.com/openclaw/openclaw/commit/347f7b9550064f5f5b33c6e07f64e85b9657b6f1):

  ```diff
  -    const pendingFile = getPendingUpload(uploadId);
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`347f7b9550064f5f5b33c6e07f64e85b9657b6f1`](https://github.com/openclaw/openclaw/commit/347f7b9550064f5f5b33c6e07f64e85b9657b6f1) - [PATCH] fix(msteams): bind file consent invokes to conversation.

  Fix excerpt from `extensions/msteams/src/monitor-handler.ts`:

  ```diff
  +  const pendingFile = getPendingUpload(uploadId);
  +  if (pendingFile) {
  +    const pendingConversationId = normalizeMSTeamsConversationId(pendingFile.conversationId);
  +    const invokeConversationId = normalizeMSTeamsConversationId(activity.conversation?.id ?? "");
  +    if (!invokeConversationId || pendingConversationId !== invokeConversationId) {
  +      log.info("file consent conversation mismatch", {
  +        uploadId,
  +        expectedConversationId: pendingConversationId,
  +        receivedConversationId: invokeConversationId || undefined,
  +      });
  +      if (consentResponse.action === "accept") {
  +        await context.sendActivity(expiredUploadMessage);
  +      }
  +      return true;
  +    }
  +  }
  ```
- **16. Fix Summary**: Upgrade to `openclaw` `2026.2.25` (or later) once published.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.25`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.24`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.25`
- **20. Disclosure and Fix Dates**: Published: `2026-02-26T03:58:32Z`; last advisory update: `2026-02-26T03:58:32Z`; fix commit authored date(s): `Thu, 26 Feb 2026 02:49:41 +0100`; public npm release time(s): `openclaw@2026.2.25` published 2026-02-26T04:16:34.010Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-j26j-7qc4-3mrf)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-j26j-7qc4-3mrf)
  - [Commit `347f7b9550064f5f5b33c6e07f64e85b9657b6f1`](https://github.com/openclaw/openclaw/commit/347f7b9550064f5f5b33c6e07f64e85b9657b6f1)
  - [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
  - [CWE-862](https://cwe.mitre.org/data/definitions/862.html)
