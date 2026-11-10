# GHSA-h656-5vcf-cm23: Telegram: Unauthorized Senders Trigger Media Download and Disk Write Before Access Check

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Telegram: Unauthorized Senders Trigger Media Download and Disk Write Before Access Check
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-h656-5vcf-cm23`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-208` (Observable Timing Discrepancy) [source: GitHub Global Advisory]; `CWE-284` (Improper Access Control) [source: GitHub Repository Advisory]; `CWE-404` (Improper Resource Shutdown or Release) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-406` (Insufficient Control of Network Message Volume (Network Amplification)) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-770` (Allocation of Resources Without Limits or Throttling) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: In Telegram DM mode, inbound media was downloaded and written to disk before sender authorization checks completed. An unauthorized sender could trigger inbound media download/write activity (including media groups) even when DM access should be denied.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Telegram: Unauthorized Senders Trigger Media Download and Disk Write Before Access Check
- **7. Technical Root Cause**: The Telegram handler flow now enforces DM authorization before media download/write paths execute, including media-group handling. Inbound channel activity tracking was also moved to run after DM authorization in the Telegram message context path.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: An unauthorized sender could trigger inbound media download/write activity (including media groups) even when DM access should be denied.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: Official advisory narrative: An unauthorized sender could trigger inbound media download/write activity (including media groups) even when DM access should be denied.
- **12. Direct Impact**: In Telegram DM mode, inbound media was downloaded and written to disk before sender authorization checks completed. An unauthorized sender could trigger inbound media download/write activity (including media groups) even when DM access should be denied.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/telegram/bot-message-context.ts` at [`9514201fb9b5`](https://github.com/openclaw/openclaw/commit/9514201fb9b51de5d0b23151110d0ff5d9c8bd67):

  ```diff
  -import { buildPairingReply } from "../pairing/pairing-messages.js";
  -import { upsertChannelPairingRequest } from "../pairing/pairing-store.js";
  -import {
  -  firstDefined,
  -  isSenderAllowed,
  -  normalizeAllowFromWithStore,
  -  resolveSenderAllowMatch,
  -} from "./bot-access.js";
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`9514201fb9b51de5d0b23151110d0ff5d9c8bd67`](https://github.com/openclaw/openclaw/commit/9514201fb9b51de5d0b23151110d0ff5d9c8bd67) - [PATCH] fix(telegram): block unauthorized DM media downloads.

  Fix excerpt from `src/telegram/bot-message-context.ts`:

  ```diff
  +import { firstDefined, isSenderAllowed, normalizeAllowFromWithStore } from "./bot-access.js";
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.24`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<=2026.2.23`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.24`
- **20. Disclosure and Fix Dates**: Published: `2026-02-25T04:37:39Z`; last advisory update: `2026-02-25T04:37:39Z`; fix commit authored date(s): `Tue, 24 Feb 2026 23:43:37 +0000`; public npm release time(s): `openclaw@2026.2.24` published 2026-02-25T02:50:19.980Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-h656-5vcf-cm23)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-h656-5vcf-cm23)
  - [Commit `9514201fb9b51de5d0b23151110d0ff5d9c8bd67`](https://github.com/openclaw/openclaw/commit/9514201fb9b51de5d0b23151110d0ff5d9c8bd67)
  - [CWE-208](https://cwe.mitre.org/data/definitions/208.html)
  - [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
  - [CWE-404](https://cwe.mitre.org/data/definitions/404.html)
  - [CWE-406](https://cwe.mitre.org/data/definitions/406.html)
  - [CWE-770](https://cwe.mitre.org/data/definitions/770.html)
