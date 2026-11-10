# GHSA-846p-hgpv-vphc: QQ Bot structured payloads could read arbitrary local files

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: QQ Bot structured payloads could read arbitrary local files
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-846p-hgpv-vphc`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-22` (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) [source: GitHub Global Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Before OpenClaw 2026.4.2, QQ Bot structured media payloads could read local files from attacker-chosen paths. A crafted structured payload could escape QQ Bot-owned media roots and cause arbitrary file reads on the host.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.9 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: Prompt-influenced structured payload output could exfiltrate any host file readable by the OpenClaw process through the QQ Bot media-send path. This was a real confidentiality bug on the host filesystem boundary.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `extensions/qqbot/src/reply-dispatcher.ts` at [`2c45b06afdd6`](https://github.com/openclaw/openclaw/commit/2c45b06afdd6f7c621038b5419d8e661cff34a7f):

  ```diff
  -import {
  -  checkFileSize,
  -  readFileAsync,
  -  fileExistsAsync,
  -  formatFileSize,
  -} from "./utils/file-utils.js";
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`2c45b06afdd6f7c621038b5419d8e661cff34a7f`](https://github.com/openclaw/openclaw/commit/2c45b06afdd6f7c621038b5419d8e661cff34a7f) - [PATCH] fix(qqbot): restrict structured payload local paths (#58453).

  Fix excerpt from `extensions/qqbot/src/reply-dispatcher.ts`:

  ```diff
  +import { MAX_UPLOAD_SIZE, formatFileSize } from "./utils/file-utils.js";
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.4.2`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.4.1`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.4.2`
- **20. Disclosure and Fix Dates**: Published: `2026-04-02T19:21:36Z`; last advisory update: `2026-04-03T01:33:55Z`; fix commit authored date(s): `Thu, 2 Apr 2026 02:20:52 -0700`; public npm release time(s): `openclaw@2026.4.2` published 2026-04-02T19:02:03.564Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-846p-hgpv-vphc)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-846p-hgpv-vphc)
  - [Commit `2c45b06afdd6f7c621038b5419d8e661cff34a7f`](https://github.com/openclaw/openclaw/commit/2c45b06afdd6f7c621038b5419d8e661cff34a7f)
  - [Pull request #58453](https://github.com/openclaw/openclaw/pull/58453)
  - [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
