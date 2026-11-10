# GHSA-jxrq-8fm4-9p58: Zip extraction symlink traversal could write outside destination

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Zip extraction symlink traversal could write outside destination
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-jxrq-8fm4-9p58`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-59` (Improper Link Resolution Before File Access ('Link Following')) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: `src/infra/archive.ts`.
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A path confinement bypass in OpenClaw ZIP extraction allowed writes outside the intended destination when a pre-existing symlink was present under the extraction root.
- **7. Technical Root Cause**: The vulnerable path was in `src/infra/archive.ts` ZIP extraction logic. Output-path checks were lexical, but writes could still traverse an existing symlink in destination path segments. The fix blocks this by: rejecting symlink traversal in destination path segments, validating resolved destination paths remain inside the extraction root, using no-follow file opens for ZIP output writes where supported, adding a regression test for pre-seeded destination symlink traversal.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: A path confinement bypass in OpenClaw ZIP extraction allowed writes outside the intended destination when a pre-existing symlink was present under the extraction root. The fix blocks this by: rejecting symlink traversal in destination path segments, validating resolved destination paths remain inside the extraction root, using no-follow file opens for ZIP output writes where supported, adding a regression test for pre-seeded destination symlink traversal.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **7.1 High** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: Type: Arbitrary file write outside extraction root via symlink traversal during ZIP extraction. Preconditions: attacker-controlled archive extraction plus pre-existing symlink in destination path.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/infra/archive.ts` at [`4b226b74f5fd`](https://github.com/openclaw/openclaw/commit/4b226b74f5fd3b106a83a6347fd404172e2fd246):

  ```diff
  -import { createWriteStream } from "node:fs";
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`4b226b74f5fd3b106a83a6347fd404172e2fd246`](https://github.com/openclaw/openclaw/commit/4b226b74f5fd3b106a83a6347fd404172e2fd246) - [PATCH] fix(security): block zip symlink escape in archive extraction.

  Fix excerpt from `src/infra/archive.ts`:

  ```diff
  +import { constants as fsConstants } from "node:fs";
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.22`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.21-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.22`
- **20. Disclosure and Fix Dates**: Published: `2026-02-23T00:52:17Z`; last advisory update: `2026-02-23T00:52:17Z`; fix commit authored date(s): `Sat, 21 Feb 2026 19:42:11 +0100`; public npm release time(s): `openclaw@2026.2.22` published 2026-02-23T00:36:27.582Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-jxrq-8fm4-9p58)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-jxrq-8fm4-9p58)
  - [Commit `4b226b74f5fd3b106a83a6347fd404172e2fd246`](https://github.com/openclaw/openclaw/commit/4b226b74f5fd3b106a83a6347fd404172e2fd246)
  - [CWE-59](https://cwe.mitre.org/data/definitions/59.html)
