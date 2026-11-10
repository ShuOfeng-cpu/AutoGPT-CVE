# GHSA-534w-2vm4-89xr: Zalo group sender allowlist bypass permits unauthorized GROUP dispatch

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Zalo group sender allowlist bypass permits unauthorized GROUP dispatch
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-534w-2vm4-89xr`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-284` (Improper Access Control) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: A missing group-sender authorization check in the Zalo plugin allowed unauthorized `GROUP` messages to enter agent dispatch paths in configurations intended to restrict group traffic. When Zalo group handling was configured with allowlist-style controls, a sender not present in the intended group allowlist could still trigger agent processing through the `GROUP` message path.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Zalo group sender allowlist bypass permits unauthorized GROUP dispatch
- **7. Technical Root Cause**: Group access checks were not consistently enforced before dispatch for Zalo `GROUP` messages. The fix adds explicit runtime group-policy evaluation (`groupPolicy`, `groupAllowFrom`, fallback to `allowFrom`) and fail-closed behavior for missing provider config.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: When Zalo group handling was configured with allowlist-style controls, a sender not present in the intended group allowlist could still trigger agent processing through the `GROUP` message path.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **5.3 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: When Zalo group handling was configured with allowlist-style controls, a sender not present in the intended group allowlist could still trigger agent processing through the `GROUP` message path.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `extensions/zalo/src/channel.ts` at [`b4010a0b6270`](https://github.com/openclaw/openclaw/commit/b4010a0b627025c809c0e5dbdbd4770f3bc59ef8):

  ```diff
  -    chatTypes: ["direct"],
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`b4010a0b627025c809c0e5dbdbd4770f3bc59ef8`](https://github.com/openclaw/openclaw/commit/b4010a0b627025c809c0e5dbdbd4770f3bc59ef8) - [PATCH] fix(zalo): enforce group sender policy in groups.

  Fix excerpt from `extensions/zalo/src/channel.ts`:

  ```diff
  +    chatTypes: ["direct", "group"],
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.24`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.23`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.24`
- **20. Disclosure and Fix Dates**: Published: `2026-02-25T04:37:33Z`; last advisory update: `2026-02-25T04:37:33Z`; fix commit authored date(s): `Tue, 24 Feb 2026 23:30:05 +0000`; public npm release time(s): `openclaw@2026.2.24` published 2026-02-25T02:50:19.980Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-534w-2vm4-89xr)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-534w-2vm4-89xr)
  - [Commit `b4010a0b627025c809c0e5dbdbd4770f3bc59ef8`](https://github.com/openclaw/openclaw/commit/b4010a0b627025c809c0e5dbdbd4770f3bc59ef8)
  - [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
