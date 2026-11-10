# GHSA-6x2m-hqfw-hvpj: Node exec approvals could be replayed across nodes

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Node exec approvals could be replayed across nodes
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-6x2m-hqfw-hvpj`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-285` (Improper Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: `exec.approval` requests for `host=node` were not explicitly bound to the target `nodeId`, so an approval intended for one node could be replayed for a different node under the same operator-controlled gateway fleet. An operator approval for a `system.run` request could be reused across nodes if the request payload did not carry node identity through approval and execution checks.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: `exec.approval` requests for `host=node` were not explicitly bound to the target `nodeId`, so an approval intended for one node could be replayed for a different node under the same operator-controlled gateway fleet.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: An operator approval for a `system.run` request could be reused across nodes if the request payload did not carry node identity through approval and execution checks.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.9 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: An operator approval for a `system.run` request could be reused across nodes if the request payload did not carry node identity through approval and execution checks.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/gateway/server-methods/exec-approval.ts` at [`4a3f8438e527`](https://github.com/openclaw/openclaw/commit/4a3f8438e527ac371a67fe7ac68a287f0dbe6063):

  ```diff
  -        host: p.host ?? null,
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`4a3f8438e527ac371a67fe7ac68a287f0dbe6063`](https://github.com/openclaw/openclaw/commit/4a3f8438e527ac371a67fe7ac68a287f0dbe6063) - [PATCH] fix(gateway): bind node exec approvals to nodeId.

  Fix excerpt from `src/gateway/server-methods/exec-approval.ts`:

  ```diff
  +        nodeId: host === "node" ? nodeId : null,
  +        host: host || null,
  ```
- **16. Fix Summary**: The fix requires and persists `nodeId` for `host=node` approval requests and rejects execution when the approving node binding does not match the invoking node.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.23`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.22-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.23`
- **20. Disclosure and Fix Dates**: Published: `2026-02-24T05:27:18Z`; last advisory update: `2026-02-24T05:27:18Z`; fix commit authored date(s): `Tue, 24 Feb 2026 03:05:36 +0000`; public npm release time(s): `openclaw@2026.2.23` published 2026-02-24T05:40:17.896Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-6x2m-hqfw-hvpj)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-6x2m-hqfw-hvpj)
  - [Commit `4a3f8438e527ac371a67fe7ac68a287f0dbe6063`](https://github.com/openclaw/openclaw/commit/4a3f8438e527ac371a67fe7ac68a287f0dbe6063)
  - [CWE-285](https://cwe.mitre.org/data/definitions/285.html)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
