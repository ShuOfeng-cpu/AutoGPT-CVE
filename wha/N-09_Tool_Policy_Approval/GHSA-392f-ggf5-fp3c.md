# GHSA-392f-ggf5-fp3c: Unicode canonicalization drift in node metadata policy classification could broaden node allowlists

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Unicode canonicalization drift in node metadata policy classification could broaden node allowlists
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-392f-ggf5-fp3c`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-176` (Improper Handling of Unicode Encoding) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-436` (Interpretation Conflict) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: A paired node could supply Unicode-confusable `platform` or `deviceFamily` metadata that passed metadata pinning but classified differently for command policy resolution, broadening default node command allowlists. This is a policy-bypass issue within the paired-node trust boundary and can expand node command availability beyond intended defaults.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A paired node could supply Unicode-confusable `platform` or `deviceFamily` metadata that passed metadata pinning but classified differently for command policy resolution, broadening default node command allowlists.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.9 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: This is a policy-bypass issue within the paired-node trust boundary and can expand node command availability beyond intended defaults.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Not publicly extractable from a specific fix patch. The advisory may describe the affected flow, but no qualifying removed-code excerpt was available.
- **15. Fix Patch (Commit)**: No specific vulnerability-fixing commit is publicly identified by the advisory.
- **16. Fix Summary**: Node metadata canonicalization was hardened against confusables, and unknown platform defaults were made conservative (excluding `system.run` and `system.which` unless explicitly allowlisted).
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.3.1`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.26`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.3.1`
- **20. Disclosure and Fix Dates**: Published: `2026-03-02T05:46:02Z`; last advisory update: `2026-03-02T05:46:02Z`; public npm release time(s): `openclaw@2026.3.1` published 2026-03-02T04:50:50.547Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-392f-ggf5-fp3c)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-392f-ggf5-fp3c)
  - [CWE-176](https://cwe.mitre.org/data/definitions/176.html)
  - [CWE-436](https://cwe.mitre.org/data/definitions/436.html)
