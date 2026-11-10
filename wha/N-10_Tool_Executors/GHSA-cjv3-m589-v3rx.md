# GHSA-cjv3-m589-v3rx: Canvas route hardening for mixed-trust deployments

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Canvas route hardening for mixed-trust deployments
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-cjv3-m589-v3rx`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-79` (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-1021` (Improper Restriction of Rendered UI Layers or Frames) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Official advisory narrative: In strict single-operator trusted-host setups, practical exposure is lower.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: This advisory tracks a defense-in-depth hardening for canvas routes. In mixed-trust or network-visible deployments, prior canvas auth/fallback behavior could broaden access beyond intended boundaries.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: In mixed-trust or network-visible deployments, prior canvas auth/fallback behavior could broaden access beyond intended boundaries.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.3 Medium** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: Risk was highest in non-loopback or mixed-trust environments. In strict single-operator trusted-host setups, practical exposure is lower.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/canvas-host/a2ui.ts` at [`c45f3c5b004c`](https://github.com/openclaw/openclaw/commit/c45f3c5b004c8d63dc0e282e2176f8c9355d24f1):

  ```diff
  -    const ws = new WebSocket(proto + "://" + location.host + ${JSON.stringify(CANVAS_WS_PATH)});
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`c45f3c5b004c8d63dc0e282e2176f8c9355d24f1`](https://github.com/openclaw/openclaw/commit/c45f3c5b004c8d63dc0e282e2176f8c9355d24f1) - [PATCH] fix(gateway): harden canvas auth with session capabilities; [`08a7967936cfc0b2af6b27ec1f9272542648ad6c`](https://github.com/openclaw/openclaw/commit/08a7967936cfc0b2af6b27ec1f9272542648ad6c) - [PATCH] fix(security): fail closed on gateway bind fallback and tighten canvas IP fallback.

  Fix excerpt from `src/canvas-host/a2ui.ts`:

  ```diff
  +    const cap = new URLSearchParams(location.search).get("oc_cap");
  +    const capQuery = cap ? "?oc_cap=" + encodeURIComponent(cap) : "";
  +    const ws = new WebSocket(proto + "://" + location.host + ${JSON.stringify(CANVAS_WS_PATH)} + capQuery);
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>=2026.2.21`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.19-2`
- **19. Fixed Versions**: `openclaw` (npm): `>=2026.2.21`
- **20. Disclosure and Fix Dates**: Published: `2026-02-21T18:16:09Z`; last advisory update: `2026-02-21T18:16:09Z`; fix commit authored date(s): `Thu, 19 Feb 2026 15:50:42 +0100`; `Thu, 19 Feb 2026 14:36:39 +0100`; public npm release time(s): `openclaw@2026.2.21` published 2026-02-21T16:02:01.230Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-cjv3-m589-v3rx)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-cjv3-m589-v3rx)
  - [Commit `c45f3c5b004c8d63dc0e282e2176f8c9355d24f1`](https://github.com/openclaw/openclaw/commit/c45f3c5b004c8d63dc0e282e2176f8c9355d24f1)
  - [Commit `08a7967936cfc0b2af6b27ec1f9272542648ad6c`](https://github.com/openclaw/openclaw/commit/08a7967936cfc0b2af6b27ec1f9272542648ad6c)
  - [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
  - [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html)
