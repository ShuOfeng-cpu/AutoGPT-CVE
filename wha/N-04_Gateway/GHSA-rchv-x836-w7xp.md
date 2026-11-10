# GHSA-rchv-x836-w7xp: Dashboard leaked gateway auth material via browser URL/query and localStorage

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Dashboard leaked gateway auth material via browser URL/query and localStorage
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-rchv-x836-w7xp`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-200` (Exposure of Sensitive Information to an Unauthorized Actor) [source: GitHub Global Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Dashboard leaked gateway auth material via browser URL/query and localStorage
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Before the fix, the macOS app appended the shared Gateway `token` and `password` to the Dashboard URL query string when opening the Control UI in the browser.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **7.1 High** (`CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: An attacker with access to browser-controlled surfaces or persistent browser storage could recover a valid Gateway admin token and reuse it against the OpenClaw management interface. The exposure chain was: 1. macOS `Open Dashboard` constructed a URL with auth material. 2. The browser received that credential-bearing URL. 3. The Control UI imported the token from the URL. 4. The Control UI persisted the token in `localStorage`.
- **13. Chained/Indirect Impact**: The exposure chain was: 1.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `apps/macos/Sources/OpenClaw/GatewayEndpointStore.swift` at [`10d0e3f3ca92`](https://github.com/openclaw/openclaw/commit/10d0e3f3ca92326df0ca071fabffe463742f263c):

  ```diff
  -        var queryItems: [URLQueryItem] = []
  -            queryItems.append(URLQueryItem(name: "token", value: token))
  -        if let password = config.password?.trimmingCharacters(in: .whitespacesAndNewlines),
  -           !password.isEmpty
  -        {
  -            queryItems.append(URLQueryItem(name: "password", value: password))
  -        components.queryItems = queryItems.isEmpty ? nil : queryItems
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`10d0e3f3ca92326df0ca071fabffe463742f263c`](https://github.com/openclaw/openclaw/commit/10d0e3f3ca92326df0ca071fabffe463742f263c) - [PATCH] fix(dashboard): keep gateway tokens out of URL storage.

  Fix excerpt from `apps/macos/Sources/OpenClaw/GatewayEndpointStore.swift`:

  ```diff
  +        var fragmentItems: [URLQueryItem] = []
  +            fragmentItems.append(URLQueryItem(name: "token", value: token))
  +        components.queryItems = nil
  +        if fragmentItems.isEmpty {
  +            components.fragment = nil
  +        } else {
  +            var fragment = URLComponents()
  +            fragment.queryItems = fragmentItems
  +            components.fragment = fragment.percentEncodedQuery
  ```
- **16. Fix Summary**: The fix aligns the macOS Dashboard flow with the safer existing CLI/bootstrap pattern and removes persistent browser token storage: macOS Dashboard now passes the Gateway token via URL fragment instead of query parameters. macOS Dashboard no longer propagates the shared Gateway password into browser URLs. Control UI keeps Gateway tokens in memory only for the current tab. Control UI scrubs legacy persisted tokens from `openclaw.control.settings.v1` on load. Regression tests cover fragment transport, password omission, and token-scrubbing behavior.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.3.7`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.3.2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.3.7`
- **20. Disclosure and Fix Dates**: Published: `2026-03-08T14:26:54Z`; last advisory update: `2026-03-08T14:26:54Z`; fix commit authored date(s): `Sat, 7 Mar 2026 18:33:19 +0000`; public npm release time(s): `openclaw@2026.3.7` published 2026-03-08T05:46:01.183Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-rchv-x836-w7xp)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-rchv-x836-w7xp)
  - [Commit `10d0e3f3ca92326df0ca071fabffe463742f263c`](https://github.com/openclaw/openclaw/commit/10d0e3f3ca92326df0ca071fabffe463742f263c)
  - [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
