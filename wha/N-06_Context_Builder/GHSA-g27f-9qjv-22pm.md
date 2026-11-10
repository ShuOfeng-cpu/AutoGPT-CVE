# GHSA-g27f-9qjv-22pm: OpenClaw log poisoning (indirect prompt injection) via WebSocket headers

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: OpenClaw log poisoning (indirect prompt injection) via WebSocket headers
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-g27f-9qjv-22pm`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-117` (Improper Output Neutralization for Logs) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: `src/gateway/server/ws-connection.ts`.
- **5. Trust Boundary Crossing**: Official advisory narrative: If an unauthenticated client can reach the gateway and send crafted header values, those values may be written into core logs.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: In `openclaw` versions prior to `2026.2.13`, OpenClaw logged certain WebSocket request headers (including `Origin` and `User-Agent`) without neutralization or length limits on the "closed before connect" path. If an unauthenticated client can reach the gateway and send crafted header values, those values may be written into core logs. Under workflows where logs are later read or interpreted by an LLM (for example via AI-assisted debugging), this can increase the risk of indirect prompt injection (log poisoning).
- **7. Technical Root Cause**: Component: `src/gateway/server/ws-connection.ts` Trigger: WebSocket connection closes before completing the connect/handshake; header values are included in the log message and structured context.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: If an unauthenticated client can reach the gateway and send crafted header values, those values may be written into core logs. If you do not feed logs into an LLM or other automation, impact is limited.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **3.1 Low** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N`); GitHub Repository Advisory qualitative severity: **Low**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: This issue is primarily an indirect prompt injection risk and depends on downstream log consumption behavior. If you do not feed logs into an LLM or other automation, impact is limited.
- **13. Chained/Indirect Impact**: This issue is primarily an indirect prompt injection risk and depends on downstream log consumption behavior.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/gateway/server/ws-connection.ts` at [`d637a2635054`](https://github.com/openclaw/openclaw/commit/d637a263505448bf4505b85535babbfaacedbaac):

  ```diff
  -        host: requestHost,
  -        origin: requestOrigin,
  -        userAgent: requestUserAgent,
  -        forwardedFor,
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`d637a263505448bf4505b85535babbfaacedbaac`](https://github.com/openclaw/openclaw/commit/d637a263505448bf4505b85535babbfaacedbaac) - [PATCH] Gateway: sanitize WebSocket log headers (#15592); [`e84318e4bcdc948d92e57fda1eb763a65e1774f0`](https://github.com/openclaw/openclaw/commit/e84318e4bcdc948d92e57fda1eb763a65e1774f0) - [PATCH] fix: replace control-char regex with explicit sanitizer.

  Fix excerpt from `src/gateway/server/ws-connection.ts`:

  ```diff
  +        host: logHost,
  +        origin: logOrigin,
  +        userAgent: logUserAgent,
  +        forwardedFor: logForwardedFor,
  ```
- **16. Fix Summary**: Header values written to gateway logs are now sanitized and truncated (including removal of control/format characters and length limiting). Fix commits: `d637a263505448bf4505b85535babbfaacedbaac`, `e84318e4bcdc948d92e57fda1eb763a65e1774f0` (PR #15592)
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `2026.2.13`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.12`
- **19. Fixed Versions**: `openclaw` (npm): `2026.2.13`
- **20. Disclosure and Fix Dates**: Published: `2026-02-14T20:19:44Z`; last advisory update: `2026-02-14T20:19:44Z`; fix commit authored date(s): `Fri, 13 Feb 2026 11:11:54 -0600`; `Fri, 13 Feb 2026 17:57:14 +0000`; public npm release time(s): `openclaw@2026.2.13` published 2026-02-14T03:20:08.219Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-g27f-9qjv-22pm)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-g27f-9qjv-22pm)
  - [Commit `d637a263505448bf4505b85535babbfaacedbaac`](https://github.com/openclaw/openclaw/commit/d637a263505448bf4505b85535babbfaacedbaac)
  - [Commit `e84318e4bcdc948d92e57fda1eb763a65e1774f0`](https://github.com/openclaw/openclaw/commit/e84318e4bcdc948d92e57fda1eb763a65e1774f0)
  - [Pull request #15592](https://github.com/openclaw/openclaw/pull/15592)
  - [CWE-117](https://cwe.mitre.org/data/definitions/117.html)
