# GHSA-w5c7-9qqw-6645: Inter-session prompts could be treated as direct user instructions

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Inter-session prompts could be treated as direct user instructions
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-w5c7-9qqw-6645`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-345` (Insufficient Verification of Data Authenticity) [source: GitHub Global Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: Inter-session messages sent via `sessions_send` could be interpreted as direct end-user instructions because they were persisted as `role: "user"` without provenance metadata.
- **7. Technical Root Cause**: Before the fix, routed inter-session prompts were stored as regular user turns without a verifiable source marker. As a result, downstream workers and transcript readers could not distinguish: External user input Internal inter-session routed input
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **7.1 High** (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: A delegated or internal session could inject instructions into another session that appeared equivalent to externally-originated user input. This is an instruction-provenance confusion issue (confused-deputy style), which can lead to unintended privileged behavior in workflows that trust `role: "user"` as a sole authority signal.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/agents/pi-embedded-runner/google.ts` at [`85409e401b65`](https://github.com/openclaw/openclaw/commit/85409e401b6586f83954cb53552395d7aab04797):

  ```diff
  -  const sanitizedImages = await sanitizeSessionMessagesImages(params.messages, "session:history", {
  -    sanitizeMode: policy.sanitizeMode,
  -    sanitizeToolCallIds: policy.sanitizeToolCallIds,
  -    toolCallIdMode: policy.toolCallIdMode,
  -    preserveSignatures: policy.preserveSignatures,
  -    sanitizeThoughtSignatures: policy.sanitizeThoughtSignatures,
  -  });
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`85409e401b6586f83954cb53552395d7aab04797`](https://github.com/openclaw/openclaw/commit/85409e401b6586f83954cb53552395d7aab04797) - [PATCH] fix: preserve inter-session input provenance (thanks @anbecker).

  Fix excerpt from `src/agents/pi-embedded-runner/google.ts`:

  ```diff
  +  const withInterSessionMarkers = annotateInterSessionUserMessages(params.messages);
  +  const sanitizedImages = await sanitizeSessionMessagesImages(
  +    withInterSessionMarkers,
  +    "session:history",
  +    {
  +      sanitizeMode: policy.sanitizeMode,
  +      sanitizeToolCallIds: policy.sanitizeToolCallIds,
  +      toolCallIdMode: policy.toolCallIdMode,
  +      preserveSignatures: policy.preserveSignatures,
  +      sanitizeThoughtSignatures: policy.sanitizeThoughtSignatures,
  +    },
  +  );
  ```
- **16. Fix Summary**: OpenClaw now carries explicit input provenance end-to-end for routed prompts. Key changes: Added structured provenance model (`inputProvenance`) with `kind` values including `inter_session`. `sessions_send` and agent-to-agent steps now set inter-session provenance when invoking target runs. Provenance is persisted on user messages as `message.provenance.kind = "inter_session"` (role remains `user` for provider compatibility). Transcript readers and memory helpers were updated to respect provenance and avoid treating inter-session prompts as external user-originated input. Runtime context rebuilding now annotates inter-session turns with an explicit in-memory marker (`[Inter-session message]`) for clearer model-side disambiguation. Regression tests were added for transcript parsing, session tools flow, runner sanitization, and memory hook behavior.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>=2026.2.13`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<2026.2.13`
- **19. Fixed Versions**: `openclaw` (npm): `>=2026.2.13`
- **20. Disclosure and Fix Dates**: Published: `2026-02-15T23:31:43Z`; last advisory update: `2026-02-21T10:37:10Z`; fix commit authored date(s): `Fri, 13 Feb 2026 02:01:53 +0100`; public npm release time(s): `openclaw@2026.2.13` published 2026-02-14T03:20:08.219Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-w5c7-9qqw-6645)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-w5c7-9qqw-6645)
  - [Commit `85409e401b6586f83954cb53552395d7aab04797`](https://github.com/openclaw/openclaw/commit/85409e401b6586f83954cb53552395d7aab04797)
  - [CWE-345](https://cwe.mitre.org/data/definitions/345.html)
