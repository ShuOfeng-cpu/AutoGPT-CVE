# GHSA-hv93-r4j3-q65f: Hook Session Key Override Enables Targeted Cross-Session Routing

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Hook Session Key Override Enables Targeted Cross-Session Routing
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-hv93-r4j3-q65f`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-330` (Use of Insufficiently Random Values) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-639` (Authorization Bypass Through User-Controlled Key) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: An authenticated HTTP hook request crosses into the internal agent-session namespace. The hook token authenticates the ingress request, but the request body is still caller-controlled. Before the fix, `POST /hooks/agent` accepted a caller-provided `sessionKey` and passed it to the agent dispatcher without proving that the key belonged to the hook ingress context. A value such as `agent:main:dm:<peer>` could therefore select a session outside the hook-specific namespace.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: In the parent tree, `normalizeAgentPayload()` treated a non-empty request `payload.sessionKey` as authoritative, and otherwise generated `hook:<uuid>`. `createHooksRequestHandler()` then dispatched the normalized object directly. Any party possessing the hook token could choose an existing agent, DM, or shared session key and inject a message into that session. The impact is targeted cross-session routing, not merely the use of predictable or deterministic hook keys.
- **7. Technical Root Cause**: Parent `src/gateway/hooks.ts` declared `sessionKey` as required and assigned `payload.sessionKey.trim()` when present. Parent `src/gateway/server-http.ts` called `dispatchAgentHook({ ...normalized.value })` for `/hooks/agent`, and used `mapped.action.sessionKey ?? ""` for mapped hooks; neither path applied a trust-specific policy. The vulnerable code had no distinction between a request-originated key and a trusted mapping/default key, no prefix validation, and no default fixed hook session. The fixed tree introduces `resolveHookSessionKey()` and invokes it separately for `source: "request"` and `source: "mapping"` before dispatch.
- **8. Architectural/Design Root Cause**: The ingress authentication token was treated as if it also authorized arbitrary session selection. Session identity and request authentication are separate security decisions: a valid hook token should authorize submission of a hook event, but should not implicitly authorize selection of another user's or agent's session. The old design also applied normalization at the payload boundary and let downstream dispatch consume the result, so every later handler inherited the unsafe identity choice. The fix moves the decision to an explicit session-policy boundary with a deny-by-default request mode, optional fixed default, and optional namespace allowlist.
- **9. Trigger Prerequisites**: The hook endpoint must be enabled and reachable, the attacker must possess the hook token (the advisory rates this as low privilege), and the deployment must use an affected version. The request must be a valid authenticated `POST /hooks/agent` (or a mapped hook whose action contains a session key) with a chosen key. A target session must already exist or be meaningful to the agent runtime for cross-session context reuse. Persistence is possible when the selected session is reused by later turns; the changed tests exercise authorization and dispatch with mocked agent execution, not a live multi-tenant deployment.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **7.1 High** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`); GitHub Repository Advisory qualitative severity: **High**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: Integrity: a hook-token holder can inject an untrusted message into a selected session rather than an isolated hook session. The selected session's existing conversation state and agent configuration are then used for processing, so the attacker can target a privileged or otherwise sensitive context. The patch itself does not establish direct credential disclosure or code execution; those would require additional capabilities reachable from the targeted session.
- **13. Chained/Indirect Impact**: A poisoned prompt can persist into subsequent turns that reuse the chosen session key and can influence downstream tool/model behavior under that session's normal permissions. If the same hook token is exposed to multiple integrations, the arbitrary key choice also defeats intended per-integration isolation. The advisory does not publish a separate confidentiality impact, so any data disclosure claim remains conditional on the target session's tools and later model behavior.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Parent-tree code at [`0a7201fa8475a6156cd9bc28ee3fbcfb831d88c0`](https://github.com/openclaw/openclaw/commit/0a7201fa8475a6156cd9bc28ee3fbcfb831d88c0) in `src/gateway/hooks.ts` made the request key authoritative. The parent `src/gateway/server-http.ts` then forwarded the value without a session-origin check.

  ```ts
  sessionKey: string;
  ```

  ```ts
  // Parent normalizeAgentPayload(): caller input wins over the generated hook key.
  const sessionKey =
    typeof sessionKeyRaw === "string" && sessionKeyRaw.trim()
      ? sessionKeyRaw.trim()
      : `hook:${idFactory()}`;

  // Parent server-http.ts: direct hook dispatch receives the unvalidated key.
  const runId = dispatchAgentHook({
    ...normalized.value,
    agentId: resolveHookTargetAgentId(hooksConfig, normalized.value.agentId),
  });
  ```
- **15. Fix Patch (Commit)**: Specific fix commit published by the advisory: [`3421b2ec1ee5ae1300e7a89844340c10f5606ad1`](https://github.com/openclaw/openclaw/commit/3421b2ec1ee5ae1300e7a89844340c10f5606ad1) - [PATCH] fix: harden hook session key routing defaults. The patch changes the payload field to optional, adds a resolved `HookSessionPolicy`, and gates both direct requests and mappings before `dispatchAgentHook()`.

  Fix excerpt from `src/gateway/hooks.ts`:

  ```diff
  +  sessionKey?: string;
  +
  +  const sessionKey = resolveHookSessionKey({
  +    hooksConfig,
  +    source: "request",
  +    sessionKey: normalized.value.sessionKey,
  +  });
  +  if (!sessionKey.ok) {
  +    sendJson(res, 400, { ok: false, error: sessionKey.error });
  +    return true;
  +  }
  +  const runId = dispatchAgentHook({
  +    ...normalized.value,
  +    sessionKey: sessionKey.value,
  +  });
  ```
- **16. Fix Summary**: The fixed tree establishes three controls. (1) `hooks.allowRequestSessionKey` defaults to `false`, so a request-supplied key is rejected with HTTP 400. (2) `hooks.defaultSessionKey` can pin hook runs to a known session; otherwise the generated fallback remains in the `hook:` namespace. (3) `hooks.allowedSessionKeyPrefixes` constrains explicit request and mapping keys, and configuration validation checks that the default/generated namespace is compatible with the prefix list. The patch applies the resolver to both `/hooks/agent` and mapped agent actions. `src/security/audit-extra.sync.ts` and `src/security/audit.ts` add warnings, escalating to critical for remotely exposed gateways with unrestricted request overrides. Changed tests in `src/gateway/hooks.test.ts`, `src/gateway/server.hooks.e2e.test.ts`, and `src/security/audit.test.ts` cover default denial, explicit opt-in, prefix enforcement, fixed defaults, and audit severity. Tests were inspected, not run locally.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.12`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `>= 2.0.0-beta3, < 2026.2.12`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.12`
- **20. Disclosure and Fix Dates**: Published: `2026-02-14T13:36:56Z`; last advisory update: `2026-02-21T14:11:04Z`; fix commit authored date(s): `Fri, 13 Feb 2026 02:09:01 +0100`; public npm release time(s): `openclaw@2026.2.12` published 2026-02-13T01:53:22.639Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-hv93-r4j3-q65f)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-hv93-r4j3-q65f)
  - [Commit `3421b2ec1ee5ae1300e7a89844340c10f5606ad1`](https://github.com/openclaw/openclaw/commit/3421b2ec1ee5ae1300e7a89844340c10f5606ad1)
  - [Parent commit `0a7201fa8475a6156cd9bc28ee3fbcfb831d88c0`](https://github.com/openclaw/openclaw/commit/0a7201fa8475a6156cd9bc28ee3fbcfb831d88c0)
  - [Parent source: `src/gateway/hooks.ts`](https://github.com/openclaw/openclaw/blob/0a7201fa8475a6156cd9bc28ee3fbcfb831d88c0/src/gateway/hooks.ts)
  - [Fixed source: `src/gateway/hooks.ts`](https://github.com/openclaw/openclaw/blob/3421b2ec1ee5ae1300e7a89844340c10f5606ad1/src/gateway/hooks.ts)
  - [Changed test: `src/gateway/hooks.test.ts`](https://github.com/openclaw/openclaw/blob/3421b2ec1ee5ae1300e7a89844340c10f5606ad1/src/gateway/hooks.test.ts)
  - [Changed E2E test: `src/gateway/server.hooks.e2e.test.ts`](https://github.com/openclaw/openclaw/blob/3421b2ec1ee5ae1300e7a89844340c10f5606ad1/src/gateway/server.hooks.e2e.test.ts)
  - [CWE-330](https://cwe.mitre.org/data/definitions/330.html)
  - [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
