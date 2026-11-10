# GHSA-hfpr-jhpq-x4rm: `operator.write` chat.send could reach admin-only config writes

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: `operator.write` chat.send could reach admin-only config writes
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-hfpr-jhpq-x4rm`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: `/config`, ` / `, `/config set|unset`, `/config show`.
- **5. Trust Boundary Crossing**: Official advisory narrative: A gateway client authenticated with `operator.write` could route `/config set` or `/config unset` through `chat.send` and reach persistent config mutation even though direct config RPC methods are admin-scoped. That allowed an authenticated `operator.write` gateway client to bridge into persistent config writes even though direct `config.*` RPC methods remain `operator.admin` scoped.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A gateway client authenticated with `operator.write` could route `/config set` or `/config unset` through `chat.send` and reach persistent config mutation even though direct config RPC methods are admin-scoped.
- **7. Technical Root Cause**: Before the fix, `chat.send` ran slash commands in an internal gateway-chat context with `CommandAuthorized: true`, and `/config` write paths only checked command authorization plus `commands.config` / `channels.<provider>.configWrites` gates. That allowed an authenticated `operator.write` gateway client to bridge into persistent config writes even though direct `config.*` RPC methods remain `operator.admin` scoped. The fix keeps command functionality intact while restoring the intended scope boundary: persistent `/config set|unset` writes routed through gateway `chat.send` now require `operator.admin` read-only `/config show` remains available to normal write-scoped gateway clients normal messaging-channel `/config` behavior remains unchanged
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: The fix keeps command functionality intact while restoring the intended scope boundary: persistent `/config set|unset` writes routed through gateway `chat.send` now require `operator.admin` read-only `/config show` remains available to normal write-scoped gateway clients normal messaging-channel `/config` behavior remains unchanged This is a real authorization mismatch, but exploitability requires an already authenticated gateway client with `operator.write`, `chat.send` access, and `/config` command support enabled.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **4.3 Medium** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: This is a real authorization mismatch, but exploitability requires an already authenticated gateway client with `operator.write`, `chat.send` access, and `/config` command support enabled. Maintainer severity is set to medium because the bug is a scoped control-plane privilege mismatch rather than a broad unauthenticated or generic remote compromise. The main consequence is unintended persistent config mutation.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/auto-reply/reply/commands-approve.ts` at [`5f8f58ae25e2`](https://github.com/openclaw/openclaw/commit/5f8f58ae25e2a78f31b06edcf26532d634ca554e):

  ```diff
  -import {
  -  GATEWAY_CLIENT_MODES,
  -  GATEWAY_CLIENT_NAMES,
  -  isInternalMessageChannel,
  -} from "../../utils/message-channel.js";
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`5f8f58ae25e2a78f31b06edcf26532d634ca554e`](https://github.com/openclaw/openclaw/commit/5f8f58ae25e2a78f31b06edcf26532d634ca554e) - [PATCH] fix(gateway): require admin for chat config writes.

  Fix excerpt from `src/auto-reply/reply/commands-approve.ts`:

  ```diff
  +import { GATEWAY_CLIENT_MODES, GATEWAY_CLIENT_NAMES } from "../../utils/message-channel.js";
  +import { requireGatewayClientScopeForInternalChannel } from "./command-gates.js";
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.3.7`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.3.2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.3.7`
- **20. Disclosure and Fix Dates**: Published: `2026-03-08T14:26:56Z`; last advisory update: `2026-03-08T14:26:56Z`; fix commit authored date(s): `Sat, 7 Mar 2026 19:38:40 +0000`; public npm release time(s): `openclaw@2026.3.7` published 2026-03-08T05:46:01.183Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-hfpr-jhpq-x4rm)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-hfpr-jhpq-x4rm)
  - [Commit `5f8f58ae25e2a78f31b06edcf26532d634ca554e`](https://github.com/openclaw/openclaw/commit/5f8f58ae25e2a78f31b06edcf26532d634ca554e)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
