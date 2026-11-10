# GHSA-jjgj-cpp9-cvpv: Local File Exfiltration via MCP Tool Result MEDIA: Directive Injection

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Local File Exfiltration via MCP Tool Result MEDIA: Directive Injection
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-jjgj-cpp9-cvpv`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-22` (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-200` (Exposure of Sensitive Information to an Unauthorized Actor) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: OpenClaw (all versions up to and including latest as of 2026-02-19)
- **5. Trust Boundary Crossing**: An untrusted MCP/plugin tool result crossed the tool-output boundary into OpenClaw's local-media loader and then into outbound channel delivery. The vulnerable path allowed a tool-controlled `MEDIA:` or `details.path` value to select a local file under a broad default root; the file bytes could then leave the host as a messaging attachment.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A malicious or compromised MCP (Model Context Protocol) tool server can exfiltrate arbitrary local files from the host system by injecting `MEDIA:` directives into tool result text content. OpenClaw's tool result processing pipeline extracts file paths from `MEDIA:` tokens without source-level validation, passes them through a `localRoots` allowlist check that includes `os.tmpdir()` by default (covering `/tmp` on Linux/macOS and `%TEMP%` on Windows), and then reads and delivers the file contents to external messaging channels such as Discord, Slack, Telegram, and WhatsApp.
- **7. Technical Root Cause**: In the affected parent source [`67edc7790f2c1f69da48847e4623f5d3e76fbc15`](https://github.com/openclaw/openclaw/commit/67edc7790f2c1f69da48847e4623f5d3e76fbc15), `extractToolResultMediaPaths()` parsed line-start `MEDIA:` tokens and image `details.path` values without knowing whether the producing tool was trusted. `handleToolExecutionEnd()` then forwarded the result directly to `onToolResult`. The local-media policy separately included the process-wide `os.tmpdir()` in `buildMediaLocalRoots()`, so a path selected by an MCP/plugin result could pass the allowlist and be read. The same extraction path was also used by the streaming subscription path, so filtering only one sink would have left a duplicate delivery route.
- **8. Architectural/Design Root Cause**: The design conflated “a tool result contains a media-looking token” with “OpenClaw is authorized to read and deliver that local path.” Source provenance was discarded before media policy evaluation, and the default local root was a shared OS directory rather than an OpenClaw-owned, permission-controlled directory. The fix restores provenance at both result-delivery sinks and narrows the default temp root, preserving remote HTTP media for untrusted tools without granting them local-file read capability.
- **9. Trigger Prerequisites**: Practical exploitation required an OpenClaw deployment that ran a malicious or compromised MCP/plugin tool, processed its result through the embedded-agent media path, and had an outbound channel configured for attachment delivery. The attacker-controlled tool emitted a local path (or `file://`/`details.path`) in a result; on affected systems the target had to resolve under the broad temp/state roots. The published PoC was self-contained with Node.js 18+, but that standalone PoC does not by itself prove every deployment has an exposed channel.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.9 Medium** (`CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: **File exfiltration**: Any file within `os.tmpdir()` (or the OpenClaw state directory) can be read and sent to external messaging channels **Secret theft**: Temporary files often contain API keys, database credentials, SSH keys, session tokens, and application secrets **Cross-application data theft**: Other applications' temp files (browser caches, build artifacts, CI/CD secrets) are accessible **Silent exfiltration**: The file content is sent as a media attachment to messaging channels the attacker can monitor, with no user-visible indication **Automated exploitation**: If auto-reply is enabled, the malicious tool can be triggered without user interaction
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: The affected parent [`67edc7790f2c1f69da48847e4623f5d3e76fbc15`](https://github.com/openclaw/openclaw/commit/67edc7790f2c1f69da48847e4623f5d3e76fbc15) had no tool-provenance gate at the delivery sink:

  ```ts
  // src/agents/pi-embedded-subscribe.handlers.tools.ts
  if (ctx.params.onToolResult && !isToolError && !ctx.shouldEmitToolOutput()) {
    const mediaPaths = extractToolResultMediaPaths(result);
    if (mediaPaths.length > 0) {
      void ctx.params.onToolResult({ mediaUrls: mediaPaths });
    }
  }
  ```

  The parser accepted arbitrary path forms from text or image details:

  ```ts
  if (p && p.length <= 4096) {
    paths.push(p);
  }
  // src/media/local-roots.ts
  return [os.tmpdir(), path.join(resolvedStateDir, "media"), ...];
  ```

  Thus the later root check was operating on attacker-selected local paths, and `os.tmpdir()` made a shared temp directory part of the default allowlist.
- **15. Fix Patch (Commit)**: Verified repository security fix [`c378439246bb26683fc1c43d14a9e435643ea34f`](https://github.com/openclaw/openclaw/commit/c378439246bb26683fc1c43d14a9e435643ea34f), direct parent [`67edc7790f2c1f69da48847e4623f5d3e76fbc15`](https://github.com/openclaw/openclaw/commit/67edc7790f2c1f69da48847e4623f5d3e76fbc15), message `Security: harden tool media paths`. The patch adds a normalized core-tool allowlist and `filterToolResultMediaUrls()`: trusted core tools may emit local paths, while untrusted plugin/MCP tools retain only `http(s)` URLs. It applies that filter in both `handleToolExecutionEnd()` and the streaming `subscribeEmbeddedPiSession()` path. It also replaces `os.tmpdir()` with `resolvePreferredOpenClawTmpDir()` and creates OpenClaw temp directories with a `0700` default where the CLI/TTS paths create them. The advisory does not name this hash; it is labeled verified repository remediation. The advisory's affected label `2026.2.19-2` has no matching public tag, so the vulnerable source is cited by the direct parent and `v2026.2.19` reference tree instead of claiming an unavailable tag.
- **16. Fix Summary**: The security boundary is enforced before local media loading: an untrusted tool can still return a remote HTTP attachment, but cannot cause a local path or `file://` path to be emitted through the tool-result channel. The default temp root is now OpenClaw-owned and permission-aware, reducing cross-application exposure. Changed tests assert that `plugin_tool` with `MEDIA:/tmp/secret.png` does not call `onToolResult`, while `MEDIA:https://example.com/file.png` is preserved; the patch also updates temp-root/media-root coverage. Tests were inspected but not run locally; no live MCP server, local secret file, or external messaging channel was exercised. Upgrade to `openclaw` `2026.2.21` or later.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.21`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.19-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.21`
- **20. Disclosure and Fix Dates**: Published: `2026-02-21T10:42:36Z`; last advisory update: `2026-02-21T10:42:36Z`; public npm release time(s): `openclaw@2026.2.21` published 2026-02-21T16:02:01.230Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-jjgj-cpp9-cvpv)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-jjgj-cpp9-cvpv)
  - [Verified repository security commit `c378439246bb26683fc1c43d14a9e435643ea34f`](https://github.com/openclaw/openclaw/commit/c378439246bb26683fc1c43d14a9e435643ea34f)
  - [Parent media-result source](https://raw.githubusercontent.com/openclaw/openclaw/67edc7790f2c1f69da48847e4623f5d3e76fbc15/src/agents/pi-embedded-subscribe.tools.ts)
  - [Fixed media-result source](https://raw.githubusercontent.com/openclaw/openclaw/c378439246bb26683fc1c43d14a9e435643ea34f/src/agents/pi-embedded-subscribe.tools.ts)
  - [Changed media filtering tests](https://github.com/openclaw/openclaw/blob/c378439246bb26683fc1c43d14a9e435643ea34f/src/agents/pi-embedded-subscribe.handlers.tools.media.test.ts)
  - [Fixed local media roots](https://github.com/openclaw/openclaw/blob/c378439246bb26683fc1c43d14a9e435643ea34f/src/media/local-roots.ts)
  - [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
  - [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
