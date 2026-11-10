# GHSA-pjvx-rx66-r3fg: Cross-account sender authorization expansion in `/allowlist ... --store` account scoping

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: Cross-account sender authorization expansion in `/allowlist ... --store` account scoping
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-pjvx-rx66-r3fg`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-639` (Authorization Bypass Through User-Controlled Key) [source: GitHub Global Advisory, GitHub Repository Advisory]; `CWE-863` (Incorrect Authorization) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm); code paths named by the advisory: `src/auto-reply/reply/commands-allowlist.ts:386-393`, `src/auto-reply/reply/commands-allowlist.ts:697-702`, `src/auto-reply/reply/commands-allowlist.ts:730-733`, `src/pairing/pairing-store.ts:231-234`.
- **5. Trust Boundary Crossing**: Official advisory narrative: Because default-account reads still merge legacy unscoped entries, a store entry intended for one account could silently authorize the same sender on the `default` account. This is a real cross-account sender-authorization scoping bug.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: `/allowlist ... --store` resolved the selected channel `accountId` for reads, but store writes still dropped that `accountId` and wrote into the legacy unscoped pairing allowlist store. Because default-account reads still merge legacy unscoped entries, a store entry intended for one account could silently authorize the same sender on the `default` account. This is a real cross-account sender-authorization scoping bug. Severity is set to **medium** because exploitation requires an already-authorized user who can run `/allowlist` edits.
- **7. Technical Root Cause**: The affected path was: `src/auto-reply/reply/commands-allowlist.ts:386-393` resolved `accountId` and read store state with it `src/auto-reply/reply/commands-allowlist.ts:697-702` and `src/auto-reply/reply/commands-allowlist.ts:730-733` wrote store state without passing `accountId` `src/pairing/pairing-store.ts:231-234` and `src/pairing/pairing-store.ts:534-554` still merged legacy unscoped allowlist entries into the `default` account The fix scopes `/allowlist ... --store` writes to the resolved account and clears legacy default-account store entries on removal so legacy reads no longer create cross-account authorization bleed-through.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Severity is set to **medium** because exploitation requires an already-authorized user who can run `/allowlist` edits. Vulnerability class: improper authorization scoping / incorrect authorization Exploitation requires: an already-authorized sender who can run `/allowlist` edits Security effect: unintended authorization expansion from one channel account into `default`

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory + GitHub Repository Advisory CVSS v3.x: **5.4 Medium** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:L` (Low), according to GitHub Global Advisory CVSS v3.x.
- **12. Direct Impact**: Vulnerability class: improper authorization scoping / incorrect authorization Exploitation requires: an already-authorized sender who can run `/allowlist` edits Security effect: unintended authorization expansion from one channel account into `default`
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/auto-reply/reply/commands-allowlist.ts` at [`70da80bcb557`](https://github.com/openclaw/openclaw/commit/70da80bcb5574a10925469048d2ebb2abf882e73):

  ```diff
  -      if (parsed.action === "add") {
  -        await addChannelAllowFromStoreEntry({ channel: channelId, entry: parsed.entry });
  -      } else if (parsed.action === "remove") {
  -        await removeChannelAllowFromStoreEntry({ channel: channelId, entry: parsed.entry });
  -      }
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`70da80bcb5574a10925469048d2ebb2abf882e73`](https://github.com/openclaw/openclaw/commit/70da80bcb5574a10925469048d2ebb2abf882e73) - [PATCH] Auto-reply: scope allowlist store writes by account (#39015). Other advisory commit reference(s), not classified as fix commits: [`70da80bcb5574a10925469048d2ebb2abf882e73`](https://github.com/openclaw/openclaw/commit/70da80bcb5574a10925469048d2ebb2abf882e73).

  Fix excerpt from `src/auto-reply/reply/commands-allowlist.ts`:

  ```diff
  +      await updatePairingStoreAllowlist({
  +        action: parsed.action,
  +        channelId,
  +        accountId,
  +        entry: parsed.entry,
  +      });
  ```
- **16. Fix Summary**: The official advisory identifies patched versions but does not publish a separate fix summary.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.3.7`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.3.2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.3.7`
- **20. Disclosure and Fix Dates**: Published: `2026-03-08T14:26:55Z`; last advisory update: `2026-03-08T14:26:55Z`; fix commit authored date(s): `Sat, 7 Mar 2026 11:51:20 -0500`; public npm release time(s): `openclaw@2026.3.7` published 2026-03-08T05:46:01.183Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-pjvx-rx66-r3fg)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-pjvx-rx66-r3fg)
  - [Commit `70da80bcb5574a10925469048d2ebb2abf882e73`](https://github.com/openclaw/openclaw/commit/70da80bcb5574a10925469048d2ebb2abf882e73)
  - [Pull request #39015](https://github.com/openclaw/openclaw/pull/39015)
  - [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
  - [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
