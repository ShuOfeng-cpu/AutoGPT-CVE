# GHSA-2j9j-gf59-p4p5: iOS deep link (openclaw://agent) can trigger gateway agent requests without local confirmation

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: iOS deep link (openclaw://agent) can trigger gateway agent requests without local confirmation
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-2j9j-gf59-p4p5`; no confirmed CVE assignment
- **3. CWE Classification**: No CWE is published by the available CVE or GitHub advisory sources.
- **4. Affected Component**: Affected package(s): `openclaw` (swift).
- **5. Trust Boundary Crossing**: Official advisory narrative: This is a user-interaction deep-link abuse issue, not unauthenticated server takeover.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: A crafted `openclaw://agent` deep link could cause OpenClaw iOS to forward an `agent.request` event to a connected Gateway without local confirmation on iOS.
- **7. Technical Root Cause**: Not separately disclosed by the official advisory.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: Not separately specified by the official advisory.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Repository Advisory qualitative severity: **Low**
- **11. Required Attacker Privileges**: Official advisory narrative: This is a user-interaction deep-link abuse issue, not unauthenticated server takeover.
- **12. Direct Impact**: External deep-link trigger could cause unintended agent action initiation in an already-connected iOS node context. This is a user-interaction deep-link abuse issue, not unauthenticated server takeover. Severity is set to **Low** because iOS distribution is internal preview/super-alpha and not public/TestFlight release.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `apps/ios/Sources/Model/NodeAppModel.swift` at [`ff4e6ca0d942`](https://github.com/openclaw/openclaw/commit/ff4e6ca0d942ef52330dcbe116321ae4fed21749):

  ```diff
  -    private func applyMainSessionKey(_ key: String?) {
  -        let trimmed = (key ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
  -        guard !trimmed.isEmpty else { return }
  -        let current = self.mainSessionBaseKey.trimmingCharacters(in: .whitespacesAndNewlines)
  -        if trimmed == current { return }
  -        self.mainSessionBaseKey = trimmed
  -        self.talkMode.updateMainSessionKey(self.mainSessionKey)
  -    }
  -
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`ff4e6ca0d942ef52330dcbe116321ae4fed21749`](https://github.com/openclaw/openclaw/commit/ff4e6ca0d942ef52330dcbe116321ae4fed21749) - [PATCH] fix(ios): gate agent deep links with local confirmation.

  Fix excerpt from `apps/ios/Sources/Model/NodeAppModel.swift`:

  ```diff
  +    private static let deepLinkKeyUserDefaultsKey = "deeplink.agent.key"
  +    private static let canvasUnattendedDeepLinkKey: String = NodeAppModel.generateDeepLinkKey()
  ```
- **16. Fix Summary**: The iOS deep-link path now requires local confirmation unless a trusted deep-link key is provided, and unkeyed deep links have delivery-routing fields stripped before submission.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (swift): `2026.2.23`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (swift): `<= 2026.2.22-2`
- **19. Fixed Versions**: `openclaw` (swift): `2026.2.23`
- **20. Disclosure and Fix Dates**: Published: `2026-02-24T05:27:20Z`; last advisory update: `2026-02-24T05:27:20Z`; fix commit authored date(s): `Tue, 24 Feb 2026 02:51:27 +0000`; independent package-registry release time not available for this record.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-2j9j-gf59-p4p5)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [Commit `ff4e6ca0d942ef52330dcbe116321ae4fed21749`](https://github.com/openclaw/openclaw/commit/ff4e6ca0d942ef52330dcbe116321ae4fed21749)
