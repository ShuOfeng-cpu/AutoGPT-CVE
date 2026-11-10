# GHSA-qhrr-grqp-6x2g: tools.exec.safeBins trusted PATH directories allowed binary shadowing in allowlist mode

> Evidence policy: the GitHub Repository Security Advisory API defines the corpus and supplies vendor narrative, versions, and repository metadata. CVE.org and NVD search results discover candidate CVE IDs only; a filename mapping requires the repository API, an explicit CVE List V5 CNA GitHub Security Advisory URL, or an exact GitHub Global GHSA-ID join that CNA evidence does not contradict. A CVE that explicitly names multiple GHSAs uses a CVE-and-GHSA suffix for additional records. Malformed CNA links carrying a non-advisory label are disclosed but not used as mappings. Multiple published CVEs for one GHSA and other mapping conflicts are retained explicitly. For published CVEs, CVE List V5 CNA CVSS/CWE data is primary; differing source values are retained with labels. Rejected or unavailable CVE records are labeled. A commit is called a fix commit only when the advisory explicitly identifies it as such; a verified fixed tree is labeled separately. Unpublished facts are not inferred.
>
> Corpus snapshot: `2026-10-28` (Asia/Shanghai).

### Basic Identification and Classification

- **1. Vulnerability Name**: tools.exec.safeBins trusted PATH directories allowed binary shadowing in allowlist mode
- **2. Vulnerability Identifier (CVE/GHSA)**: `GHSA-qhrr-grqp-6x2g`; no confirmed CVE assignment
- **3. CWE Classification**: `CWE-426` (Untrusted Search Path) [source: GitHub Global Advisory, GitHub Repository Advisory]
- **4. Affected Component**: Affected package(s): `openclaw` (npm).
- **5. Trust Boundary Crossing**: Not separately characterized as a structured trust-boundary field by the official advisory.

### Root Cause and Trigger Conditions

- **6. Vulnerability Summary**: In `openclaw` allowlist mode, `tools.exec.safeBins` trusted PATH-derived directories for safe-bin resolution. A same-name binary placed in a trusted PATH directory could satisfy safe-bin checks and execute.
- **7. Technical Root Cause**: Safe-bin trust accepted PATH-derived directories instead of explicit trusted directories. Safe-bin execution used shell command tokens that could resolve to shadowed binaries.
- **8. Architectural/Design Root Cause**: Not separately characterized by the official advisory. See fields 5 and 7 for the published boundary and technical details.
- **9. Trigger Prerequisites**: This is an allowlist bypass in exec policy that can lead to command execution in the OpenClaw runtime context when allowlist mode relies on safe bins and an attacker can influence trusted binary locations.

### Severity and Impact

- **10. CVSS Score and Vector**: GitHub Global Advisory CVSS v4.0: **6.9 Medium** (`CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`); GitHub Repository Advisory qualitative severity: **Medium**
- **11. Required Attacker Privileges**: `PR:N` (None), according to GitHub Global Advisory CVSS v4.0.
- **12. Direct Impact**: This is an allowlist bypass in exec policy that can lead to command execution in the OpenClaw runtime context when allowlist mode relies on safe bins and an attacker can influence trusted binary locations.
- **13. Chained/Indirect Impact**: No separate chained or indirect impact is published by the official advisory.

### Code and Remediation

- **14. Vulnerable Code Snippet**: Removed lines from the published fix patch in `src/config/io.ts` at [`64b273a71cf0`](https://github.com/openclaw/openclaw/commit/64b273a71cf0b2f2419c974832cede1fc2158729):

  ```diff
  -    const typedExec = exec as { safeBinProfiles?: Record<string, unknown> };
  ```
- **15. Fix Patch (Commit)**: Specific fix commit(s) published by the advisory: [`64b273a71cf0b2f2419c974832cede1fc2158729`](https://github.com/openclaw/openclaw/commit/64b273a71cf0b2f2419c974832cede1fc2158729) - [PATCH] fix(exec): harden safe-bin trust and add explicit trusted dirs.

  Fix excerpt from `src/config/io.ts`:

  ```diff
  +  const normalizeTrustedDirs = (entries?: readonly string[]) => {
  +    if (!Array.isArray(entries)) {
  +      return undefined;
  +    }
  +    const normalized = entries.map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  +    return normalized.length > 0 ? Array.from(new Set(normalized)) : undefined;
  +  };
  +
  +    const typedExec = exec as {
  +      safeBinProfiles?: Record<string, unknown>;
  +      safeBinTrustedDirs?: string[];
  +    };
  ```
- **16. Fix Summary**: Stop trusting PATH-derived directories for safe-bin trust. Add explicit `tools.exec.safeBinTrustedDirs` for opt-in extra trusted paths. Pin safe-bin shell execution to resolved absolute executable paths.
- **17. Official Release Available?**: Yes. The official advisory identifies patched release range(s): `openclaw` (npm): `>= 2026.2.22`

### Timeline and Versions

- **18. Affected Versions**: `openclaw` (npm): `<= 2026.2.21-2`
- **19. Fixed Versions**: `openclaw` (npm): `>= 2026.2.22`
- **20. Disclosure and Fix Dates**: Published: `2026-02-23T00:52:00Z`; last advisory update: `2026-02-23T00:52:00Z`; fix commit authored date(s): `Sun, 22 Feb 2026 22:42:29 +0100`; public npm release time(s): `openclaw@2026.2.22` published 2026-02-23T00:36:27.582Z.

### References

- **21. References**:
  - [GitHub Security Advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-qhrr-grqp-6x2g)
  - [Repository security policy](https://github.com/openclaw/openclaw/blob/main/SECURITY.md)
  - [GitHub Global Advisory](https://github.com/advisories/GHSA-qhrr-grqp-6x2g)
  - [Commit `64b273a71cf0b2f2419c974832cede1fc2158729`](https://github.com/openclaw/openclaw/commit/64b273a71cf0b2f2419c974832cede1fc2158729)
  - [CWE-426](https://cwe.mitre.org/data/definitions/426.html)
