---
id: "sok-vulnerabilities-GHSA-4hqw-7f5j-5v66-autogpt-classic-litellm-version-constraint-permitted-compromised-releases-supply-chain"
title: "GHSA-4hqw-7f5j-5v66: AutoGPT Classic: litellm version constraint permitted compromised releases (supply chain)"
created: "2026-10-06"
synthesizes: []
links: []
---

# GHSA-4hqw-7f5j-5v66: AutoGPT Classic: litellm version constraint permitted compromised releases (supply chain)

| Field | Value |
|-------|-------|
| **ID** | GHSA-4hqw-7f5j-5v66 |
| **Class** | GitHub Security Advisory |
| **Component** | litellm version constraint permitted compromised releases (supply chain) |
| **Affected Product** | AutoGPT |
| **Severity** | Low |
| **CWE** | CWE-1395 |
| **Affected** | < 0.6.66 |
| **Fix Version** | `0.6.66` |
| **Source** | GitHub Security Advisory / Fix PR |

## 1. Overview

BerriAI/litellm#24512 Litellm was involved in a supply chain attack compromising all package versions ^=1.82.7. Litellm is a transitive dependency in both original_autogpt and classic forge. #12539 fixes the transitive dep in the mainline, but the pinned versions still exist in current poetry locks for above ecosystems.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable behavior comes from dependency constraints or lock files that could resolve to the compromised package range described by the advisory. The affected component is litellm version constraint permitted compromised releases (supply chain).

### 2.2 Affected Code

The affected surface is AutoGPT's dependency specification and lock-file resolution for the `litellm` package family.

### 2.3 Exploitation Path

Impact is low as PyPI packages have been yanked already, but it may be worth changing the pins to `^=1.17.X,<1.82.7`

### 2.4 Attack Surface Summary

| Surface | Source-supported detail |
|---------|--------------------------|
| Component | litellm version constraint permitted compromised releases (supply chain) |
| Affected versions | < 0.6.66 |
| Patched version | `0.6.66` |

### 2.5 Source Evidence

#### Implementation evidence

Specifically, the compromised versions ship with a litellm_init.pth which acts as a credential stealer. See litellm issue for details

#### Proof-of-concept evidence

Doing a poetry update could cause poetry to try and pull compromised version of the package.

## 3. Vulnerable Code Pattern

The vulnerable pattern is a dependency constraint that can resolve to a compromised upstream package version. The risk appears when dependency installation or update tooling accepts the affected range instead of pinning or excluding it.

## 4. The Fix

Fix strategy:

- Upgrade AutoGPT to `0.6.66` or a later release containing the patch.
- Pin or constrain `litellm` so dependency resolution cannot select the compromised release range identified by the advisory.
- Regenerate lock files after the constraint change and verify the resolved package set.
- Add dependency-audit coverage so the compromised range is caught if it reappears in a future lock file.
- Use the linked PR or commit as the authoritative patch reference when backporting the fix to a self-hosted deployment.

Validation and regression checks:

- Dependency resolution should not select the compromised `litellm` release range identified by the advisory.
- Lock files and package constraints should resolve to a safe version below the compromised range or to a later fixed version.
- Automated dependency checks should flag any reintroduction of the affected version range.

Operational follow-up:

- Inventory self-hosted AutoGPT deployments and confirm whether their running version falls inside the affected range.
- If an immediate upgrade is not possible, backport the same validation, authorization, or dependency constraint shown by the linked fix material.
- Rebuild environments from refreshed lock files so old cached dependency artifacts are not reused.

Linked fix material:

- https://github.com/Significant-Gravitas/AutoGPT/pull/12539

## 5. Impact

Impact is low as PyPI packages have been yanked already, but it may be worth changing the pins to `^=1.17.X,<1.82.7`

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-4hqw-7f5j-5v66
- https://github.com/Significant-Gravitas/AutoGPT/pull/12539
