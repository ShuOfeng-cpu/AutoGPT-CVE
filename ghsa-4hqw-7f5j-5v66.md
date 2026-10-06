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

BerriAI/litellm#24512 Litellm was involved in a supply chain attack compromising all package versions ^=1.82.7. Litellm is a transitive dependecy in both original_autogpt and classic forge. #12539 fixes the transitive dep in the mainline, but the pinned versions still exist in current poetry locks for above ecosystems.

## 2. Technical Details

### 2.1 Root Cause

The issue is rooted in insufficient validation or authorization in litellm version constraint permitted compromised releases (supply chain). BerriAI/litellm#24512 Litellm was involved in a supply chain attack compromising all package versions ^=1.82.7. Litellm is a transitive dependecy in both original_autogpt and classic forge. #12539 fixes the transitive dep in the mainline, but the pinned versions still exist in current poetry locks for above ecosystems.

### 2.2 Affected Code

The affected component is `litellm version constraint permitted compromised releases (supply chain)`. No precise file path is required for this summary because the advisory identifies the vulnerable functionality by component or feature name.

### 2.3 Exploitation Path

Impact is low as PyPI packages have been yanked already, but it may be worth changing the pins to ^=1.17.X,<1.82.7

## 3. Vulnerable Code Pattern

The vulnerable pattern is the missing validation or authorization boundary in litellm version constraint permitted compromised releases (supply chain).

## 4. The Fix

The issue is fixed in `0.6.66`.

Linked fix material:

- https://github.com/Significant-Gravitas/AutoGPT/pull/12539

## 5. Impact

Impact is low as PyPI packages have been yanked already, but it may be worth changing the pins to ^=1.17.X,<1.82.7

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-4hqw-7f5j-5v66
- https://github.com/Significant-Gravitas/AutoGPT/pull/12539
