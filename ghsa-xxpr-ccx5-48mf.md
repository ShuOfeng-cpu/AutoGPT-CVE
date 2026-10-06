---
id: "sok-vulnerabilities-GHSA-xxpr-ccx5-48mf-autogpt-classic-http-client-domain-allowlist-bypass-via-userinfo-and-backslash-url-tricks"
title: "GHSA-xxpr-ccx5-48mf: AutoGPT Classic: HTTP client domain allowlist bypass via userinfo and backslash URL tricks"
created: "2026-10-06"
synthesizes: []
links: []
---

# GHSA-xxpr-ccx5-48mf: AutoGPT Classic: HTTP client domain allowlist bypass via userinfo and backslash URL tricks

| Field | Value |
|-------|-------|
| **ID** | GHSA-xxpr-ccx5-48mf |
| **Class** | GitHub Security Advisory |
| **Component** | HTTP client domain allowlist bypass / HTTP client domain allowlist |
| **Affected Product** | AutoGPT |
| **Severity** | Moderate |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-918 |
| **Affected** | < 0.6.66 |
| **Fix Version** | `0.6.66` |
| **Source** | GitHub Security Advisory |

## 1. Overview

The URL checking logic in _is_domain_allowed has a logical flaw that could be bypassed by attackers, leading to SSRF attacks.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component accepted an attacker-controlled URL or network target and did not apply sufficient destination validation before the backend made the outbound request. In this case, the affected component is HTTP client domain allowlist bypass / HTTP client domain allowlist.

### 2.2 Affected Code

The affected component is `HTTP client domain allowlist bypass / HTTP client domain allowlist`. No precise file path is required for this summary because the advisory identifies the vulnerable functionality by component or feature name.

### 2.3 Exploitation Path

An attacker exercises the vulnerable component using the conditions described in the advisory, causing the documented security impact.

## 3. Vulnerable Code Pattern

The vulnerable pattern is the missing validation or authorization boundary in HTTP client domain allowlist bypass / HTTP client domain allowlist.

## 4. The Fix

The issue is fixed in `0.6.66`.

## 5. Impact

An attacker exercises the vulnerable component using the conditions described in the advisory, causing the documented security impact.

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-xxpr-ccx5-48mf
