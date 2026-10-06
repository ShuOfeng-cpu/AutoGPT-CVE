---
id: "sok-vulnerabilities-GHSA-vj3m-g4cv-8j93-autogpt-classic-ssrf-in-web-fetch-commands-via-missing-internal-private-address-validation"
title: "GHSA-vj3m-g4cv-8j93: AutoGPT Classic: SSRF in web fetch commands via missing internal/private address validation"
created: "2026-10-06"
synthesizes: []
links: []
---

# GHSA-vj3m-g4cv-8j93: AutoGPT Classic: SSRF in web fetch commands via missing internal/private address validation

| Field | Value |
|-------|-------|
| **ID** | GHSA-vj3m-g4cv-8j93 |
| **Class** | GitHub Security Advisory |
| **Component** | web fetch commands (`classic/forge/forge/utils/url_validator.py`) |
| **Affected Product** | AutoGPT |
| **Severity** | High |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| **CWE** | CWE-918 |
| **Affected** | < 0.6.66 |
| **Fix Version** | `0.6.66` |
| **Source** | GitHub Security Advisory |

## 1. Overview

AutoGPT_SSRF_01 Vulnerability Report We discovered a SSRF vulnerability in the AutoGPT project. Overview Vulnerability Type: SSRF Affected Location: classic/forge/forge/utils/url_validator.py:27 Trigger Scenario: Classic forge web URL validator permits SSRF to internal hosts

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component accepted an attacker-controlled URL or network target and did not apply sufficient destination validation before the backend made the outbound request. In this case, the affected component is web fetch commands (`classic/forge/forge/utils/url_validator.py`).

### 2.2 Affected Code

The advisory identifies the following affected file(s):

- `classic/forge/forge/utils/url_validator.py`
- `classic/forge/forge/components/web/web_fetch.py`

### 2.3 Exploitation Path

Attackers may access internal services, probe restricted endpoints, and exfiltrate sensitive metadata or responses through backend-initiated requests. Remediation Enforce resolver-based SSRF filtering for internal/reserved ranges. Re-validate every redirect target. Canonicalize numeric/alternative IP formats before checks. Finder credits (please keep GitHub account association): Yuremin (@Yuremin) - https://github.com/Yuremin FORIMOC (@FORIMOC) - https://github.com/FORIMOC invoke1442 (@invoke1442) - https://github.com/invoke1442

## 3. Vulnerable Code Pattern

The vulnerable pattern is located in `classic/forge/forge/utils/url_validator.py` and is tied to the web fetch commands (`classic/forge/forge/utils/url_validator.py`) functionality described above.

## 4. The Fix

The issue is fixed in `0.6.66`.

## 5. Impact

Attackers may access internal services, probe restricted endpoints, and exfiltrate sensitive metadata or responses through backend-initiated requests. Remediation Enforce resolver-based SSRF filtering for internal/reserved ranges. Re-validate every redirect target. Canonicalize numeric/alternative IP formats before checks. Finder credits (please keep GitHub account association): Yuremin (@Yuremin) - https://github.com/Yuremin FORIMOC (@FORIMOC) - https://github.com/FORIMOC invoke1442 (@invoke1442) - https://github.com/invoke1442

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-vj3m-g4cv-8j93
