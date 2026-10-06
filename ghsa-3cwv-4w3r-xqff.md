---
id: "sok-vulnerabilities-GHSA-3cwv-4w3r-xqff-autogpt-classic-incomplete-url-validation-in-forge-allows-ssrf-in-browser-commands"
title: "GHSA-3cwv-4w3r-xqff: AutoGPT Classic: incomplete URL validation in forge allows SSRF in browser commands"
created: "2026-10-06"
synthesizes: []
links: []
---

# GHSA-3cwv-4w3r-xqff: AutoGPT Classic: incomplete URL validation in forge allows SSRF in browser commands

| Field | Value |
|-------|-------|
| **ID** | GHSA-3cwv-4w3r-xqff |
| **Class** | GitHub Security Advisory |
| **Component** | incomplete URL validation (`classic/forge/forge/utils/url_validator.py`) |
| **Affected Product** | AutoGPT |
| **Severity** | High |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| **CWE** | CWE-918 |
| **Affected** | < 0.6.66 |
| **Fix Version** | `0.6.66` |
| **Source** | GitHub Security Advisory |

## 1. Overview

The URL validation mechanism (validate_url) in the forge component is insufficient. It only verifies that the URL scheme is http or https but fails to block access to private IP ranges, loopback addresses (localhost), or link-local addresses. This allows the Agent (via read_webpage command) to access internal network resources and cloud metadata services, leading to a Server-Side Request Forgery (SSRF) vulnerability.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component accepted an attacker-controlled URL or network target and did not apply sufficient destination validation before the backend made the outbound request. In this case, the affected component is incomplete URL validation (`classic/forge/forge/utils/url_validator.py`).

### 2.2 Affected Code

The advisory identifies the following affected file(s):

- `classic/forge/forge/utils/url_validator.py`
- `classic/forge/forge/components/web/selenium.py`

### 2.3 Exploitation Path

This vulnerability allows a malicious actor (via direct prompt to the agent or prompt injection from a visited webpage) to: Exfiltrate Cloud Credentials: Access http://169.254.169.254/latest/meta-data/ to steal AWS/GCP/Azure IAM credentials if the agent is running in a cloud environment. Internal Network Reconnaissance: Scan for open ports on localhost or other devices in the local network (e.g., http://192.168.1.1). Interact with Internal Services: Send GET requests to internal APIs or databases that expose HTTP interfaces without authentication (assuming they are safe behind a firewall).

## 3. Vulnerable Code Pattern

The vulnerable pattern is located in `classic/forge/forge/utils/url_validator.py` and is tied to the incomplete URL validation (`classic/forge/forge/utils/url_validator.py`) functionality described above.

## 4. The Fix

The issue is fixed in `0.6.66`.

## 5. Impact

This vulnerability allows a malicious actor (via direct prompt to the agent or prompt injection from a visited webpage) to: Exfiltrate Cloud Credentials: Access http://169.254.169.254/latest/meta-data/ to steal AWS/GCP/Azure IAM credentials if the agent is running in a cloud environment. Internal Network Reconnaissance: Scan for open ports on localhost or other devices in the local network (e.g., http://192.168.1.1). Interact with Internal Services: Send GET requests to internal APIs or databases that expose HTTP interfaces without authentication (assuming they are safe behind a firewall).

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-3cwv-4w3r-xqff
