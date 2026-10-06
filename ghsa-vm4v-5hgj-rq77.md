---
id: "sok-vulnerabilities-GHSA-vm4v-5hgj-rq77-autogpt-classic-ssrf-in-llamafile-setup-script-via-unvalidated-download-url-and-redirects"
title: "GHSA-vm4v-5hgj-rq77: AutoGPT Classic: SSRF in llamafile setup script via unvalidated download URL and redirects"
created: "2026-10-06"
synthesizes: []
links: []
---

# GHSA-vm4v-5hgj-rq77: AutoGPT Classic: SSRF in llamafile setup script via unvalidated download URL and redirects

| Field | Value |
|-------|-------|
| **ID** | GHSA-vm4v-5hgj-rq77 |
| **Class** | GitHub Security Advisory |
| **Component** | llamafile setup script (`classic/original_autogpt/scripts/llamafile/serve.py`) |
| **Affected Product** | AutoGPT |
| **Severity** | High |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **CWE** | CWE-918 |
| **Affected** | < 0.6.66 |
| **Fix Version** | `0.6.66` |
| **Source** | GitHub Security Advisory |

## 1. Overview

A Server-Side Request Forgery (SSRF) vulnerability exists in classic/original_autogpt/scripts/llamafile/serve.py at line 148. The code passes a URL derived from configurable or user-influenced input directly to urllib.request.urlretrieve() without validating the scheme, host, or destination. An attacker who can influence the URL value (via environment variables, config files, or other input vectors) can cause the AutoGPT process to issue HTTP requests to arbitrary internal or external hosts. Affected Version Repository: https://github.com/Significant-Gravitas/AutoGPT File: classic/original_autogpt/scripts/llamafile/serve.py, line 148 Affected: Current master branch (verified at time of report) Vulnerability Details Vulnerable Code # serve.py, line 148 request.urlretrieve (url,...) The url variable is constructed from a host and/or path value that is configurable at runtime (e.g., sourced from environment variables or a settings file) rather than being a fixed, trusted constant.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component accepted an attacker-controlled URL or network target and did not apply sufficient destination validation before the backend made the outbound request. In this case, the affected component is llamafile setup script (`classic/original_autogpt/scripts/llamafile/serve.py`).

### 2.2 Affected Code

The advisory identifies the following affected file(s):

- `classic/original_autogpt/scripts/llamafile/serve.py`

### 2.3 Exploitation Path

Exfiltration of cloud instance metadata (e.g., AWS IMDSv1 IAM credentials) if running in a cloud environment. Probing of internal network services not exposed to the public internet. Potential credential theft if internal services (e.g., databases, Vault, Kubernetes API) are reachable from the host. The severity is High in cloud-hosted deployments. The exploitability is contingent on an attacker's ability to influence the URL value, which is a realistic threat in misconfigured or multi-tenant environments. Fix Before calling urlretrieve, validate the URL against a strict allowlist of expected values: # One-line fix: assert the URL matches the expected local llamafile download source assert url.startswith ("https://huggingface.co/Mozilla/"), f"Blocked untrusted URL: {url} " For a more robust fix, parse the URL with urllib.parse.urlparse() and explicitly validate that the scheme is https and the hostname matches the expected download host before proceeding.

## 3. Vulnerable Code Pattern

The vulnerable pattern is located in `classic/original_autogpt/scripts/llamafile/serve.py` and is tied to the llamafile setup script (`classic/original_autogpt/scripts/llamafile/serve.py`) functionality described above.

## 4. The Fix

The issue is fixed in `0.6.66`.

## 5. Impact

Exfiltration of cloud instance metadata (e.g., AWS IMDSv1 IAM credentials) if running in a cloud environment. Probing of internal network services not exposed to the public internet. Potential credential theft if internal services (e.g., databases, Vault, Kubernetes API) are reachable from the host. The severity is High in cloud-hosted deployments. The exploitability is contingent on an attacker's ability to influence the URL value, which is a realistic threat in misconfigured or multi-tenant environments. Fix Before calling urlretrieve, validate the URL against a strict allowlist of expected values: # One-line fix: assert the URL matches the expected local llamafile download source assert url.startswith ("https://huggingface.co/Mozilla/"), f"Blocked untrusted URL: {url} " For a more robust fix, parse the URL with urllib.parse.urlparse() and explicitly validate that the scheme is https and the hostname matches the expected download host before proceeding.

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-vm4v-5hgj-rq77
