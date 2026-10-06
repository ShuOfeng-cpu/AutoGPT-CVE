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

A Server-Side Request Forgery (SSRF) vulnerability exists in `classic/original_autogpt/scripts/llamafile/serve.py` at line 148. The code passes a URL derived from configurable or user-influenced input directly to `urllib.request.urlretrieve()` without validating the scheme, host, or destination. An attacker who can influence the URL value (via environment variables, config files, or other input vectors) can cause the AutoGPT process to issue HTTP requests to arbitrary internal or external hosts.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component accepted an attacker-controlled URL or network target and did not apply sufficient destination validation before the backend made the outbound request. In this case, the affected component is llamafile setup script (`classic/original_autogpt/scripts/llamafile/serve.py`).

### 2.2 Affected Code

The advisory identifies the following affected file(s):

- `classic/original_autogpt/scripts/llamafile/serve.py`

The advisory/source text also names the following relevant symbols or runtime objects:

- `_`

### 2.3 Exploitation Path

- Exfiltration of cloud instance metadata (e.g., AWS IMDSv1 IAM credentials) if running in a cloud environment. - Probing of internal network services not exposed to the public internet. - Potential credential theft if internal services (e.g., databases, Vault, Kubernetes API) are reachable from the host. The severity is High in cloud-hosted deployments. The exploitability is contingent on an attacker's ability to influence the URL value, which is a realistic threat in misconfigured or multi-tenant environments.

### 2.4 Attack Surface Summary

| Surface | Source-supported detail |
|---------|--------------------------|
| Component | llamafile setup script (`classic/original_autogpt/scripts/llamafile/serve.py`) |
| Source file(s) | `classic/original_autogpt/scripts/llamafile/serve.py` |
| Named code objects | `_` |
| Affected versions | < 0.6.66 |
| Patched version | `0.6.66` |

### 2.5 Source Evidence

#### Root-cause evidence

The root cause is the absence of any allowlist validation before the URL is passed to `urlretrieve()`. Specifically:

1. The URL's scheme is never checked — allowing `file://`, `http://`, `https://`, or other schemes.
2. The URL's hostname is never compared against an expected value (e.g., `localhost` or `127.0.0.1`).
3. The URL's port is never validated against the expected llamafile server port.

Because the URL value can be influenced by environment-level configuration, an attacker with write access to the environment (e.g., via a compromised `.env` file, CI/CD pipeline injection, or a path traversal in a config loader) can redirect this request to an arbitrary destination — including internal cloud metadata endpoints, internal services, or external attacker-controlled servers.

#### Vulnerable-code evidence

```
# serve.py, line 148
request.urlretrieve(url,.)
```

The `url` variable is constructed from a host and/or path value that is configurable at runtime (e.g., sourced from environment variables or a settings file) rather than being a fixed, trusted constant.

#### Proof-of-concept evidence

```
import urllib.request as request
import os

# Attacker sets or influences the URL (e.g., via environment variable or config)
# Targeting AWS EC2 metadata endpoint as a realistic internal target
attacker_controlled_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# This mirrors the vulnerable call at serve.py:148
# No validation occurs before the request is issued
response_path, _ = request.urlretrieve(attacker_controlled_url, "/tmp/ssrf_output")

with open("/tmp/ssrf_output") as f:
    print("[SSRF] Response from internal endpoint:")
    print(f.read())
```

Expected result: The AutoGPT process fetches the cloud metadata endpoint and writes the response (potentially including IAM credentials) to disk — demonstrating that the request was issued to an unintended internal host.

## 3. Vulnerable Code Pattern

The vulnerable pattern is located in `classic/original_autogpt/scripts/llamafile/serve.py` and is tied to the llamafile setup script (`classic/original_autogpt/scripts/llamafile/serve.py`) functionality described above.

## 4. The Fix

Fix strategy:

- Upgrade AutoGPT to `0.6.66` or a later release containing the patch.
- Route outbound HTTP requests through AutoGPT's hardened request helper instead of direct library calls such as `urllib.request.urlopen` or unvalidated SMTP/HTTP clients.
- Validate the resolved destination, not only the URL string or scheme, and block loopback, private, link-local, multicast, and cloud metadata addresses.
- Preserve destination checks across redirects and DNS resolution so DNS rebinding and alternate IP encodings cannot bypass the blocklist.

Validation and regression checks:

- Requests to loopback, private, link-local, multicast, and cloud metadata addresses should be blocked.
- Redirect chains should be revalidated after each redirect target is resolved.
- Allowed public HTTP and HTTPS destinations should still work through the hardened request path.

Operational follow-up:

- Inventory self-hosted AutoGPT deployments and confirm whether their running version falls inside the affected range.
- If an immediate upgrade is not possible, backport the same validation, authorization, or dependency constraint shown by the linked fix material.
- Review outbound request logs for attempts to reach loopback, private, link-local, or metadata-service addresses.

## 5. Impact

- Exfiltration of cloud instance metadata (e.g., AWS IMDSv1 IAM credentials) if running in a cloud environment. - Probing of internal network services not exposed to the public internet. - Potential credential theft if internal services (e.g., databases, Vault, Kubernetes API) are reachable from the host. The severity is High in cloud-hosted deployments. The exploitability is contingent on an attacker's ability to influence the URL value, which is a realistic threat in misconfigured or multi-tenant environments.
CVSS metric breakdown:

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| Scope | Changed |
| Confidentiality | High |
| Integrity | None |
| Availability | None |

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-vm4v-5hgj-rq77
