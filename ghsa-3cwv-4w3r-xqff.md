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

The URL validation mechanism (validate_url) in the `forge` component is insufficient. It only verifies that the URL scheme is `http` or `https` but fails to block access to private IP ranges, loopback addresses (localhost), or link-local addresses. This allows the Agent (via read_webpage command) to access internal network resources and cloud metadata services, leading to a Server-Side Request Forgery (SSRF) vulnerability.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component accepted an attacker-controlled URL or network target and did not apply sufficient destination validation before the backend made the outbound request. In this case, the affected component is incomplete URL validation (`classic/forge/forge/utils/url_validator.py`).

### 2.2 Affected Code

The advisory identifies the following affected file(s):

- `classic/forge/forge/utils/url_validator.py`
- `classic/forge/forge/components/web/selenium.py`

The advisory/source text also names the following relevant symbols or runtime objects:

- `do_GET`
- `read_webpage`
- `Handler`
- `MockComponent`

### 2.3 Exploitation Path

This vulnerability allows a malicious actor (via direct prompt to the agent or prompt injection from a visited webpage) to: 1. Exfiltrate Cloud Credentials: Access `http://169.254.169.254/latest/meta-data/` to steal AWS/GCP/Azure IAM credentials if the agent is running in a cloud environment. 2. Internal Network Reconnaissance: Scan for open ports on localhost or other devices in the local network (e.g., `http://192.168.1.1`). 3. Interact with Internal Services: Send GET requests to internal APIs or databases that expose HTTP interfaces without authentication (assuming they are safe behind a firewall).

### 2.4 Attack Surface Summary

| Surface | Source-supported detail |
|---------|--------------------------|
| Component | incomplete URL validation (`classic/forge/forge/utils/url_validator.py`) |
| Source file(s) | `classic/forge/forge/utils/url_validator.py`<br>`classic/forge/forge/components/web/selenium.py` |
| Named code objects | `do_GET`<br>`read_webpage`<br>`Handler`<br>`MockComponent` |
| Affected versions | < 0.6.66 |
| Patched version | `0.6.66` |

### 2.5 Source Evidence

#### Implementation evidence

The vulnerability is located in classic/forge/forge/utils/url_validator.py.

The validate_url decorator is intended to secure URL inputs for the agent's web browsing capabilities. However, the current implementation only performs a simple regex check:

```
# classic/forge/forge/utils/url_validator.py
if not re.match(r"^https?://", url):
    raise ValueError("Invalid URL format: URL must start with http:// or https://")
if check_local_file_access(url):
    raise ValueError("Access to local files is restricted")
```

It completely fails to validate the hostname or resolved IP address against private network ranges (e.g., `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`) or cloud metadata IP (`169.254.169.254`).

As a result, the read_webpage function in classic/forge/forge/components/web/selenium.py, which is decorated with `@validate_url`, accepts and visits internal URLs when instructed by a user or a malicious prompt injection.

#### Proof-of-concept evidence

To reproduce this vulnerability, you can run a local mock server and attempt to access it using the validate_url logic.

1. Start a mock internal service (e.g., on port 1337):
# http_server.py
import http.server, socketserver
PORT = 1337
class Handler(http.server.SimpleHTTPRequestHandler):
 def do_GET(self):
 self.send_response(200)
 self.wfile.write(b"CRITICAL_INTERNAL_SECRET")
with socketserver.TCPServer(("localhost", PORT), Handler) as httpd:
 httpd.serve_forever()
2. Run the exploit script (verifying the validator allows the connection):
# poc.py
import sys, os
# Adjust path to point to your AutoGPT/classic/forge directory
sys.path.append(os.path.abspath("classic/forge"))
from forge.utils.url_validator import validate_url

class MockComponent:
 @validate_url
 def read_webpage(self, url):
 print(f"Validator ALLOWED access to: {url}")

# This should raise a ValueError if properly secured, but it does NOT.
try:
 MockComponent().read_webpage(url="http://localhost:1337")
 print("[!] Vulnerability Reproduced: Validator allowed localhost access.")
except ValueError as e:
 print(f"[-] Blocked: {e}")
3. Observation: The script outputs "Validator ALLOWED access to: http://localhost:1337".

## 3. Vulnerable Code Pattern

The vulnerable pattern is located in `classic/forge/forge/utils/url_validator.py` and is tied to the incomplete URL validation (`classic/forge/forge/utils/url_validator.py`) functionality described above.

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

This vulnerability allows a malicious actor (via direct prompt to the agent or prompt injection from a visited webpage) to: 1. Exfiltrate Cloud Credentials: Access `http://169.254.169.254/latest/meta-data/` to steal AWS/GCP/Azure IAM credentials if the agent is running in a cloud environment. 2. Internal Network Reconnaissance: Scan for open ports on localhost or other devices in the local network (e.g., `http://192.168.1.1`). 3. Interact with Internal Services: Send GET requests to internal APIs or databases that expose HTTP interfaces without authentication (assuming they are safe behind a firewall).
CVSS metric breakdown:

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Changed |
| Confidentiality | High |
| Integrity | None |
| Availability | None |

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-3cwv-4w3r-xqff
