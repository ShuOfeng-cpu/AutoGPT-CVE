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

- Vulnerability Type: SSRF - Affected Location: classic/forge/forge/utils/url_validator.py:27 - Trigger Scenario: Classic forge web URL validator permits SSRF to internal hosts

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component accepted an attacker-controlled URL or network target and did not apply sufficient destination validation before the backend made the outbound request. In this case, the affected component is web fetch commands (`classic/forge/forge/utils/url_validator.py`).

### 2.2 Affected Code

The advisory identifies the following affected file(s):

- `classic/forge/forge/utils/url_validator.py`
- `classic/forge/forge/components/web/web_fetch.py`

The advisory/source text also names the following relevant symbols or runtime objects:

- `response`

### 2.3 Exploitation Path

This issue enables server-side request forgery by letting attacker-controlled targets reach backend networking sinks. Attackers may access internal services, probe restricted endpoints, and exfiltrate sensitive metadata or responses through backend-initiated requests. 1. The attacker can control a URL/host input that reaches backend request construction. 2. The affected service is allowed to make outbound network connections. 3. Destination validation and egress restrictions are insufficient for untrusted targets.

### 2.4 Attack Surface Summary

| Surface | Source-supported detail |
|---------|--------------------------|
| Component | web fetch commands (`classic/forge/forge/utils/url_validator.py`) |
| Source file(s) | `classic/forge/forge/utils/url_validator.py`<br>`classic/forge/forge/components/web/web_fetch.py` |
| Named code objects | `response` |
| Affected versions | < 0.6.66 |
| Patched version | `0.6.66` |

### 2.5 Source Evidence

#### Root-cause evidence

AutoGPT applies `@validate_url` before web-fetch commands (`classic/forge/forge/components/web/web_fetch.py:219,328`), but `validate_url` only enforces:

- `http(s)` prefix (`classic/forge/forge/utils/url_validator.py:27`)
- non-empty scheme/netloc (`classic/forge/forge/utils/url_validator.py:31,45-56`)
- `file://` prefix deny-list (`classic/forge/forge/utils/url_validator.py:33,75-90`)
- max length (`classic/forge/forge/utils/url_validator.py:35`)

It does not resolve hostnames or block loopback/private/link-local ranges, so internal targets remain reachable.

#### Implementation evidence

1. Source (user-controlled input)

- Attacker-controlled URL is provided to command handlers:

`fetch_webpage(url,.)`: `classic/forge/forge/components/web/web_fetch.py:220-223`
`fetch_raw_html(url,.)`: `classic/forge/forge/components/web/web_fetch.py:329`

1. Data flow

- Input first passes `@validate_url` (`classic/forge/forge/components/web/web_fetch.py:219,328`).
- Validator accepts internal URLs as long as syntax checks pass (`classic/forge/forge/utils/url_validator.py:27-40`).
- Validated URL is then forwarded into `_fetch_url(url)` (`classic/forge/forge/components/web/web_fetch.py:242,340`).

1. Sink (dangerous execution point)

- Backend request sink:

`response = self.client.get(url)`
Location: `classic/forge/forge/components/web/web_fetch.py:100`
- Because no internal-address restriction is enforced before this call, attacker input can drive server-side requests to internal services.

#### Exploitation preconditions

1. The attacker can control a URL/host input that reaches backend request construction.
2. The affected service is allowed to make outbound network connections.
3. Destination validation and egress restrictions are insufficient for untrusted targets.

## 3. Vulnerable Code Pattern

The vulnerable pattern is located in `classic/forge/forge/utils/url_validator.py` and is tied to the web fetch commands (`classic/forge/forge/utils/url_validator.py`) functionality described above.

## 4. The Fix

Fix strategy:

- Upgrade AutoGPT to `0.6.66` or a later release containing the patch.
- Apply the source-stated remediation: 1.
- Apply the source-stated remediation: Enforce resolver-based SSRF filtering for internal/reserved ranges. 2.
- Apply the source-stated remediation: Re-validate every redirect target. 3.
- Apply the source-stated remediation: Canonicalize numeric/alternative IP formats before checks.
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

This issue enables server-side request forgery by letting attacker-controlled targets reach backend networking sinks. Attackers may access internal services, probe restricted endpoints, and exfiltrate sensitive metadata or responses through backend-initiated requests. 1. The attacker can control a URL/host input that reaches backend request construction. 2. The affected service is allowed to make outbound network connections. 3. Destination validation and egress restrictions are insufficient for untrusted targets.
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

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-vj3m-g4cv-8j93
