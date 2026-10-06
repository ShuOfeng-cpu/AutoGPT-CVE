---
id: "sok-vulnerabilities-GHSA-57mf-wqwq-6g6x-hardcoded-default-fernet-encryption-key-exposes-all-stored-oauth-credentials"
title: "GHSA-57mf-wqwq-6g6x: Hardcoded Default Fernet Encryption Key Exposes All Stored OAuth Credentials"
created: "2026-10-06"
synthesizes: []
links: []
---

# GHSA-57mf-wqwq-6g6x: Hardcoded Default Fernet Encryption Key Exposes All Stored OAuth Credentials

| Field | Value |
|-------|-------|
| **ID** | GHSA-57mf-wqwq-6g6x |
| **Class** | GitHub Security Advisory |
| **Component** | Hardcoded Default Fernet Encryption Key / Fernet Encryption Key (`backend/.env`) |
| **Affected Product** | AutoGPT |
| **Severity** | High |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **CWE** | CWE-321, CWE-798 |
| **Affected** | >= 0.6.23, <= 0.7.4 |
| **Fix Version** | `0.8.0` |
| **Source** | GitHub Security Advisory / Fix PR |

## 1. Overview

AutoGPT Platform ships with a hardcoded default Fernet symmetric encryption key (`ENCRYPTION_KEY=dvziYgz0KSK8FENhju0ZYi8-fRTfAdlz6YLhdB_jhNw=`) committed to the public repository in `backend/.env.default`. This key encrypts all user OAuth tokens, API keys, and integration credentials stored in the `User.integrations` database column. Any attacker with database read access can decrypt the entire credential store using this publicly known key.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable behavior comes from forwarding or recording credentials outside the intended trust boundary. The affected component is Hardcoded Default Fernet Encryption Key / Fernet Encryption Key (`backend/.env`).

### 2.2 Affected Code

The advisory identifies the following affected file(s):

- `backend/.env`
- `autogpt_platform/backend/backend/util/encryption.py`
- `autogpt_platform/backend/backend/data/user.py`
- `docker-compose.platform.yml`
- `autogpt_platform/.env`

The advisory/source text also names the following relevant symbols or runtime objects:

- `__init__`
- `update_user_integrations`
- `JSONCryptor`
- `ENCRYPTION_KEY`
- `fernet`
- `encrypted_data`
- `plaintext`
- `credentials`

### 2.3 Exploitation Path

An attacker can cause AutoGPT to send a request or follow a redirect to a destination outside the intended trust boundary, while sensitive headers, cookies, or credentials remain attached to the request.

### 2.4 Attack Surface Summary

| Surface | Source-supported detail |
|---------|--------------------------|
| Component | Hardcoded Default Fernet Encryption Key / Fernet Encryption Key (`backend/.env`) |
| Source file(s) | `backend/.env`<br>`autogpt_platform/backend/backend/util/encryption.py`<br>`autogpt_platform/backend/backend/data/user.py`<br>`docker-compose.platform.yml`<br>`autogpt_platform/.env` |
| Named code objects | `__init__`<br>`update_user_integrations`<br>`JSONCryptor`<br>`ENCRYPTION_KEY`<br>`fernet`<br>`encrypted_data`<br>`plaintext`<br>`credentials` |
| Affected versions | >= 0.6.23, <= 0.7.4 |
| Patched version | `0.8.0` |

### 2.5 Source Evidence

#### Implementation evidence

Details

`autogpt_platform/backend/backend/util/encryption.py`:

```
ENCRYPTION_KEY = Settings().secrets.encryption_key

class JSONCryptor:
    def __init__(self, key: Optional[str] = None):
        self.key = key or ENCRYPTION_KEY
        self.fernet = Fernet(
            self.key.encode() if isinstance(self.key, str) else self.key
        )
```

`autogpt_platform/backend/backend/data/user.py`:

```
async def update_user_integrations(user_id: str, data: UserIntegrations):
    encrypted_data = JSONCryptor().encrypt(data.model_dump(exclude_none=True))
    await PrismaUser.prisma().update(
        where={"id": user_id},
        data={"integrations": encrypted_data},
    )
```

`backend/.env.default` ships:

```
ENCRYPTION_KEY=dvziYgz0KSK8FENhju0ZYi8-fRTfAdlz6YLhdB_jhNw=
```

This is a valid Fernet key committed to the public repository. Any deployment using the default `.env` stores all user credentials encrypted with a key any attacker already knows.

Note: this same key is used as the HMAC key fallback in the Redis cache (ts-ag2-001), compounding the risk.

Affected commit: `94ebce7f633f40af8fd59e5cdaea75159cf2e6d1`

🤖 Carried from GHSA-x7fr-7grv-gqxc, closed as a duplicate of this report

Two remediation-relevant facts the duplicate stated and this record did not. Both verified against `dev` at `c91105ff36`.

1. There is no way to rotate off the compromised key. `encryption.py:8` binds `ENCRYPTION_KEY` to a module-level constant and `scoped_credentials.py:20` builds one process-wide `JSONCryptor()` from it; `IntegrationCredential` carries no key-version column, and the repository contains no rotation or re-encryption code. Changing `ENCRYPTION_KEY` therefore makes existing ciphertext undecryptable rather than re-keying it, and `JSONCryptor.decrypt` swallows the failure and returns `{}`. Remediating this needs a re-encryption migration, not just a new key.
2. The public default key is what a deployment actually runs, even when setup was followed correctly. `docker-compose.platform.yml:42-46` always loads `backend/.env.default` as the base env file, with `backend/.env` only an optional override, and `autogpt_platform/.env.default` — the file the setup documentation has operators copy — defines no `ENCRYPTION_KEY` at all. "Deployments using the default.env" understates the exposure.

#### Proof-of-concept evidence

```
from cryptography.fernet import Fernet
import json

KNOWN_KEY = "dvziYgz0KSK8FENhju0ZYi8-fRTfAdlz6YLhdB_jhNw="
fernet = Fernet(KNOWN_KEY.encode())

# ciphertext obtained from User.integrations database column
ciphertext = "<base64_fernet_token_from_db>"
plaintext = fernet.decrypt(ciphertext.encode())
credentials = json.loads(plaintext)
# → { "oauth_tokens": { "github": { "access_token": "gho_." },. }, "api_keys": { "openai": "sk-." } }
```

Full reproduction: `python3 poc_ts_ag3_002.py --demo` reproduce.zip

#### Workaround guidance

None.

## 3. Vulnerable Code Pattern

The vulnerable pattern is relying on a static default secret for authentication or credential encryption instead of requiring a deployment-specific secret. A known secret collapses the intended trust boundary for tokens, signatures, or encrypted values that depend on it.

## 4. The Fix

Fix strategy:

- Upgrade AutoGPT to `0.8.0` or a later release containing the patch.
- Apply the source-stated remediation: A key-rotation command was added in `ef3c9c6967` (#14712).
- Apply the source-stated remediation: None.
- Bind credentials and protected headers to the intended destination host before forwarding requests.
- Strip credentials on cross-origin redirects or when the destination host no longer matches the trusted origin.
- Redact sensitive values from logs and error propagation paths.
- Use the linked PR or commit as the authoritative patch reference when backporting the fix to a self-hosted deployment.

Validation and regression checks:

- A redirect to a different host should not receive the original `Authorization`, `Proxy-Authorization`, cookie, or protected header values.
- A same-origin redirect should preserve only the headers that are still valid for the redirected request.
- Logs and propagated errors should not expose token, cookie, API key, or credential values.

Operational follow-up:

- Inventory self-hosted AutoGPT deployments and confirm whether their running version falls inside the affected range.
- If an immediate upgrade is not possible, backport the same validation, authorization, or dependency constraint shown by the linked fix material.
- Rotate any credentials, tokens, cookies, or encrypted material that may have crossed the affected trust boundary.

Linked fix material:

- https://github.com/Significant-Gravitas/AutoGPT/pull/14518
- https://github.com/Significant-Gravitas/AutoGPT/pull/14712

## 5. Impact

An attacker can cause AutoGPT to send a request or follow a redirect to a destination outside the intended trust boundary, while sensitive headers, cookies, or credentials remain attached to the request.
CVSS metric breakdown:

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | High |
| Privileges Required | Low |
| User Interaction | None |
| Scope | Changed |
| Confidentiality | High |
| Integrity | High |
| Availability | None |

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-57mf-wqwq-6g6x
- https://github.com/Significant-Gravitas/AutoGPT/pull/14518
- https://github.com/Significant-Gravitas/AutoGPT/pull/14712
