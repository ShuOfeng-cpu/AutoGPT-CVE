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

AutoGPT Platform ships with a hardcoded default Fernet symmetric encryption key (ENCRYPTION_KEY=dvziYgz0KSK8FENhju0ZYi8-fRTfAdlz6YLhdB_jhNw=) committed to the public repository in backend/.env.default.This key encrypts all user OAuth tokens, API keys, and integration credentials stored in the User.integrations database column. Any attacker with database read access can decrypt the entire credential store using this publicly known key.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable behavior comes from using a static or default secret in Hardcoded Default Fernet Encryption Key / Fernet Encryption Key (`backend/.env`), which makes authentication or encryption dependent on a value that attackers may know.

### 2.2 Affected Code

The advisory identifies the following affected file(s):

- `backend/.env`
- `autogpt_platform/backend/backend/util/encryption.py`
- `autogpt_platform/backend/backend/data/user.py`
- `docker-compose.platform.yml`
- `autogpt_platform/.env`

### 2.3 Exploitation Path

Any self-hosted AutoGPT Platform deployment using the default.env is affected. An attacker who obtains database contents (via the companion ts-ag3-001 auth bypass, SQL injection, or a backup leak) can: Decrypt all OAuth access/refresh tokens for every connected service (GitHub, Google, Notion, Twitter/X, Linear, Discord, etc.) and act on behalf of all users Extract OpenAI, Anthropic, and other LLM API keys and use them at victims' expense Silently exfiltrate the complete integration credential store for every user in the system

## 3. Vulnerable Code Pattern

The vulnerable pattern is located in `backend/.env` and is tied to the Hardcoded Default Fernet Encryption Key / Fernet Encryption Key (`backend/.env`) functionality described above.

## 4. The Fix

The issue is fixed in `0.8.0`.

Linked fix material:

- https://github.com/Significant-Gravitas/AutoGPT/pull/14518
- https://github.com/Significant-Gravitas/AutoGPT/pull/14712

## 5. Impact

Any self-hosted AutoGPT Platform deployment using the default.env is affected. An attacker who obtains database contents (via the companion ts-ag3-001 auth bypass, SQL injection, or a backup leak) can: Decrypt all OAuth access/refresh tokens for every connected service (GitHub, Google, Notion, Twitter/X, Linear, Discord, etc.) and act on behalf of all users Extract OpenAI, Anthropic, and other LLM API keys and use them at victims' expense Silently exfiltrate the complete integration credential store for every user in the system

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-57mf-wqwq-6g6x
- https://github.com/Significant-Gravitas/AutoGPT/pull/14518
- https://github.com/Significant-Gravitas/AutoGPT/pull/14712
