---
id: "sok-vulnerabilities-GHSA-m2wr-7m3r-p52c-redos-regular-expression-denial-of-service-at-code-extraction-block"
title: "GHSA-m2wr-7m3r-p52c: ReDoS (Regular Expression Denial of Service) at Code Extraction Block"
created: "2026-10-06"
synthesizes: []
links: []
---

# GHSA-m2wr-7m3r-p52c: ReDoS (Regular Expression Denial of Service) at Code Extraction Block

| Field | Value |
|-------|-------|
| **ID** | GHSA-m2wr-7m3r-p52c |
| **Class** | GitHub Security Advisory |
| **Component** | ReDoS (Regular Expression Denial of Service) at Code Extraction Block (`autogpt_platform/backend/backend/blocks/code_extraction_block.py`) |
| **Affected Product** | AutoGPT |
| **Severity** | Moderate |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` |
| **CWE** | CWE-1333 |
| **Affected** | >= 0.4.0 |
| **Fix Version** | `autogpt-platform-beta-v0.6.32` |
| **Source** | GitHub Security Advisory |

## 1. Overview

The `autogpt` is vulnerable to Regular Expression Denial of Service due to the use of regex at Code Extraction Block. The vulnerable code is: ``` pattern = (r"```(?:" + "|".join(re.escape(alias) for aliases in language_aliases.values() for alias in aliases) + r")\s+[\s\S]*?```") ``` and ``` pattern = re.compile(rf"```{language}\s+(.*?)```", re.DOTALL | re.IGNORECASE) ``` The two Regex are used containing the corresponding dangerous patterns `\s+[\s\S]*?` and `\s+(.*?)`. They share a common characteristic — the combination of two adjacent quantifiers that can match the same space character (`\s`). As a result, an attacker can supply a long sequence of space characters to trigger excessive regex backtracking, potentially leading to a Denial of Service (DoS).

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component can be driven into excessive resource consumption by attacker-controlled input. The affected component is ReDoS (Regular Expression Denial of Service) at Code Extraction Block (`autogpt_platform/backend/backend/blocks/code_extraction_block.py`).

### 2.2 Affected Code

The advisory identifies the following affected file(s):

- `autogpt_platform/backend/backend/blocks/code_extraction_block.py`

The advisory/source text also names the following relevant symbols or runtime objects:

- `pattern`

### 2.3 Exploitation Path

An attacker can exploit this by providing maliciously crafted input strings. This forces the application into intensive processing, resulting in: - High CPU usage - Potential application downtime Effectively, this creates a Denial of Service (DoS) scenario.

### 2.4 Attack Surface Summary

| Surface | Source-supported detail |
|---------|--------------------------|
| Component | ReDoS (Regular Expression Denial of Service) at Code Extraction Block (`autogpt_platform/backend/backend/blocks/code_extraction_block.py`) |
| Source file(s) | `autogpt_platform/backend/backend/blocks/code_extraction_block.py` |
| Named code objects | `pattern` |
| Affected versions | >= 0.4.0 |
| Patched version | `autogpt-platform-beta-v0.6.32` |

### 2.5 Source Evidence

#### Occurrences

https://github.com/Significant-Gravitas/AutoGPT/blob/master/autogpt_platform/backend/backend/blocks/code_extraction_block.py#L86-L96
https://github.com/Significant-Gravitas/AutoGPT/blob/master/autogpt_platform/backend/backend/blocks/code_extraction_block.py#L106-L109

#### Proof-of-concept evidence

Attacker can exploit this vulnerability to conduct DoS attack by:

- Create Code Extraction Block

- Then, save the agent

- Run the Python code below to generate a payload and save it to a file:

```
with open("output.txt", "w") as f:
    f.write("```html" + " " * 200000)
```

- Copy the payload from this file

- Paste into the text input → Click Save → Click Run

- Observe that it take over 8 minutes to run successfully. Larger inputs will take more time.

- Performing a few runs with the same input can cause CPU exhaustion.

## 3. Vulnerable Code Pattern

The vulnerable pattern is located in `autogpt_platform/backend/backend/blocks/code_extraction_block.py` and is tied to the ReDoS (Regular Expression Denial of Service) at Code Extraction Block (`autogpt_platform/backend/backend/blocks/code_extraction_block.py`) functionality described above.

## 4. The Fix

Fix strategy:

- Upgrade AutoGPT to `autogpt-platform-beta-v0.6.32` or a later release containing the patch.
- Apply the source-stated remediation: The sub-pattern `\s+[\s\S]*?` and `\s+(.*?)` can be replaced by `[\t]*\n([\s\S]*?)`.
- Add explicit resource limits for attacker-controlled input size, iteration count, output size, memory use, disk growth, or execution time.
- Reject or truncate inputs before expensive processing begins.
- Add regression tests covering worst-case inputs that previously exhausted resources.

Validation and regression checks:

- Inputs matching the advisory's worst-case path should be rejected, bounded, or processed within a safe resource limit.
- Normal-sized inputs should still complete successfully after the limit is added.
- Tests should cover both the attack-sized input and the largest accepted benign input.

Operational follow-up:

- Inventory self-hosted AutoGPT deployments and confirm whether their running version falls inside the affected range.
- If an immediate upgrade is not possible, backport the same validation, authorization, or dependency constraint shown by the linked fix material.
- Check disk, memory, CPU, and job-queue telemetry for abnormal growth during the vulnerable period.

## 5. Impact

An attacker can exploit this by providing maliciously crafted input strings. This forces the application into intensive processing, resulting in: - High CPU usage - Potential application downtime Effectively, this creates a Denial of Service (DoS) scenario.
CVSS metric breakdown:

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | None |
| Integrity | None |
| Availability | High |

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-m2wr-7m3r-p52c
