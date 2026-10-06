---
id: "sok-vulnerabilities-GHSA-4m2w-qfr5-9f3v-preset-creation-can-bind-a-foreign-webhook-enabling-known-id-forged-victim-webhook-executi"
title: "GHSA-4m2w-qfr5-9f3v: Preset creation can bind a foreign webhook, enabling known-ID forged victim webhook executions and exposing its signing secret"
created: "2026-10-06"
synthesizes: []
links: []
---

# GHSA-4m2w-qfr5-9f3v: Preset creation can bind a foreign webhook, enabling known-ID forged victim webhook executions and exposing its signing secret

| Field | Value |
|-------|-------|
| **ID** | GHSA-4m2w-qfr5-9f3v |
| **Class** | GitHub Security Advisory |
| **Component** | LibraryAgentPreset / AgentGraphExecution / webhook-triggered preset |
| **Affected Product** | AutoGPT |
| **Severity** | Moderate |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N` |
| **CWE** | CWE-863 |
| **Affected** | >= 0.6.14, <= 0.6.67 |
| **Fix Version** | `0.6.68` |
| **Source** | GitHub Security Advisory / Fix PR / Fix Commit / Fixed Release |

## 1. Overview

The webhook-triggered preset feature introduced in #10167 (efa4b6d), first released in v0.6.14, didn't guard against attaching a preset to another user's webhook: the user-supplied webhook_id was passed directly into the create_preset DB call without an ownership check on that webhook. Knowing the UUID of another user's webhook was enough for an attacker to create triggered presets attached to that webhook, causing any number of undesired extra graph runs on the victim user's behalf when the webhook receives a payload, draining their automation credit balance. An amendment introduced by #10309 (0e755a5), first released in v0.6.26, also allowed the attacker to access the victim's Webhook object by inclusion in the LibraryAgentPreset response (GET /presets/{id}, POST /presets, PATCH /presets/{id}). Note: these vulnerabilities did not allow an attacker to steal or tamper with the victim's legitimate webhook payloads.

## 2. Technical Details

### 2.1 Root Cause

The vulnerable component performed an action on an object identified by user-controlled input without enforcing the expected ownership or authorization check. The affected component is LibraryAgentPreset / AgentGraphExecution / webhook-triggered preset.

### 2.2 Affected Code

The advisory identifies the following affected endpoint(s):

- `GET /presets/{id}`
- `POST /presets`
- `PATCH /presets/{id}`

### 2.3 Exploitation Path

Having obtained a victim's webhook_id, an attacker could create a preset (LibraryAgentPreset) like: {"user_id": "<attacker_user_id>", "graph_id": "<graph_id>", // must be owned by victim or publicly available in Marketplace "inputs": {<attacker_trigger_config>}, "credentials": {<attacker_selected_credentials>} // if the attacker knows the victims' credential IDs} When a webhook payload arrives, this will create an agent run (AgentGraphExecution) like: {"user_id": "<victim_user_id>", // agent run is owned by victim -> payload not leaked "graph_id": "<graph_id>", "graph_credentials_inputs": {<attacker_selected_credentials>}, "nodes_input_masks": {"<trigger_node_id>": {**<attacker_trigger_config>, "payload": <victim_webhook_payload>}},} As you can see, the impact was mostly determined by what information the attacker already had: if they know a UUID of a webhook belonging to the victim, they could: trigger undesired extra agent runs on behalf of the victim, draining their automation cr...

## 3. Vulnerable Code Pattern

The vulnerable pattern is exposed through `GET /presets/{id}`, where the request path or body can reach the affected operation without the required validation or authorization check.

## 4. The Fix

The issue is fixed in `0.6.68`.

Linked fix material:

- https://github.com/Significant-Gravitas/AutoGPT/pull/10167
- https://github.com/Significant-Gravitas/AutoGPT/commit/efa4b6d2a097a140645233d673f1f89db64edb50
- https://github.com/Significant-Gravitas/AutoGPT/pull/10309
- https://github.com/Significant-Gravitas/AutoGPT/commit/0e755a5c8579601ee3228c6cd3342aefe338b7f1
- https://github.com/Significant-Gravitas/AutoGPT/releases/tag/autogpt-platform-beta-v0.6.68

## 5. Impact

Having obtained a victim's webhook_id, an attacker could create a preset (LibraryAgentPreset) like: {"user_id": "<attacker_user_id>", "graph_id": "<graph_id>", // must be owned by victim or publicly available in Marketplace "inputs": {<attacker_trigger_config>}, "credentials": {<attacker_selected_credentials>} // if the attacker knows the victims' credential IDs} When a webhook payload arrives, this will create an agent run (AgentGraphExecution) like: {"user_id": "<victim_user_id>", // agent run is owned by victim -> payload not leaked "graph_id": "<graph_id>", "graph_credentials_inputs": {<attacker_selected_credentials>}, "nodes_input_masks": {"<trigger_node_id>": {**<attacker_trigger_config>, "payload": <victim_webhook_payload>}},} As you can see, the impact was mostly determined by what information the attacker already had: if they know a UUID of a webhook belonging to the victim, they could: trigger undesired extra agent runs on behalf of the victim, draining their automation cr...

## 6. References

- https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-4m2w-qfr5-9f3v
- https://github.com/Significant-Gravitas/AutoGPT/pull/10167
- https://github.com/Significant-Gravitas/AutoGPT/commit/efa4b6d2a097a140645233d673f1f89db64edb50
- https://github.com/Significant-Gravitas/AutoGPT/pull/10309
- https://github.com/Significant-Gravitas/AutoGPT/commit/0e755a5c8579601ee3228c6cd3342aefe338b7f1
- https://github.com/Significant-Gravitas/AutoGPT/releases/tag/autogpt-platform-beta-v0.6.68
