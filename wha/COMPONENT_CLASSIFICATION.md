# OpenClaw Component Classification (Initial)

Snapshot: `2026-11-04`

The 722 advisory records are placed in one primary component folder each. This is a first-pass research classification, not an official OpenClaw or CVE label. The assignment uses the advisory title and technical root-cause text, with the existing dataset's architecture label as a fallback. When a finding crosses components, the folder follows the component where the failed check or execution boundary is implemented.

| Component | Records |
|---|---:|
| [N-02 Channel Adapter](./N-02_Channel_Adapter/) | 183 |
| [N-03 Skills / Plugins Registry](./N-03_Skills_Plugins_Registry/) | 23 |
| [N-04 Gateway](./N-04_Gateway/) | 198 |
| [N-05 Router / Session Store](./N-05_Router_Session_Store/) | 9 |
| [N-06 Context Builder](./N-06_Context_Builder/) | 7 |
| [N-07 Agent Runtime](./N-07_Agent_Runtime/) | 40 |
| [N-08 LLM Provider](./N-08_LLM_Provider/) | 0 |
| [N-09 Tool Policy / Approval](./N-09_Tool_Policy_Approval/) | 98 |
| [N-10 Tool Executors](./N-10_Tool_Executors/) | 105 |
| [N-11 Node Host / Sandbox](./N-11_Node_Host_Sandbox/) | 59 |

N-08 is empty in this first pass because no record clearly identifies a flaw in OpenClaw's own model request/response, streaming, or tool-call adapter code. Provider credentials, plugin setup, Gateway authentication, and tool execution remain assigned to the component that owns those paths.

The root [README](./README.md) remains the corpus index. `CODE_PATCH_ENRICHMENT_STATUS.md` also remains at the root because it describes the corpus rather than one vulnerability. Channel-specific sender, webhook, pairing, and message handling issues go to N-02; skill and plugin acquisition or loading issues go to N-03; Gateway routes, scopes, and control-plane access go to N-04. Tool authorization and approval failures go to N-09, while concrete tool input and execution failures go to N-10. Sandbox and node-host boundary failures go to N-11. Session ownership and memory access go to N-05, context trust and prompt construction to N-06, and hooks or agent orchestration to N-07.

Treat records that span multiple boundaries as candidates for manual review before using the folders as final research labels.
