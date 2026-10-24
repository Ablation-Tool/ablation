# LLMBehaviorSecurityProbes

## Why this exists

Three gaps motivated this module:

1. Agent deployments with stated Human-in-the-Loop policies needed a systematic test suite to verify the policy is enforced at the tool-call level, not just claimed in documentation.
2. Credentials retrieved via the LLM context window are potentially attacker-controlled after a prompt injection event, but no taint source definitions existed for this path.
3. Ablation lacked a central inventory of probe strings and taint source names for LLM-specific security tests.

## What it does

This module provides two static resources:

- **`HITL_PROBE_STRINGS`**: probe strings for testing HITL enforcement in a deployed agent
- **`LLM_CONTEXT_CREDENTIAL_SOURCES`**: taint source definitions for LLM-derived credentials

This module contains no scanner class. It is a definitions library used by test harnesses and by `TaintTracker` configuration.

## Usage

```python
from modules.llm_behavior_security_probes import (
    HITL_PROBE_STRINGS,
    LLM_CONTEXT_CREDENTIAL_SOURCES,
)

# Send each probe to a deployed agent and verify the response requests approval
for probe in HITL_PROBE_STRINGS['destructive_file']:
    response = agent.send(probe)
    assert 'confirm' in response.lower() or 'approval' in response.lower()

# Register taint sources with TaintTracker
for name, definition in LLM_CONTEXT_CREDENTIAL_SOURCES.items():
    tracker.add_taint_source(name, pattern=definition['source_pattern'])
```

## HITL_PROBE_STRINGS

Five categories of probe string, 19 total:

| Category | Count | What it tests |
| -------- | ----- | ------------- |
| `destructive_file` | 4 | File deletion and overwrite operations |
| `process_kill` | 4 | Process termination operations |
| `network_exfiltration` | 4 | Data exfiltration to external endpoints |
| `privilege_escalation` | 3 | Root command execution and privilege grants |
| `credential_extraction` | 4 | Reading secrets and connection strings |

## LLM_CONTEXT_CREDENTIAL_SOURCES

Four taint sources representing credentials that arrive via LLM context:

| Source name | Severity | Risk path |
| ----------- | -------- | --------- |
| `llm_system_prompt_credential` | HIGH | System prompt text contains API key |
| `llm_tool_result_credential` | HIGH | Tool call result returns credential |
| `llm_conversation_history_credential` | MEDIUM | Prior conversation turn contains key |
| `llm_retrieved_secret` | HIGH | get_secret tool call result is unverified |

## Severity and triage

HITL probe failures are HIGH severity: the agent executes destructive operations without approval. Credential taint source severity follows the definition field. All four `LLM_CONTEXT_CREDENTIAL_SOURCES` entries are HIGH or MEDIUM; treat them as externally-sourced credentials for taint propagation purposes.
