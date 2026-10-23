# AgentObservabilityAudit

## Why this exists

One thing was not possible before in Ablation:

1. **Detect LLM agent runtimes that lack the logging, human-in-the-loop checkpoints, and kernel audit trail needed to reconstruct what actions the agent took.** Without these components, post-incident analysis of a compromised agentic system is impossible: there is no record of which tool the model invoked, what the tool returned, or whether a human had an opportunity to intervene. `AgentObservabilityAudit` gates on agent indicator strings (`tool_call`, `function_call`, `agent_loop`) to confirm the binary is an agent runtime, then checks PLT imports for structured logging sinks, scans function names for HITL confirmation patterns, and checks for kernel audit trail sinks.

## Usage

```python
from modules.agent_observability_audit import AgentObservabilityAudit

auditor = AgentObservabilityAudit('/path/to/binary')
findings = auditor.scan()
print(auditor.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
auditor = AgentObservabilityAudit.from_context(ctx)
findings = auditor.scan()
```

## Output: ObservabilityFinding

| Field | Type | Description |
|-------|------|-------------|
| `category` | str | Absent component class (see table) |
| `detail` | str | What was searched and not found |
| `severity` | str | `HIGH` or `MEDIUM` |

## Checked components

| Category | Severity | What is checked |
|----------|----------|-----------------|
| `structured_logging` | HIGH | PLT imports include syslog, openlog, log4c_init, zlog_init, sd_journal_print, or audit_log functions |
| `hitl_checkpoint` | HIGH | Function names match: confirm, approve, checkpoint, interrupt_agent, human_review, request_approval |
| `audit_trail` | MEDIUM | PLT imports include audit_open or audit_log_user_message |

## Agent runtime gate

No findings are emitted if the binary does not contain agent indicator strings: `tool_call`, `tool_result`, `function_call`, `function_result`, `agent_loop`, `agentic`, `run_agent`, or `agent_step`. This prevents false positives on ordinary network daemons.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on synthetic agent binary with no log sinks or HITL functions: all three absence findings emitted.

## See also

- [AgentAuthorityAudit](agent-authority-audit.md): capability excess
- [AgentToolSurfaceEnumerator](agent-tool-surface-enumerator.md): what tools the LLM can invoke
- [PolicyEngineAbsenceDetector](policy-engine-absence-detector.md): missing rate-limit and authorization layers
