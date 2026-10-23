# AgentAuthorityAudit

## Why this exists

One thing was not possible before in Ablation:

1. **Map agent capability scope and flag authority surplus.** An agent binary that calls an LLM API but also imports `system()`, `execve()`, or `WriteProcessMemory` has more authority than its task requires. No prior Ablation module compared the agent's inferred role against its imported capability set. `AgentAuthorityAudit` detects the agent type from string patterns, maps PLT imports to seven capability categories, and flags capabilities that exceed what the detected agent type needs. This is the binary-level version of least-privilege enforcement.

## Usage

```python
from modules.agent_authority_audit import AgentAuthorityAudit

auditor = AgentAuthorityAudit('/path/to/binary')
findings = auditor.scan()
print(auditor.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
auditor = AgentAuthorityAudit.from_context(ctx)
findings = auditor.scan()
```

## Output: AuthorityFinding

| Field | Type | Description |
|-------|------|-------------|
| `agent_type` | str | `ai_agent`, `web_agent`, or `cli_agent` |
| `excess_capabilities` | list[str] | Capabilities beyond what the agent type requires |
| `all_capabilities` | list[str] | All detected capability categories |
| `severity` | str | `HIGH` when excess includes high-risk categories; `MEDIUM` otherwise |

## Capability categories

| Category | Sample imports |
|----------|----------------|
| `process_execution` | `system`, `execve`, `CreateProcessA`, `popen` |
| `file_write` | `fwrite`, `write`, `unlink`, `chmod`, `WriteFile` |
| `network_raw` | `socket`, `bind`, `connect`, `send`, `recv` |
| `credential_access` | `getpwnam`, `pam_authenticate`, `keyctl` |
| `system_config` | `setuid`, `chroot`, `ptrace`, `ioctl`, `prctl` |
| `memory_injection` | `VirtualAllocEx`, `WriteProcessMemory`, `mprotect` |
| `persistence` | `RegSetValueExA`, `systemctl`, `crontab` |

An AI agent is expected to have `network_raw` (to reach the API). All other categories are flagged as excess.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** for `process_execution` excess, run `TaintTracker` to check whether the execution path is reachable from LLM-controlled output. Use `PolicyEngineAbsenceDetector` to confirm whether there is a policy layer gating the execution.

## See also

- [PolicyEngineAbsenceDetector](policy-engine-absence-detector.md): check for missing rate limit and auth policy
- [TaintTracker](taint-analysis.md): trace LLM output to execution sinks
- [ProcessInjectionComboScanner](process-injection-combo-scanner.md): detect full injection API triads
