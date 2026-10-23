# PolicyEngineAbsenceDetector

## Why this exists

One thing was not possible before in Ablation:

1. **Detect AI/LLM API calls without policy enforcement in firmware.** Traditional Ablation modules track `system()` without auth checks or `strcpy()` without bounds checks. AI-enabled firmware introduces a new class of structural gap: a binary that calls an LLM inference endpoint but has no observable rate limiting, input validation, authorization checks, or audit logging. `PolicyEngineAbsenceDetector` is the AI-agent analogue of pre-auth command injection detection: it finds the combination of AI API usage and absent policy layer as a single structural finding rather than requiring manual correlation.

## Usage

```python
from ablation.analyzers.policy_engine_absence_detector import PolicyEngineAbsenceDetector

detector = PolicyEngineAbsenceDetector('/path/to/binary')
findings = detector.scan()
print(detector.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
detector = PolicyEngineAbsenceDetector.from_context(ctx)
findings = detector.scan()
```

## Output: PolicyAbsenceFinding

| Field | Type | Description |
|-------|------|-------------|
| `ai_indicators` | list[str] | Evidence of AI API usage: hostnames, SDK strings, PLT symbols |
| `missing_layers` | list[str] | Policy layers not found: `rate_limiting`, `input_validation`, `authorization`, `audit_logging` |
| `present_layers` | list[str] | Policy layers found |
| `severity` | str | `HIGH` when all four layers are absent; `MEDIUM` when some are present |

## AI detection

Two detection channels are combined:

**String-based:** 11 AI provider hostname and SDK name patterns including `api.openai.com`, `api.anthropic.com`, `huggingface.co`, `bedrock.amazonaws.com`, and `ChatCompletion`, `messages.create`, `GenerateContent`, `invoke_model`.

**PLT-based:** known AI SDK function symbols in the import table.

## Policy layer detection

Four layers are checked via 24 regex patterns across the raw binary:

| Layer | Sample patterns |
|-------|----------------|
| `rate_limiting` | `rate_limit`, `token_bucket`, `throttle`, `quota` |
| `input_validation` | `validate_input`, `sanitize`, `schema_check`, `prompt_filter` |
| `authorization` | `check_permission`, `authorize`, `rbac`, `acl` |
| `audit_logging` | `audit_log`, `write_audit`, `log_event` |

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on:
- Binary with `api.openai.com` hostname and no policy strings: `HIGH` finding with all four missing layers.
- Binary with `api.openai.com` and all four policy layer patterns present: no finding.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** use `AgentAuthorityAudit` to check whether the agent's capability scope is bounded. If `PolicyEngineAbsenceDetector` fires HIGH, flag the binary for manual review of every LLM call site identified by `TaintTracker` with the AI hostname as a terminal sink.

## See also

- [AgentAuthorityAudit](agent-authority-audit.md): agent permission scope analysis
- [TaintTracker](taint-analysis.md): trace user input to AI API sinks
- [HardcodedCredentialScanner](hardcoded-credential-scanner.md): detect embedded API keys used to call AI services
