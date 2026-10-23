# PromptInjectionSinkClassifier

## Why this exists

One thing was not possible before in Ablation:

1. **Identify binary code paths where untrusted external input reaches an LLM API call site that also embeds a system prompt.** No prior Ablation module recognized LLM API endpoints or system-prompt injection patterns. `PromptInjectionSinkClassifier` searches for LLM provider host strings (10 providers), checks for 12 system-prompt indicator patterns such as `"role":"system"`, `<<SYS>>`, and `system_prompt`, and then walks function disassembly to find functions that both read from external input sources and write to HTTP/network sinks. When both signals appear in the same function, user-controlled data is combining with a system prompt before reaching the LLM, making the application vulnerable to prompt injection.

## Usage

```python
from modules.prompt_injection_sink_classifier import PromptInjectionSinkClassifier

classifier = PromptInjectionSinkClassifier('/path/to/binary')
findings = classifier.scan()
print(classifier.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
classifier = PromptInjectionSinkClassifier.from_context(ctx)
findings = classifier.scan()
```

## Output: PromptInjectionFinding

| Field | Type | Description |
|-------|------|-------------|
| `func_va` | int | VA of the function with both signals |
| `func_name` | str | Function name or `sub_VA` |
| `has_system_prompt` | bool | System-prompt indicator strings present in binary |
| `has_input_source` | bool | Function calls a read/recv/getenv source |
| `has_http_sink` | bool | Function calls send/write/curl to transmit the request |
| `llm_host` | str | First LLM host string found in the binary |
| `severity` | str | `HIGH` when both input source and HTTP sink present; `MEDIUM` otherwise |

## LLM API providers tracked

`api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `inference.ai.azure.com`, `api.cohere.ai`, `api.mistral.ai`, `api.together.xyz`, `api.groq.com`, `bedrock-runtime.*`, `aiplatform.googleapis.com`.

## System prompt indicators

12 patterns: `"role":"system"`, `role=system`, `SYSTEM:`, `<|system|>`, `[SYSTEM]`, `system_prompt`, `systemPrompt`, `system_message`, `<<SYS>>`, `[INST]`, `<|im_start|>system`.

## Limitations

This module detects the co-occurrence of signals, not confirmed taint flow. A function that reads external input and sends an HTTP request may be making an unrelated API call. Use `TaintTracker` with the HTTP-write sink configured to confirm data flows from the input source to the request body.

If no LLM host string or no system-prompt indicator exists in the binary at all, no findings are emitted regardless of network calls present.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## See also

- [AgentAuthorityAudit](agent-authority-audit.md): capability excess in agent runtimes
- [PolicyEngineAbsenceDetector](policy-engine-absence-detector.md): missing rate-limit and authorization layers
- [LethalTrifectaScanner](lethal-trifecta-scanner.md): private data + untrusted input + external comms
- [TaintTracker](taint-analysis.md): confirm data flow from input source to HTTP sink
