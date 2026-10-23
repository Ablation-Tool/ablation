# LethalTrifectaScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Flag binaries that combine the three conditions required for data exfiltration: access to sensitive data, untrusted input ingestion, and outbound communications.** Individual signals are common and not findings on their own. It is the combination that matters. `LethalTrifectaScanner` checks for three simultaneous signals: 20 sensitive data string patterns in rodata such as `api_key`, `password`, `jwt`, and `aws_access_key`; 13 untrusted input PLT imports such as `recv`, `read`, `getenv`, and `scanf`; and outbound communication PLT imports or LLM API host strings. All three together is a HIGH finding. Any two is MEDIUM.

## Usage

```python
from modules.lethal_trifecta_scanner import LethalTrifectaScanner

scanner = LethalTrifectaScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = LethalTrifectaScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: TrifectaFinding

| Field | Type | Description |
|-------|------|-------------|
| `has_private_data` | bool | Sensitive string patterns found in rodata |
| `has_input_source` | bool | Input-source PLT imports present |
| `has_outbound` | bool | Outbound sink PLT imports or LLM host strings present |
| `private_matches` | list[str] | Matched sensitive string patterns |
| `input_imports` | list[str] | Matched input PLT function names |
| `outbound_signals` | list[str] | Matched outbound imports and LLM host strings |
| `severity` | str | `HIGH` for all three present; `MEDIUM` for any two |

## Signal categories

**Private data strings (20 patterns):** `api_key`, `apikey`, `api_secret`, `private_key`, `secret`, `credential`, `password`, `access_token`, `auth_token`, `bearer`, `jwt`, `certificate`, `cert_chain`, `client_secret`, `aws_secret`, `aws_access_key`.

**Input source imports (13):** `recv`, `recvfrom`, `recvmsg`, `read`, `fread`, `fgets`, `gets`, `getenv`, `scanf`, `sscanf`, `fscanf`, `HttpQueryInfo`, `WinHttpQueryHeaders`.

**Outbound communication (21 PLT imports plus 6 LLM API host strings):** `connect`, `send`, `SSL_connect`, `SSL_write`, `curl_easy_perform`, `BIO_write`, `getaddrinfo`, `WinHttpConnect`, plus `api.openai.com`, `api.anthropic.com`, `api.cohere.ai`, and others.

## Limitations

`LethalTrifectaScanner` uses PLT import presence as a proxy for actual data flow. A binary that imports `recv` and `connect` may route those through separate code paths that never combine with the sensitive data. Use `TaintTracker` to confirm actual flow from input source to outbound sink.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## See also

- [PromptInjectionSinkClassifier](prompt-injection-sink-classifier.md): LLM API sink co-location
- [PolicyEngineAbsenceDetector](policy-engine-absence-detector.md): authorization and audit layer absence
- [TaintTracker](taint-analysis.md): confirm data flow from input to outbound sink
