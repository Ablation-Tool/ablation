# HardcodedCredentialScanner

## Why this exists

Three things were not possible before in Ablation:

1. **Find credential material in firmware without taint analysis.** TaintTracker and SinkArgClassifier trace how attacker-controlled data reaches exec sinks. Neither detects a static secret already embedded in the binary. An AWS access key, a private key PEM block, or a password literal in rodata does not flow anywhere; it just sits there. `HardcodedCredentialScanner` finds it directly, requiring no CFG, no arch-specific register analysis, and no prior BinaryContext triage.

2. **Cover all architectures in a single pass.** Because the scanner operates on the string table rather than disassembly, it works identically on x86-64, ARM32, ARM64, MIPS, PPC64, S390X, and any other ELF target Ablation supports. A single `scan()` call handles whatever the firmware is.

3. **Produce immediate red-team triage output.** When an initial triage must be fast, checking for embedded credentials before running full taint analysis surfaces the highest-severity finding class: pre-auth static secrets. This takes seconds rather than minutes.

## Usage

```python
from ablation.analyzers.hardcoded_credential_scanner import HardcodedCredentialScanner

scanner = HardcodedCredentialScanner('/path/to/firmware.elf')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/firmware.elf')
scanner = HardcodedCredentialScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: CredentialFinding

Each finding contains:

| Field | Type | Description |
|-------|------|-------------|
| `kind` | str | Pattern class: `AWS_ACCESS_KEY`, `PRIVATE_KEY_PEM`, `JWT`, `BEARER_TOKEN`, `PASSWORD_LITERAL`, `GENERIC_API_KEY`, `BASIC_AUTH_B64`, `AWS_SECRET_KEY`, `PRIVATE_KEY_DER` |
| `value` | str | Matched credential text, truncated to 80 characters |
| `context` | str | Surrounding string context, up to 120 characters |
| `va` | int | Virtual address of the string in the binary |
| `severity` | str | `HIGH` or `MEDIUM` |

## Pattern classes

| Kind | Pattern | Severity |
|------|---------|----------|
| `AWS_ACCESS_KEY` | `AKIA` followed by 16 uppercase alphanumeric chars | HIGH |
| `PRIVATE_KEY_PEM` | `-----BEGIN … PRIVATE KEY-----` header | HIGH |
| `JWT` | Three base64url segments separated by `.` | HIGH |
| `BEARER_TOKEN` | `Bearer ` followed by 20+ chars | HIGH |
| `PASSWORD_LITERAL` | `password=`/`passwd=`/`pwd=` with non-placeholder value | HIGH |
| `GENERIC_API_KEY` | `api_key=`/`secret_key=`/`access_token=` with 16+ char value | HIGH |
| `AWS_SECRET_KEY` | `aws_secret_access_key=` with 40-char base64 value | HIGH |
| `BASIC_AUTH_B64` | `Authorization: Basic` with base64-encoded value | MEDIUM |
| `PRIVATE_KEY_DER` | `PRIVATE KEY` string or PEM certificate header | MEDIUM |

Common placeholders are filtered automatically: `changeme`, `example`, `xxxx`, `test`, `dummy`, `none`, and `null`.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on:
- Test strings with AWS AKIA key: `AWS_ACCESS_KEY` found correctly.
- Password literal with placeholder `changeme`: filtered correctly.
- Bearer token with JWT header: `BEARER_TOKEN` found correctly.
- String with no credentials: 0 findings.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` (optional but provides VA-accurate string locations).

**After this module:** Use findings as immediate HIGH-severity report entries. Cross-reference `va` addresses with `BinaryContext.name()` to identify which function or data region contains the credential.

## See also

- [SemanticSearcher](semantic-code-search.md): query-based string and pattern search across the binary
- [TaintTracker](taint-analysis.md): trace how user input reaches exec sinks
- [IOCCandidateExtraction](ioc-candidate-extraction.md): extract IPs, domains, hashes from rodata
