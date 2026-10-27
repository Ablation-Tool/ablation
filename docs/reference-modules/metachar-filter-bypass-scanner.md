# MetacharFilterBypassScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Detect input sanitizers that check metacharacter bytes individually without validating multi-byte encoding sequences.** A sanitizer that checks for the literal byte `0x2F` rejects a plain `/` but misses `0xE0 0x80 0xAF`, which is an overlong UTF-8 sequence that many parsers decode as `/`. `MetacharFilterBypassScanner` identifies functions that perform 3 or more CMP instructions against shell metacharacter byte values but never compare against UTF-8 multi-byte lead bytes or the percent-encoding marker `0x25`. Those functions are single-byte filters bypassable via encoding.

## Usage

```python
from modules.metachar_filter_bypass_scanner import MetacharFilterBypassScanner

scanner = MetacharFilterBypassScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = MetacharFilterBypassScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: MetacharBypassFinding

| Field | Type | Description |
|-------|------|-------------|
| `func_va` | int | VA of the filter function |
| `func_name` | str | Function name or `sub_VA` |
| `metachar_hits` | list[int] | Metacharacter byte values found in CMP instructions |
| `has_multibyte` | bool | Always False for emitted findings; True means no finding |
| `has_exec_sink` | bool | True when the same function also calls an exec-family sink |
| `severity` | str | `HIGH` for named sanitizers or exec-sink co-location; `MEDIUM` otherwise |

## Shell metacharacters tracked

30 byte values: NUL, TAB, LF, CR, SPACE, `!`, `"`, `#`, `$`, `%`, `&`, `'`, `(`, `)`, `*`, `+`, `,`, `/`, `:`, `;`, `<`, `>`, `?`, `@`, `[`, `\`, `]`, `` ` ``, `|`, `~`.

## Multi-byte indicator bytes

`0xC0`, `0xC1` (overlong 2-byte), `0xC2`-`0xDF` (valid 2-byte leads), `0xE0`-`0xEF` (3-byte leads), `0xF0`-`0xF4` (4-byte leads), and `0x25` (`%` for percent-encoding). A function that checks any of these is NOT flagged.

## Severity logic

- `HIGH`: function name contains `sanitize`, `filter`, `escape`, `strip`, `clean`, `validate`, `check`, `encode`, `allow`, `deny`, or `block`.
- `HIGH`: function contains 3 or more metacharacter CMPs AND also calls an exec-family sink such as `system`, `execve`, or `popen` in the same function body.
- `MEDIUM`: metacharacter CMPs present but no named sanitizer pattern and no exec sink.

## False positives

Not every CMP against 0x2F is a security filter. Protocol parsers and path parsers also compare against `/`. A finding is most credible when the function name matches the sanitizer pattern or when the function calls an exec sink.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

## See also

- [TaintTracker](taint-analysis.md): trace filtered input to exec sinks
- [SemanticSearcher](semantic-code-search.md): find sanitizer candidates by name
- [SinkArgClassifier](sink-arg-classifier.md): classify exec sink argument provenance
