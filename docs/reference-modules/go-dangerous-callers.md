# GoDangerousCallers

**File:** `modules/go_dangerous_callers.py`

## Why this exists

Pre-built callgraph scanner for Go binaries: identifies dangerous call sites (unsafe.Pointer casts, reflect.NewAt, os.exec, net/http.Get) with rodata-first string extraction and Go itab resolution. Single text scan builds the full callgraph; subsequent lookups are O(1).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. `lief.parse()` used in `_build_section_map()` (L167), wrapped in `try/except Exception` + `if self._lb is None` check. No HTTP reads.

---

## How it works

`GoDangerousCallers.from_context(ctx).scan()` builds a pre-computed callgraph from a single sequential disassembly pass (`{callee_va: caller_va_set}` and `{caller_va: callee_va_set}`) rather than iterating func_starts. Identifies dangerous call targets fmt.Sprintf with tainted variadics, os.exec, unsafe.Pointer casts by Go 1.17+ register ABI (`rax/rbx` = arg0, `rcx/rdx` = arg1). Resolves itabs from `.rodata` for virtual dispatch sites. Returns `List[DangerousCallHit]` sorted by severity.

---

## Usage

```python
from modules.go_dangerous_callers import GoDangerousCallerScanner

scanner = GoDangerousCallerScanner('/path/to/go_binary')
hits = scanner.scan(dangerous_targets=['exec.Command', 'os/exec.Command'])
for h in hits:
    print(h)
```

---

## Example output

```
DangerousCallHit  os/exec.Command  at 0x0041f820 in runUserScript (0x0041f800)
  string refs: "sh" (0x0041f814), "-c" (0x0041f818)

DangerousCallHit  os.Getenv  at 0x00423c10 in buildAuthToken (0x00423be0)
  string refs: "SECRET_KEY" (0x00423c04)
```

---

## False positives

Calls to `os/exec.Command` with fully static string arguments hardcoded command paths are not exploitable. Check `string_refs`: if all arguments are constant strings in `.rodata`, the call is likely benign. Context strings that appear only in comment or log branches also produce false hits.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` with a Go stripped binary. The scanner requires `ctx.func_starts` and uses `pclntab` for Go name resolution.

**After this module:** For `os/exec.Command` hits with non-constant arguments, run `TaintTracker` to determine whether the arguments trace back to network input. Register with `FindingRegistry`.

---

## Reading findings

`GoDangerousCallerScanner.build(ctx).query_dangerous_callers()` returns `List[DangerousCallHit]`:

| Attribute | Content |
|:---|:---|
| `func_name` | Name of the function containing the dangerous call |
| `func_va` | Start VA of the containing function |
| `call_va` | VA of the specific call instruction |
| `call_target_va` | VA of the dangerous function being called |
| `call_target_name` | Resolved name of the dangerous callee |
| `string_refs` | `List[Tuple[int, str]]`: VA, string pairs for string refs in the same function |

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
