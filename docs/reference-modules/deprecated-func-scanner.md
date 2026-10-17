# DeprecatedFuncScanner

## Why this exists

Four things were not possible before in Ablation:

1. **Detect CWE-242 without taint analysis.** `gets()`, `mktemp()`, `tmpnam()`, and `getwd()` have no safe use. Their presence in PLT is a confirmed finding regardless of call context, no path analysis or data-flow tracing needed. Before this module, these functions would only surface if a TaintTracker happened to sweep the same binary.

2. **Calculate overflow offset at each `gets()` call site.** For call sites where the destination buffer is at `[rbp-N]`, the module extracts N from the preceding LEA instruction and computes the exact byte count to overwrite the saved RIP. Finding a `gets()` used to mean "there's an overflow somewhere"; now it means "the saved RIP is at offset 8232 bytes."

3. **Report the reachability chain per call site.** The module walks one level up the call graph via `call_edges` to show which functions can trigger each dangerous call. Manual call graph tracing before every TaintTracker run is eliminated.

4. **Distinguish CWE-121 (stack overflow) from CWE-377 (race condition in temp file creation).** `gets/getwd` findings carry CWE-121 with overflow metadata. `mktemp/tmpnam` findings carry CWE-377 without overflow metadata. Triagers see the correct class immediately.

## Dangerous functions detected

| Function | CWE | Overflow calc | Reason |
|-----------|-------------------|:---:|------|
| `gets` | CWE-242 / CWE-121 | ✓ | reads stdin with no bounds check |
| `getwd` | CWE-242 / CWE-121 | ✓ | unbounded `getcwd` alternative |
| `mktemp` | CWE-242 / CWE-377 | ✗ | predictable temp filename (race condition) |
| `tmpnam` | CWE-242 / CWE-377 | ✗ | predictable temp filename (race condition) |

## Usage

```python
from ablation.analyzers.deprecated_func_scanner import DeprecatedFuncScanner

# Fastest path with an existing context
scanner = DeprecatedFuncScanner.from_context(ctx)
hits = scanner.scan()
print(scanner.report(hits))

# From path (builds BinaryContext internally)
scanner = DeprecatedFuncScanner.from_path('/opt/hsc/bin/commandcontrol')
for hit in scanner.scan():
    print(f"{hit.plt_name}() at {hit.va:#x} — overflow offset: {hit.overflow_offset:#x}")
```

## Key API

| Symbol | Description |
|--------|-------------|
| `DeprecatedFuncScanner.from_context(ctx)` | Constructor from existing `BinaryContext` |
| `DeprecatedFuncScanner.from_path(path)` | Constructor from binary path |
| `scan()` | Returns `list[DeprecatedHit]`, one per call site (deduped by VA) |
| `report(hits)` | Returns formatted string report |
| `DeprecatedHit.va` | VA of the dangerous `call` instruction |
| `DeprecatedHit.func_name` | Name of the containing function |
| `DeprecatedHit.plt_name` | Name of the dangerous function (`gets`, `mktemp`, etc.) |
| `DeprecatedHit.buf_size` | Destination buffer size in bytes; -1 if unknown |
| `DeprecatedHit.overflow_offset` | Bytes from buffer start to saved RIP; -1 if unknown |
| `DeprecatedHit.callers` | Names of functions that call the containing function |

## Limitations

- **x86-64 only.** Buffer size calculation uses `[rbp-N]` frame convention. No ARM/MIPS support.
- **One-level caller walk.** `callers` shows direct callers only: not the full reachability chain.
- **Buffer size is -1 for wrapper functions.** If `gets(rdi)` where rdi is a parameter (e.g., `readStdin(char* buf)`), the buffer is allocated in the caller. The scanner reports the buffer in the caller only if the caller directly calls `gets`.

## FORGE audit

Gate: **PASSED** (0 CRITICAL, 0 HIGH).

- 1 MEDIUM (§2): `_gets_buf_size` only extracts buffer size from `lea [rbp-N]` patterns. RSP-relative buffers and indirect pointer loads return -1. Documented as a known limitation.
- 1 LOW (§3): `FileNotFoundError` guard added: raises `ValueError` if `ctx.path` is empty.
- 1 LOW (§5): `_find_func_start` changed from O(n) linear scan to `bisect.bisect_right` O(log n).

Confirmed on: `commandcontrol` (setuid, 1 confirmed `gets()` hit, 3 callers correctly attributed).

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Example output

```
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading findings

`DeprecatedFuncScanner.from_context(ctx).scan()` returns `List[DeprecatedHit]`:

| Attribute | Content |
|:---|:---|
| `va` | VA of the call instruction |
| `func_va` | Start VA of the containing function |
| `func_name` | Name of the containing function |
| `plt_name` | Name of the dangerous deprecated function (e.g., `gets`, `mktemp`) |
| `cwe` | CWE identifier (e.g., `CWE-242/CWE-121`, `CWE-242/CWE-377`) |
| `reason` | One-line description of why this function is dangerous |
| `buf_size` | Bytes from buffer start to frame base (`-1` if unknown) |
| `frame_size` | Total stack frame allocation in bytes (`-1` if unknown) |
| `overflow_offset` | Bytes to reach saved RIP (`-1` if unknown) |
| `callers` | `List[str]` — names of functions that call the containing function |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
