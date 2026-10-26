# FuncReachabilityAnalyzer

Determine whether a function is reachable at runtime: filtering dead code from `SinkArgClassifier` findings before taint tracing begins.

---

## Why this exists

1. **An ARG_PROPAGATED finding in dead code is not exploitable.** `SinkArgClassifier` makes no distinction between functions that execute at runtime and functions that exist only as unreferenced debug artifacts. Every `ARG_PROPAGATED` site in dead code produces a false positive that `TaintTracker` then spends time on.

2. **The gap is measurable.** IBM RecoveryRMd CSM SAM 2.2.0.1: `func@0x839c14f` contained an `ARG_PROPAGATED` `system()` site. Manual investigation established the function had no callers: all references to `0x839c14f` existed only in `.debug_pubnames` file offsets `0x3020c` and `0x11eb730`. That investigation took ~20 minutes. This module would have classified it `UNREACHABLE_DEBUG` in milliseconds.

3. **Call-graph edges alone are insufficient.** A function with no `call_edges` entry could be dead code or could be reached via a function pointer. Checking the call graph without scanning for VA references misclassifies function-pointer-called functions as unreachable.

---

## How it works

Two independent checks determine the verdict.

**Check 1: call edges.** Scan `BinaryContext.call_edges` for any `src, dst, name` triple where `dst == func_va`. A single match returns `REACHABLE` immediately.

**Check 2: binary VA scan.** If no call edges exist, scan the entire binary for the function VA as a 4-byte or 8-byte little-endian word. Each hit is mapped to its section by file offset. Sections fall into three buckets:

```
Runtime-loadable sections (.text, .data, .rodata, .got, .init_array, ...):
    → REACHABLE_VIA_PTR (function pointer or dispatch table)

Non-call sections (.dynsym, .symtab, .debug_*, .gnu.hash, ...):
    → UNREACHABLE_DEBUG (dead code; symbol/debug reference only)

No references at all:
    → UNREACHABLE_NOREF
```

---

## Verdicts

| Verdict | Meaning | Action |
|:---|:---|:---|
| `REACHABLE` | At least one call edge exists | Normal ARG_PROPAGATED path: proceed to TaintTracker |
| `REACHABLE_VIA_PTR` | No call edges; VA appears in runtime section | Investigate function pointer usage before discarding |
| `UNREACHABLE_DEBUG` | No call edges; VA only in debug/symbol sections | Discard finding: dead code, not reachable at runtime |
| `UNREACHABLE_NOREF` | No call edges; no references found | Discard finding: function is orphaned |

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.func_reachability import FuncReachabilityAnalyzer

ctx = BinaryContext.load_or_build('/path/to/target')
rz = FuncReachabilityAnalyzer.from_context(ctx)

# Single function
result = rz.check(0x839c14f)
print(result.verdict, result.reason)
# UNREACHABLE_DEBUG  no call edges; VA only in .debug_pubnames → dead code

# Batch-filter ARG_PROPAGATED findings from SinkArgClassifier
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier, ARG_PROPAGATED

sac = SinkArgClassifier.from_context(ctx)
findings = [r for r in sac.classify_all() if r.verdict == ARG_PROPAGATED]
filtered = rz.filter_unreachable(findings)

print(f'Before filter: {len(findings)}  After: {len(filtered)}')
print(rz.report(rz.check_all([r.func_va for r in findings])))
```

**Typical output:**
```
FuncReachabilityAnalyzer results:
  0x805842b  REACHABLE              3 call edge(s)
  0x839c14f  UNREACHABLE_DEBUG      no call edges; VA only in .debug_pubnames → dead code
  0x83a1200  REACHABLE_VIA_PTR      no call edges but VA in runtime section(s): .data.rel.ro
```

---

## Result fields

| Field | Type | Content |
|:---|:---|:---|
| `func_va` | `int` | The function VA checked |
| `verdict` | `str` | One of the four verdicts above |
| `callers` | `list[int]` | Call-edge source VAs (non-empty for `REACHABLE`) |
| `refs` | `list[VaRef]` | VA references found in binary non-empty for `REACHABLE_VIA_PTR` and `UNREACHABLE_DEBUG` |
| `is_reachable` | `bool` | True for `REACHABLE` and `REACHABLE_VIA_PTR` |
| `reason` | `str` | Human-readable explanation of the verdict |

Each `VaRef` has `file_offset`, `section` (section name or `''`), and `va`.

---

## Pointer size detection

The analyzer auto-detects whether to search for 4-byte or 8-byte VA patterns. It first checks `ctx.arch` such as `'x86_32'` and `'ppc32'`, then falls back to the ELF class field. For XCOFF and non-ELF binaries without LIEF support, default is 8 bytes (x86_64). Pass `ctx` with a correct `arch` attribute to ensure the right pointer size.

---

## False positives and limitations

**Partially stripped binaries.** A binary with `.debug_*` sections stripped but `.symtab` retained will have function VAs appearing in `.symtab`. The `.symtab` section is in `_NON_CALL_SECTIONS`, so the function will be classified `UNREACHABLE_DEBUG` even though `.symtab` is a debug-like artifact. If the binary retains `.symtab`, verify independently before discarding the finding.

**Big-endian binaries.** The VA scan uses little-endian byte order. PPC32 BE, SPARC, and MIPS BE binaries store VAs as big-endian words. The scan will miss function pointer references in those binaries. Use with caution on BE targets.

---

## Pipeline position

**Before:** `SinkArgClassifier.classify_all()`: produces the findings to filter.

**After:** `FuncReachabilityAnalyzer.filter_unreachable(findings)` removes `UNREACHABLE_DEBUG` and `UNREACHABLE_NOREF` entries before `TaintTracker` runs.

---

## See also

- [Sink Arg Classifier](sink-arg-classifier.md): produces the ARG_PROPAGATED findings this module filters
- [Caller Arg Resolver](caller-arg-resolver.md): for REACHABLE ARG_PROPAGATED sites, traces what callers actually pass
- [Taint Analysis](taint-analysis.md): runs on the surviving REACHABLE findings
