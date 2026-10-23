# InterprocFieldWriter

**File:** `modules/interproc_field_writer.py`

## Why this exists

Demand-driven inter-procedural field-writer finder for stripped ARM64 binaries. Given a struct field offset, traces all functions that write to that field across call boundaries, used to identify all code paths that can corrupt a security-sensitive struct member.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.

---

## How it works

`interprocedural_field_writes(ctx, target_gv)` iterates `ctx.func_starts`, disassembles each function with Capstone, and tracks writes to the memory address of `target_gv` (a global variable VA). For each write, it records the value written and the call path leading to the write. Returns a `Dict[int, FuncSummary]` mapping function VA to a summary of field writes within that function.

---

## Usage

```python
from modules.interproc_field_writer import find_field_writers, Binary

# Binary takes a path; TEXT_VA/TEXT_SIZE/GOT_VA are hardcoded class-level
# constants for the target — subclass or override them for other binaries.
binary = Binary('/path/to/target.elf')
writers = find_field_writers(
    binary,
    target_name='session_state',
    target_offset=0x18,
    max_depth=8,
)
for w in writers:
    print(f"{w['fn']:#x}  pc={w['pc']:#x}  field+{w['field_offset']:#x}")
```

---

## Example output

```
interprocedural_field_writes(ctx, target_gv=0x00620040):

  0x00401200 (set_auth_flag):
    writes: {0x00620040+0x00: [0x1, 0x0]}  (auth_enabled: True/False)
    callers: [handle_login, handle_logout]

  0x00403800 (reset_session):
    writes: {0x00620040+0x08: [0x0]}  (session_token: cleared)
    callers: [session_expire]
```

---

## False positives

Conditional writes on rarely-taken paths for example error recovery are included in the write set even if the main path never exercises them. Review `callers` to assess reachability of each write site before reporting.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` with `ctx.func_starts` populated. Identify the target global variable VA via `SemanticSearcher` or `PatternLibrary`.

**After this module:** For security-relevant global writes for example auth flags, trace whether an attacker-controlled value can reach the write site via `TaintTracker`.

---

## Reading output

`interprocedural_field_writes(ctx, target_gv)` returns a `Dict[int, FuncSummary]` keyed by function VA. Each `FuncSummary`:

| Attribute | Content |
|:---|:---|
| `addr` | Function VA |
| `global_field_writes` | `List[Tuple[name, field_offset, store_pc, store_bytes]]`: stores to a known global struct field |
| `global_to_callee` | `List[Tuple[callee_va, global_name, callee_arg_idx, call_pc]]`: global forwarded to a callee |
| `arg_field_writes` | `List[Tuple[arg_idx, field_offset, store_pc, store_bytes]]`: stores to a field of an argument struct |
| `arg_to_callee` | `List[Tuple[callee_va, caller_arg_idx, callee_arg_idx, call_pc]]`: argument forwarded to a callee |
| `direct_callees` | `Set[int]`: all direct callee VAs found in BL instructions |
| `insns_scanned` | Number of instructions analyzed |

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
