# CallsiteTracer

**File:** `modules/callsite_tracer.py`

## Why this exists

Backward-slices argument registers (x0–x7) at ARM64 BL call sites to confirm that a target function receives a specific value. Primary use: verifying GOT-based struct pointer aliasing in stripped ARM64 shared objects for example WeChat libwechatnetwork.so.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_SO_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `if binary is None` check. `_MAX_SO_BYTES=256MB`. No HTTP reads.

---

## How it works

`backward_slice` is a forward symbolic simulation that seeds the enclosing function's argument registers (`x0`–`x7`) as `Arg(0)`–`Arg(7)` symbolic values, then simulates instruction by instruction from the function prologue (located by scanning backward for `STP x29, x30, [sp, #-k]!`) to the target call site VA. At each instruction, the simulator updates register state: `ADRP`+`ADD`/`LDR` produces a `Global(name, delta)` if the GOT entry is in the catalogue, `MOV`+`immediate` produces `Const(v)`, register copies propagate the existing symbolic value, and `BL` to an internal function resets caller-saved registers (`x0`–`x18`) to `Unknown`. When the simulation reaches `callsite_va`, the current state of each requested `arg_regs` register is returned as the symbolic value that function will receive.

GOT entries are resolved via a static `_GOT` dictionary mapping `(segment_base, got_offset)` → `Global(symbol_name)`. This catalogue is populated per-target and must be extended manually for new shared objects. Entries not in the catalogue resolve to `Unknown`.

---

## Usage

```python
from modules.callsite_tracer import backward_slice, _load

# Load binary (applies _MAX_SO_BYTES size guard)
binary, raw = _load('/path/to/libwechatnetwork.so')

# Slice x0 and x1 at a BL call site to confirm struct pointer arguments
callsite_va = 0xC8F3A0
sliced = backward_slice(raw, binary, callsite_va, arg_regs=['x0', 'x1'])
for reg, val in sliced.items():
    print(f"  {reg}: {val}")

# Use isinstance checks to identify argument-derived values
from modules.callsite_tracer import Arg, Global, Const, Unknown
for reg, val in sliced.items():
    if isinstance(val, Arg):
        print(f"  {reg} carries caller arg {val.idx} (taintable)")
    elif isinstance(val, Global):
        print(f"  {reg} is GOT global {val.name!r} + {val.delta:#x}")
```

---

## Example output

```
backward_slice(callsite_va=0xC8F3A0, arg_regs=['x0', 'x1']):
  x0: Global(mmtls::gILinkKey)
  x1: Arg(1)

# x0 resolves to a known GOT global — struct pointer aliasing confirmed
# x1 passes through from caller argument 1 — taintable path
```

---

## False positives

**GOT entries not in the `_GOT` catalogue resolve to `Unknown`**: the catalogue is hardcoded to specific `(segment_base, got_offset)` pairs for WeChat libwechatnetwork.so. On any other binary, all GOT-derived values return `Unknown` unless you extend the catalogue. Check the `_GOT` dict at the top of `callsite_tracer.py` and add entries after inspecting GOT entries with `lief`.

**Prologue detection is heuristic**: `_fn_start()` scans backward up to 4 KB for an `STP x29, x30, [sp, #-k]!` frame setup instruction. If the enclosing function has an unusual prologue for example a tail-call optimized leaf, the simulation starts at the wrong address and may return `Unknown` for all registers.

**`BL` to internal functions resets caller-saved registers**: any `x0`–`x18` value established before an intermediate function call is overwritten with `Unknown` at that `BL`. If the target call site is reached through a call chain, `backward_slice` may under-report `Arg(n)` provenance.

---

## Pipeline position

**Before this module:** Identify the target call site VA using `SemanticSearcher` or `FuncProfiler`. Use `SinkArgClassifier` to confirm the call site is `ARG_PROPAGATED` or `UNKNOWN` (not `RODATA_CONST`) before slicing: `RODATA_CONST` call sites cannot have argument-derived values in `x0`–`x7`.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading output

`backward_slice(raw, binary, callsite_va, arg_regs, max_depth=128)` returns `Dict[str, Any]`: a map from each register name in `arg_regs` to one of five symbolic value types at `callsite_va`:

| Type | Fields | Meaning |
|:---|:---|:---|
| `Const(v)` | `v: int` | Register holds an immediate constant |
| `Global(name, delta=0)` | `name: str`, `delta: int` | GOT-catalogue global symbol address + byte delta |
| `Add(base, imm)` | `base: Any`, `imm: int` | `base` (any type) plus an immediate offset |
| `Arg(idx, delta=0)` | `idx: int`, `delta: int` | Caller's `idx`-th argument, optionally shifted by `delta` |
| `Unknown(reg, pc)` | `reg: str`, `pc: int` | Provenance not resolved before `pc` |

All five types are frozen dataclasses exported from `modules.callsite_tracer`. Use `isinstance(val, Arg)` to check for taintable argument-derived values. `str(val)` produces a human-readable string for all five types (e.g., `'Arg(1)'`, `'Global(mmtls::gILinkKey)'`, `'Unknown(x2@0xC8F3A0)'`).

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
