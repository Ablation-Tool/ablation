# BinaryLifter

Lift native binary functions to annotated C pseudocode.

**Module:** `ablation.analyzers.binary_lifter`  
**Exports:** `BinaryLifter`, `NativeVal`

---

## Purpose

BinaryLifter converts a stripped ARM64 (and later x86-64, LoongArch64) function
at a virtual address into readable pseudo-C IR, using the existing CFG
infrastructure (`cfg_arm64`, `insn_arm64`). DEXLifter is the structural template.

This is Phase 1 of the Active Architecture Tomography plan: a purely static
CFG-based IR emitter. Dynamic execution is Phase 3 (QEMU adapter).

---

## Usage

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/binary')
print(lifter.lift_function(0x12340))
```

### With a BinaryContext (recommended)

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.binary_lifter import BinaryLifter

ctx = BinaryContext.load_or_build('/path/to/binary')
lifter = BinaryLifter.from_context(ctx)
print(lifter.lift_function(0x12340))
```

### With taint annotations

```python
from ablation.analyzers.taint_tracker_arm64 import ARM64TaintTracker
from ablation.analyzers.binary_lifter import BinaryLifter

findings = ARM64TaintTracker.from_path_full(elf).run_interprocedural()
lifter = BinaryLifter.from_path(elf).with_taint(findings)
print(lifter.lift_function(0x12340))
```

### Convenience one-liner

```python
BinaryLifter.report('/path/to/binary', 0x12340)
```

---

## API

### `BinaryLifter.from_path(binary_path, arch='arm64') → BinaryLifter`

Construct from a binary path. `arch` must be `'arm64'` (default); `'x86_64'`
and `'la64'` are stubs.

### `BinaryLifter.from_context(ctx, arch='arm64') → BinaryLifter`

Construct from a `BinaryContext`. Inherits PLT symbol names and confirmed
function names from the context's name overlay.

### `.with_taint(findings) → BinaryLifter`

Accept a list of `TaintFindingARM64` objects. Returns a new `BinaryLifter`
whose `lift_function` output annotates tainted registers with `/* TAINTED */`.
Does not mutate the original instance.

### `.lift_function(va, max_insns=512) → str`

Lift the function at virtual address `va` to pseudo-C IR. Returns a multi-line
string. `max_insns` bounds how many instructions are disassembled before the
CFG walk begins.

### `BinaryLifter.report(binary_path, va, arch='arm64') → None`

Convenience: construct, lift, and print.

---

## Output format

```c
// fn_12340 @ 0x12340
{
  uint64_t v0 = arg0 + 0x10;
  uint64_t v1 = *(uint64_t *)(v0);   /* TAINTED */
  uint64_t v2 = fn_5678(arg0, arg1, arg2);
  if (arg0 == arg1) goto loc_12380;
  return v2;
  loc_12380:
  return 0;
}
```

---

## NativeVal

```python
@dataclass
class NativeVal:
    ctype:   str    # "uint64_t", "uint32_t", "uint8_t", "int32_t", "void *", ...
    expr:    str    # expression: "arg0", "v3", "0x1234", "*(uint64_t*)v1 + 8"
    is_ptr:  bool   # True when expression is known to be a pointer
    tainted: bool   # True when sourced from a tainted register
    uses:    int    # incremented on each read
```

---

## Architecture road map

| Arch | Status |
|---|---|
| ARM64 | Full — CFG + register state machine + calling convention |
| x86-64 | Stub (Phase 1 extension) |
| LoongArch64 | Stub (Phase 1 extension) |

---

## Design

BinaryLifter uses the same walk-CFG-emit-IR pattern as DEXLifter, adapted for
native binary analysis:

1. **lief** extracts section bytes at the target VA.
2. `insn_arm64.from_capstone` produces `Insn` objects from raw bytes.
3. `cfg_arm64.build_cfg` constructs `Block`/`CFG` from the instruction stream.
4. `_ARM64State` walks blocks in address order, tracking `NativeVal` per
   physical register, and emits C-like statements per instruction.

Type inference follows operation width: `ldrb` → `uint8_t`, `ldrsw` → `int32_t`,
arithmetic on `w`-registers → `uint32_t`, etc. Calling convention: `x0`–`x7`
are `arg0`–`arg7` on function entry; each `bl` target clobbers `x1`–`x7` and
writes a new variable for the return in `x0`.

See `active-hypothesis-engine-plan.md` for the broader Phase 2 and Phase 3
context in which this module operates.
