# TriCoreTaintTracker

**File:** `ablation/analyzers/taint_tracker_tricore.py`

---

## Why this exists

3 things that were not possible before in Ablation:

**1. No source-to-sink taint analysis for TriCore AURIX ECU firmware.**  After
`EcuArchDetector` correctly identifies a flat ROM dump as TriCore (e.g., Bosch ME17,
Continental MG1, Waqas GEN3), there was no taint tracker to follow attacker-controlled
data from a SecurityAccess response or CAN frame through the cipher function to any
dangerous sink.  `TriCoreTaintTracker` fills this gap.

**2. No TriCore calling-convention model in Ablation.**  TriCore uses a hardware-enforced
CSA (Context Save Area) mechanism where CALL automatically saves the upper context
(D[8]–D[15], A[10]–A[15]) to a dedicated memory area, and RET restores it.  No software
push/pop is generated.  Without a model of this, a taint tracker either over-clears
(treats all registers as clobbered) or under-clears (doesn't clobber anything), producing
false negatives or false positives at every call site.  This module implements the
Infineon TriCore EABI V2.9 / GHS EABI calling convention (GHS-RE-REFERENCE.md §1.2–1.3):
D[4]–D[7] / A[4]–A[7] in; D[2] / A[2] out; lower context clobbered on CALL.

**3. No FCALL/FRET leaf-function support.**  GHS-compiled TriCore firmware uses FCALL
(saves A[11] only, no CSA) for leaf functions, and FRET to return from them.  These
mnemonics are absent from all other Ablation trackers.  This module recognises FCALL and
FRET as call/return boundaries with the same calling-convention semantics as CALL/RET.

---

## ABI summary (Infineon TriCore EABI V2.9, GHS-RE-REFERENCE.md §1.2–1.3)

| Role | Registers | Capstone names |
|---|---|---|
| Integer/scalar args | D[4]–D[7] | `d4` `d5` `d6` `d7` |
| Pointer args | A[4]–A[7] | `a4` `a5` `a6` `a7` |
| Integer return | D[2] | `d2` |
| Pointer return | A[2] | `a2` |
| Stack pointer | A[10] | `sp` |
| Link register | A[11] | `a11` |
| Caller-saved (lower context) | D[0]–D[7], A[2]–A[7], A[11], D[15], A[15] | — |
| Callee-saved (upper context, HW-enforced) | D[8]–D[15], A[0], A[1], sp, A[12]–A[15] | — |

---

## Usage

```python
from ablation.analyzers.taint_tracker_tricore import TriCoreTaintTracker

# --- Flat ROM dump (EcuArchDetector returned 'tricore') ---
data = open('waqas_gen3.bin', 'rb').read()
tracker = TriCoreTaintTracker.from_bytes(data, base_va=0x80000000)

# Scan one function (caller must supply boundaries from EcuArchDetector/FlatBinaryFuncStartScanner)
findings = tracker.scan_function(
    func_va=0x800aba10,
    func_end=0x800abb80,
    init_labels={'sa_seed'},
)
print(tracker.report(findings))

# --- ELF binary ---
tracker = TriCoreTaintTracker.from_path('firmware.elf')
findings = tracker.run()               # intraprocedural
chains   = tracker.run_interprocedural(depth=3)
print(tracker.report(chains))
```

---

## Constructor parameters

| Parameter | Default | Description |
|---|---|---|
| `data` | — | `bytes` of the binary image |
| `base_va` | `0x80000000` | PFLASH base VA for flat ROMs (from TC1.8 §8 Table 13) |
| `tc_mode` | `CS_MODE_TRICORE_162` | Capstone TC ISA mode (162 = AURIX TC1.6x) |

`from_path(elf)` auto-detects text section VA from lief/pyelftools.

---

## TaintFindingTriCore fields

```python
@dataclass
class TaintFindingTriCore:
    func_va:      int        # VA of the containing function
    func_name:    str        # symbol name or fn_0xNNNN
    sink_va:      int        # VA of the call/store/jump that is the sink
    sink_name:    str        # e.g. 'memcpy', 'ji[tainted-target]', 'st.w[tainted-addr]'
    tainted_args: List[str]  # register names that were tainted at sink
    labels:       FrozenSet[str]  # taint label set
    severity:     str        # 'CRITICAL' or 'HIGH'
```

---

## Taint propagation rules

| Instruction class | Rule |
|---|---|
| `ld.w / ld.h / ld.b` | Dest ← taint(base_reg) ∪ taint(mem[base,disp]) |
| `ld.bu / ld.hu` | Same as above; bound = 0xFF / 0xFFFF (zero-extending) |
| `st.w / st.h / st.b` | mem[base,disp] ← taint(src_reg); tainted base = FINDING |
| `mov / mov.a / mov.d` | Dest ← taint(src_reg); immediate = clean |
| `movh / movh.a` | Dest = clean (constant high half load) |
| ALU 2-operand (`add d4, d5`) | Dest ← taint(dest) ∪ taint(src) — in-place |
| ALU 3-operand (`add d4, d5, d6`) | Dest ← taint(src1) ∪ taint(src2) |
| `and` with immediate | Dest bound = imm & 0xFFFF |
| `extr.u` | Dest bound = (1 << width) - 1 |
| `ji Aa` with tainted Aa | CRITICAL finding: tainted-indirect-call target |
| `call / calla / calli / fcall` | Apply calling-convention effects |
| `ret / rfe / fret` | End of function trace |
| Unknown mnemonic | Conservative: dest ← union of all source reg taints |

---

## Calling convention effects at call site

```
arg_labels = union(taint[r] for r in {d4,d5,d6,d7,a4,a5,a6,a7})
clobber caller-saved: {d0-d7, a2-a7, a11, d15, a15}
if arg_labels:
    taint[d2] = taint[a2] = arg_labels   # return value tainted
```

Source function (e.g. `recv`): forces `taint[d2] = {recv}` regardless of args.
Sink function (e.g. `memcpy`): records finding if any arg reg is tainted.

---

## FCALL / FRET (GHS-RE-REFERENCE.md §1.7)

GHS-compiled leaf functions use FCALL (saves A[11] only, no CSA save).  The tracker
treats FCALL identically to CALL at the call site, and FRET identically to RET.  The
mnemonic set `{'call', 'calla', 'calli', 'fcall'}` covers all call forms;
`{'ret', 'rfe', 'fret'}` covers all return forms.

---

## Limitations

- Intra-procedural by default.  `run_interprocedural(depth=N)` follows tainted D[4]–D[7]
  / A[4]–A[7] into callees but does not model return-value aliasing across call chains.
- No loop fixpoint: linear forward trace only.  A function with a loop may produce
  inconsistent taint after the second iteration.
- `run()` requires ELF symbols for function boundaries.  Flat ROM users must supply
  `func_va` and `func_end` from `FlatBinaryFuncStartScanner`.
- Capstone 5.0+ required (`CS_ARCH_TRICORE` absent in Capstone ≤ 4.x).
- CSA memory-dump taint (STLCX/LDLCX) is not modelled; these are rare in normal firmware
  flow outside interrupt handlers.
