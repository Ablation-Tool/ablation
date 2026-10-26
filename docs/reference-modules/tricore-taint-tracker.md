# TriCoreTaintTracker

**File:** `ablation/analyzers/taint_tracker_tricore.py`

---

## What this is <sup>[↑](#tricoretainttracker)</sup>

Infineon TriCore is the dominant MCU in modern automotive ADAS and powertrain ECUs. TriCore uses a hardware-enforced Context Save Area (CSA) mechanism where CALL automatically saves upper-context registers to a dedicated memory region. No software push/pop is generated. Standard taint trackers treat all registers as clobbered at every call, which misses paths through TriCore's callee-saved registers. `TriCoreTaintTracker` implements the full Infineon EABI V2.9 calling convention including FCALL/FRET leaf functions so taint paths through SecurityAccess and CAN frame handlers trace correctly.

---

## Where it's used <sup>[↑](#tricoretainttracker)</sup>

- **Bosch ME17 ECUs**: AURIX TC2xx/TC3xx powertrain firmware
- **Continental MG1 ECUs**: TriCore-based engine and transmission controllers
- Any flat ROM dump where `EcuArchDetector` returns `tricore`

---

## Safe usage <sup>[↑](#tricoretainttracker)</sup>

**Pass the correct `base_va` for flash-mapped binaries.** AURIX maps flash at 0x80000000 or 0xA0000000. A wrong `base_va` shifts every function address so findings report incorrect VAs and byte-verification fails.

**Use `from_bytes()` for flat ROM dumps.** `from_path()` requires an ELF header. Raw ECU ROM images have no ELF header so `from_path()` raises.

**Supply `func_va` and `func_end` boundaries from `EcuArchDetector`.** `scan_function()` requires explicit boundaries. Without them, the tracker walks past the function end and produces findings in adjacent code.

**Flag FCALL/FRET findings for separate review.** FCALL functions save only A[11] and allocate no CSA. A finding in an FCALL function means the full call chain from the caller is needed to confirm exploitability, because the saved register state differs from a normal CALL/RET frame.

---

## Why this exists <sup>[↑](#tricoretainttracker)</sup>

Three things were not possible before in Ablation:

**1. No source-to-sink taint analysis for TriCore AURIX ECU firmware.** After
`EcuArchDetector` correctly identifies a flat ROM dump as TriCore, there was no taint tracker to follow attacker-controlled
data from a SecurityAccess response or CAN frame through the cipher function to any
dangerous sink. `TriCoreTaintTracker` fills this gap.

**2. No TriCore calling-convention model in Ablation.** TriCore uses a hardware-enforced
CSA Context Save Area mechanism where CALL automatically saves the upper context registers D[8]–D[15] and A[10]–A[15] to a dedicated memory area, and RET restores it. No software
push/pop is generated. Without a model of this, a taint tracker either over-clears
treats all registers as clobbered or under-clears (doesn't clobber anything), producing
false negatives or false positives at every call site. This module implements the
Infineon TriCore EABI V2.9 / GHS EABI calling convention GHS-RE-REFERENCE.md §1.2–1.3:
D[4]–D[7] / A[4]–A[7] in; D[2] / A[2] out; lower context clobbered on CALL.

**3. No FCALL/FRET leaf-function support.** GHS-compiled TriCore firmware uses FCALL for leaf functions. FCALL saves A[11] only;
no CSA is allocated. FRET returns from them. These mnemonics are absent from all
other Ablation trackers. This module recognises FCALL and
FRET as call/return boundaries with the same calling-convention semantics as CALL/RET.

---

## ABI summary: Infineon TriCore EABI V2.9 / GHS-RE-REFERENCE.md §1.2–1.3 <sup>[↑](#tricoretainttracker)</sup>

| Role | Registers | Capstone names |
|---|---|---|
| Integer/scalar args | D[4]–D[7] | `d4` `d5` `d6` `d7` |
| Pointer args | A[4]–A[7] | `a4` `a5` `a6` `a7` |
| Integer return | D[2] | `d2` |
| Pointer return | A[2] | `a2` |
| Stack pointer | A[10] | `sp` |
| Link register | A[11] | `a11` |
| Caller-saved lower context | D[0]–D[7], A[2]–A[7], A[11], D[15], A[15] |: |
| Callee-saved: upper context, HW-enforced | D[8]–D[15], A[0], A[1], sp, A[12]–A[15] |: |

---

## Usage <sup>[↑](#tricoretainttracker)</sup>

```python
from ablation.analyzers.taint_tracker_tricore import TriCoreTaintTracker

# --- Flat ROM dump (EcuArchDetector returned 'tricore') ---
import pathlib
data = pathlib.Path('waqas_gen3.bin').read_bytes()
tracker = TriCoreTaintTracker.from_bytes(
    data, base_va=0x80000000
)

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

## Constructor parameters <sup>[↑](#tricoretainttracker)</sup>

| Parameter | Default | Description |
|---|---|---|
| `data` |: | `bytes` of the binary image |
| `base_va` | `0x80000000` | PFLASH base VA for flat ROMs from TC1.8 §8 Table 13 |
| `tc_mode` | `CS_MODE_TRICORE_162` | Capstone TC ISA mode (162 = AURIX TC1.6x) |

`from_path(elf)` auto-detects text section VA from lief/pyelftools.

---

## TaintFindingTriCore fields <sup>[↑](#tricoretainttracker)</sup>

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

## Taint propagation rules <sup>[↑](#tricoretainttracker)</sup>

| Instruction class | Rule |
|---|---|
| `ld.w / ld.h / ld.b` | Dest ← taint[base_reg] ∪ taint[mem[base,disp]] |
| `ld.bu / ld.hu` | Same as above; bound = 0xFF / 0xFFFF, zero-extending |
| `st.w / st.h / st.b` | mem[base,disp] ← taint[src_reg]; tainted base = FINDING |
| `mov / mov.a / mov.d` | Dest ← taint[src_reg]; immediate = clean |
| `movh / movh.a` | Dest = clean; constant high-half load |
| ALU 2-operand, example: `add d4, d5` | Dest ← taint[dest] ∪ taint[src]: in-place |
| ALU 3-operand, example: `add d4, d5, d6` | Dest ← taint[src1] ∪ taint[src2] |
| DSP MAC variants: `maddr`, `msubr`, `maddrs`, `msubrs`, `mulm`, `mulms`, `mulr` | Route via ALU dispatch; source registers propagate to dest |
| `and` with immediate | Dest bound = imm & 0xFFFF |
| `extr.u` | Dest bound = 1 << width - 1 |
| `LOOP / LOOPU` | A_reg: labels preserved, bound cleared decrement removes range constraint |
| `ji Aa` with tainted Aa | CRITICAL finding: tainted-indirect-call target |
| `call / calla / calli / fcall` | Apply calling-convention effects |
| `ret / rfe / fret` | End of function trace |
| Unknown mnemonic | Conservative: dest ← union of all source reg taints |

---

## Calling convention effects at call site <sup>[↑](#tricoretainttracker)</sup>

```
for r in {d4,d5,d6,d7,a4,a5,a6,a7}:
    arg_labels |= taint[r]
clobber caller-saved: {d0-d7, a2-a7, a11, d15, a15}
if arg_labels:
    taint[d2] = taint[a2] = arg_labels   # return value tainted
```

Source function (e.g. `recv`): forces `taint[d2] = {recv}` regardless of args.
Sink function (e.g. `memcpy`): records finding if any arg reg is tainted.

---

## FCALL / FRET GHS-RE-REFERENCE.md §1.7 <sup>[↑](#tricoretainttracker)</sup>

GHS-compiled leaf functions use FCALL. FCALL saves A[11] only; no CSA save is performed.
The tracker treats FCALL identically to CALL at the call site, and FRET identically to RET. The
mnemonic set `{'call', 'calla', 'calli', 'fcall'}` covers all call forms;
`{'ret', 'rfe', 'fret'}` covers all return forms.

---

## Limitations <sup>[↑](#tricoretainttracker)</sup>

- Intra-procedural by default. `run_interprocedural(depth=N)` follows tainted D[4]–D[7]
 / A[4]–A[7] into callees but does not model return-value aliasing across call chains.
- No loop fixpoint: linear forward trace only. A function with a loop may produce
 inconsistent taint after the second iteration.
- `run()` requires ELF symbols for function boundaries. Flat ROM users must supply
  `func_va` and `func_end` from `FlatBinaryFuncStartScanner`.
- Capstone 5.0+ required (`CS_ARCH_TRICORE` absent in Capstone ≤ 4.x).
- CSA memory-dump taint STLCX/LDLCX is not modelled; these are rare in normal firmware
 flow outside interrupt handlers.

---

## How it works <sup>[↑](#tricoretainttracker)</sup>

Seeds the worklist with every call site of each configured source function. For each seeded location, a linear Capstone disassembly pass applies the taint lattice rules instruction by instruction, propagating taint through register moves, arithmetic, and memory operations. When a call instruction targets a PLT stub that resolves to a sink function and the relevant argument register is tainted, a `TaintFinding` is emitted. Internal calls push a new entry onto the worklist so taint follows the call graph interprocedurally up to `max_depth` levels.

---

## Example output <sup>[↑](#tricoretainttracker)</sup>

```
[CRITICAL] system() at 0x4023A0
  source:   recv() at 0x401F00
  arg:      rdi (arg 0)
  chain:    recv→rdi → strcpy buf → system rdi
  path:     [0x401F00, 0x4020C0, 0x4023A0]
  severity: CRITICAL (exec sink, externally controlled argument)
```

---

## False positives <sup>[↑](#tricoretainttracker)</sup>

The most common false positive is taint surviving a zero-clear instruction `xor rax, rax`. The `CLR` rule in the taint lattice clears taint unconditionally on self-XOR, but some architectures use different clearing idioms. Use `SinkArgClassifier` to pre-filter `RODATA_CONST` call sites before running the taint tracker, these are not findings regardless of register state.

---

## Pipeline position <sup>[↑](#tricoretainttracker)</sup>

**Before this module:** `BinaryContext.load_or_build()`, then `SinkArgClassifier.classify_all()` to eliminate `RODATA_CONST` call sites. Only pass `ARG_PROPAGATED` and `UNKNOWN` sinks to the taint tracker.

**After this module:** `PathSolver` to confirm path feasibility. `FindingRegistry.register()` to record confirmed findings.

---

## Reading findings <sup>[↑](#tricoretainttracker)</sup>

| Field | Content |
|:---|:---|
| `sink_name` | Name of the dangerous function reached |
| `sink_va` | Virtual address of the call site |
| `source_name` | Name of the taint source for example `recv`, `read` |
| `arg_index` | Which argument to the sink carries taint 0-indexed |
| `chain` | `[va, register, operation]` steps from source to sink |
| `path` | `[caller_va, ...]` function VAs traversed interprocedurally |
| `severity` | `CRITICAL` for exec sinks, `HIGH` for memory sinks |

---

## See also <sup>[↑](#tricoretainttracker)</sup>

- [TaintAnalysis](taint-analysis.md): multi-architecture taint tracking reference
- [SinkArgClassifier](sink-arg-classifier.md): pre-filter RODATA_CONST sinks before taint
- [PathSolver](path-solver.md): confirm path feasibility after a taint hit
- [SinkPropagator](sink-propagator.md): extend sink coverage across wrappers
