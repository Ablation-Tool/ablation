# RH850TaintTracker

**File:** `ablation/analyzers/taint_tracker_rh850.py`

---

## Why this exists

3 things that were not possible before in Ablation:

**1. No flat-ROM / `from_bytes` support for RH850 ECU firmware.**  Automotive RH850
ECU images (Denso GS327, Bosch RH850/G3M) are frequently shipped as raw binary
dumps with no ELF header.  `V850TaintTracker` requires `from_path(elf)` and will
raise on a bare binary.  `RH850TaintTracker.from_bytes(data, base_va)` +
`scan_function(func_va, func_end, init_labels)` gives the same flat-ROM scanning
workflow as `TriCoreTaintTracker`.

**2. GHS CC-RH / IAR `double=32-bit` default not modelled.**  In the IAR RH850 ABI
(§2.7 of GHS-RE-REFERENCE.md), `double` is 32 bits by default — identical to
`float`.  `V850TaintTracker` uses the GCC V850 ABI where `double=64-bit` consumes
a register pair (R6:R7 for the first `double` parameter).  In GHS-compiled firmware,
that same parameter fits in R6 alone, leaving R7 free for the next argument.
Without the `double_is_32bit` flag, an analyst reading a finding that says "r7
tainted" might misinterpret it as the high half of a 64-bit double rather than an
independent tainted argument.  `RH850TaintTracker` stores this flag on the tracker
and propagates it into every `TaintFindingRH850` and the `report()` output.

**3. GHS old-style symbol mangling (`__ct`, `__dt`, `__vtbl`) not handled.**
GHS MULTI uses GCC 2.9.x / ARM libiberty mangling (not Itanium ABI `_Z...`).
Constructors appear as `Foo__ct`, destructors as `Foo__dt`, vtable symbols as
`__vtblFoo`.  Renesas assembler additionally prepends a leading `_` to every C
symbol (`_recv`, `_memcpy`).  `V850TaintTracker`'s source/sink resolver compares
raw ELF symbol names against C-level source/sink sets, so `_recv` is not matched
as `recv` and `Foo__ct` is not matched at all.  `RH850TaintTracker` applies
`_ghs_c_name()` normalisation at every call site before checking source/sink
membership, so all GHS-mangled variants resolve correctly.

---

## ABI summary (GHS CC-RH / IAR RH850, GHS-RE-REFERENCE.md §2.2-2.4)

| Role | Registers |
|---|---|
| Argument registers | R6, R7, R8, R9 |
| Return value (32-bit) | R10 |
| Return value (64-bit) | R10:R11 |
| Link register | R31 = LP |
| Stack pointer | R3 = SP |
| Global pointer | R4 = GP (never modify) |
| Table pointer | R5 = TP (never modify) |
| Element pointer | R30 = EP (preserved) |
| Caller-saved | R1, R6–R19, LP |
| Callee-saved | R2, R4 (GP), R5 (TP), R20–R29, EP |

**`double` type (§2.7):** 32-bit by default (`double_is_32bit=True`).
Set `double_is_32bit=False` if firmware was compiled with `--double=64`.

---

## Usage

```python
from ablation.analyzers.taint_tracker_rh850 import RH850TaintTracker

# --- Flat ROM dump ---
data = open('denso_gs327.bin', 'rb').read()
tracker = RH850TaintTracker.from_bytes(data, base_va=0x0)

# Scan one function (boundaries from EcuArchDetector / FlatBinaryFuncStartScanner)
findings = tracker.scan_function(
    func_va=0x0000_8200,
    func_end=0x0000_8400,
    init_labels={'can_payload'},
)
print(tracker.report(findings))

# --- ELF binary ---
tracker = RH850TaintTracker.from_path('firmware.elf')
findings = tracker.run()                      # intraprocedural
chains   = tracker.run_interprocedural(depth=4)
print(tracker.report(chains))

# --- Compiled with --double=64 ---
tracker = RH850TaintTracker.from_path('fw64.elf', double_is_32bit=False)
```

---

## Constructor parameters

| Parameter | Default | Description |
|---|---|---|
| `data` | — | Raw binary bytes |
| `base_va` | `0x0` | Load address of first byte (flat ROM) |
| `double_is_32bit` | `True` | GHS/IAR default: `double` = 32-bit |

`from_path(elf)` auto-detects text section VA and endianness from lief/pyelftools.

---

## TaintFindingRH850 fields

```python
@dataclass
class TaintFindingRH850:
    func_va:         int         # VA of the containing function
    func_name:       str         # symbol name or fn_0xNNNN
    sink_va:         int         # VA of the dangerous call/store
    sink_name:       str         # C-level sink name (GHS-normalised)
    tainted_args:    List[str]   # register names tainted at call site
    source_name:     str         # label of origin source function
    severity:        str         # 'CRITICAL' or 'HIGH'
    double_is_32bit: bool        # reflects tracker's ABI flag
```

---

## GHS symbol normaliser

`_ghs_c_name(sym)` maps any GHS/Renesas symbol to its C-level name:

| Input | Output | Rule |
|---|---|---|
| `_recv` | `recv` | Renesas assembler underscore prefix (§2.10) |
| `Foo__ctFv` | `Foo` | GHS constructor mangling |
| `Bar__dt` | `Bar` | GHS destructor mangling |
| `__vtblSocket` | `Socket` | vtable symbol |
| `memcpy` | `memcpy` | no mangling (pass-through) |

`_ghs_name_in(sym, name_set)` is the preferred helper: returns `True` if `sym`
or its GHS-normalised form is in `name_set`.

---

## `double=32-bit` ABI detail

GHS CC-RH and IAR default to `double=32-bit` (IEC 60559 single precision).
Practical consequence for taint tracking:

```
GCC V850 ABI (double=64-bit):
  f(double d, int n) → R6:R7 = d, R8 = n
                        first tainted "arg" at sink uses R6 AND R7

GHS CC-RH ABI (double=32-bit, DEFAULT):
  f(double d, int n) → R6 = d, R7 = n
                        first tainted "arg" at sink uses R6 only
```

A finding that names `r7` as tainted at a sink means different things in
the two ABIs.  The `[double=32b]` annotation in finding strings and the
`report()` header ensures the analyst can immediately see which model applies.

---

## Limitations

- Capstone does not support V850/RH850; a custom byte-level decoder (V850Decoder)
  is used.  Instruction decoding quality depends on the V850Decoder's opcode
  coverage for the specific RH850 variant.
- `scan_function` requires caller-supplied function boundaries (no automatic
  function boundary detection in flat ROM mode).
- `__callt` / `__interrupt` / `__trap` special function types (§2.11) are not
  modelled; these have non-standard return mechanisms (CTRET, EIRET, FERET) and
  no scratch-register semantics.  CALLT appears as an unknown call site.
- GHS `__vtbl` symbols are call-target normalised but vtable dispatch itself
  (indirect call through vtable pointer) is not tracked.
- Loop fixpoint is not computed: taint accumulated on the second loop iteration
  is not propagated to later instructions.
