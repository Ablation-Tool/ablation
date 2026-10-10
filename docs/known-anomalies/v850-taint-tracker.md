# Known Anomalies — V850TaintTracker

**Module:** `ablation/analyzers/taint_tracker_v850.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `V850TaintTracker` is known to produce an incorrect
result — either a false negative (missed finding) or a false positive (spurious finding).
Each entry documents the triggering condition, the impact, and the recommended workaround.

`V850TaintTracker` is the base tracker for V850/RH850 ELF binaries using the GCC V850 ABI.
For GHS-compiled or IAR-compiled RH850 firmware (the majority of automotive ECU binaries),
use `RH850TaintTracker` instead — it corrects the ABI defaults and symbol normalisation
issues documented in V850-KA-001 and V850-KA-002 below.

---

## V850-KA-001 — GCC double=64-bit ABI mismatches GHS/IAR firmware (false positives)

**Description:**  
`V850TaintTracker` models the GCC V850 ABI where `double` is 64 bits, consuming a register
pair (R6:R7) for the first double-precision floating-point argument. GHS CC-RH and IAR
RH850 compilers default to `double=32-bit` (IEC 60559 single precision). In GHS-compiled
firmware, a function `f(double d, int n)` uses R6 for `d` and R7 for `n`. If
`V850TaintTracker` analyses the same binary, it interprets R7 as the high half of the first
double argument, not as an independent second argument. A finding that names `r7` as tainted
at a sink may be misattributed.

**Triggering conditions:**  
- Any RH850/G3M ECU firmware compiled with GHS MULTI or IAR Embedded Workbench
- Functions with double-precision floating-point parameters in the first four argument slots
- Sensor fusion, PID control, and calibration-reading functions (common in ECU firmware)

**Impact:** False positive. `V850TaintTracker` may report `r7` as tainted at a sink when
`r7` actually contains an independent unrelated argument in the GHS ABI. The finding may
overstate the attack surface.

**Workaround:**  
Use `RH850TaintTracker` (with `double_is_32bit=True`, the default) for any firmware compiled
by GHS or IAR. `V850TaintTracker` is correct only for GCC-compiled V850 ELF binaries.

**Resolved in version:** By design. `RH850TaintTracker` was created to fix this. Use that
module for GHS/IAR firmware.

---

## V850-KA-002 — GHS symbol mangling not normalised; sources and sinks not matched

**Description:**  
`V850TaintTracker` compares ELF symbol names directly against source/sink name sets.
GHS CC-RH applies Renesas assembler underscore prefix (`_recv`, `_memcpy`) and GHS constructor
mangling (`Foo__ct`, `Bar__dt`, `__vtblSocket`). These symbols are not matched by
`V850TaintTracker`'s source/sink resolver. A function that is `recv` in C appears as `_recv`
in GHS-compiled ELF, and the tracker will not recognise it as a source.

**Triggering conditions:**  
- GHS-compiled V850/RH850 ELF binaries with Renesas underscore prefix on C symbols
- C++ firmware with GHS old-style mangling (constructor/destructor/vtable symbols)
- Any binary where the taint source or sink name is prefixed with `_` in the ELF symtab

**Impact:** False negative. The tracker will not seed taint from `_recv` even though it is
the `recv` source function. The entire taint chain from that source will be missed.

**Workaround:**  
Use `RH850TaintTracker`, which applies `_ghs_c_name()` normalisation at every call site
before checking source/sink membership.

**Resolved in version:** By design. `RH850TaintTracker` was created to fix this.

---

## V850-KA-003 — No flat ROM support; raises on bare binary input

**Description:**  
`V850TaintTracker` requires an ELF binary with valid section headers for function boundary
detection and VA-to-offset translation. Calling `from_path()` on a flat ROM image (no ELF
header) raises `lief.bad_file` or equivalent. Unlike `RH850TaintTracker` and
`TriCoreTaintTracker`, there is no `from_bytes(data, base_va)` constructor.

**Triggering conditions:**  
- Flat ROM images extracted from automotive ECU flash dumps
- Binary images without an ELF header

**Impact:** Analysis abort. Not a silent miss — the error surfaces immediately at load time.

**Workaround:**  
Use `RH850TaintTracker.from_bytes(data, base_va)` for flat ROM inputs, which was built to
fill this gap.

**Resolved in version:** By design. `RH850TaintTracker` was created to fix this.

---

## V850-KA-004 — Custom decoder opcode gaps produce false negatives

**Description:**  
Capstone does not support V850/RH850. `V850TaintTracker` uses the same custom byte-level
decoder (`V850Decoder`) as `RH850TaintTracker`. Instructions whose opcodes are not in the
decoder's table are handled by a conservative fallback (destination register inherits the
union of all source register taints). If the unrecognised instruction uses a non-standard
operand encoding, taint propagation at that instruction is incorrect.

**Triggering conditions:**  
- RH850 variant-specific extended opcodes
- FPU instructions (V850E2M floating-point extension)
- V850E3V5 SIMD extensions

**Impact:** False negative. Taint may stop propagating at the unrecognised instruction.

**Workaround:**  
Same as RH850-KA-001: run `V850Decoder.scan_unknown_opcodes()` to identify unrecognised
bytes before tracing, and verify those instruction sites manually.

**Resolved in version:** Open. New opcodes must be added to `V850Decoder` as encountered.

---

## V850-KA-005 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`V850TaintTracker` performs a linear forward trace and does not compute a fixpoint over loops.
Taint accumulated after the second and subsequent iterations of a loop is not fed back to
re-evaluate earlier instructions in the loop body. This is the same limitation as
RH850-KA-004 and TRICORE-KA-002.

**Triggering conditions:**  
- Any function with a loop body that processes tainted data
- Buffer-fill or string-copy loops from tainted sources

**Impact:** False negative. Sink reaches that depend on loop-carried taint accumulation may
not appear in findings.

**Workaround:**  
Manually inspect loop bodies in functions flagged by `SemanticSearcher` as copy or fill
patterns.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers. Tracked
as a cross-module gap.
