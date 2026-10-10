# Known Anomalies — ARM32TaintTracker

**Module:** `ablation/analyzers/taint_tracker_arm32.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `ARM32TaintTracker` is known to produce an incorrect
result — either a false negative (missed finding) or a false positive (spurious finding).
Each entry documents the triggering condition, the impact, and the recommended workaround.

---

## ARM32-KA-001 — Thumb/ARM interworking false negatives when thumb_funcs is incomplete

**Description:**  
`ARM32TaintTracker` disassembles each function using either ARM or Thumb mode. The mode is
determined by the `thumb_funcs` set supplied at construction, the LSB of ELF export symbols,
and `.eh_frame` CIE personality records. If a function is Thumb-compiled but its VA is not
in `thumb_funcs` (e.g., in a stripped binary with no exports and no `.eh_frame`), the tracker
disassembles it in ARM mode. ARM and Thumb encodings share the same byte stream; mismatched
decode produces incorrect instruction boundaries, wrong operands, and missed control flow.

**Triggering conditions:**  
- Stripped ARM32 binaries with no `.symtab`, no `.dynsym` exports, and no `.eh_frame`
- Binaries compiled with `-fomit-frame-pointer` where `.eh_frame` is not generated
- Mixed ARM/Thumb binaries where only some functions appear in the dynamic symbol table

**Impact:** False negative. Thumb functions decoded in ARM mode produce garbage decode results:
taint propagation rules are applied to incorrect operands, and sink calls encoded as 16-bit
Thumb instructions are not recognised. The entire taint chain through a misidentified Thumb
function is lost.

**Workaround:**  
1. Use `from_path_full()` or pass a `BinaryContext` built with `from_context()` — both
   populate `thumb_funcs` from `.eh_frame` and all available symbol sources.
2. If the binary is fully Thumb, pass `thumb=True` at construction:
   `ARM32TaintTracker(path, thumb=True)`.
3. For partially-stripped binaries, supplement `thumb_funcs` manually by scanning for
   `BX LR` / `POP {PC}` Thumb return patterns.

**Resolved in version:** Open. Requires heuristic Thumb detection for binaries with no
metadata. Tracked as a future gap.

---

## ARM32-KA-002 — IT block condition codes not modelled; conditional sink calls not suppressed

**Description:**  
Thumb-2 IT (If-Then) blocks encode up to four conditionally executed instructions. The
tracker traces taint through all instructions in a Thumb-2 IT block regardless of the
condition code. A sink call inside an IT block may only execute on one condition outcome, but
the tracker treats it as unconditionally executed.

**Triggering conditions:**  
- Thumb-2 compiled firmware with IT blocks containing sink calls (`BL strcpy`, `BL system`)
- Conditions guarded by input validation checks (e.g., `ITTT EQ` after a length comparison)

**Impact:** False positive. The tracker may report a finding at a sink that is only reached
when the condition is false (i.e., after validation passes). The finding may overstate
exploitability for inputs that satisfy the length check.

**Workaround:**  
For any HIGH or CRITICAL finding where the sink call appears inside a Thumb-2 IT block,
manually inspect the condition code to determine whether the finding survives when
the input fails the validation test.

**Resolved in version:** Open

---

## ARM32-KA-003 — Indirect BLX register calls not followed interprocedurally

**Description:**  
`ARM32TaintTracker` resolves direct `BL <imm>` calls interprocedurally. Indirect calls via
`BLX Rn` (branch-link to a register) are treated as unknown calls: caller-saved registers
are clobbered and the callee is not entered. If the callee is a sink or contains a sink, the
taint chain is broken at the indirect call.

**Triggering conditions:**  
- Function pointers stored in structs and dispatched via `BLX R3` or `BLX R1`
- Callback-based architectures (HAL dispatch tables, RTOS task functions)
- VTable dispatch in C++ firmware compiled without devirtualisation

**Impact:** False negative. Taint flowing into an indirect callee is not propagated through
the callee's body. A tainted argument reaching a sink inside the callee does not surface as
a finding.

**Workaround:**  
Identify indirect call targets using `VtableResolver` or by tracing the register through
`BinaryContext.callees_of()`. Add resolved callees as custom sinks or trace them separately
with `scan_function()`.

**Resolved in version:** Open

---

## ARM32-KA-004 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`ARM32TaintTracker` performs a linear forward trace and does not compute a loop fixpoint.
Taint accumulated after the second and subsequent iterations of a loop is not fed back to
re-evaluate earlier instructions in the loop body. This is the same limitation as
RH850-KA-004, TRICORE-KA-002, and V850-KA-005.

**Triggering conditions:**  
- Any function containing a loop that builds up a result incrementally from tainted input
- Buffer-copy loops, string-processing loops, CRC computation loops

**Impact:** False negative. Taint that depends on a loop-carried accumulator may not appear
in the tracker's final taint state, causing a missed finding at a sink reached after the loop.

**Workaround:**  
Manually inspect loop bodies in functions flagged by `SemanticSearcher` as copy or fill
patterns. Treat loop body output as tainted when the loop reads from an attacker-controlled
source.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.

---

## ARM32-KA-005 — VFP/NEON floating-point registers not tracked

**Description:**  
The taint model covers integer registers (r0–r15) and the CPSR. VFP/NEON registers (s0–s31,
d0–d31, q0–q15) are not tracked. Data that passes through a VFP register before reaching a
sink (e.g., a `VLDR`/`VSTR` path) will have its taint lost.

**Triggering conditions:**  
- Sensor data pipelines that load network-received bytes into floating-point registers for
  processing before writing them to a memory buffer
- Signal/audio processing firmware that routes attacker input through NEON SIMD lanes

**Impact:** False negative. Taint that enters a VFP/NEON register is considered clean
from that point forward. A subsequent store to a memory location that is then passed to a
sink will not be flagged.

**Workaround:**  
For functions that process network data through VFP/NEON paths, supplement with
`WindowAnalyzer.dump_text()` and manually check whether the floating-point output is
eventually passed to an exec or memory-corruption sink.

**Resolved in version:** Open
