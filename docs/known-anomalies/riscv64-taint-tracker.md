# Known Anomalies — RISCV64TaintTracker

**Module:** `ablation/analyzers/taint_tracker_riscv64.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `RISCV64TaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## RISCV64-KA-001 — Capstone 5.x required; silent decode failure on older versions

**Description:**  
`RISCV64TaintTracker` requires Capstone with `CS_ARCH_RISCV`. Capstone 4.x does not include
RISC-V support. In an environment with Capstone 4.x the tracker raises `CsError` at
construction. Error suppression in batch runners can convert this to a false clean result.
This is the same limitation as RISCV32-KA-001.

**Triggering conditions:**  
- Capstone pinned to 4.x
- CI environments that install the system capstone package

**Impact:** Analysis abort; possible false clean in batch runners.

**Workaround:**  
Verify `import capstone; print(capstone.__version__)` returns 5.0+.

**Resolved in version:** Mitigated by `requirements.txt` pin.

---

## RISCV64-KA-002 — RVC compressed instruction coverage is best-effort for RV64C variants

**Description:**  
RV64GC includes the C extension (RVC). The tracker handles the standard RVC instruction set
(RV32C + shared RV32C/RV64C forms). Some 2-operand C extension forms use operand positions
that differ from the 3-operand standard forms (`c.addi rd, imm` vs. `add rd, rs1, rs2`).
The tracker applies corrections for the known 2-operand forms documented in the ISA spec.
Undocumented or non-standard RVC forms fall through to the conservative fallback.

**Triggering conditions:**  
- SiFive or VisionFive 2 firmware using non-standard RVC instruction sequences
- RISC-V Linux kernel modules with hand-written assembly using C extension forms
  not in the standard ISA spec

**Impact:** False negative at the specific unhandled instruction. Taint may stop propagating
at the instruction boundary.

**Workaround:**  
Identify unhandled RVC forms via manual inspection when a function is suspicious but the
tracker finds nothing. Add corrections to the `_COPY_MNEMS` table in `taint_tracker_riscv64.py`
as new cases are encountered (flywheel principle).

**Resolved in version:** Open

---

## RISCV64-KA-003 — Indirect JALR calls not followed interprocedurally

**Description:**  
Direct `JAL ra, target` calls and PLT stubs are resolved interprocedurally. Indirect calls
via `JALR ra, rs1, 0` or `c.jalr rs1` to a non-PLT target are treated as unknown calls.

**Triggering conditions:**  
- Function pointer dispatch in RISC-V 64 firmware

**Impact:** False negative. Taint flowing into an indirect internal callee is lost.

**Workaround:**  
Resolve the callee VA manually and add it as a custom sink, or trace it with
`scan_function()`.

**Resolved in version:** Open

---

## RISCV64-KA-004 — Stack taint not tracked; buffer-passing flows produce false negatives

**Description:**  
The tracker models register taint. It does not track taint stored to stack memory and later
reloaded. Flows where tainted data passes through a local stack buffer are invisible.

**Triggering conditions:**  
- SiFive or StarFive Linux SoC daemons that buffer network data before passing to sinks

**Impact:** False negative. Use `SinkArgClassifier` as a complement.

**Workaround:**  
Run `SinkArgClassifier.from_path(elf).classify_all()` when the tracker returns no findings.

**Resolved in version:** Open

---

## RISCV64-KA-005 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`RISCV64TaintTracker` performs a linear forward trace without loop fixpoint computation.
Taint accumulated after the second and subsequent loop iterations is not propagated. This is
the same shared limitation as the other Ablation taint trackers.

**Triggering conditions:**  
- Any function containing a loop that processes tainted data

**Impact:** False negative.

**Workaround:**  
Inspect loop bodies manually for functions flagged by `SemanticSearcher` as copy or parse
patterns.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.
