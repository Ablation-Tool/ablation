# Known Anomalies — ARCTaintTracker

**Module:** `ablation/analyzers/taint_tracker_arc.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `ARCTaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## ARC-KA-001 — Partial ARCDecoder coverage; has_full_decode flag must be checked

**Description:**  
`ARCTaintTracker` uses `ARCDecoder` for instruction decode. `ARCDecoder` covers the ARC HS
instruction set as documented in the ARC HS 4.x Programmer Reference. ARC HS DSP extensions,
ARC EM extensions, and vendor-specific custom instructions (common in Marvell and Synopsys
SoC integrations) may not be covered. The tracker exposes `ARCDecoder().has_full_decode` to
signal whether the installed decoder covers the binary's instruction set.

When `has_full_decode` is `False`, the tracker applies a conservative fallback for
unrecognised instructions: the destination register inherits the union of all source
register taints. If the unrecognised instruction has a non-standard operand layout, the
fallback propagation is incorrect.

**Triggering conditions:**  
- ARC HS binaries that use DSP or EM extension opcodes not in the base ARC HS 4.x table
- Synopsys ARC HS SoC firmware with custom instruction extensions
- Seagate or Marvell ARC-based storage controller firmware with vendor opcodes

**Impact:** False negative. Taint may stop propagating at the unrecognised instruction.

**Workaround:**  
1. Check `ARCDecoder().has_full_decode` before running the tracker.
2. Run `ARCDecoder.scan_unknown_opcodes(data, base_va)` to enumerate unrecognised bytes.
3. For each unknown opcode, manually confirm whether it modifies a register carrying taint.
4. Add new opcode entries to `ARCDecoder` as a new module gap (flywheel principle).

**Resolved in version:** Open. New opcodes must be added to `ARCDecoder` as encountered.

---

## ARC-KA-002 — 16-bit compact instruction handling limited

**Description:**  
ARC HS supports a compact instruction set (16-bit instructions) for code density. The
`ARCDecoder` decodes 32-bit instructions completely. 16-bit compact instructions are decoded
on a best-effort basis. Instructions not covered by the compact decoder fall through to the
conservative fallback.

**Triggering conditions:**  
- ARC HS firmware compiled with `-msize-level=2` or higher (compact instructions enabled)
- Boot-stage code or ISR handlers where code size is constrained

**Impact:** False negative. Taint propagation at unrecognised compact instructions is
best-effort.

**Workaround:**  
Same as ARC-KA-001: use `scan_unknown_opcodes()` to identify compact instructions that fell
through to the fallback, and verify them manually.

**Resolved in version:** Open

---

## ARC-KA-003 — Indirect JL/JLR calls not followed interprocedurally

**Description:**  
`ARCTaintTracker` resolves direct `BL <imm>` calls and PLT stubs. Indirect calls via
`JL blink` or `JLR` are treated as unknown calls. Caller-saved registers are clobbered
and the callee is not entered.

**Triggering conditions:**  
- Function pointer dispatch and callback tables in ARC firmware

**Impact:** False negative. Taint flowing into an indirect internal callee is lost.

**Workaround:**  
Resolve the callee VA manually and add it as a custom sink, or trace it with
`scan_function()`.

**Resolved in version:** Open

---

## ARC-KA-004 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`ARCTaintTracker` performs a linear forward trace without loop fixpoint computation. Taint
accumulated after the second and subsequent loop iterations is not propagated. This is the
same shared limitation as the other Ablation taint trackers.

**Triggering conditions:**  
- Any function containing a loop that processes tainted data

**Impact:** False negative.

**Workaround:**  
Inspect loop bodies manually for functions flagged by `SemanticSearcher` as copy or parse
patterns.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.
