# Known Anomalies — RH850TaintTracker

**Module:** `ablation/analyzers/taint_tracker_rh850.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `RH850TaintTracker` is known to produce an incorrect
result — either a false negative (missed finding) or a false positive (spurious finding).
Each entry documents the triggering condition, the impact, and the recommended workaround.

---

## RH850-KA-001 — Custom decoder opcode gaps produce false negatives

**Description:**  
Capstone does not support V850/RH850. `RH850TaintTracker` uses a custom byte-level decoder
(`V850Decoder`) for instruction decode. Instructions whose opcodes are not covered by
`V850Decoder` are treated as unknown mnemonics. The tracker applies a conservative fallback
(destination register inherits the union of all source register taints), but the fallback
assumes a standard register operand layout. If the unrecognised instruction uses a non-standard
operand encoding, taint propagation at that instruction is incorrect.

**Triggering conditions:**  
- RH850 variant opcodes not present in the current `V850Decoder` opcode table
- Extended instruction sets (RH850/E2x, RH850/E3x FPU extensions, SIMDxxx)
- Binaries compiled for custom silicon with vendor-specific instruction extensions

**Impact:** False negative. Taint may stop propagating at the unrecognised instruction,
causing the tracker to miss a real sink reach.

**Workaround:**  
1. Run `V850Decoder.scan_unknown_opcodes(data, base_va)` on the function before tracing — it
   reports instruction bytes that fell through to the unknown fallback.
2. For each unknown opcode, manually confirm whether it modifies a tainted register.
3. If a new opcode pattern is encountered repeatedly, add it to `V850Decoder` as a new module
   gap (flywheel principle).

**Resolved in version:** Open

---

## RH850-KA-002 — CALLT / interrupt / trap entry points break taint chains

**Description:**  
`__callt`, `__interrupt`, and `__trap` function types (GHS CC-RH §2.11) use non-standard
return mechanisms: `CTRET` (CALLT return), `EIRET` (exception return), `FERET` (FE return).
These return instructions are not recognised as function boundaries by `RH850TaintTracker`.
When the tracker encounters a CALLT call site, it treats it as an unknown call site and
applies the conservative fallback (return register tainted if any arg is tainted), but does
not enter the callee. When the tracker encounters a CALLT return (`CTRET`), it may not
terminate the trace correctly.

**Triggering conditions:**  
- Firmware using `__callt` table entries for hot-path dispatch (Renesas CTBP pattern)
- Interrupt handlers (`__interrupt`) that process CAN / LIN receive data
- Trap handlers used as OS call gates in RTOS-based firmware

**Impact:** False negative. Taint that enters a CALLT callee or interrupt handler is not
tracked through it. If an interrupt handler receives attacker data and writes it to a global,
that global will not be tainted.

**Workaround:**  
1. Identify `__callt` table entries in the binary (CTBP register + table base) and scan them
   separately using `scan_function()` with `init_labels` seeded from the calling context.
2. For interrupt handlers, check whether the handler writes to memory also read by traceable
   functions; if so, seed those read sites directly.

**Resolved in version:** Open

---

## RH850-KA-003 — Vtable dispatch (indirect call through vtable pointer) not tracked

**Description:**  
`RH850TaintTracker` resolves direct calls and CALLT entries but does not follow indirect
calls through vtable pointers (load-from-pointer then `jmp`/`jr` sequence). GHS C++ code
on RH850 dispatches virtual methods through a vtable pointer held in a base-pointer register.
The tracker recognises a register-indirect call (`jarl [reg]` or `jmp [reg]`) where the
register holds a tainted value as a CRITICAL finding (tainted indirect call target). However,
if the indirect call target is a sink (e.g., a virtual destructor that eventually calls
`memcpy`), and the register holding the call target is clean but the argument registers are
tainted, the tracker will not follow into the callee.

**Triggering conditions:**  
- C++ firmware compiled with GHS MULTI
- Virtual method dispatch through class hierarchies
- Callback tables dispatched via function pointer arrays

**Impact:** False negative. Taint flowing into a virtual method call is not propagated
through the callee if the call is register-indirect and the callee is not statically resolvable.

**Workaround:**  
Run `VtableResolver` (if ELF) or inspect the vtable manually to identify the concrete callee
VA. Add the callee to the taint tracker as a custom sink or trace it separately with
`scan_function()`.

**Resolved in version:** Open

---

## RH850-KA-004 — Loop fixpoint not computed; second-iteration taint is not propagated

**Description:**  
`RH850TaintTracker` performs a linear forward trace through the function body. It does not
compute a fixpoint over loops. On the first pass through a loop body, taint accumulated
after the loop header is propagated forward. On the second and subsequent iterations, any
new taint introduced by the loop condition or the loop body is not carried back to re-evaluate
earlier instructions in the loop body.

**Triggering conditions:**  
- Any function that contains a loop whose body processes tainted data
- Particularly: buffer-fill loops (`for (i=0; i<len; i++) buf[i] = src[i]`)
- String-processing loops where a length accumulator is tainted on iteration N

**Impact:** False negative. Taint that depends on a loop variable or loop-carried accumulator
may not appear in findings. The tracker may report clean exit from a loop even when the
loop body processes tainted data.

**Workaround:**  
Manually inspect loop bodies in flagged functions. If the function has a high-confidence
semantic match (via `SemanticSearcher`) to a copy or fill pattern, apply extra scrutiny
regardless of tracker output.

**Resolved in version:** Open. Requires fixpoint computation (worklist algorithm over the
CFG). Tracked as a future ablation gap.

---

## RH850-KA-005 — scan_function requires caller-supplied function boundaries

**Description:**  
In flat ROM mode (`from_bytes`), `RH850TaintTracker.scan_function()` requires the caller to
supply `func_va` and `func_end`. If the supplied boundaries are incorrect — in particular, if
`func_end` is too short — the trace terminates early and may miss sink calls that appear
after the truncation point.

**Triggering conditions:**  
- Flat ROM inputs where function boundaries come from `FlatBinaryFuncStartScanner`
- Functions where `FlatBinaryFuncStartScanner` underestimates the end boundary
- Tail-call optimised functions where a fall-through to another function is misread as padding

**Impact:** False negative. The trace may terminate before reaching the sink if `func_end`
is set too early.

**Workaround:**  
Extend `func_end` by 64–128 bytes beyond the `FlatBinaryFuncStartScanner` estimate and
re-run. If the finding appears on the extended run, the boundary was the cause. Validate
the true function end by locating the RET/CTRET instruction.

**Resolved in version:** Open
