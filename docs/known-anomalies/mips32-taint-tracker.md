# Known Anomalies — MIPS32TaintTracker

**Module:** `ablation/analyzers/taint_tracker_mips.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `MIPS32TaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## MIPS32-KA-001 — O32 mandatory argument homing produces false negatives when stack taint is not tracked

**Description:**  
The MIPS O32 ABI requires every function to home its four argument registers ($a0-$a3) to
the stack at $sp+0 through $sp+12 on entry, whether or not the arguments are used. The
tracker recognises these store-and-reload pairs and treats them as the same data. However,
the tracker does not model general stack-slot taint. If a function copies tainted data into
a local buffer and then passes a pointer to that buffer to a sink, the sink call receives a
stack pointer, not the original tainted register. The tracker does not flag that call.

**Triggering conditions:**  
- Functions that receive tainted data via argument registers and then buffer it locally
  before passing a pointer to a sink
- Any flow where the tainted value passes through stack memory before reaching the sink

**Impact:** False negative. Binaries that route all network data through stack buffers before
sinks show zero findings. Use `SinkArgClassifier` when the tracker returns no findings.

**Workaround:**  
Run `SinkArgClassifier.from_path(elf).classify_all()` when `MIPS32TaintTracker` finds
nothing. It classifies sink arguments by provenance, catching ARG_PROPAGATED cases that
the register-level taint model misses.

**Resolved in version:** Open

---

## MIPS32-KA-002 — Branch delay slots handled but only for the direct path

**Description:**  
MIPS32 branch and jump instructions execute the instruction in the delay slot before the
branch takes effect. The tracker consumes the delay-slot instruction correctly for direct
branches. If a delay-slot instruction is itself a call instruction (unusual but valid in
MIPS32), the tracker does not handle the nested call interaction.

**Triggering conditions:**  
- Hand-written assembly with a call placed in a branch delay slot
- Compiler-generated code that places an `addiu` or `lw` in the delay slot of a `JR`

**Impact:** False negative in the pathological nested-call case. Standard compiler output
is not affected because compilers do not place calls in delay slots.

**Workaround:**  
The common case is safe. For hand-written assembly, verify delay-slot instructions manually
when a suspicious call site is flagged by `SemanticSearcher`.

**Resolved in version:** Not applicable for standard compiler output. Open for edge case.

---

## MIPS32-KA-003 — Indirect JR/JALR calls not followed interprocedurally

**Description:**  
The tracker resolves direct `JAL <target>` calls and PLT stubs. Indirect calls via `JALR $t9`
are treated as unknown calls. The target register is checked against the PLT map, and if it
matches an import name the sink check fires. If the target is an internal function pointer,
the callee is not entered.

**Triggering conditions:**  
- Function pointer dispatch (callback tables, virtual dispatch in C++)
- GOT-based indirect calls where the target resolves to an internal function

**Impact:** False negative. Taint flowing into an indirect internal callee is not propagated
through the callee's body.

**Workaround:**  
Resolve the indirect call target manually using `ctx.callers_of()` and `ctx.callees_of()`.
Add resolved callees as custom sinks or trace them with `scan_function()`.

**Resolved in version:** Open

---

## MIPS32-KA-004 — Endian mismatch defaults produce wrong results on big-endian targets

**Description:**  
`MIPS32TaintTracker.from_path()` defaults to little-endian (`endian='little'`). RouterOS,
Cisco embedded, and most enterprise firmware targets use big-endian MIPS. Running the
tracker with the wrong endian parameter produces garbled instruction decode and zero valid
findings.

**Triggering conditions:**  
- Any big-endian MIPS32 binary analysed without passing `endian='big'`
- RouterOS builds, Cisco IOS-based appliances, Broadcom set-top box firmware

**Impact:** False negative (no valid findings). The error is not silent: the decode produces
recognisably wrong instructions so the garbled output is obvious on inspection. However if
the tracker is run in batch mode the empty results may be misread as a clean binary.

**Workaround:**  
Always pass `endian='big'` for embedded enterprise and router targets. Check the ELF header
`e_ident[EI_DATA]` byte: `0x02` is big-endian.

**Resolved in version:** By design. Endian must be specified by the caller.

---

## MIPS32-KA-005 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`MIPS32TaintTracker` performs a linear forward trace. It does not compute a loop fixpoint.
Taint accumulated on the second and subsequent passes through a loop body is not fed back
into earlier instructions. This is the same limitation as RH850-KA-004, TRICORE-KA-002, and
ARM64-KA-004.

**Triggering conditions:**  
- Any function containing a loop that builds up a result from tainted input

**Impact:** False negative. Taint that depends on a loop-carried accumulator may not appear
in findings.

**Workaround:**  
Manually inspect loop bodies in functions with high-confidence semantic matches to copy or
fill patterns.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.
