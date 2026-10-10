# Known Anomalies — MIPS64TaintTracker

**Module:** `ablation/analyzers/taint_tracker_mips64.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `MIPS64TaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## MIPS64-KA-001 — N64 extended argument registers alias to Capstone t-register names

**Description:**  
The MIPS64 N64 ABI uses eight argument registers: $a0-$a3 ($4-$7) and four additional
registers that the N64 ABI designates as $a4-$a7. Capstone names these four as t0-t3
($8-$11, the O32 temporary register names). The tracker correctly aliases t0-t3 as extra
argument registers for taint seeding. However, Capstone names $12-$15 as t4-t7. In O32,
these are callee-saved; in N64, they are also callee-saved. Any analysis that mixes O32
and N64 ABI assumptions (e.g., a binary that calls both O32-compiled and N64-compiled
functions) may attribute taint to t4-t7 incorrectly.

**Triggering conditions:**  
- Heterogeneous binaries that mix O32 and N64 ABI-compiled object files
- IOS-XE components where vendor-supplied `.o` files use a different ABI than the main image

**Impact:** False positive or false negative depending on which direction the ABI mismatch
runs. Standard Cisco IOS OCTEON binaries are uniformly N64 and are not affected.

**Workaround:**  
Confirm the ABI from the ELF header (`e_flags` bits 0-2 indicate O32, N32, or N64) before
running. For heterogeneous images, split the analysis by linked object if the function
boundaries are known.

**Resolved in version:** By design. N64 is the default. O32 MIPS64 support is not
implemented.

---

## MIPS64-KA-002 — Stack taint not tracked; buffer-passing flows produce false negatives

**Description:**  
The tracker models register taint. It does not track taint that passes through stack memory.
In N64 binaries, functions that buffer tainted data locally before passing a pointer to a
sink call are invisible to the tracker.

**Triggering conditions:**  
- Functions that receive tainted data via argument registers, copy it to a local buffer, and
  then pass a pointer to that buffer to a sink
- Cisco IOS parsing functions with intermediate stack buffers between `recv` and `sprintf`

**Impact:** False negative. Flows through stack buffers are not detected. Supplement with
`SinkArgClassifier` when the tracker returns no findings.

**Workaround:**  
Run `SinkArgClassifier.from_path(elf).classify_all()` as a complement. It catches
ARG_PROPAGATED sink calls that the register-level model misses.

**Resolved in version:** Open

---

## MIPS64-KA-003 — Indirect JALR calls not followed interprocedurally

**Description:**  
Direct `JAL` and PLT-resolved indirect calls are handled interprocedurally. Indirect calls
via `JALR` to a non-PLT target are treated as unknown calls. Caller-saved registers are
clobbered and the callee is not entered.

**Triggering conditions:**  
- Function pointer dispatch in N64 ELF binaries
- Callback tables in network protocol handlers

**Impact:** False negative. Taint flowing into an indirect internal callee is lost.

**Workaround:**  
Identify the callee VA manually and add it as a custom sink, or trace it with
`scan_function()`.

**Resolved in version:** Open

---

## MIPS64-KA-004 — Endian mismatch defaults produce wrong results on little-endian targets

**Description:**  
`MIPS64TaintTracker.from_path()` defaults to big-endian (`endian='big'`). Little-endian
MIPS64 targets such as RouterOS 64 must be passed `endian='little'` explicitly.

**Triggering conditions:**  
- RouterOS 64 firmware analysed without `endian='little'`
- Any little-endian MIPS64 ELF where `e_ident[EI_DATA]` is `0x01`

**Impact:** False negative. The decode produces garbled instructions so the failure is
obvious on inspection, but batch analysis may misread empty results as a clean binary.

**Workaround:**  
Check `e_ident[EI_DATA]` in the ELF header before running. Pass `endian='little'` for
RouterOS 64 and other LE MIPS64 targets.

**Resolved in version:** By design.

---

## MIPS64-KA-005 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`MIPS64TaintTracker` performs a linear forward trace. It does not compute a loop fixpoint.
Taint that accumulates on the second and subsequent passes through a loop body is not fed
back into earlier instructions. This is the same limitation as MIPS32-KA-005 and the other
cross-architecture shared anomaly.

**Triggering conditions:**  
- Any function containing a loop that builds up a result from tainted input

**Impact:** False negative.

**Workaround:**  
Inspect loop bodies manually in functions flagged by `SemanticSearcher` as parse or copy
patterns.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.
