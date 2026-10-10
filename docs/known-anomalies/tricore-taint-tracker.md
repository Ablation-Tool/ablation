# Known Anomalies — TriCoreTaintTracker

**Module:** `ablation/analyzers/taint_tracker_tricore.py`  
**Tracker version:** v2.56.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `TriCoreTaintTracker` is known to produce an incorrect
result — either a false negative (missed finding) or a false positive (spurious finding).
Each entry documents the triggering condition, the impact, and the recommended workaround.

---

## TRICORE-KA-001 — Return-value aliasing across call chains not modelled

**Description:**  
`TriCoreTaintTracker` propagates taint into callees via the argument registers
(D[4]–D[7], A[4]–A[7]). If a callee is tainted and returns a value, the return registers
(D[2], A[2]) are marked tainted in the caller. However, the tracker does not model aliasing
between what the callee returns and which specific input it was derived from. In a call chain
where function A returns a value derived from its second argument (D[5]), but the tracker
only knows "D[2] in caller is tainted because D[5] was tainted", any subsequent operation
that conditionally depends on the specific source label (`D[5]` vs. `D[4]`) will not be
correctly attributed.

**Triggering conditions:**  
- Multi-hop call chains where a function transforms one specific tainted argument into its
  return value
- Functions with selective output based on input argument (e.g., `get_field(msg, field_id)`)
- SecurityAccess handlers that compute a seed from a received CAN frame field

**Impact:** False negative (label over-approximation). The tracker may report tainted output
from a function when only one of several tainted inputs was actually used to produce it. This
is a conservatism that could miss cases where a specific sanitiser on one path prevents taint.
In most security analysis scenarios this is acceptable, but in cases where the sanitizer
on D[4] is the only one that matters, the tracker may miss that the flow through D[5] bypasses it.

**Workaround:**  
For high-criticality findings involving multi-hop call chains, trace each hop individually
using `scan_function()` with `init_labels` set to the specific source register of interest.

**Resolved in version:** Open

---

## TRICORE-KA-002 — No loop fixpoint; second-iteration taint not propagated

**Description:**  
`TriCoreTaintTracker` performs a linear forward trace. It does not compute a loop fixpoint.
On the second and subsequent passes through a loop body, taint accumulated from the loop
header or a previous iteration is not fed back to re-evaluate earlier instructions. A
loop-carried accumulator that becomes tainted on iteration N will not be reflected in
the taint state for iteration N+1 instructions that were already traced.

**Triggering conditions:**  
- Any function containing a loop that builds up a result incrementally from tainted input
- Buffer-fill loops reading from a tainted source buffer
- CRC or hash computation loops processing received CAN frame bytes
- SecurityAccess computations with iterative XOR or shift patterns

**Impact:** False negative. Taint that accumulates across loop iterations may not reach the
tracker's final taint state, causing a missed finding at a sink reached after the loop exits.

**Workaround:**  
Manually inspect loop bodies in any function flagged by `SemanticSearcher` as a
copy/hash/crypto pattern. If the function processes attacker-controlled data in a loop,
treat the loop body's output as tainted regardless of tracker output.

**Resolved in version:** Open. Requires CFG fixpoint (worklist). Tracked as a future gap.

---

## TRICORE-KA-003 — ELF mode requires symbols; flat ROM interprocedural uses caller-supplied boundaries

**Description:**  
`TriCoreTaintTracker.run()` and `run_interprocedural()` in ELF mode require ELF symbols for
function boundary detection. In stripped ELF binaries or flat ROM images used via
`from_bytes()`, function boundaries must be supplied by the caller (from
`FlatBinaryFuncStartScanner` or manual analysis). If the supplied `func_end` is too small,
the trace terminates early; if too large, it may decode data or padding as instructions and
produce spurious results.

**Triggering conditions:**  
- Stripped TriCore ELF binaries (no `.symtab`, no DWARF)
- Flat ROM images from automotive ECU flash dumps (Bosch ME17, Continental MG1)
- Functions with non-standard epilogues or tail-call fall-through

**Impact:** False negative (boundary too small) or false positive (boundary too large, spurious
instruction decode). The more common failure is false negative from early termination.

**Workaround:**  
Use `FlatBinaryFuncStartScanner` to obtain candidate boundaries, then verify the true function
end by locating the RET/FRET instruction in the region. Extend boundaries by 32 bytes past
the scanner estimate and re-run if a finding is suspected but not appearing.

**Resolved in version:** Open for stripped ELF. Flat ROM boundary supply is by design
(no automatic detection in flat binary without ELF metadata).

---

## TRICORE-KA-004 — CSA memory-dump taint (STLCX / LDLCX) not modelled

**Description:**  
TriCore's hardware CSA (Context Save Area) mechanism uses the `STLCX` / `LDLCX` instructions
to save and restore the full upper context to/from memory. `TriCoreTaintTracker` models the
register-level effects of CSA (upper context preserved across CALL; lower context clobbered)
but does not track taint flowing through the memory CSA area itself. If attacker-controlled
data is stored into the CSA via `STLCX` (e.g., a corrupted upper context during an overflow)
and then reloaded into a register by `LDLCX`, the tracker will not propagate that taint.

**Triggering conditions:**  
- Interrupt handlers that save/restore context using STLCX/LDLCX
- Deeply nested call stacks where CSA save areas may overlap or be corrupted
- Findings involving upper context registers (D[8]–D[15], A[12]–A[15]) after interrupt
  return or context switch

**Impact:** False negative. Taint originating from a corrupted CSA area will not appear in
tracker output. This primarily affects interrupt-context overflow scenarios, which are rare
in standard PSIRT analysis but relevant to stack-corruption findings.

**Workaround:**  
If a finding involves potential CSA corruption (e.g., a stack overflow that could reach the
CSA save area), analyse the CSA layout manually. The CSA is a linked list at the address
held in FCX/PCX; the number of CSA frames needed is bounded by the call depth.

**Resolved in version:** Open

---

## TRICORE-KA-005 — Capstone 5.0+ required; silent decode failure on older versions

**Description:**  
`CS_ARCH_TRICORE` is absent from Capstone 4.x and earlier. If `TriCoreTaintTracker` is
imported in an environment with Capstone ≤ 4.x, the `cs.Cs(CS_ARCH_TRICORE, ...)` call will
raise `CsError`. This is an environment error, not a decode error, and it surfaces at
`__init__` time rather than at decode time. The anomaly is listed here because older
environments may silently fall through to a catch-all handler that masks the error.

**Triggering conditions:**  
- Ablation installed in a virtualenv where `capstone` was pinned to 4.x before the TriCore
  tracker was added
- CI environments that install the system `capstone` package rather than the pinned version

**Impact:** Analysis abort. No findings produced. This is a hard error, not a silent miss,
but it may be masked by environment-level error suppression.

**Workaround:**  
Verify `import capstone; print(capstone.__version__)` returns 5.0+ before running. The
pinned version in `requirements.txt` covers this for standard installs; the risk is only
in non-standard environments.

**Resolved in version:** Mitigated by `requirements.txt` pin. Version check at import TBD.
