# Known Anomalies — NanoMIPSTaintTracker

**Module:** `ablation/analyzers/taint_tracker_nanomips.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `NanoMIPSTaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## NANOMIPS-KA-001 — Conservative fallback path marks all $a0-$a3 tainted; produces false positives

**Description:**  
When Capstone 5.x or older is installed, `NanoMIPSTaintTracker` cannot decode nanoMIPS
instructions operand-by-operand because Capstone 5.x has no nanoMIPS support. The tracker
falls back to a conservative path: after any source call, it marks all four argument
registers ($a0-$a3) tainted on entry to the next function. This over-approximates taint.
Functions that receive untainted arguments in $a1-$a3 are treated as if all four are tainted.

**Triggering conditions:**  
- Any environment where `capstone.__version__ < '6.0.0a1'`
- CI environments that install the system capstone package rather than the pinned version
- `tracker.has_full_decode` returns `False`

**Impact:** False positive. The conservative path produces more sink hits than the full
decode path. Some of those hits are for arguments that are not actually tainted at runtime.
Every finding from the fallback path requires manual confirmation before it is reported.

**Workaround:**  
Install Capstone 6.x: `pip install capstone>=6.0.0a1`. Verify with
`python -c "import capstone; print(capstone.__version__)"`. Always check
`tracker.has_full_decode` before treating output as precise.

**Resolved in version:** Mitigated by upgrading Capstone. The fallback path remains
intentionally conservative because zero false negatives are more important than zero false
positives in a security scanner.

---

## NANOMIPS-KA-002 — P48 (48-bit) instruction encoding not fully modelled

**Description:**  
nanoMIPS has 16-bit (P16), 32-bit (P32), and 48-bit (P48) instruction widths. The P48
encoding is used for `LI48` and `ADDIU48`, which load large immediates. The full decode
path does not assign data-propagation taint rules to P48 instructions. The 6-byte
instruction is consumed correctly so PC advances correctly, but taint produced by a P48
large-immediate load is not tracked.

**Triggering conditions:**  
- Functions that use `LI48` to load a large address into a register that later reaches
  a sink
- Rare in compiler output; more common in hand-written firmware init code

**Impact:** False negative. Taint that originates in a P48 immediate load is not propagated.
In practice, large immediates are typically addresses rather than attacker-controlled data,
so this anomaly rarely produces missed security findings.

**Workaround:**  
Scan for P48 encoding bytes manually when a function is suspicious but the tracker finds
nothing. The P48 prefix is bits [15:11] = `0x18` in the first halfword.

**Resolved in version:** Open

---

## NANOMIPS-KA-003 — Indirect JALRC calls not followed interprocedurally

**Description:**  
`BALC` (direct call) and PLT stubs are resolved interprocedurally. Indirect calls via
`JALRC` (branch-link-register-compact) are treated as unknown calls: caller-saved registers
are clobbered and the callee is not entered.

**Triggering conditions:**  
- Function pointer dispatch and callback tables in nanoMIPS firmware

**Impact:** False negative. Taint flowing into an indirect internal callee is lost.

**Workaround:**  
Resolve the callee VA manually and add it as a custom sink, or trace it with
`scan_function()`.

**Resolved in version:** Open

---

## NANOMIPS-KA-004 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`NanoMIPSTaintTracker` performs a linear forward trace. It does not compute a loop fixpoint.
Taint that accumulates on the second and subsequent passes through a loop is not fed back
into earlier instructions. This is the same shared limitation as the other Ablation taint
trackers.

**Triggering conditions:**  
- Any function containing a loop that builds up a result from tainted input

**Impact:** False negative.

**Workaround:**  
Inspect loop bodies manually for functions flagged as copy or parse patterns by
`SemanticSearcher`.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.
