# Known Anomalies — ARM64TaintTracker

**Module:** `ablation/analyzers/taint_tracker_arm64.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `ARM64TaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## ARM64-KA-001 — from_path misses functions in stripped binaries

**Description:**  
`ARM64TaintTracker.from_path()` finds function starts from the ELF symbol table. Stripped
binaries have no `.symtab` entries, so `from_path()` returns very few or zero function
starts. The interprocedural walk can only visit functions it knows about, so a stripped
binary analysed with `from_path()` produces significantly fewer findings than a symbolled one.

**Triggering conditions:**  
- Stripped production binaries without `.symtab` (common on embedded Linux targets)
- Binaries built with `--strip-all` or `strip -s`

**Impact:** False negative. Functions that contain taint chains are simply not visited because
their start VAs are unknown to the tracker.

**Workaround:**  
Use `ARM64TaintTracker.from_path_full()`. It injects function starts from `.eh_frame` FDE
records and BL-target discovery on top of symbol-table entries. This recovers most functions
even in heavily stripped binaries.

**Resolved in version:** Mitigated by `from_path_full()`. Residual gap: leaf functions with
no `.eh_frame` entry and never called by a BL-discovered site remain unseen.

---

## ARM64-KA-002 — Indirect BLR calls not followed interprocedurally

**Description:**  
The tracker resolves direct `BL <imm>` calls and PLT stubs. Indirect calls via `BLR Xn`
(branch-link-register) are treated as unknown calls: caller-saved registers are clobbered
and the callee is not entered. A tainted argument that reaches a sink inside an indirect
callee does not surface as a finding.

**Triggering conditions:**  
- C++ virtual dispatch (vtable pointer loaded into a register, then `BLR X8`)
- Callback tables and function pointer arrays
- RTOS task function dispatch

**Impact:** False negative. The tracker detects a tainted-indirect-call finding when the
register holding the callee address is itself tainted. However, if the callee address is
clean but the callee body contains a sink that receives tainted arguments, the tracker
does not enter the callee.

**Workaround:**  
Use `VtableResolver` to identify concrete callee VAs. Add them as custom sinks or trace
each with `scan_function()` directly. The tainted-indirect-call finding flags the call site
so you know to investigate the callees.

**Resolved in version:** Open

---

## ARM64-KA-003 — SVE / NEON vector registers not tracked

**Description:**  
The taint model covers 64-bit general-purpose registers (X0-X30, SP, XZR). NEON/AdvSIMD
vector registers (V0-V31, Q0-Q31) and SVE registers are not tracked. Data routed through
vector registers loses taint.

**Triggering conditions:**  
- Firmware with NEON-optimised memory-copy routines (`memcpy` implemented with `LD1`/`ST1`)
- AArch64 NEON string processing
- Network data processed through SVE gather-load instructions

**Impact:** False negative. Taint entering a vector register is treated as clean on exit.
A sink reached via a path that goes through NEON is not flagged.

**Workaround:**  
Identify NEON-heavy functions via `SemanticSearcher` queries for copy patterns, then inspect
them manually to check whether vector outputs flow to exec or memory-corruption sinks.

**Resolved in version:** Open

---

## ARM64-KA-004 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`ARM64TaintTracker` performs a linear forward trace and does not compute a loop fixpoint.
Taint accumulated after the second and subsequent iterations of a loop is not fed back into
earlier instructions in the same loop body. This is the same limitation as RH850-KA-004 and
TRICORE-KA-002.

**Triggering conditions:**  
- Any function that loops over tainted input data
- Buffer-fill loops, string-processing loops, packet-parsing loops

**Impact:** False negative. A sink reached only after a loop-carried variable accumulates
enough taint may not appear in the tracker output.

**Workaround:**  
For functions with high-confidence semantic matches to copy or fill patterns, inspect loop
bodies manually even when the tracker reports no findings.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.

---

## ARM64-KA-005 — Kernel module relocation patch-up required before analysis

**Description:**  
ARM64 kernel modules (`.ko`) are relocatable ELF objects. The `BL` instructions targeting
external symbols have displacement=0 before the kernel loads and patches them. The tracker
reads the unrelocated bytes and cannot resolve those BL targets to symbol names without
`.rela.text` processing.

`from_path_full()` reads `.rela.text` and patches symbol names into the call graph before
the interprocedural walk begins. `from_path()` does not perform this step.

**Triggering conditions:**  
- ARM64 Linux kernel modules (`.ko` files) not run through `from_path_full()`

**Impact:** False negative. BL calls targeting external sinks (e.g., `copy_from_user`,
`kmalloc`) are not resolved to their symbol names, so the sink table match never fires.

**Workaround:**  
Always use `from_path_full()` for kernel modules. It performs relocation patching and
injects BTF func_info when the `.BTF` section is present.

**Resolved in version:** Mitigated by `from_path_full()`.
