# Known Anomalies — WindowsPoolTaintTracker

**Module:** `ablation/analyzers/windows_pool_taint_tracker.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `WindowsPoolTaintTracker` is known to produce an
incorrect result. Each entry documents the triggering condition, the impact, and the
recommended workaround.

---

## WINPOOL-KA-001 — Register-identity heuristic produces false positives when size register is reused

**Description:**  
`WindowsPoolTaintTracker` pairs allocation sites with copy sites where the same register
holds the size argument at both calls. It does not perform full SSA-based dataflow. If a
register holds the allocation size at an `ExAllocatePool` call, is then clobbered and
reloaded with a different value, and that different value happens to be in the same register
when `RtlCopyMemory` is called, the tracker treats the pair as a match. The copy size at
the sink may be smaller, larger, or unrelated to the allocation size.

**Triggering conditions:**  
- Functions where the compiler reuses the same register for different values between the
  allocation and the copy call
- Optimised driver code where register allocation minimises register pressure across
  function bodies of more than ~50 instructions

**Impact:** False positive. The reported pairing may not represent a real allocation-size
to copy-size flow. Every HIGH finding requires manual confirmation of the register value
at both call sites before reporting.

**Workaround:**  
For every HIGH or MEDIUM finding, confirm the register value at both call sites using
`TaintTracker` or a manual Capstone trace on the flagged function. If the register is
clobbered between the two call sites, eliminate the finding.

**Resolved in version:** Open. Full SSA-based confirmation is the correct fix. Use
`TaintTracker` for deep confirmation.

---

## WINPOOL-KA-002 — 200-instruction forward window may miss allocation-to-copy pairs in large functions

**Description:**  
The tracker pairs allocation and copy call sites within a forward instruction window of
approximately 200 instructions. In large driver dispatch functions (common in transport
and filesystem drivers), the allocation call and the copy call may be more than 200
instructions apart even though they are in the same function body and share the same
size variable.

**Triggering conditions:**  
- IRP dispatch routines longer than approximately 200 instructions
- Functions that perform allocation near the top of the function and copy near the bottom

**Impact:** False negative. Allocation-copy pairs separated by more than the window size
are not detected.

**Workaround:**  
For large dispatch functions identified by `KernelDriverAnalyzer`, supplement with a
manual trace: locate `ExAllocatePool*` call sites and `RtlCopyMemory` call sites
separately using `WindowAnalyzer.dump_text()`, then trace the size register manually
between the two sites.

**Resolved in version:** Open. The window is a performance trade-off. Extend by passing
a larger `window_insns` parameter if it becomes available.

---

## WINPOOL-KA-003 — Dynamic-resolve drivers with zero IAT produce no findings

**Description:**  
`WindowsPoolTaintTracker` builds its allocation and copy call site maps from the IAT
(Import Address Table). Drivers that resolve pool allocation functions at runtime via
`MmGetSystemRoutineAddress` and call them through function pointers have a zero-entry IAT
for those functions. The tracker returns zero findings for such drivers.

**Triggering conditions:**  
- BYOVD-style drivers or packers that dynamically resolve `ExAllocatePool*`
- Drivers flagged by `KernelDriverAnalyzer` as zero-IAT with `[dynamic-resolve]` tag

**Impact:** False negative. No pool allocation call sites are found, so no pairs are
formed.

**Workaround:**  
Check `KernelDriverAnalyzer.report.kernel_apis` for `[dynamic-resolve]` entries. For
zero-IAT drivers, fall back to `WindowAnalyzer.dump_text()` and search for the
`MmGetSystemRoutineAddress` call pattern manually.

**Resolved in version:** Open

---

## WINPOOL-KA-004 — lief 0.14.0+ required; older versions may fail PE parsing

**Description:**  
`WindowsPoolTaintTracker` uses lief for PE parsing (IAT, section headers). lief versions
before 0.14.0 have known parsing regressions on certain PE/COFF features used by Windows
kernel drivers (e.g., the `/GUARD:CF` CFG flag table). An environment with lief < 0.14.0
may fail to parse the IAT correctly and return zero entries.

**Triggering conditions:**  
- lief pinned below 0.14.0

**Impact:** False negative. Zero IAT entries means zero findings.

**Workaround:**  
Verify `import lief; print(lief.__version__)` returns 0.14.0+. The pinned version in
`requirements.txt` covers standard installs.

**Resolved in version:** Mitigated by `requirements.txt` pin.
