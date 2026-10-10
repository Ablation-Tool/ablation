# Known Anomalies — PPC32TaintTracker

**Module:** `ablation/analyzers/taint_tracker_ppc32.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `PPC32TaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## PPC32-KA-001 — Stack buffer taint not tracked; buffer-passing flows produce false negatives

**Description:**  
The tracker models register taint. It does not track taint stored to stack memory via
`stw` and later reloaded via `lwz`. Binaries that copy tainted data into a local stack
buffer and then pass a pointer to that buffer to a sink call show zero findings from the
register-level model alone.

**Triggering conditions:**  
- Any PPC32 function that receives network data via r3 (the `read`/`recv` return value),
  copies it into a local buffer, and then passes a pointer to a sink
- Cisco IOS 7200 parsing functions with intermediate stack buffers
- Huawei VRP PPC32 command handlers

**Impact:** False negative. The register-level taint model does not see a flow because
the taint passes through stack memory between the source and the sink.

**Workaround:**  
Run `SinkArgClassifier.from_path(elf).classify_all()` as a complement. It catches
ARG_PROPAGATED sink calls that the register-level model misses. Note: `read`/`recv` write
into a buffer argument (r4 before the call), not into the return value (r3). Use
`SinkArgClassifier` for flows where the buffer pointer is what reaches the sink.

**Resolved in version:** Open

---

## PPC32-KA-002 — Unresolved GOT2 internal function pointers treated as clobbering calls

**Description:**  
`PPC32TaintTracker` resolves GOT2 entries that point to PLT stubs (imported functions).
GOT2 entries that point to internal function pointers or data constants are not resolved.
An indirect `bctrl` through an unresolved GOT2 entry is treated as an unknown call that
clobbers r3 (the return register). If the callee contains a sink reached via tainted
arguments, the finding is missed.

**Triggering conditions:**  
- GOT2-PIC binaries with internal function pointer tables (common in Cisco IOS)
- Dispatch tables where a network handler selects a function pointer from a GOT2 slot

**Impact:** False negative. Taint that reaches a sink inside an internal GOT2-dispatched
callee is not propagated through the callee.

**Workaround:**  
Use `PPC32GOT2Resolver.from_path(elf).resolve()` to identify GOT2 entries that resolve to
internal VAs. Add those VAs as custom sinks or trace them separately.

**Resolved in version:** Open

---

## PPC32-KA-003 — LIEF relocation bug silently drops PLT entries on Huawei-specific binaries

**Description:**  
Huawei bootloaders use a vendor-specific ELF relocation type (0x40000054) that LIEF reports
as invalid and discards. The tracker detects this case (zero JUMP_SLOT relocations from LIEF)
and falls back to `_load_plt_from_dynsym_raw()`, which loads PLT stub VAs directly from
SHN_UNDEF dynamic symbols. This fallback works for Huawei GOT2-PIC binaries. It must not
run on SYSV PIC binaries (IBM HPS, glibc `.so`) because SYSV undefined symbols have
`st_value=0`.

If this guard fires incorrectly on a SYSV PIC binary, all PLT entries will be corrupted
and the tracker will produce completely wrong results.

**Triggering conditions:**  
- SYSV PIC `.so` files where LIEF populates zero PLT entries for reasons other than the
  Huawei vendor reloc (e.g., a malformed or obfuscated binary, or a future LIEF regression)

**Impact:** False positive or corrupted analysis. The guard condition is `if not self._plt:`,
so any binary where LIEF returns zero entries triggers the fallback.

**Workaround:**  
Verify LIEF is returning zero entries because of the Huawei vendor reloc, not because the
binary is a SYSV PIC `.so` with an unusual build. Check `e_type == ET_EXEC` for Huawei
bootloaders before running. Report unexpected LIEF PLT count drops as a potential bug.

**Resolved in version:** Partially mitigated. The guard uses `if not self._plt:`, which is
correct for all known Huawei targets. SYSV binaries with zero-LIEF-PLT edge cases remain
a theoretical risk.

---

## PPC32-KA-004 — Endian mismatch defaults produce wrong results on little-endian targets

**Description:**  
`PPC32TaintTracker.from_path()` defaults to big-endian (`endian='big'`). POWER LE Linux
userspace binaries require `endian='little'`.

**Triggering conditions:**  
- POWER LE Linux userspace binaries analysed without `endian='little'`

**Impact:** False negative. Garbled decode produces no valid findings.

**Workaround:**  
Pass `endian='little'` for POWER LE targets. Check `e_ident[EI_DATA]`.

**Resolved in version:** By design.

---

## PPC32-KA-005 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`PPC32TaintTracker` performs a linear forward trace without loop fixpoint computation.
Taint accumulated after the second and subsequent loop iterations is not propagated. This
is the same shared limitation as the other Ablation taint trackers.

**Triggering conditions:**  
- Any function containing a loop that processes tainted data

**Impact:** False negative.

**Workaround:**  
Inspect loop bodies manually for functions flagged by `SemanticSearcher` as copy or parse
patterns.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.
