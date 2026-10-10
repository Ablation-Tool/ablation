# Known Anomalies — PPC64TaintTracker

**Module:** `ablation/analyzers/taint_tracker_ppc64.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `PPC64TaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## PPC64-KA-001 — ELFv1 function descriptors (.opd) require symbol-table resolution

**Description:**  
PPC64 ELFv1 (AIX, old Linux PPC64 big-endian) stores function descriptors in the `.opd`
section: each descriptor is a tuple of (code VA, TOC pointer, environment pointer). A `BL`
to an ELFv1 function goes through the descriptor. The tracker resolves ELFv1 descriptors
when the binary has a symbol table that maps descriptor addresses to function names.

In stripped ELFv1 binaries, descriptor VAs are unknown so the interprocedural walk cannot
enter the callee. The function start set is populated from the symbol table, not from
`.eh_frame`, because ELFv1 binaries typically lack `.eh_frame`.

**Triggering conditions:**  
- Stripped AIX or old Linux PPC64 ELFv1 binaries without `.symtab`
- IBM POWER binaries where the `.opd` section has no corresponding symbol names

**Impact:** False negative. Functions are not visited because their start VAs are unknown.

**Workaround:**  
Supplement function starts from PPC64 BL-target discovery: scan for `BL <imm>` instructions
and use their targets as candidate function starts. Pass the augmented set via
`from_context(ctx)` after injecting names with `ctx.set_name()`.

**Resolved in version:** Open for stripped ELFv1.

---

## PPC64-KA-002 — TOC pointer (r2) not emulated; GOT-relative sink resolution limited

**Description:**  
PPC64 ELFv2 uses r2 as the TOC pointer. External function calls load the callee address
from the TOC via `ld r12, N(r2)` then `mtctr r12` then `bctrl`. The tracker identifies
`bctrl` call sites and resolves them via the PLT map. TOC slots that point to PLT stubs
are resolved. TOC slots that point to internal function pointers are not resolved because
the tracker does not emulate r2 per-function.

**Triggering conditions:**  
- ELFv2 binaries with indirect calls through non-PLT TOC entries
- Internal function pointer dispatch via TOC slots

**Impact:** False negative. Taint flowing into an internal function dispatched via TOC is
lost.

**Workaround:**  
Use `PPC32GOT2Resolver` principles: identify `ld r12, N(r2)` patterns and trace the TOC
offset to the target VA. Add resolved callees as custom sinks.

**Resolved in version:** Open

---

## PPC64-KA-003 — Stack taint not tracked; buffer-passing flows produce false negatives

**Description:**  
The tracker models register taint. It does not track taint stored to stack memory and later
reloaded. Flows where tainted data passes through a local stack buffer before reaching a sink
are invisible to the tracker.

**Triggering conditions:**  
- IBM AIX network services that buffer attacker-controlled data in local arrays
- POWER8/POWER9 JVM or database server code with stack-allocated message buffers

**Impact:** False negative. Use `SinkArgClassifier` as a complement.

**Workaround:**  
Run `SinkArgClassifier.from_path(elf).classify_all()` when the tracker returns no findings.

**Resolved in version:** Open

---

## PPC64-KA-004 — Endian mismatch defaults produce wrong results on little-endian targets

**Description:**  
`PPC64TaintTracker.from_path()` defaults to big-endian (`endian='big'`). OpenPOWER Linux
ELFv2 binaries from modern POWER8/POWER9 systems are little-endian and require
`endian='little'`.

**Triggering conditions:**  
- OpenPOWER Linux ELFv2 binaries analysed without `endian='little'`

**Impact:** False negative. Garbled decode produces no valid findings.

**Workaround:**  
Check `e_ident[EI_DATA]`. Pass `endian='little'` for modern OpenPOWER Linux targets.

**Resolved in version:** By design.

---

## PPC64-KA-005 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`PPC64TaintTracker` performs a linear forward trace without loop fixpoint computation.
Taint accumulated on the second and subsequent loop iterations is not propagated. This is
the same shared limitation as the other Ablation taint trackers.

**Triggering conditions:**  
- Any function containing a loop that processes tainted data

**Impact:** False negative.

**Workaround:**  
Inspect loop bodies manually for functions flagged by `SemanticSearcher` as copy or parse
patterns.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.
