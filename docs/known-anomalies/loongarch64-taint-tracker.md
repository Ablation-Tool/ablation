# Known Anomalies — LoongArch64TaintTracker

**Module:** `ablation/analyzers/taint_tracker_loongarch64.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `LoongArch64TaintTracker` is known to produce an
incorrect result. Each entry documents the triggering condition, the impact, and the
recommended workaround.

---

## LA64-KA-001 — from_path misses functions in stripped binaries without eh_frame

**Description:**  
`LoongArch64TaintTracker.from_path()` finds function starts from the ELF symbol table and
`addi.d $sp,$sp,-N` prologues. Stripped binaries with neither `.symtab` nor
frame-pointer prologues (e.g., leaf functions, tail-call optimised bodies) are not found.
`from_path_full()` adds `.eh_frame` FDE records, DWARF subprogram entries, and BTF
`func_info` as additional sources.

**Triggering conditions:**  
- Stripped TencentOS 4.6 binaries without `.symtab`
- Leaf functions and tail-call-optimised functions with no `addi.d $sp` prologue

**Impact:** False negative. Functions not in the function start set are never visited by
the interprocedural walk.

**Workaround:**  
Use `from_path_full()` for stripped TencentOS binaries. `.eh_frame` recovers the majority
of missed functions. When `.debug_info` is present, `high_pc` values are stored in
`tt._dwarf_ends` for precise function boundaries.

**Resolved in version:** Mitigated by `from_path_full()`.

---

## LA64-KA-002 — KASAN/KCOV instrumentation produces false edges without stripping

**Description:**  
TencentOS kernel binaries built with `CONFIG_KASAN=y` insert a 4-6 instruction shadow-map
check preamble before virtually every memory access. Without `LoongArchDecoderV2`
instrumentation stripping, taint analysis on the debug kernel misattributes the preamble
hooks as real program logic. This produces thousands of false call edges into
`__asan_load8_noabort` and similar KASAN symbols.

**Triggering conditions:**  
- TencentOS kernel images built with `CONFIG_KASAN=y`
- Any LA64 kernel binary where approximately 40% of instructions are instrumentation hooks

**Impact:** False positive. The tracker reports sink calls that do not exist in the
non-instrumented build. Findings in `__asan_load*`/`__asan_store*` functions are always
false positives.

**Workaround:**  
Use `LoongArchDecoderV2.from_system_map(System.map)` and call `decode_frames_clean()` to
strip instrumentation before running the tracker. Check
`dec.count_instrumentation(section, base)['pct_instrumentation']` to confirm stripping
worked. Expect ~40% instrumentation on KASAN kernels.

**Resolved in version:** Mitigated by `LoongArchDecoderV2`. Run on KASAN kernels only.

---

## LA64-KA-003 — LSX/LASX vector instructions decoded as .word; taint through vectors lost

**Description:**  
The pure-Python decoder decodes LSX (128-bit SIMD) and LASX (256-bit SIMD) instructions
as `.word` (opaque word). No taint propagation rules are applied to LSX/LASX instructions.
Data that passes through LSX/LASX registers loses taint.

**Triggering conditions:**  
- TencentOS server binaries compiled with LSX/LASX optimisations
- Cryptographic or signal processing libraries using LASX intrinsics

**Impact:** False negative. Taint entering an LSX/LASX register is treated as clean on exit.

**Workaround:**  
Identify LSX/LASX-heavy functions via the `.word` density in decoder output. Inspect them
manually to confirm whether vector outputs flow to exec or memory-corruption sinks.

**Resolved in version:** Open. LSX/LASX decode tables are a future gap.

---

## LA64-KA-004 — Syscall classification requires known $a7 value; indirect syscalls not classified

**Description:**  
The syscall source/sink classification fires only when the constant-folding path has
resolved `$a7` to a known immediate value (set by `ori $a7,$zero,N` or
`addi.d $a7,$zero,N`). When `$a7` is loaded from memory or passed as an argument, it is
unknown and the syscall cannot be classified. The tracker then conservatively clobbers
all caller-saved registers, which produces no taint finding even if the syscall is a
source or sink.

**Triggering conditions:**  
- Dynamic syscall dispatch where the syscall number comes from a table lookup
- Syscall wrappers that receive the number as a function argument

**Impact:** False negative. Dynamic syscall dispatch paths are not traced through sources
or sinks.

**Workaround:**  
Identify dynamic syscall dispatch patterns via `SemanticSearcher` queries for syscall
wrapper patterns. Trace the dispatch function manually using `WindowAnalyzer.dump_text()`.

**Resolved in version:** Open

---

## LA64-KA-005 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`LoongArch64TaintTracker` uses a flow-sensitive, path-insensitive fixpoint analysis with
loop widening. Loop widening (bounded iteration then widen to top) approximates the loop
fixpoint but does not guarantee precision. Taint that accumulates on the third and
subsequent iterations beyond the widening threshold may not be reflected in the final
taint state.

**Triggering conditions:**  
- Functions with loops that process tainted data beyond the widening iteration threshold
- Deep nested loops where the inner loop body first becomes tainted after multiple outer
  iterations

**Impact:** False negative. A sink reached only after multiple loop iterations produce
a tainted accumulator may not appear in the tracker output.

**Workaround:**  
Inspect loop bodies manually for functions flagged by `SemanticSearcher` as copy or parse
patterns when the tracker returns no findings.

**Resolved in version:** Open. Loop widening is a known approximation trade-off.
