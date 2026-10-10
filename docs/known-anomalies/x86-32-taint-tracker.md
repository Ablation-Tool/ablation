# Known Anomalies — X86_32TaintTracker

**Module:** `ablation/analyzers/taint_tracker_x86_32.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `X86_32TaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## X8632-KA-001 — Intraprocedural only; interprocedural taint not followed into callees

**Description:**  
`X86_32TaintTracker` is an intraprocedural analyser. It does not follow taint into callees
the way the other Ablation taint trackers do. When the tracker reaches a `call` instruction
to a non-PLT target (an internal function), it applies the CDECL32 caller-save rule:
eax, ecx, edx are cleared. Taint that flows into the callee via a push argument is not
propagated through the callee's body.

**Triggering conditions:**  
- Any i386 ELF binary where the taint path crosses a function boundary before reaching
  the sink
- Network parsers that call a helper function to process the tainted data before the
  helper calls the sink

**Impact:** False negative. Multi-hop taint paths where the sink is more than one call
deep from the source are not detected.

**Workaround:**  
Combine with `XRefGraph.callers_of(sink_plt_va)` to identify entry functions that call
the sink directly. Then run `X86_32TaintTracker` on each entry function independently.
For deep call chains, trace each hop manually using `WindowAnalyzer.dump_text()`.

**Resolved in version:** Open. The design choice is deliberate: i386 binaries are rare
and interprocedural i386 analysis is a low-priority gap.

---

## X8632-KA-002 — FPO functions not found by prologue scan; use from_context

**Description:**  
`X86_32TaintTracker.from_path()` finds function starts by scanning for the `55 89 e5`
prologue (`push ebp; mov ebp, esp`). Functions compiled with `-fomit-frame-pointer` (FPO)
do not use ebp as a frame pointer and do not start with this byte sequence. FPO functions
are not found by the prologue scanner.

**Triggering conditions:**  
- i386 binaries compiled with `-fomit-frame-pointer` (common in optimised release builds)
- Functions where the compiler chose not to use a frame pointer

**Impact:** False negative. FPO functions are not analysed. If a sink call appears inside
an FPO function, the taint path to it is not traced.

**Workaround:**  
Pass a `BinaryContext` built with `BinaryContext.load_or_build()` via `from_context(ctx)`.
The context includes function starts from all available sources, including symbols and
cross-reference analysis, which covers FPO functions when symbols exist.

**Resolved in version:** Open for stripped FPO binaries.

---

## X8632-KA-003 — GOT-base (ebx in PIC binaries) not emulated

**Description:**  
In PIC i386 binaries, the GOT base is held in `ebx`, set by the `__x86.get_pc_thunk.bx`
sequence. The tracker does not perform GOT-base emulation. Format-string constants accessed
as `[ebx + disp32]` are not resolved. This affects `SinkArgClassifier` integration but not
the register-level taint model, because GOT addresses are constants and not tainted.

**Triggering conditions:**  
- PIC i386 shared libraries where format strings or command templates are in the GOT
  data area

**Impact:** `SinkArgClassifier` may return UNKNOWN for GOT-relative string arguments.
This does not affect whether taint is detected, only whether the argument is classified
as a RODATA constant.

**Workaround:**  
Use `SinkArgClassifier.from_path(elf).classify_all()` and treat UNKNOWN results with
GOT-relative access patterns as candidates for manual verification.

**Resolved in version:** By design. ebx carries no security-relevant taint.

---

## X8632-KA-004 — esp arithmetic limited to push/pop and call cleanup

**Description:**  
The stack frame model tracks `esp_delta` via explicit `push`, `pop`, and `add esp, N`
(call cleanup) instructions. A `sub esp, N` for frame allocation does not adjust
`esp_delta`; only explicit push/pop operations do. Stack-based copy loops (e.g., a loop
that moves data 4 bytes at a time using `esp` as the destination pointer) are not modelled.

**Triggering conditions:**  
- Hand-written assembly that manipulates esp directly
- Inline memory-copy loops using esp offsets

**Impact:** False negative. Stack-based copy loops that route tainted data to a sink are
not detected.

**Workaround:**  
Identify stack-manipulation patterns manually using `WindowAnalyzer.dump_text()` when
`SemanticSearcher` flags a function as a copy pattern but the tracker returns no findings.

**Resolved in version:** Open

---

## X8632-KA-005 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`X86_32TaintTracker` performs a single linear pass. It does not compute a loop fixpoint.
Taint accumulated after the second and subsequent loop iterations is not propagated. This
is the same shared limitation as the other Ablation taint trackers.

**Triggering conditions:**  
- Any function containing a loop that processes tainted data

**Impact:** False negative.

**Workaround:**  
Inspect loop bodies manually.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.
