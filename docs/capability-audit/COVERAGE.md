# Ablation Capability Audit — Coverage Matrix

Generated: 2026-10-24  
Tool: `check_coverage.py` + `build_coverage_md.py`

---

## 1. Coverage Summary

| Metric | Count |
|--------|-------|
| Total code files | 407 |
| Covered (≥1 unit) | 401 |
| Unmapped | 6 |
| Coverage | 98% |

**File type breakdown:**

| Type | Files |
|------|-------|
| code-ablation | 293 |
| code-modules | 102 |
| code-other | 1 |
| code-sweep | 11 |

---

## 2. Per-Unit Coverage

| Unit | Title | Primary Files | Covered | % |
|------|-------|--------------|---------|---|
| A01 | Core Infrastructure | 12 | 12 | 100% |
| A02 | CFG Builders + Analysis Engines | 28 | 28 | 100% |
| A03 | ISA + Instruction Models | 15 | 15 | 100% |
| A04 | Taint Trackers | 11 | 11 | 100% |
| A05 | Path / Constraint Solvers | 10 | 10 | 100% |
| A06 | Scanners: Format String, Overflow, Stack, Heap | 16 | 16 | 100% |
| A07 | Protocol + Service Analyzers | 16 | 16 | 100% |
| A08 | Platform-Specific Analyzers | 25 | 25 | 100% |
| A09 | Utility / Support Analyzers | 19 | 19 | 100% |
| A10 | Archive + Firmware Extractors | 24 | 24 | 100% |
| A11 | Corpus + Pattern Infrastructure | 17 | 17 | 100% |
| A12 | LLM-Assisted Analysis | 34 | 34 | 100% |
| A13 | Cross-Version Diff + Version Tracking | 19 | 19 | 100% |
| A14 | Specialized Scanners | 24 | 24 | 100% |
| C01 | FORGE Audit Engine | 24 | 24 | 100% |
| M01 | Modules: Network/Cloud Enumeration | 17 | 17 | 100% |
| M02 | Modules: Post-Exploitation | 13 | 13 | 100% |
| M03 | Modules: Exploitation + Payloads | 29 | 29 | 100% |
| M04 | Modules: Cisco + IoT Platform | 38 | 38 | 100% |
| S01 | Sweep Drivers | 10 | 10 | 100% |

*'Primary Files' = files for which this unit is the primary documenting unit.*
*'Covered' = those files are mentioned in the unit notes.*

---

## 3. Full File-to-Capability Mapping

Grouped by primary unit. Status key: **covered** = full capability entry; **partial** = mentioned but no capability block extracted; **stub** = file exists but minimal content; **unmapped** = not in any unit.

### A01: Core Infrastructure

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/beam_context.py` | 1487 | BeamContext — Erlang BEAM bytecode analysis; Files covered (11) | covered |
| `ablation/analyzers/binary_context.py` | 3475 | BinaryContext — session cache and session anchor; Files covered (11); NameRegistry *(also: A12)* | covered |
| `ablation/analyzers/binary_lifter.py` | 4596 | BinaryLifter — pseudo-C lifter with ISA state machines; Files covered (11) | covered |
| `ablation/analyzers/cfg_builder.py` | 547 | CFGBuilder — control flow graph construction + security gap analysis; Files covered (11); CFG Builder — x86/x86-64; Doc/code discrepancies; insn_x86 — x86/x86-64 Instruction Model *(also: A02, A03)* | covered |
| `ablation/analyzers/dataflow_engine.py` | 1627 | DataflowEngine — generic monotone dataflow framework + analyses; Files covered (11); Cross-cutting observations; Doc/code discrepancies; Summary *(also: A02)* | covered |
| `ablation/analyzers/encoding_dag.py` | 596 | EncodingDAG — ISA encoding specification and decode/encode framework; Files covered (11) | covered |
| `ablation/analyzers/entropy_mapper.py` | 320 | EntropyMapper — sliding-window Shannon entropy analysis; Files covered (11) | covered |
| `ablation/analyzers/expr_lifter.py` | 676 | ExprLifter — expression AST with simplification and value numbering; Files covered (11) | covered |
| `ablation/analyzers/structurizer.py` | 538 | Structurizer — dominator-based structured control flow recovery; Files covered (11) | covered |
| `ablation/analyzers/window_analyzer.py` | 1019 | WindowAnalyzer — disassembly window with pseudo-C annotation; Files covered (11) | covered |
| `ablation/analyzers/xref_graph.py` | 776 | XRefGraph — cross-reference graph; Files covered (11) | covered |
| `modules/build_integrity_analyzer.py` | 235 | Reference doc audit (A01 assigned docs — 33 total); 5. BuildIntegrityAnalyzer *(also: M04)* | covered |

### A02: CFG Builders + Analysis Engines

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/analysis_arc.py` | 114 | CFG Builder — ARC EM/HS; Fixpoint Analysis Engine — ARC EM/HS; Doc/code discrepancies | covered |
| `ablation/analyzers/analysis_arm32.py` | 114 | Fixpoint Analysis Engine — ARM32 | covered |
| `ablation/analyzers/analysis_arm64.py` | 110 | Fixpoint Analysis Engine — AArch64 | covered |
| `ablation/analyzers/analysis_loongarch64.py` | 117 | Fixpoint Analysis Engine — LoongArch64 | covered |
| `ablation/analyzers/analysis_mips.py` | 114 | Fixpoint Analysis Engine — MIPS32/64 | covered |
| `ablation/analyzers/analysis_ppc.py` | 114 | Fixpoint Analysis Engine — PPC32/64; Doc/code discrepancies | covered |
| `ablation/analyzers/analysis_riscv.py` | 125 | Fixpoint Analysis Engine — RISC-V; TaintEngine (RISC-V Labeled — taint_tracker_riscv.py) *(also: A05)* | covered |
| `ablation/analyzers/analysis_v850.py` | 113 | Fixpoint Analysis Engine — V850/RH850 | covered |
| `ablation/analyzers/analysis_x86.py` | 114 | Fixpoint Analysis Engine — x86/x86-64; Doc/code discrepancies | covered |
| `ablation/analyzers/cfg_arc.py` | 165 | CFG Builder — ARC EM/HS; Fixpoint Analysis Engine — ARC EM/HS | covered |
| `ablation/analyzers/cfg_arm32.py` | 138 | CFG Builder — ARM32/Thumb; Fixpoint Analysis Engine — ARM32 | covered |
| `ablation/analyzers/cfg_arm64.py` | 121 | CFG Builder — AArch64; Fixpoint Analysis Engine — AArch64 | covered |
| `ablation/analyzers/cfg_loongarch64.py` | 172 | CFG Builder — LoongArch64; Fixpoint Analysis Engine — LoongArch64 | covered |
| `ablation/analyzers/cfg_mips.py` | 172 | CFG Builder — MIPS32/64; Fixpoint Analysis Engine — MIPS32/64; Cross-cutting observations | covered |
| `ablation/analyzers/cfg_ppc.py` | 127 | CFG Builder — PPC32/64; Fixpoint Analysis Engine — PPC32/64 | covered |
| `ablation/analyzers/cfg_riscv.py` | 132 | CFG Builder — RISC-V; Fixpoint Analysis Engine — RISC-V; TaintEngine (RISC-V Labeled — taint_tracker_riscv.py) *(also: A05)* | covered |
| `ablation/analyzers/cfg_sh2a.py` | 286 | CFG Builder — SH-2A; Cross-cutting observations | covered |
| `ablation/analyzers/cfg_v850.py` | 162 | CFG Builder — V850/RH850; Fixpoint Analysis Engine — V850/RH850 | covered |
| `ablation/analyzers/cfg_x86.py` | 128 | CFG Builder — x86/x86-64; Fixpoint Analysis Engine — x86/x86-64; Doc/code discrepancies | covered |
| `ablation/analyzers/insn_arc.py` | 254 | CFG Builder — ARC EM/HS; isa_arc — ARC ISA/ABI Model; insn_arc — ARC Instruction Model; ISA Support Matrix; isa_arc *(also: A03)* | covered |
| `ablation/analyzers/insn_arm32.py` | 475 | CFG Builder — ARM32/Thumb; isa_arm32 — ARM32/Thumb ISA/ABI Model; insn_arm32 — ARM32/Thumb Instruction Model; insn-models.md; ISA Support Matrix *(also: A03)* | covered |
| `ablation/analyzers/insn_arm64.py` | 266 | CFG Builder — AArch64; isa_arm64 — AArch64 ISA/ABI Model; insn_arm64 — AArch64 Instruction Model; insn-models.md; ISA Support Matrix *(also: A03)* | covered |
| `ablation/analyzers/isa_arc.py` | 230 | CFG Builder — ARC EM/HS; Fixpoint Analysis Engine — ARC EM/HS; isa_arc — ARC ISA/ABI Model; insn_arc — ARC Instruction Model; ISA Support Matrix *(also: A03)* | covered |
| `ablation/analyzers/isa_arm64.py` | 236 | CFG Builder — AArch64; isa_arm64 — AArch64 ISA/ABI Model; insn_arm64 — AArch64 Instruction Model; ISA Support Matrix; IsaModel *(also: A03)* | covered |
| `ablation/analyzers/taint_tracker_arc_labeled.py` | 857 | Fixpoint Analysis Engine — ARC EM/HS; TaintTracker (ARC Labeled) *(also: A05)* | covered |
| `ablation/analyzers/taint_tracker_mips_labeled.py` | 915 | Fixpoint Analysis Engine — MIPS32/64; TaintTracker (MIPS32/64 Labeled) *(also: A05)* | covered |
| `ablation/analyzers/taint_tracker_ppc_labeled.py` | 963 | Fixpoint Analysis Engine — PPC32/64; PPC64TaintTracker; TaintTracker (PPC32/64 Labeled); HIGH — Likely to Mislead LLM Analyst; MEDIUM — Potentially Misleading *(also: A05)* | covered |
| `ablation/analyzers/taint_tracker_riscv.py` | 578 | Fixpoint Analysis Engine — RISC-V; TaintEngine (RISC-V Labeled — taint_tracker_riscv.py); RISCV64TaintTracker *(also: A05)* | covered |

### A03: ISA + Instruction Models

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/insn_loongarch64.py` | 118 | CFG Builder — LoongArch64; isa_loongarch64 — LoongArch64 ISA/ABI Model; insn_loongarch64 — LoongArch64 Instruction Model; insn-models.md; Structural Observations *(also: A02)* | covered |
| `ablation/analyzers/insn_m88k.py` | 259 | insn_m88k — Motorola MC88100 Instruction Decoder; insn-models.md; ISA Support Matrix; M88kInsn | covered |
| `ablation/analyzers/insn_mips.py` | 298 | CFG Builder — MIPS32/64; isa_mips — MIPS32/64 ISA/ABI Model; insn_mips — MIPS Instruction Model; insn-models.md; ISA Support Matrix *(also: A02)* | covered |
| `ablation/analyzers/insn_ppc.py` | 409 | CFG Builder — PPC32/64; isa_ppc — PowerPC ISA/ABI Model; insn_ppc — PowerPC Instruction Model; insn-models.md; ISA Support Matrix *(also: A02)* | covered |
| `ablation/analyzers/insn_riscv.py` | 219 | CFG Builder — RISC-V; isa_riscv — RISC-V ISA/ABI Model; insn_riscv — RISC-V Instruction Model; insn-models.md; Structural Observations *(also: A02)* | covered |
| `ablation/analyzers/insn_v850.py` | 274 | CFG Builder — V850/RH850; isa_v850 — V850/RH850 ISA/ABI Model; insn_v850 — V850/RH850 Instruction Model; insn-models.md; Structural Observations *(also: A02)* | covered |
| `ablation/analyzers/insn_x86.py` | 429 | CFG Builder — x86/x86-64; isa_x86 — x86/x86-64 ISA/ABI Model; insn_x86 — x86/x86-64 Instruction Model; ISA Support Matrix; AbiModel *(also: A02)* | covered |
| `ablation/analyzers/isa_arm32.py` | 369 | Fixpoint Analysis Engine — ARM32; isa_arm32 — ARM32/Thumb ISA/ABI Model; insn_arm32 — ARM32/Thumb Instruction Model; ISA Support Matrix; isa_arm32 *(also: A02)* | covered |
| `ablation/analyzers/isa_loongarch64.py` | 243 | isa_loongarch64 — LoongArch64 ISA/ABI Model; insn_loongarch64 — LoongArch64 Instruction Model; isa-models.md; ISA Support Matrix | covered |
| `ablation/analyzers/isa_m88k.py` | 173 | isa_m88k — Motorola MC88100 ISA/ABI Constants; insn_m88k — Motorola MC88100 Instruction Decoder; isa-models.md; ISA Support Matrix | covered |
| `ablation/analyzers/isa_mips.py` | 276 | CFG Builder — MIPS32/64; Fixpoint Analysis Engine — MIPS32/64; isa_mips — MIPS32/64 ISA/ABI Model; insn_mips — MIPS Instruction Model; isa-models.md *(also: A02)* | covered |
| `ablation/analyzers/isa_ppc.py` | 412 | CFG Builder — PPC32/64; Fixpoint Analysis Engine — PPC32/64; isa_ppc — PowerPC ISA/ABI Model; insn_ppc — PowerPC Instruction Model; ISA Support Matrix *(also: A02)* | covered |
| `ablation/analyzers/isa_riscv.py` | 297 | CFG Builder — RISC-V; Fixpoint Analysis Engine — RISC-V; isa_riscv — RISC-V ISA/ABI Model; insn_riscv — RISC-V Instruction Model; isa-models.md *(also: A02)* | covered |
| `ablation/analyzers/isa_v850.py` | 224 | CFG Builder — V850/RH850; Fixpoint Analysis Engine — V850/RH850; isa_v850 — V850/RH850 ISA/ABI Model; insn_v850 — V850/RH850 Instruction Model; isa-models.md *(also: A02)* | covered |
| `ablation/analyzers/isa_x86.py` | 364 | Fixpoint Analysis Engine — x86/x86-64; isa_x86 — x86/x86-64 ISA/ABI Model; insn_x86 — x86/x86-64 Instruction Model; isa-models.md; ISA Support Matrix *(also: A02)* | covered |

### A04: Taint Trackers

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/bss_taint_tracker.py` | 310 | 9. BssTaintTracker; Taint Tracker Architecture Matrix (A04 scope); Issues / Discrepancies Found | covered |
| `ablation/analyzers/taint_tracker.py` | 296 | 1. TaintTracker (base x86-64 intraprocedural); 2. TaintTracker (full interprocedural x86-64); 9. BssTaintTracker; 11. WindowsPoolTaintTracker; SourceTaintTracker — inter-procedural source code taint tracing *(also: A06)* | covered |
| `ablation/analyzers/taint_tracker_arm32.py` | 517 | 6. ARM32TaintTracker; 7. TaintTracker (ARM32/Thumb labeled — instruction-stream variant); Taint Tracker Architecture Matrix (A04 scope) | covered |
| `ablation/analyzers/taint_tracker_arm32_labeled.py` | 1209 | Fixpoint Analysis Engine — ARM32; 7. TaintTracker (ARM32/Thumb labeled — instruction-stream variant); Taint Tracker Architecture Matrix (A04 scope) *(also: A02)* | covered |
| `ablation/analyzers/taint_tracker_arm64.py` | 1103 | Fixpoint Analysis Engine — AArch64; 5. ARM64TaintTracker; Taint Tracker Architecture Matrix (A04 scope) *(also: A02)* | covered |
| `ablation/analyzers/taint_tracker_i386.py` | 412 | 8. TaintTrackerI386; Taint Tracker Architecture Matrix (A04 scope); Issues / Discrepancies Found; Summary for Parent Agent | covered |
| `ablation/analyzers/taint_tracker_x86.py` | 1520 | 1. TaintTracker (base x86-64 intraprocedural); 2. TaintTracker (full interprocedural x86-64); Taint Tracker Architecture Matrix (A04 scope); Issues / Discrepancies Found; CrossBinaryTaintTracker — cross-library interprocedural taint *(also: A06)* | covered |
| `ablation/analyzers/taint_tracker_x86_32.py` | 653 | 3. X86_32TaintTracker (i386 interprocedural, CDECL32); Taint Tracker Architecture Matrix (A04 scope); Issues / Discrepancies Found | covered |
| `ablation/analyzers/taint_tracker_x86_labeled.py` | 936 | Fixpoint Analysis Engine — x86/x86-64; 4. TaintTracker (x86 labeled — instruction-stream variant); Taint Tracker Architecture Matrix (A04 scope); Issues / Discrepancies Found *(also: A02)* | covered |
| `ablation/analyzers/tainted_string_tracker.py` | 268 | 10. TaintedStringTracker; Taint Tracker Architecture Matrix (A04 scope); Issues / Discrepancies Found | covered |
| `ablation/analyzers/windows_pool_taint_tracker.py` | 361 | 11. WindowsPoolTaintTracker; Taint Tracker Architecture Matrix (A04 scope); Issues / Discrepancies Found | covered |

### A05: Path / Constraint Solvers

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/ppc64_be_call_scanner.py` | 177 | PPC64TaintTracker; 7. PPC32ELF (helper class); 9. PPC64BECallScanner *(also: A13)* | covered |
| `ablation/analyzers/sink_arg_classifier_mips.py` | 776 | MIPS32TaintTracker; CAP-A07-04 — SinkArgClassifierMIPS; Summary Table *(also: A07)* | covered |
| `ablation/analyzers/taint_tracker_arc.py` | 548 | ARCTaintTracker | covered |
| `ablation/analyzers/taint_tracker_mips.py` | 568 | MIPS32TaintTracker; TaintTracker (MIPS32/64 Labeled) | covered |
| `ablation/analyzers/taint_tracker_mips64.py` | 751 | MIPS64TaintTracker | covered |
| `ablation/analyzers/taint_tracker_nanomips.py` | 678 | NanoMIPSTaintTracker | covered |
| `ablation/analyzers/taint_tracker_ppc32.py` | 1068 | PPC32TaintTracker | covered |
| `ablation/analyzers/taint_tracker_ppc64.py` | 712 | PPC64TaintTracker | covered |
| `ablation/analyzers/taint_tracker_riscv32.py` | 731 | RISCV32TaintTracker | covered |
| `ablation/analyzers/taint_tracker_riscv64.py` | 666 | RISCV64TaintTracker | covered |

### A06: Scanners: Format String, Overflow, Stack, Heap

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/cross_binary_taint.py` | 479 | CrossBinaryTaintTracker — cross-library interprocedural taint; Files covered (15) | covered |
| `ablation/analyzers/lib_graph.py` | 275 | LibGraph — cross-binary import/export matrix; Files covered (15) | covered |
| `ablation/analyzers/priv_drop_before_exec.py` | 288 | PrivDropBeforeExec — privilege drop before exec detector; Files covered (15) | covered |
| `ablation/analyzers/pthread_once_detector.py` | 494 | PthreadOnceDetector — pthread_once double-initialization detector; Files covered (15) | covered |
| `ablation/analyzers/source_arch_risk.py` | 289 | SourceArchRisk — "safe now, catastrophic later" architectural risk scanner; Files covered (15) | covered |
| `ablation/analyzers/source_audit_compressor.py` | 392 | SourceAuditCompressor — profile-based batch source audit; Files covered (15) | covered |
| `ablation/analyzers/source_entry_classifier.py` | 319 | SourceEntryClassifier — HTTP route auth-level classification; Files covered (15) | covered |
| `ablation/analyzers/source_ingestion.py` | 317 | SourceContext — source repo ingestion and indexing; Files covered (15) | covered |
| `ablation/analyzers/source_isolation_checker.py` | 498 | SourceIsolationChecker — tenant isolation / IDOR scanner; Files covered (15) | covered |
| `ablation/analyzers/source_sink_scanner.py` | 314 | SourceSinkScanner — dangerous sink detection in source RE; Files covered (15) | covered |
| `ablation/analyzers/source_taint_tracker.py` | 567 | SourceTaintTracker — inter-procedural source code taint tracing; Files covered (15) | covered |
| `ablation/analyzers/taint_tracker_loongarch64.py` | 1049 | Fixpoint Analysis Engine — LoongArch64; TaintTrackerLoongArch64 — LoongArch64 kernel-ABI taint; Files covered (15) *(also: A02)* | covered |
| `ablation/analyzers/taint_tracker_rh850.py` | 350 | TaintTrackerRH850 — GHS CC-RH / IAR RH850 ABI taint tracker; Files covered (15) | covered |
| `ablation/analyzers/taint_tracker_tricore.py` | 875 | TaintTrackerTriCore — Infineon AURIX TriCore TC1.6x taint; Files covered (15) | covered |
| `ablation/analyzers/taint_tracker_v850.py` | 993 | Fixpoint Analysis Engine — V850/RH850; TaintTrackerV850 — Renesas V850/RH850 source-to-sink taint; Files covered (15) *(also: A02)* | covered |
| `modules/interproc_field_writer.py` | 685 | SourceIsolationChecker — tenant isolation / IDOR scanner; interproc_field_writer.py (lines 1–686); find_field_writers(); Hardcoded WeChat binary constants (CRITICAL limitation for reuse); InstallerBinaryAnalyzer *(also: M03)* | covered |

### A07: Protocol + Service Analyzers

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/argv_build_to_sink.py` | 292 | CAP-A07-17 — ArgvBuildToSinkClassifier; Summary Table | covered |
| `ablation/analyzers/network_sink_finder.py` | 189 | CAP-A07-15 — NetworkSinkFinder; Summary Table | covered |
| `ablation/analyzers/pe_sink_classifier.py` | 212 | CAP-A07-16 — PESinkClassifier; Summary Table | covered |
| `ablation/analyzers/sanitizer_detector.py` | 854 | CAP-A07-13 — SanitizerDetector; Summary Table | covered |
| `ablation/analyzers/sink_arg_classifier.py` | 1464 | CAP-A07-01 — SinkArgClassifier (x86-64 dispatch hub); Summary Table | covered |
| `ablation/analyzers/sink_arg_classifier_arm32.py` | 597 | CAP-A07-02 — SinkArgClassifierARM32; Summary Table | covered |
| `ablation/analyzers/sink_arg_classifier_i386.py` | 360 | CAP-A07-03 — SinkArgClassifierI386 (forward register-state pass); Summary Table | covered |
| `ablation/analyzers/sink_arg_classifier_ppc32.py` | 686 | PPC32TaintTracker; Tests Coverage Summary; CAP-A07-05 — SinkArgClassifierPPC32BE; Summary Table; 8. PPC32PLTTracer *(also: A05, A13)* | covered |
| `ablation/analyzers/sink_arg_classifier_ppc64.py` | 670 | PPC64TaintTracker; Tests Coverage Summary; CAP-A07-06 — SinkArgClassifierPPC64 (ELFv2 LE); Summary Table; 10. Ppc64BeSinkClassifier *(also: A05, A13)* | covered |
| `ablation/analyzers/sink_arg_classifier_ppc64_elfv1.py` | 778 | CAP-A07-07 — SinkArgClassifierPPC64ELFv1 (BE); Summary Table | covered |
| `ablation/analyzers/sink_arg_classifier_ppc64_elfv2.py` | 1022 | CAP-A07-08 — SinkArgClassifierPPC64ELFv2; Summary Table | covered |
| `ablation/analyzers/sink_arg_classifier_s390.py` | 597 | CAP-A07-09 — SinkArgClassifierS390X; Summary Table | covered |
| `ablation/analyzers/sink_arg_classifier_x86_32.py` | 977 | 3. X86_32TaintTracker (i386 interprocedural, CDECL32); 8. TaintTrackerI386; CAP-A07-03 — SinkArgClassifierI386 (forward register-state pass); CAP-A07-10 — SinkArgClassifierI386 (backward push-backtrack); Summary Table *(also: A04)* | covered |
| `ablation/analyzers/sink_propagator.py` | 535 | CAP-A07-11 — SinkPropagator; Summary Table | covered |
| `ablation/analyzers/sink_sanitizer_filter.py` | 521 | CAP-A07-12 — SinkSanitizerFilter; Summary Table | covered |
| `ablation/analyzers/static_link_sink_scanner.py` | 452 | CAP-A07-14 — StaticLinkSinkScanner; Summary Table | covered |

### A08: Platform-Specific Analyzers

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/apache_module_analyzer.py` | 650 | 21. ApacheModuleAnalyzer; ApacheModuleAnalyzer | covered |
| `ablation/analyzers/byovd_detector.py` | 602 | 14. ByovdDetector; ByovdDetector | covered |
| `ablation/analyzers/cmdb_surface_mapper.py` | 465 | 22. CMDBSurfaceMapper; CMDBSurfaceMapper | covered |
| `ablation/analyzers/command_table_scanner.py` | 406 | 23. CommandTableScanner; CommandTableScanner | covered |
| `ablation/analyzers/compiler_security_gate.py` | 459 | 18. CompilerSecurityGate; CompilerSecurityGate | covered |
| `ablation/analyzers/deprecated_func_scanner.py` | 299 | 7. DeprecatedFuncScanner; DeprecatedFuncScanner | covered |
| `ablation/analyzers/flatui_method_decoder.py` | 177 | 24. FlatuiMethodDecoder; Notes for DOC_CODE_MAP.md; FlatuiMethodDecoder | covered |
| `ablation/analyzers/fork_exec_classifier.py` | 530 | 13. ForkExecClassifier; ForkExecClassifier | covered |
| `ablation/analyzers/format_string_scanner.py` | 415 | 1. FormatStringScanner; FormatStringScanner | covered |
| `ablation/analyzers/go_subprocess_scanner.py` | 470 | 25. GoSubprocessScanner; Notes for DOC_CODE_MAP.md; GoSubprocessScanner | covered |
| `ablation/analyzers/heap_vuln_scanner.py` | 529 | 2. HeapVulnScanner; 3. LA64HeapVulnScanner; HeapVulnScanner; LA64HeapVulnScanner | covered |
| `ablation/analyzers/intoverflow_scanner_arm32.py` | 415 | 10. ARM32IntOverflowScanner; ARM32IntOverflowScanner | covered |
| `ablation/analyzers/kernel_driver_analyzer.py` | 1731 | 15. KernelDriverAnalyzer; KernelDriverAnalyzer | covered |
| `ablation/analyzers/kernel_module_subsystem_classifier.py` | 231 | 16. KernelModuleSubsystemClassifier; Notes for DOC_CODE_MAP.md; KernelModuleSubsystemClassifier | covered |
| `ablation/analyzers/la64_heap_vuln_scanner.py` | 491 | 3. LA64HeapVulnScanner; LA64HeapVulnScanner | covered |
| `ablation/analyzers/length_underflow.py` | 436 | 9. LengthUnderflowScanner; LengthUnderflowScanner | covered |
| `ablation/analyzers/loongarch64_max_not_min_scanner.py` | 753 | 19. LA64MaxNotMinScanner; LA64MaxNotMinScanner | covered |
| `ablation/analyzers/lua_injection_analyzer.py` | 534 | 5. LuaInjectionAnalyzer; LuaInjectionAnalyzer | covered |
| `ablation/analyzers/mcp_tool_taint_scanner.py` | 564 | 17. MCPToolTaintScanner; MCPToolTaintScanner | covered |
| `ablation/analyzers/perl_taint_scanner.py` | 472 | 6. PerlTaintScanner; PerlTaintScanner | covered |
| `ablation/analyzers/preauth_route_auditor.py` | 493 | 20. PreAuthRouteAuditor; Notes for DOC_CODE_MAP.md; PreAuthRouteAuditor | covered |
| `ablation/analyzers/setuid_before_fork.py` | 284 | 11. SetuidBeforeForkAnalyzer; SetuidBeforeForkAnalyzer | covered |
| `ablation/analyzers/setuid_obfuscated_exec.py` | 316 | 12. SetuidObfuscatedExecDetector; SetuidObfuscatedExecDetector | covered |
| `ablation/analyzers/sql_sink_scanner.py` | 551 | 4. SqlSinkScanner; SqlSinkScanner | covered |
| `ablation/analyzers/sscanf_sink_classifier.py` | 696 | 8. SscanfSinkClassifier; SscanfSinkClassifier | covered |

### A09: Utility / Support Analyzers

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/aix_bff_extractor.py` | 820 | AixBffExtractor + XCOFF32Info | covered |
| `ablation/analyzers/aix_big_ar_extractor.py` | 167 | AixBigArExtractor | covered |
| `ablation/analyzers/aix_type0f_stream_splitter.py` | 287 | AixType0fStreamSplitter | covered |
| `ablation/analyzers/appledouble_extractor.py` | 291 | AppleDoubleExtractor | covered |
| `ablation/analyzers/ar_archive_scanner.py` | 212 | ArArchiveScanner | covered |
| `ablation/analyzers/cfg_bypass_detector.py` | 339 | CFGBypassDetector | covered |
| `ablation/analyzers/com_attack_surface_mapper.py` | 381 | COMAttackSurfaceMapper | covered |
| `ablation/analyzers/etw_provider_extractor.py` | 378 | ETWProviderExtractor | covered |
| `ablation/analyzers/firmware_container.py` | 212 | FirmwareContainer | covered |
| `ablation/analyzers/firmware_container_key_extractor.py` | 539 | FirmwareContainer; FirmwareContainerKeyExtractor | covered |
| `ablation/analyzers/fortibuild_track_classifier.py` | 180 | FortiBuildTrackClassifier | covered |
| `ablation/analyzers/fortigate_cert_key_scanner.py` | 626 | FortiGateCertKeyScanner | covered |
| `ablation/analyzers/fortimail_vmdk_extractor.py` | 588 | FortiMailVmdkExtractor | covered |
| `ablation/analyzers/fortios_firmware_extractor.py` | 422 | FortiOSHardwareExtractor | covered |
| `ablation/analyzers/ne_format_parser.py` | 304 | NEFormatParser | covered |
| `ablation/analyzers/nested_archive_scanner.py` | 225 | NestedArchiveScanner | covered |
| `ablation/analyzers/pdb_symbol_integrator.py` | 454 | PDBSymbolIntegrator | covered |
| `ablation/analyzers/rpc_server_analyzer.py` | 457 | RPCServerAnalyzer | covered |
| `ablation/analyzers/seh_chain_analyzer.py` | 305 | SEHChainAnalyzer | covered |

### A10: Archive + Firmware Extractors

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/arc_decoder.py` | 392 | ARCTaintTracker; ARCDecoder — Synopsys ARC decoder (Capstone-optional); Reference doc status (A10) *(also: A05)* | covered |
| `ablation/analyzers/ecu_a2l_parser.py` | 643 | CAP-A10-09b: EcuA2LParser (ASAM A2L / ASAP2); Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_arch_detector.py` | 712 | EcuArchDetector — flat ECU ROM ISA identification; Discrepancies found (A10); Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_c166_decoder.py` | 710 | EcuC166Decoder — C166/C167 pure-Python decoder; Discrepancies found (A10); Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_c28x_decoder.py` | 491 | EcuC28xDecoder — TMS320C28x pure-Python decoder; Discrepancies found (A10); Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_cal_def.py` | 117 | Calibration parsers — ECU label maps and calibration tables; CAP-A10-09a: EcuXDFParser (TunerPro XDF); CAP-A10-09b: EcuA2LParser (ASAM A2L / ASAP2); CAP-A10-09c: EcuConecanParser (conescan XML) | covered |
| `ablation/analyzers/ecu_conescan_parser.py` | 427 | CAP-A10-09c: EcuConecanParser (conescan XML); Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_m68k_decoder.py` | 295 | EcuM68kDecoder — M68K/CPU32 Capstone decoder; Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_open_damos_parser.py` | 377 | CAP-A10-09d: EcuOpenDamosParser (open_damos.json); Discrepancies found (A10); Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_rom_layout_analyzer.py` | 489 | EcuRomLayoutAnalyzer — ROM region classification; Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_romraider_parser.py` | 676 | CAP-A10-09e: EcuRomRaiderParser (RomRaider XML); Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_security_access_scanner.py` | 331 | EcuSecurityAccessScanner — static-seed SecurityAccess fingerprinter; Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_sh2a_decoder.py` | 484 | CFG Builder — SH-2A; EcuSH2aDecoder — SH-2A pure-Python decoder; Reference doc status (A10) *(also: A02)* | covered |
| `ablation/analyzers/ecu_vle_decoder.py` | 572 | EcuVLEDecoder — PowerPC VLE pure-Python decoder; Reference doc status (A10) | covered |
| `ablation/analyzers/ecu_xdf_parser.py` | 354 | CAP-A10-09a: EcuXDFParser (TunerPro XDF); Discrepancies found (A10); Reference doc status (A10) | covered |
| `ablation/analyzers/epilogue_share_scanner.py` | 186 | EpilogueShareScanner — shared epilogue block detector; Reference doc status (A10) | covered |
| `ablation/analyzers/flat_binary_func_start_scanner.py` | 471 | FlatBinaryFuncStartScanner — arch-agnostic function-start scanner; Reference doc status (A10) | covered |
| `ablation/analyzers/hisi_rv32_ext.py` | 576 | HiSiRV32Ext — HiSilicon RISC-V custom extension correct-size decoder; Reference doc status (A10) | covered |
| `ablation/analyzers/loongarch_decoder.py` | 877 | insn_loongarch64 — LoongArch64 Instruction Model; Insn; TaintTrackerLoongArch64 — LoongArch64 kernel-ABI taint; LoongArchDecoder — LoongArch64 pure-Python decoder; Reference doc status (A10) *(also: A03, A06)* | covered |
| `ablation/analyzers/nanomips_decoder.py` | 324 | NanoMIPSDecoder — nanoMIPS Capstone-optional decoder; Reference doc status (A10) | covered |
| `ablation/analyzers/ti_coff_loader.py` | 353 | TiCoffLoader — TI COFF2 / AR archive parser; Reference doc status (A10) | covered |
| `ablation/analyzers/ti_nnc_scanner.py` | 563 | TiNNCScanner — TI Neural Network Compiler artifact scanner; Reference doc status (A10) | covered |
| `ablation/analyzers/v850_decoder.py` | 331 | V850Decoder — Renesas V850 pure-Python decoder; Reference doc status (A10) | covered |
| `modules/ecu_nissan_parser.py` | 542 | Discrepancies found (A10); Reference doc status (A10); 32. EcuNissanParser *(also: M04)* | covered |

### A11: Corpus + Pattern Infrastructure

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/abc_decompiler.py` | 1098 | 3. ABCDecompiler | covered |
| `ablation/analyzers/abc_disasm.py` | 608 | 1. ABCParser; 2. ARKDisasm; Doc/Code Discrepancies Summary | covered |
| `ablation/analyzers/abc_parser.py` | 742 | 1. ABCParser; 2. ARKDisasm; Doc/Code Discrepancies Summary | covered |
| `ablation/analyzers/binder_scanner.py` | 247 | 4. BinderScanner | covered |
| `ablation/analyzers/browser_extension_auditor.py` | 592 | 1. ABCParser; 5. BrowserExtensionAuditor; Coverage Summary | covered |
| `ablation/analyzers/dex_analyzer.py` | 392 | 6. DexAnalyzer | covered |
| `ablation/analyzers/dex_disasm.py` | 924 | 7. DEXDisasm | covered |
| `ablation/analyzers/dex_lifter.py` | 758 | 8. DEXLifter | covered |
| `ablation/analyzers/electron_security_scanner.py` | 552 | 9. ElectronSecurityScanner | covered |
| `ablation/analyzers/go_pclntab.py` | 255 | 10. GoFuncTable (go_pclntab); Doc/Code Discrepancies Summary | covered |
| `ablation/analyzers/go_string_resolver.py` | 469 | 11. GoStringResolver; Doc/Code Discrepancies Summary | covered |
| `ablation/analyzers/go_x86_strip_scanner.py` | 415 | 1. ABCParser; 10. GoFuncTable (go_pclntab); 12. GoX86StripScanner; Coverage Summary | covered |
| `ablation/analyzers/java_jar_scanner.py` | 299 | 13. JavaJarScanner | covered |
| `ablation/analyzers/jni_bridge_scanner.py` | 348 | 4. BinderScanner; 14. JniBridgeScanner | covered |
| `ablation/analyzers/library_inventory.py` | 718 | 15. LibraryInventory | covered |
| `ablation/analyzers/pyc_bytecode_scanner.py` | 395 | 16. PycBytecodeScanner | covered |
| `modules/analyze_all_jni.py` | 349 | 14. JniBridgeScanner; 34. analyze_all_jni (JNI Surface Analyzer — HiJoy PTT); 35. deep_jni_analysis (Deep JNI Structural Analyzer — HiJoy PTT) *(also: M04)* | covered |

### A12: LLM-Assisted Analysis

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/__init__.py` | 2 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |
| `ablation/analyzers/__init__.py` | 268 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |
| `ablation/analyzers/corpus_builder.py` | 281 | CorpusBuilder; Summary of LLM / AI Dependencies (A12) | covered |
| `ablation/analyzers/dtw_matcher.py` | 327 | DTWMatcher | covered |
| `ablation/analyzers/evidence_scorer.py` | 230 | EvidenceScorer | covered |
| `ablation/analyzers/finding_registry.py` | 589 | FindingRegistry; Summary of LLM / AI Dependencies (A12) | covered |
| `ablation/analyzers/func_id_db.py` | 574 | FuncDB (func_id_db); FuncDB | covered |
| `ablation/analyzers/hypothesis_engine.py` | 421 | HypothesisEngine | covered |
| `ablation/analyzers/hypothesis_models.py` | 440 | HypothesisModels; HypothesisRecord | covered |
| `ablation/analyzers/llm_analyst/__init__.py` | 31 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |
| `ablation/analyzers/llm_analyst/agent_loop.py` | 324 | LLM-Analyst — AgentLoop; Top Discrepancies (Code vs Docs); AgentLoop; Summary of LLM / AI Dependencies (A12) | covered |
| `ablation/analyzers/llm_analyst/context_builder.py` | 199 | LLM-Analyst — ContextBuilder; ContextBuilder | covered |
| `ablation/analyzers/llm_analyst/rag_retriever.py` | 134 | LLM-Analyst — RAGRetriever; RAGRetriever | covered |
| `ablation/analyzers/llm_analyst/tasks/__init__.py` | 0 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |
| `ablation/analyzers/llm_analyst/tasks/function_namer.py` | 131 | LLM-Analyst — AgentLoop; AgentLoop | covered |
| `ablation/analyzers/llm_analyst/tasks/struct_reconstructor.py` | 222 | LLM-Analyst — AgentLoop; AgentLoop | covered |
| `ablation/analyzers/llm_analyst/tasks/vuln_hypothesis.py` | 127 | LLM-Analyst — AgentLoop; AgentLoop | covered |
| `ablation/analyzers/llm_analyst/tool_registry.py` | 403 | LLM-Analyst — ToolRegistry; ToolRegistry | covered |
| `ablation/analyzers/matrix_profile_diff.py` | 369 | MatrixProfileDiff | covered |
| `ablation/analyzers/name_registry.py` | 139 | NameRegistry | covered |
| `ablation/analyzers/opseq.py` | 291 | SAXIndex; DTWMatcher; 19. opseq module *(also: A14)* | covered |
| `ablation/analyzers/pattern_library.py` | 493 | PatternLibrary; 11. EnginePatternLibrary; EnginePatternLibrary vs PatternLibrary *(also: A14)* | covered |
| `ablation/analyzers/probe_adapters.py` | 538 | ProbeAdapters; execute_probe | covered |
| `ablation/analyzers/probe_ranker.py` | 241 | ProbeRanker | covered |
| `ablation/analyzers/sax_index.py` | 357 | SAXIndex | covered |
| `ablation/analyzers/semantic_search.py` | 647 | SemanticSearcher; Summary of LLM / AI Dependencies (A12) | covered |
| `ablation/analyzers/sig_library.py` | 260 | SigLibrary; Summary of LLM / AI Dependencies (A12) | covered |
| `ablation/analyzers/subsequence_searcher.py` | 361 | SubsequenceSearcher | covered |
| `ablation/core/__init__.py` | 31 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |
| `ablation/data/__init__.py` | 0 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |
| `ablation/export/__init__.py` | 5 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |
| `ablation/integrations/__init__.py` | 1 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |
| `modules/__init__.py` | 2 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |
| `sweeps/__init__.py` | 0 | 2. TaintTracker (full interprocedural x86-64); Issues / Discrepancies Found; LLM-Analyst — AgentLoop; AgentLoop *(also: A04)* | covered |

### A13: Cross-Version Diff + Version Tracking

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/pef_abi_clobber_scanner.py` | 397 | 1. PEFABIClobberScanner; 2. classify (module-level function) | covered |
| `ablation/analyzers/pef_binary_analyzer.py` | 495 | 3. PEFBinaryAnalyzer | covered |
| `ablation/analyzers/ppc32_lifter.py` | 433 | 4. Ppc32Lifter; 5. Ppc476Lifter; Doc Mismatches; Duplication | covered |
| `ablation/analyzers/ppc32_plt_tracer.py` | 516 | 7. PPC32ELF (helper class); 8. PPC32PLTTracer | covered |
| `ablation/analyzers/ppc476_decompiler.py` | 697 | 4. Ppc32Lifter; 6. Ppc476Decompiler | covered |
| `ablation/analyzers/ppc476_lifter.py` | 433 | 4. Ppc32Lifter; 5. Ppc476Lifter; Doc Mismatches; Duplication | covered |
| `ablation/analyzers/ppc64_be_sink_classifier.py` | 646 | 10. Ppc64BeSinkClassifier | covered |
| `ablation/analyzers/ppc64_dynds_classifier.py` | 475 | 11. DynDSClassifier | covered |
| `ablation/analyzers/ppc64_elfv1_resolver.py` | 419 | 12. Ppc64ElfV1Resolver | covered |
| `ablation/analyzers/ppc64_power10_plt_stubs.py` | 180 | 13. scan_power10_stubs | covered |
| `ablation/analyzers/ppc64_vmx_density.py` | 353 | 14. VMXDensityScanner | covered |
| `ablation/analyzers/ps3_opd_vtable_scanner.py` | 484 | 15. PS3OPDVtableScanner | covered |
| `ablation/analyzers/ps3_self_decryptor.py` | 359 | 16. PS3SELFDecryptor | covered |
| `ablation/analyzers/rel_dyn_pc32_scanner.py` | 273 | 17. RelDynPc32Scanner | covered |
| `ablation/analyzers/vtable_dispatch_scanner.py` | 262 | 18. VtableDispatchScanner | covered |
| `ablation/analyzers/vtable_resolver.py` | 473 | 19. vtable_resolver (module-level functions + classes) | covered |
| `ablation/analyzers/wcode_parser.py` | 549 | 20. WCodeParser / WCodeBuiltinCatalog | covered |
| `ablation/analyzers/xcoff32_decompiler.py` | 832 | 21. Xcoff32Decompiler | covered |
| `ablation/analyzers/xcoff_symtab_parser.py` | 320 | 22. XcoffSymtabParser | covered |

### A14: Specialized Scanners

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/analyzers/arm32_function_scanner.py` | 181 | 1. ARM32FunctionScanner | covered |
| `ablation/analyzers/arm32_reg_annotator.py` | 278 | 2. ARM32RegAnnotator | covered |
| `ablation/analyzers/arm64_fgets_fd_discriminator.py` | 187 | 3. ARM64FgetsFdDiscriminator | covered |
| `ablation/analyzers/caller_arg_resolver.py` | 442 | 4. CallerArgResolver | covered |
| `ablation/analyzers/crypto_pattern_detector.py` | 395 | 5. HashAlgoDiscriminator; 6. CustomCBCDetector | covered |
| `ablation/analyzers/dwarf_loongarch64.py` | 299 | 7. DWARF/BTF Utilities (dwarf_loongarch64.py); 7a. extract_eh_frame_starts; 7b. extract_debug_funcs; 7c. extract_btf_funcs | covered |
| `ablation/analyzers/dynamic_sandbox.py` | 594 | 8. DynamicSandbox; 9. LeafFunctionChecker; 10. DynamicProbeAdapter; dynamic_sandbox.py: Real Unicorn sandbox | covered |
| `ablation/analyzers/engine_pattern_library.py` | 896 | 11. EnginePatternLibrary; EnginePatternLibrary vs PatternLibrary | covered |
| `ablation/analyzers/forge.py` | 678 | 12. FORGE | covered |
| `ablation/analyzers/func_profiler.py` | 319 | 13. FuncProfiler | covered |
| `ablation/analyzers/func_reachability.py` | 251 | 14. FuncReachabilityAnalyzer | covered |
| `ablation/analyzers/i386_absolute_xref_scanner.py` | 238 | 15. I386AbsoluteXrefScanner | covered |
| `ablation/analyzers/i386_call_chain_resolver.py` | 450 | 16. I386CallChainResolver | covered |
| `ablation/analyzers/ipreg_annotator.py` | 400 | 17. IPRegAnnotator | covered |
| `ablation/analyzers/lsb_stego_extractor.py` | 377 | 18. BmpKeyExtractor | covered |
| `ablation/analyzers/reg_annotator.py` | 786 | 2. ARM32RegAnnotator; 17. IPRegAnnotator; 20. RegAnnotator | covered |
| `ablation/analyzers/scan_result_version_cache.py` | 292 | 21. ScanResultVersionCache | covered |
| `ablation/analyzers/stage_commitment.py` | 230 | 22. StageCommitment | covered |
| `ablation/analyzers/static_elf32_func_start_scanner.py` | 239 | 23. StaticELF32FuncStartScanner | covered |
| `ablation/analyzers/syscall_loongarch64.py` | 475 | 24. syscall_loongarch64 module | covered |
| `ablation/analyzers/vendor_profile.py` | 155 | 25. VendorProfile | covered |
| `ablation/analyzers/version_delta.py` | 1016 | 26. VersionDelta / AnchorScan | covered |
| `ablation/analyzers/workflow_document.py` | 328 | 27. WorkflowDocument | covered |
| `ablation/analyzers/xor_solver.py` | 605 | 28. XorSolver; xor_solver.py: Brute-force only, no SMT; IC+freq is now primary; dynamic_sandbox.py: Real Unicorn sandbox | covered |

### C01: FORGE Audit Engine

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `ablation/core/aix_installp_decompressor.py` | 652 | AixInstallpDecompressor — IBM AIX installp BFF compression (steps 1–4); Test evidence (C01 — verified by source read 2026-10-24); doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/aix_installp_step4_multilevel.py` | 317 | AixInstallpStep4MultiLevel — multi-level escape decoder (hypothesis); doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/apk_parser.py` | 846 | APKParser — Android APK, AXML, and DEX parser; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/attck_tagger.py` | 829 | ATT&CK Tagger — MITRE ATT&CK technique tagging; doc-unit-mapping.json coverage for C01 modules | covered |
| `ablation/core/bff_extractor.py` | 188 | AixBffExtractor + XCOFF32Info; BffExtractor — AIX BFF archive parser; Test evidence (C01 — verified by source read 2026-10-24); doc-unit-mapping.json coverage for C01 modules *(also: A09)* | covered |
| `ablation/core/binary_parser.py` | 246 | BinaryParser — universal magic-byte format dispatch; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/bv41_decoder.py` | 285 | BV41Decoder — Apple Compression.framework chunked LZ4 decoder; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/bwt_eulerian_reconstructor.py` | 301 | BwtEulerianReconstructor — IBM multi-cycle BWT circuit reconstructor; doc-unit-mapping.json coverage for C01 modules | covered |
| `ablation/core/coff_m88k_parser.py` | 162 | CoffM88kParser — Motorola 88000 BCS COFF parser; doc-unit-mapping.json coverage for C01 modules | covered |
| `ablation/core/disasm_engine.py` | 952 | DisasmEngine — Capstone linear sweep disassembler; DisasmEngineX — angr CFG and cross-reference analysis; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/elf_parser.py` | 1366 | ELFParser — comprehensive pure-Python ELF32/64 parser; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/firmware_analyzer.py` | 518 | FirmwareAnalyzer — magic-byte scanning, entropy, credential extraction | covered |
| `ablation/core/guardian_pak_extractor.py` | 254 | GuardianPAKExtractor — Tandem NSK Guardian PAK archive extractor; Test evidence (C01 — verified by source read 2026-10-24); doc-unit-mapping.json coverage for C01 modules | covered |
| `ablation/core/macho_analyzer.py` | 261 | MachoAnalyzer — Mach-O 32/64 binary parser; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/pe_analyzer.py` | 139 | PEAnalyzer — legacy PE analyzer (STUB); doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/pe_parser.py` | 960 | 15. KernelDriverAnalyzer; KernelDriverAnalyzer; PEParser — full PE32/PE64 malware analysis parser; PEAnalyzer — legacy PE analyzer (STUB); doc-unit-mapping.json coverage for C01 modules *(also: A08)* | covered |
| `ablation/core/platform_detect.py` | 205 | PlatformDetector — HOST system capability detection; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/prose.py` | 184 | Prose — white-bronco documentation linter; doc-unit-mapping.json coverage for C01 modules | covered |
| `ablation/core/render.py` | 124 | Render — terminal color output primitives; doc-unit-mapping.json coverage for C01 modules | covered |
| `ablation/core/shellcode_utils.py` | 1646 | ShellcodeUtils — shellcode generation, ROP analysis, exploit helpers; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/swift_demangle.py` | 364 | SwiftDemangle — Swift symbol demangling; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/tls_analyzer.py` | 2770 | TLSAnalyzer — live TLS network probe and cipher analysis; doc-unit-mapping.json coverage for C01 modules; Summary of gaps and inaccuracies found | covered |
| `ablation/core/xcoff_parser.py` | 737 | 21. Xcoff32Decompiler; 22. XcoffSymtabParser; XCOFFParser — AIX XCOFF32/XCOFF64 parser; Test evidence (C01 — verified by source read 2026-10-24); doc-unit-mapping.json coverage for C01 modules *(also: A13)* | covered |
| `ablation/core/yara_generator.py` | 736 | YARAGenerator — YARA rule generation from findings; doc-unit-mapping.json coverage for C01 modules | covered |

### M01: Modules: Network/Cloud Enumeration

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `modules/docker_enum.py` | 1844 | CAP-01 — DockerEnumerator; CAP-02 — DockerEnumerator standalone functions (container isolation / image supply chain / K8s resource quota / dependency confusion / network policy / PSA / service account token / OPA / secrets / storage); Reference doc coverage summary; Gaps and anomalies | covered |
| `modules/forensics_enum.py` | 4219 | CAP-03 — forensics_enum: SEH / SSDT / DPC / PE analysis / Windows artifacts; Reference doc coverage summary; Gaps and anomalies; Module inventory (line counts) | covered |
| `modules/hyperflex_enum.py` | 1301 | CAP-04 — probe_hx_connect / HyperFlexEnumerator / standalone HX probes; Reference doc coverage summary; Module inventory (line counts) | covered |
| `modules/ios_enum.py` | 5105 | CAP-05 — IOSEnumerator / IOS standalone probes / ASA probes / L2 attack surface; Reference doc coverage summary; Gaps and anomalies; Module inventory (line counts) | covered |
| `modules/k8s_enum.py` | 5154 | CAP-06 — K8sEnumerator + standalone K8s probe functions; Reference doc coverage summary; Gaps and anomalies; Module inventory (line counts) | covered |
| `modules/lateral_movement.py` | 7817 | CAP-07 — LateralMovementEnumerator + NetworkDiscovery + CredentialHarvester + CloudMetadataProber + SSHKeyEnumerator + APITokenDetector + NTLMDetector + DatabaseProber + LateralMovementScanner + binary detectors + network live detectors; Reference doc coverage summary; Gaps and anomalies; Module inventory (line counts) | covered |
| `modules/net_sniffer.py` | 3423 | CAP-08 — RawSniffer / CredentialExtractor / MDNSDiscovery / SSDPDiscovery / probe_mqtt / scan_tcp_banner / icmp_host_discovery / detect_arp_spoofing / OS fingerprinting / web fingerprinting / industrial probes; Reference doc coverage summary; Module inventory (line counts) | covered |
| `modules/network_analyze.py` | 4234 | CAP-09 — NetworkAnalyzer / PCAPAnalyzer / ICMPScanner / WebDirBrute + messaging/streaming/infra probes; Reference doc coverage summary; Module inventory (line counts) | covered |
| `modules/nexus_dashboard_enum.py` | 1520 | CAP-10 — Nexus Dashboard / NX-OS / NXAPI / APIC / DCNM + CI/CD probes; Reference doc coverage summary; Gaps and anomalies; Module inventory (line counts) | covered |
| `modules/nxos_enum.py` | 1605 | CAP-11 — NXOSEnumerator + APIC API functions; Reference doc coverage summary; Module inventory (line counts) | covered |
| `modules/physmem_elf_vfs.py` | 730 | CAP-12 — PhysmemVFS / parse_proc_maps / ELF candidate recovery; Reference doc coverage summary; Gaps and anomalies; Module inventory (line counts) | covered |
| `modules/privesc_enum.py` | 4523 | CAP-13 — PrivescEnumerator + standalone privesc / Windows EoP / binary escalation detectors; Reference doc coverage summary; Module inventory (line counts) | covered |
| `modules/process_enum.py` | 3862 | CAP-14 — ProcessEnumerator + memory/binary/persistence detectors; Reference doc coverage summary; Module inventory (line counts) | covered |
| `modules/sip_enum.py` | 6004 | CAP-15 — SIPEnumerator + VoIP protocol probes; Reference doc coverage summary; Module inventory (line counts) | covered |
| `modules/streaming_enum.py` | 4214 | CAP-16 — Kafka / Flink / NiFi / Schema Registry / streaming infrastructure probes + DNS probes + observability/orchestration probes; Reference doc coverage summary; Gaps and anomalies; Module inventory (line counts) | covered |
| `modules/syscall_trace.py` | 2653 | CAP-17 — SyscallTracer + binary/live detectors; Reference doc coverage summary; Module inventory (line counts) | covered |
| `modules/windows_enum.py` | 784 | CAP-18 — WindowsEnumerator; Reference doc coverage summary; Gaps and anomalies; Module inventory (line counts) | covered |

### M02: Modules: Post-Exploitation

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `modules/agent_authority_audit.py` | 223 | Files in this unit; 1. AgentAuthorityAudit | covered |
| `modules/agent_observability_audit.py` | 172 | Files in this unit; 2. AgentObservabilityAudit | covered |
| `modules/agent_tool_surface_enumerator.py` | 155 | Files in this unit; 3. AgentToolSurfaceEnumerator | covered |
| `modules/ai_control_indicators.py` | 146 | Files in this unit; 4. AIControlIndicators; Docstring/code discrepancies found | covered |
| `modules/api_re.py` | 2985 | Files in this unit; 8. api_re (run_re); Two sub-themes, different integration paths; Module size asymmetry | covered |
| `modules/crypto_audit.py` | 4703 | Files in this unit; 7. CryptoAudit | covered |
| `modules/llm_behavior_security_probes.py` | 104 | Files in this unit; 11. LLM Behavior Security Probes (llm_behavior_security_probes.py); Docstring/code discrepancies found; Reference doc orphan candidates | covered |
| `modules/llm_enum.py` | 4506 | Files in this unit; 6. LLMEnumerator; Module size asymmetry | covered |
| `modules/mcp_grammar_fuzzer.py` | 294 | Files in this unit; 12. MCP Grammar Fuzzer (mcp_grammar_fuzzer.py); Reference doc orphan candidates; 11. LLM Behavior Security Probes (llm_behavior_security_probes.py) | covered |
| `modules/nginx_enum.py` | 2293 | Files in this unit; 9. NginxEnumerator (nginx_enum.py); Reference doc orphan candidates | covered |
| `modules/prompt_injection_sink_classifier.py` | 213 | Files in this unit; 5. PromptInjectionSinkClassifier | covered |
| `modules/proto_fsm.py` | 602 | Files in this unit; 13. MMTLS Protocol FSM Extractor (proto_fsm.py); Docstring/code discrepancies found; Reference doc orphan candidates | covered |
| `modules/tls_enum.py` | 2441 | Files in this unit; 10. TLS enumeration (tls_enum.py); Reference doc orphan candidates | covered |

### M03: Modules: Exploitation + Payloads

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `modules/_disasm_helper.py` | 61 | _disasm_helper.py (lines 1–50 approx); disasm_func() — shared capstone disassembly utility (internal infrastructure); loader_symbols() / loader_imports(); 42. _disasm_helper (Shared Disasm Helper) *(also: M04)* | covered |
| `modules/ami_cramfs_extractor.py` | 333 | ami_cramfs_extractor.py (lines 1–334); AmiCramFSExtractor | covered |
| `modules/arm64_global_tracker.py` | 464 | arm64_global_tracker.py (lines 1–465); arm64_global_tracker.scan() / report() / backward_sse(); Hardcoded WeChat binary constants (CRITICAL limitation for reuse); AmiCramFSExtractor | covered |
| `modules/arm_disasm.py` | 333 | arm_disasm.py (lines 1–334); ARMDisassembler; ARMSymbolicAnalyzer / VtableSlotAnalyzer; FORGE audit status (from reference docs) | covered |
| `modules/arm_symbolic.py` | 567 | arm_symbolic.py (lines 1–568); ARMSymbolicAnalyzer / VtableSlotAnalyzer; Stub inventory; ARMDisassembler | covered |
| `modules/bare_adapter.py` | 140 | bare_adapter.py (lines 1–141); findings_from_results() / run_bare() / rank_modules() / format_bare_output(); ARMSymbolicAnalyzer / VtableSlotAnalyzer | covered |
| `modules/bff_decompressor.py` | 205 | bff_decompressor.py (lines 1–206); BFFDecompressor.open() / detect() / entries(); Stub inventory; BFF _try_restore() return type bug | covered |
| `modules/callsite_tracer.py` | 323 | callsite_tracer.py (lines 1–324); backward_slice(); Hardcoded WeChat binary constants (CRITICAL limitation for reuse); FORGE audit status (from reference docs) | covered |
| `modules/cpp_vtable_reconstructor.py` | 960 | cpp_vtable_reconstructor.py (lines 1–961); CppVtableReconstructorAnalyzer; FORGE audit status (from reference docs); backward_slice() | covered |
| `modules/elf_vtable_reconstructor.py` | 319 | elf_vtable_reconstructor.py (lines 1–320); ELFVtableReconstructor; FORGE audit status (from reference docs); CppVtableReconstructorAnalyzer | covered |
| `modules/go_binary_re.py` | 1290 | go_binary_re.py (lines 1–1291); analyze() / parse_pclntab() / analyze_vmnetd() / vmnetd_send_cmd() / docker_socket_exec(); analyze_go_garble_binary() / find_pclntab() / find_garble_decrypt_stubs() / find_string_xrefs(); pclntab magic constant inconsistency (UNVERIFIED) | covered |
| `modules/go_dangerous_callers.py` | 923 | go_dangerous_callers.py (lines 1–924); GoDangerousCallerScanner; analyze() / parse_pclntab() / analyze_vmnetd() / vmnetd_send_cmd() / docker_socket_exec() | covered |
| `modules/go_garble_re.py` | 543 | analyze() / parse_pclntab() / analyze_vmnetd() / vmnetd_send_cmd() / docker_socket_exec(); go_garble_re.py (lines 1–544); analyze_go_garble_binary() / find_pclntab() / find_garble_decrypt_stubs() / find_string_xrefs(); pclntab magic constant inconsistency (UNVERIFIED) | covered |
| `modules/huawei_squashfs_extractor.py` | 569 | huawei_squashfs_extractor.py (lines 1–570); HuaweiSquashfsExtractor; analyze_go_garble_binary() / find_pclntab() / find_garble_decrypt_stubs() / find_string_xrefs() | covered |
| `modules/installer_binary_analyzer.py` | 388 | installer_binary_analyzer.py (lines 1–389); InstallerBinaryAnalyzer; Stub inventory; HuaweiSquashfsExtractor | covered |
| `modules/ioctl_attack_surface.py` | 623 | ioctl_attack_surface.py (lines 1–624); IoctlAttackSurfaceGenerator / IoctlAttackSurface / IoctlHandlerProfile / IoctlHandlerPattern; Stub inventory; find_field_writers() | covered |
| `modules/isa_8051.py` | 674 | isa_8051.py (lines 1–675); Mcs51Decoder / IntelHexLoader / Cc254xBankResolver / scan_aes_accesses() / scan_bank_switches(); Reference doc staleness: isa-8051.md; FORGE audit status (from reference docs) | covered |
| `modules/java_decompiler.py` | 1987 | java_decompiler.py (lines 1–1988); ClassFile / JavaAnalyzer / scan_java_artifacts() / report_java_findings() / detect_malicious_class_loader() / detect_java_deserialization_exploitation() / analyze_bytecode_flow() / scan_jar_for_vulnerabilities() / detect_java_runtime_exec_patterns() / analyze_spring_application_context() / detect_java_ssrf_patterns() / detect_java_xxe_patterns() / probe_spring_actuator_exposure() / probe_spring_actuator_exec() / probe_jvm_bytecode_download_surface() / probe_jvm_constant_pool_credential_exposure(); ConstantPool / parse_class_file() / parse_class_file_header() / scan_constant_pool_strings() / analyze_jar() / scan_java_artifacts() / synthesize_findings() / scan_classloader_gadgets() / scan_reflection_chains() / JavaREAnalyzer; Mcs51Decoder / IntelHexLoader / Cc254xBankResolver / scan_aes_accesses() / scan_bank_switches() | covered |
| `modules/java_re.py` | 3975 | java_re.py (lines 1–3976+); ConstantPool / parse_class_file() / parse_class_file_header() / scan_constant_pool_strings() / analyze_jar() / scan_java_artifacts() / synthesize_findings() / scan_classloader_gadgets() / scan_reflection_chains() / JavaREAnalyzer; ClassFile / JavaAnalyzer / scan_java_artifacts() / report_java_findings() / detect_malicious_class_loader() / detect_java_deserialization_exploitation() / analyze_bytecode_flow() / scan_jar_for_vulnerabilities() / detect_java_runtime_exec_patterns() / analyze_spring_application_context() / detect_java_ssrf_patterns() / detect_java_xxe_patterns() / probe_spring_actuator_exposure() / probe_spring_actuator_exec() / probe_jvm_bytecode_download_surface() / probe_jvm_constant_pool_credential_exposure() | covered |
| `modules/mpy_lifter.py` | 610 | mpy_lifter.py (lines 1–611); MpyLifter; ConstantPool / parse_class_file() / parse_class_file_header() / scan_constant_pool_strings() / analyze_jar() / scan_java_artifacts() / synthesize_findings() / scan_classloader_gadgets() / scan_reflection_chains() / JavaREAnalyzer | covered |
| `modules/path_solver.py` | 700 | path_solver.py (lines 1–701); PathSolver / solve_for_sink() / chain_depth_weight(); PathSolver status; MpyLifter | covered |
| `modules/ppc32_func_discovery.py` | 217 | ppc32_func_discovery.py; PPC32FuncDiscovery; FORGE audit status (from reference docs); PathSolver / solve_for_sink() / chain_depth_weight() | covered |
| `modules/ppc32_got2_resolver.py` | 801 | ppc32_got2_resolver.py; GOT2ResolvedCall / GOT2 resolver; FORGE audit status (from reference docs); PPC32FuncDiscovery | covered |
| `modules/ppc32_heap_slot_scanner.py` | 397 | ppc32_heap_slot_scanner.py; PPC32HeapSlotScanner; GOT2ResolvedCall / GOT2 resolver | covered |
| `modules/spu_disassembler.py` | 611 | spu_disassembler.py (lines 1–612); SPUDisassembler / decode_spu_word() / disassemble_spu_text() / extract_spu_text_from_elf() / dump_spu_elf() / frequency_report(); PPC32HeapSlotScanner | covered |
| `modules/sse_slicer.py` | 398 | sse_slicer.py (lines 1–399); SSE / backward_sse() / scan(); Hardcoded WeChat binary constants (CRITICAL limitation for reuse); SPUDisassembler / decode_spu_word() / disassemble_spu_text() / extract_spu_text_from_elf() / dump_spu_elf() / frequency_report() | covered |
| `modules/video_container.py` | 967 | video_container.py; VideoContainerAnalyzer; SSE / backward_sse() / scan() | covered |
| `modules/xcoff_executable_analyzer.py` | 135 | xcoff_executable_analyzer.py; XCOFFExecutableAnalyzer; VideoContainerAnalyzer | covered |
| `modules/xcoff_loader_symbols.py` | 289 | xcoff_loader_symbols.py; loader_symbols() / loader_imports(); XCOFFExecutableAnalyzer | covered |

### M04: Modules: Cisco + IoT Platform

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `modules/anti_analysis_string_detector.py` | 144 | 41. AntiAnalysisStringDetector | covered |
| `modules/attack_labeler.py` | 141 | 36. ATTACKLabeler | covered |
| `modules/build_provenance_extractor.py` | 213 | 6. BuildProvenanceExtractor | covered |
| `modules/can_dbc_parser.py` | 327 | 31. CanDbcParser | covered |
| `modules/chunk_walker_validator.py` | 376 | 2. ChunkWalkerValidator | covered |
| `modules/cve_byte_patterns.py` | 286 | 4. CVEBytePatterns / CVEScanner | covered |
| `modules/dead_security_check_scanner.py` | 205 | 22. DeadSecurityCheckScanner | covered |
| `modules/deep_jni_analysis.py` | 246 | 35. deep_jni_analysis (Deep JNI Structural Analyzer — HiJoy PTT) | covered |
| `modules/dependency_confusion_scanner.py` | 179 | 7. DependencyConfusionScanner | covered |
| `modules/deprecated_crypto_scanner.py` | 203 | 23. DeprecatedCryptoScanner | covered |
| `modules/elf_anomaly_scanner.py` | 157 | 28. ELFAnomalyScanner | covered |
| `modules/entropy_analyzer.py` | 173 | 29. EntropyAnalyzer | covered |
| `modules/firmware_auth_bypass_detector.py` | 333 | 25. FirmwareAuthBypassDetector | covered |
| `modules/firmware_pki_checker.py` | 172 | 26. FirmwarePKIChecker | covered |
| `modules/hardcoded_credential_scanner.py` | 177 | 24. HardcodedCredentialScanner | covered |
| `modules/hardware_root_finder.py` | 321 | 27. HardwareRootFinder | covered |
| `modules/heap_uaf_scanner.py` | 414 | 1. HeapUAFScanner | covered |
| `modules/lethal_trifecta_scanner.py` | 171 | 9. LethalTrifectaScanner | covered |
| `modules/libfunc_db.py` | 615 | 39. LibFuncDB (libfunc_db.py); 38. version_delta_finetune (Cross-Version Embedding Fine-tuning) | covered |
| `modules/metachar_filter_bypass_scanner.py` | 214 | 19. MetacharFilterBypassScanner | covered |
| `modules/mips_analyzer.py` | 699 | 33. MIPS32TaintTracker + MIPS32FuncProfiler | covered |
| `modules/non_constant_time_comparator_scanner.py` | 205 | 10. NonConstantTimeComparatorScanner | covered |
| `modules/obfuscated_string_decoder.py` | 244 | 40. ObfuscatedStringDecoder | covered |
| `modules/policy_engine_absence_detector.py` | 233 | 15. PolicyEngineAbsenceDetector | covered |
| `modules/process_injection_combo_scanner.py` | 160 | 18. ProcessInjectionComboScanner | covered |
| `modules/sbom_extractor.py` | 240 | 8. SBOMExtractor | covered |
| `modules/setuid_auth_oracle_scanner.py` | 313 | 3. SetuidAuthOracleScanner | covered |
| `modules/signal_handler_race_scanner.py` | 268 | 16. SignalHandlerRaceScanner | covered |
| `modules/signed_length_arg_scanner.py` | 229 | 12. SignedLengthArgScanner | covered |
| `modules/sizeof_ptr_detector.py` | 199 | 14. SizeofPtrDetector | covered |
| `modules/structural_sim.py` | 343 | 37. StructuralSim (structural_sim.py); 36. ATTACKLabeler | covered |
| `modules/third_party_library_identifier.py` | 260 | 21. ThirdPartyLibraryIdentifier | covered |
| `modules/toctou_scanner.py` | 222 | 17. TOCTOUScanner | covered |
| `modules/truncation_at_sink_scanner.py` | 228 | 13. TruncationAtSinkScanner | covered |
| `modules/uninitialized_var_path_scanner.py` | 303 | 20. UninitializedVarPathScanner | covered |
| `modules/version_delta_finetune.py` | 220 | 38. version_delta_finetune (Cross-Version Embedding Fine-tuning) | covered |
| `modules/vxworks_archive_scanner.py` | 302 | 30. VxWorksArchiveScanner | covered |
| `modules/weak_prng_at_security_sink_scanner.py` | 207 | 11. WeakPRNGAtSecuritySinkScanner | covered |

### S01: Sweep Drivers

| File | Lines | Capabilities | Status |
|------|-------|-------------|--------|
| `sweeps/android_sweep.py` | 341 | android_sweep.py; SWEEP: android_sweep; Cross-cutting observations | covered |
| `sweeps/base_sweep.py` | 388 | base_sweep.py; report_generator.py; WORKFLOW: Vulnerability Hunting; SWEEP: base_sweep | covered |
| `sweeps/corpus_miner.py` | 491 | corpus_miner.py; WORKFLOW: Source Code Audit; SWEEP: corpus_miner; Cross-cutting observations | covered |
| `sweeps/fortinet_sweep.py` | 714 | base_sweep.py; fortinet_sweep.py; pe_sweep.py; report_generator.py | covered |
| `sweeps/pe_sweep.py` | 1002 | pe_sweep.py; win16_ne_sweep.py; SWEEP: pe_sweep; Cross-cutting observations | covered |
| `sweeps/report_generator.py` | 225 | report_generator.py; SWEEP: report_generator | covered |
| `sweeps/ti_sweep.py` | 854 | Reference doc status (A10); ti_sweep.py; SWEEP: ti_sweep; Cross-cutting observations *(also: A10)* | covered |
| `sweeps/win16_le_vxd_sweep.py` | 911 | win16_le_vxd_sweep.py; win16_ne_sweep.py; SWEEP: win16_le_vxd_sweep | covered |
| `sweeps/win16_mz_dos_sweep.py` | 390 | win16_mz_dos_sweep.py; SWEEP: win16_mz_dos_sweep; Cross-cutting observations | covered |
| `sweeps/win16_ne_sweep.py` | 1036 | win16_ne_sweep.py; SWEEP: win16_ne_sweep | covered |

---

## 4. Unmapped Files

6 file(s) not mentioned in any unit notes:

| File | Lines | Classification | Suggested Unit |
|------|-------|---------------|----------------|
| `ablation/analyzers/loongarch_decoder_v2.py` | 348 | genuine gap — KASAN/KCOV-aware LoongArch64 decoder undocumented | A03 |
| `ablation/cli.py` | 1317 | genuine gap — CLI entry point undocumented | A04 or A12 |
| `ablation/export/json_export.py` | 66 | genuine gap — export module undocumented | A14 |
| `ablation/export/sarif.py` | 202 | genuine gap — export module undocumented | A14 |
| `ablation/integrations/binja_plugin.py` | 221 | genuine gap — Binary Ninja plugin undocumented | A14 |
| `docs/demo_curl.py` | 126 | example/demo script | S01 (example only) |

### Notes on unmapped files

**`ablation/analyzers/loongarch_decoder_v2.py`** (348 lines, code-ablation)
: genuine gap — KASAN/KCOV-aware LoongArch64 decoder undocumented. Suggested unit: A03.

**`ablation/cli.py`** (1317 lines, code-ablation)
: genuine gap — CLI entry point undocumented. Suggested unit: A04 or A12.

**`ablation/export/json_export.py`** (66 lines, code-ablation)
: genuine gap — export module undocumented. Suggested unit: A14.

**`ablation/export/sarif.py`** (202 lines, code-ablation)
: genuine gap — export module undocumented. Suggested unit: A14.

**`ablation/integrations/binja_plugin.py`** (221 lines, code-ablation)
: genuine gap — Binary Ninja plugin undocumented. Suggested unit: A14.

**`docs/demo_curl.py`** (126 lines, code-other)
: example/demo script. Suggested unit: S01 (example only).

---

## 5. Coverage by File Type

| Type | Total | Covered | % |
|------|-------|---------|---|
| code-ablation | 293 | 288 | 98% |
| code-modules | 102 | 102 | 100% |
| code-other | 1 | 0 | 0% |
| code-sweep | 11 | 11 | 100% |
