# Ablation Capability Support Matrix

**Version:** 2.86.0
**Audit date:** 2026-10-24
**Source notes:** A02–A07, A10 (primary); A01, C01, M01–M04, S01 (supplementary)

**Legend:** ✓ full | ~ partial (see footnote) | ✗ none

---

## Matrix 1 — ISA × Analysis Capabilities

Columns:
- **insn_model** — `insn_*.py` typed-operand instruction model
- **isa_model** — `isa_*.py` ABI/mnemonic classification model
- **CFG** — `cfg_*.py` basic-block CFG builder
- **analysis_engine** — `analysis_*.py` BFS worklist fixpoint engine
- **lifter/decompiler** — `*_lifter.py` / `*_decompiler.py` (multi-arch `binary_lifter.py` counts for ISA tier)
- **taint** — `taint_tracker_*.py` binary-path or labeled tracker
- **SAC** — `sink_arg_classifier_*.py` exec-sink argument classifier
- **vuln_scanners** — dedicated vulnerability scanner for this ISA

### Full tier

| ISA | insn_model | isa_model | CFG | analysis_engine | lifter/decompiler | taint | SAC | vuln_scanners |
|:----|:----------:|:---------:|:---:|:---------------:|:-----------------:|:-----:|:---:|:-------------:|
| **x86-64** | ✓ | ✓ | ✓ | ✓ | ✓ [¹] | ✓ [²] | ✓ | ✓ [³] |
| **AArch64** | ✓ | ✓ | ✓ | ✓ [⁴] | ✓ [¹] | ✓ [⁵] | ✗ [⁶] | ~ [⁷] |

### Structural tier

| ISA | insn_model | isa_model | CFG | analysis_engine | lifter/decompiler | taint | SAC | vuln_scanners |
|:----|:----------:|:---------:|:---:|:---------------:|:-----------------:|:-----:|:---:|:-------------:|
| **x86-32 / i386** | ✓ [⁸] | ✓ [⁸] | ✓ [⁸] | ✓ [⁸] | ✓ [¹] | ✓ [⁹] | ✓ [¹⁰] | ~ [¹¹] |
| **ARM32 / Thumb** | ✓ | ✓ | ✓ | ✓ | ✓ [¹] | ✓ [¹²] | ✓ | ~ [¹³] |
| **MIPS32** | ✓ | ✓ | ✓ | ✓ | ✓ [¹] | ✓ [¹⁴] | ✓ [¹⁵] | ✗ |
| **MIPS64** | ✓ [¹⁶] | ✓ [¹⁶] | ✓ [¹⁶] | ✓ [¹⁶] | ✓ [¹] | ✓ [¹⁷] | ~ [¹⁸] | ✗ |
| **nanoMIPS** | ✗ [¹⁹] | ✗ | ✗ | ✗ | ✓ [¹] | ~ [²⁰] | ✗ | ✗ |
| **PPC32** | ✓ | ✓ | ✓ | ✓ | ✓ [²¹] | ✓ | ✓ | ~ [²²] |
| **PPC64** | ✓ [¹⁶] | ✓ [¹⁶] | ✓ [¹⁶] | ✓ [¹⁶] | ✓ [¹] | ✓ [²³] | ✓ [²⁴] | ~ [²⁵] |
| **RISC-V 32** | ✓ | ✓ | ✓ | ✓ | ✓ [¹] | ✓ [²⁶] | ✗ [⁶] | ✗ |
| **RISC-V 64** | ✓ [¹⁶] | ✓ [¹⁶] | ✓ [¹⁶] | ✓ [¹⁶] | ✓ [¹] | ✓ [²⁶] | ✗ [⁶] | ✗ |
| **LoongArch64** | ✓ [²⁷] | ✓ | ✓ | ✓ [⁴] | ✓ [¹] | ✓ | ✗ | ~ [²⁸] |
| **SH-2A** | ✗ [²⁹] | ✗ | ✓ [³⁰] | ✗ [³¹] | ✓ [¹] | ✗ | ✗ | ✗ |

### Tool-dependent tier

| ISA | insn_model | isa_model | CFG | analysis_engine | lifter/decompiler | taint | SAC | vuln_scanners |
|:----|:----------:|:---------:|:---:|:---------------:|:-----------------:|:-----:|:---:|:-------------:|
| **ARC EM/HS** | ✓ [³²] | ✓ | ✓ | ✓ | ✓ [¹] | ✓ [³³] | ✗ | ✗ |
| **V850 / RH850** | ✓ | ✓ | ✓ | ✓ [³⁴] | ✓ [¹] | ✓ [³⁵] | ✗ | ✗ |

### ECU / embedded (decoder-based; no standard insn/isa pipeline)

| ISA | insn_model | isa_model | CFG | analysis_engine | lifter/decompiler | taint | SAC | vuln_scanners |
|:----|:----------:|:---------:|:---:|:---------------:|:-----------------:|:-----:|:---:|:-------------:|
| **TriCore TC1.6x** | ✗ [³⁶] | ✗ | ✗ [³⁷] | ✗ | ✗ | ✓ [³⁸] | ✗ | ~ [³⁹] |
| **M68K / CPU32** | ~ [⁴⁰] | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ [⁴¹] |
| **M88K (MC88100)** | ~ [⁴²] | ✓ | ✗ [⁴³] | ✗ | ✗ | ✗ | ✗ | ✗ |
| **PPC VLE** | ~ [⁴⁴] | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ [⁴¹] |
| **C166 / C167** | ~ [⁴⁴] | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| **TMS320C28x** | ~ [⁴⁴] | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ [⁴⁵] |
| **PPC476 Book E** | ✗ | ✗ | ✗ | ✗ | ✓ [⁴⁶] | ✗ | ✗ | ✗ |

### Other (SAC-only or decode-only)

| ISA | insn_model | isa_model | CFG | analysis_engine | lifter/decompiler | taint | SAC | vuln_scanners |
|:----|:----------:|:---------:|:---:|:---------------:|:-----------------:|:-----:|:---:|:-------------:|
| **s390 / s390x** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ [⁴⁷] | ✗ |

### Footnotes — Matrix 1

[¹] `binary_lifter.py` multi-arch BinaryLifter. Full tier (x86-64, AArch64) = NativeVal state machine + taint annotations. Structural tier = `_walk_ablation_cfg` BFS + calling-convention seeds. PPC32 also has dedicated `ppc32_lifter.py`.

[²] Six x86-64 taint files: `taint_tracker.py` (legacy intraprocedural, no classmethods, no built-in sources), `taint_tracker_x86.py` (full interprocedural MFP, 17 sources, ~35 sinks, naming collision with legacy), `taint_tracker_x86_labeled.py` (labeled/bounded stream), `bss_taint_tracker.py` (BSS-range-walker pattern), `tainted_string_tracker.py` (snprintf-rodata upgrade), `windows_pool_taint_tracker.py` (Windows kernel pool, PE x64).

[³] x86-64 dedicated scanners: `byovd_detector`, `sanitizer_detector`, `priv_drop_before_exec`, `pthread_once_detector`, `sink_sanitizer_filter`, `argv_build_to_sink`, `static_link_sink_scanner`, `pe_sink_classifier`, `format_string_scanner`, `heap_vuln_scanner`, `length_underflow_scanner`, `go_subprocess_scanner`, ~35 total across analyzers/ and modules/.

[⁴] `analysis_arm64.py` and `analysis_loongarch64.py` have no `policy` override — sink configuration is fixed. All other Structural-tier engines expose `policy=`.

[⁵] `taint_tracker_arm64.py` has labeled/bounded taint via inner `TaintEngine`. W-register writes zero-extend (bound=0xFFFFFFFF). Constructors: `from_path()`, `from_path_full()`, `from_path_ko()`, `from_context()`. Interprocedural depth=4 BFS.

[⁶] Confirmed gap per A07: no `SinkArgClassifierARM64` and no `SinkArgClassifierRISCV` exist.

[⁷] AArch64 dedicated scanners: `arm64_global_tracker` (modules/), `arm32_reg_annotator`, `arm64_fgets_fd_discriminator`.

[⁸] x86-32 shares `insn_x86.py` (Mode.X86), `isa_x86.py`, `cfg_x86.py`, `analysis_x86.py` with x86-64 via mode parameter.

[⁹] Two x86-32 taint trackers: `taint_tracker_x86_32.py` (`X86_32TaintTracker`, CDECL32, interprocedural, 17 sources, `from_context()`) and `taint_tracker_i386.py` (`TaintTrackerI386`, intraprocedural, no classmethods — legacy).

[¹⁰] Two x86-32 SAC files: `sink_arg_classifier_i386.py` (forward single-pass reg_state) and `sink_arg_classifier_x86_32.py` (backward push-backtrack). Both dispatch from `SinkArgClassifier.from_context()`.

[¹¹] x86-32 vuln scanners: `static_link_sink_scanner` (system() UNKNOWN-STATIC), `argv_build_to_sink` (x86 mode), `pe_sink_classifier` (PE32 IAT scan).

[¹²] ARM32 taint: `taint_tracker_arm32.py` (interprocedural, `from_context()`) + `taint_tracker_arm32_labeled.py` (labeled/bounded stream, VFP lane model, Mode.ARM/THUMB).

[¹³] ARM32 dedicated scanners: `intoverflow_scanner_arm32`, `arm32_function_scanner`, `arm32_reg_annotator`.

[¹⁴] MIPS32 taint: `taint_tracker_mips.py` (O32 ABI, `from_path()` only — no `from_context()`; use `endian='big'` for enterprise targets; delay slots consumed) + `taint_tracker_mips_labeled.py` (stream, Mode.MIPS32).

[¹⁵] `sink_arg_classifier_mips.py` covers MIPS O32 and N32 (via `EF_MIPS_ABI2` flag). MIPS64 N64 ABI is not covered by SAC.

[¹⁶] Shared files: MIPS32/64 share `insn_mips.py`/`isa_mips.py`/`cfg_mips.py`/`analysis_mips.py` via mode param. PPC32/64 share via Mode.PPC32/PPC64. RISC-V 32/64 share via Width.RV32/RV64.

[¹⁷] MIPS64 taint: `taint_tracker_mips64.py` (N64 ABI, default big-endian, `from_context()` present; DADD/DADDU/64-bit shifts; MFHI/MFLO conservatively clears taint) + `taint_tracker_mips_labeled.py` (Mode.MIPS64).

[¹⁸] `sink_arg_classifier_mips.py` handles N32 via `EF_MIPS_ABI2` but not N64 ABI ($4–$11 arg regs). MIPS64 N64 SAC = partial.

[¹⁹] nanoMIPS has no `insn_nanomips.py`/`isa_nanomips.py`. `nanomips_decoder.py` provides frame-boundary walking only. No CFG builder exists.

[²⁰] `taint_tracker_nanomips.py` (`NanoMIPSTaintTracker`): full decode requires Capstone 6.x. Capstone 5.x falls back to conservative mode (all $a0–$a3 tainted after any source call). No `from_context()`. P48 instructions not taint-tracked.

[²¹] PPC32 lifters: `binary_lifter.py` (Structural) + dedicated `ppc32_lifter.py` (GOT2 PIC resolver). `ppc476_lifter.py` and `ppc476_decompiler.py` are for PPC476 Book E ECU variant.

[²²] PPC32 vuln scanners: `ppc32_heap_slot_scanner` (modules/), `static_link_sink_scanner` (system() UNKNOWN-STATIC).

[²³] PPC64 taint: `taint_tracker_ppc64.py` (boolean `Dict[str,bool]`, NOT labeled — `ppc64-taint-analysis.md` incorrectly claims labeled model) + `taint_tracker_ppc_labeled.py` (labeled/bounded stream, the correct labeled PPC tracker; no reference doc).

[²⁴] PPC64 SAC: `sink_arg_classifier_ppc64.py` (ELFv2 generic LE/BE), `sink_arg_classifier_ppc64_elfv1.py` (BE ELFv1 IBM POWER), `sink_arg_classifier_ppc64_elfv2.py` (LE ELFv2 + Power10 stub support + callee-saved reg propagation).

[²⁵] PPC64 vuln scanners: `ppc64_be_call_scanner`, `ppc64_dynds_classifier`, `ppc64_vmx_density`, `static_link_sink_scanner` (UNKNOWN-STATIC).

[²⁶] RISC-V taint: `taint_tracker_riscv32.py` (RV32GC, `from_context()`, HiSilicon ext via `ext_decoder`), `taint_tracker_riscv64.py` (RV64GC, `from_context()`), `taint_tracker_riscv.py` (`TaintEngine`, labeled/bounded stream). All require Capstone 5.x+.

[²⁷] `insn_loongarch64.py` has no `Mem` type — load/store ops kept as flat `[Reg, Reg, Imm]`. No text backends (objdump/listing). `loongarch_decoder.py` required.

[²⁸] LoongArch64 vuln scanners: `loongarch64_max_not_min_scanner`, `la64_heap_vuln_scanner`.

[²⁹] No `insn_sh2a.py`. Decoding via `ecu_sh2a_decoder.py` (pure-Python; Capstone 5.0.7 has no SH-2A support).

[³⁰] `cfg_sh2a.py` adds `.flow`/`.flow_r()` for `dataflow_engine.DomTree`/`LoopInfo`. Only CFG module with this interface.

[³¹] No `analysis_sh2a.py`. SH-2A dataflow uses `dataflow_engine.py` directly (DataflowEngine, ConstPropAnalysis, SCCPAnalysis) — not the `analyze_cfg()` fixpoint pattern.

[³²] `insn_arc.py` has text backends only (GNU objdump, hand listing). No Capstone ARC in CS5. `arc_decoder.py` requires GNU cross-toolchain (Tool-dependent tier).

[³³] ARC taint: `taint_tracker_arc.py` (uses pure-Python `ARCDecoder`, partial DSP/EM coverage, `from_context()`) + `taint_tracker_arc_labeled.py` (stream, BMSK bounds, BLINK RA tracking, ENTER/LEAVE code-density).

[³⁴] V850/RH850 `analysis_v850.py` has no `policy` override. Uses `TaintEngine(variant)`.

[³⁵] V850/RH850 taint: `taint_tracker_v850.py` (labeled `Taint(labels,bound)`, flat ROM via `from_bytes()`) + `taint_tracker_rh850.py` (extends V850TaintTracker; GHS CC-RH ABI; `double_is_32bit` flag).

[³⁶] TriCore has no `insn_tricore.py`/`isa_tricore.py`. `taint_tracker_tricore.py` uses Capstone CS_ARCH_TRICORE internally.

[³⁷] `epilogue_share_scanner.py` is TriCore-only (CS_ARCH_TRICORE) — a CFG accuracy helper, not a full CFG builder.

[³⁸] `taint_tracker_tricore.py` (`TriCoreTaintTracker`): FCALL/FRET leaf-function convention; D[]/A[] register duality; `from_bytes()` for flat ECU ROM.

[³⁹] TriCore vuln scanners: `ecu_rom_layout_analyzer.py` (CODE/CALIBRATION discrimination via Capstone decode density); `epilogue_share_scanner.py` (phantom-entry CFG correction).

[⁴⁰] `ecu_m68k_decoder.py` uses Capstone CS_ARCH_M68K/CS_MODE_M68K_020. `function_starts()` is pure-Python (LINK.W A6 + MOVEM.L). Not a standard `insn_*.py` typed-operand model.

[⁴¹] `ecu_security_access_scanner.py` covers M68K/CPU32 (GM P-series), PPC32 (GM E38), and PPC VLE (GM E92 NXP e200z) — UDS/KWP2000 static-seed SecurityAccess. Does NOT cover TriCore or SH-2A.

[⁴²] `insn_m88k.py` (`M88kInsn`) uses plain `op_str` string — not typed `Reg`/`Imm`/`Mem`. Only module without typed operands. Triadic ops (0x3A–0x3C) partially decoded (placeholder mnemonics).

[⁴³] No `cfg_m88k.py`. `insn_m88k.py` provides `function_starts()` (BSR/BSR.N harvest) and `string_refs()` (ORU+OR 32-bit constant loads).

[⁴⁴] ECU decoder exists (`ecu_vle_decoder.py`, `ecu_c166_decoder.py`, `ecu_c28x_decoder.py`) — specialized decoders providing `disassemble()` and `function_starts()`, not standard `insn_*.py` typed-operand models.

[⁴⁵] `ti_nnc_scanner.py` detects TVM-generated `tvmgen_*` symbols and weak/C_UEXT override risk. Covers C28x via `TiCoffLoader` and ARM Cortex-M/R/C29x via LIEF.

[⁴⁶] PPC476 Book E: `ppc476_lifter.py` + `ppc476_decompiler.py` exist. No `insn_ppc476.py` or `isa_ppc476.py`.

[⁴⁷] `sink_arg_classifier_s390.py` covers s390 31-bit and s390x 64-bit. `R_390_JMP_SLOT` PLT layout. Stripped fallback via `_raw_brasl_scan()` BRASL byte sweep. Use `from_path()` — BinaryContext misidentifies s390 as x86_64 (plt=0).

---

## Matrix 2 — Binary Format × Capabilities

Columns: **parse** = format recognized and structurally parsed; **extract** = embedded files/sections extracted; **disassemble** = instruction-level output produced; **analyze** = taint/CFG/sink analysis runs on contents

| Format | parse | extract | disassemble | analyze | Key modules |
|:-------|:-----:|:-------:|:-----------:|:-------:|:------------|
| **ELF32** | ✓ | ✓ | ✓ | ✓ | `BinaryContext` core; all ISA taint trackers |
| **ELF64** | ✓ | ✓ | ✓ | ✓ | `BinaryContext` core; all ISA taint trackers |
| **PE32** | ✓ | ✓ | ~ [a] | ~ [b] | `pe_sink_classifier`, LIEF, `windows_pool_taint_tracker` (x64 only) |
| **PE64** | ✓ | ✓ | ~ [a] | ✓ | `pe_sink_classifier`, `windows_pool_taint_tracker`, `byovd_detector` |
| **Mach-O** | ~ [c] | ✗ | ✗ | ✗ | `binary_context.py` magic detection only |
| **XCOFF32** | ✓ | ✓ | ✓ | ~ [d] | `BinaryContext.build_xcoff()`, `xcoff_symtab_parser`, `xcoff32_decompiler` |
| **XCOFF64** | ✓ | ✓ | ~ [e] | ~ [d] | `BinaryContext.build_xcoff()`, `xcoff_executable_analyzer` (modules/) |
| **COFF-M88K** | ✓ | ✓ | ✓ | ~ [f] | `core/coff_m88k_parser`, `insn_m88k`, `isa_m88k` |
| **NE (Win16)** | ✓ | ✓ | ✗ | ~ [g] | `ne_format_parser.py`, `win16_ne_sweep.py` |
| **LE/VxD** | ✓ | ✗ | ✗ | ~ [g] | `win16_le_vxd_sweep.py`; VMM service resolution |
| **MZ/DOS** | ✓ | ✗ | ✗ | ~ [g] | `win16_mz_dos_sweep.py`; heuristic scoring |
| **APK/DEX** | ✓ | ✓ | ✓ | ~ [h] | `dex_disasm`, `dex_analyzer`, `dex_lifter`, `java_jar_scanner` |
| **ArkTS ABC** | ✓ | ✓ | ✓ | ~ [h] | `abc_parser`, `abc_disasm`, `abc_decompiler` |
| **JAR/class** | ✓ | ✓ | ~ | ~ [h] | `java_jar_scanner`, `java_decompiler` (modules/) |
| **BFF+AIX-installp** | ✓ | ✓ | ✗ | ✓ [i] | `aix_bff_extractor`, `aix_big_ar_extractor`, `aix_type0f_stream_splitter` |
| **CRAMFS** | ✓ | ✓ | ✗ | ✗ | `ami_cramfs_extractor` (modules/) |
| **SquashFS** | ✓ | ✓ | ✗ | ✗ | `huawei_squashfs_extractor` (modules/) |
| **FortiOS-firmware** | ✓ | ✓ | ✗ | ✓ [j] | `fortios_firmware_extractor`, `firmware_container` |
| **VMDK (FortiMail)** | ✓ | ✓ | ✗ | ✓ [j] | `fortimail_vmdk_extractor` |
| **Guardian-PAK** | ✓ | ✓ | ✗ | ✗ | `core/guardian_pak_extractor` |
| **BV41 (APFS)** | ✓ | ✓ | ✗ | ✗ | `core/bv41_decoder`; requires lz4 |
| **PEF-MacPPC** | ✓ | ✓ | ~ | ✓ [k] | `pef_binary_analyzer`, `pef_abi_clobber_scanner` |
| **PS3-SELF** | ✓ | ~ [l] | ✗ | ~ [m] | `ps3_self_decryptor`, `ps3_opd_vtable_scanner` |
| **TI-COFF** | ✓ | ✓ | ✗ | ~ [n] | `ti_coff_loader`, `ti_nnc_scanner` |
| **MicroPython-.mpy** | ✓ | ~ | ~ | ✗ | `mpy_lifter` (modules/); v6 only |
| **VxWorks-archive** | ✓ | ✓ | ✗ | ✗ | `vxworks_archive_scanner` (modules/); PPC32 BE confirmed |
| **Erlang BEAM** | ✓ | ✗ | ✓ | ~ [o] | `beam_context.py`, `BEAMLifter`; module-level summary; no taint |
| **AR archive** | ✓ | ✓ | ✗ | ✓ [p] | `ar_archive_scanner`, `aix_big_ar_extractor` |
| **Flat ROM** | ✓ | ✗ | ~ | ✓ [q] | `ecu_arch_detector`, `ecu_rom_layout_analyzer`, `flat_binary_func_start_scanner` |

### Footnotes — Matrix 2

[a] PE disassembly uses the x86-32/x86-64 ISA stack after LIEF parse. No dedicated PE disassembler; instructions decoded on demand at targeted VAs.

[b] PE32 analysis: `pe_sink_classifier` covers IAT-based exec-sink classification. Full taint (`windows_pool_taint_tracker`) is PE64 only.

[c] Mach-O magic bytes (0xCEFAEDFE / 0xCFFAEDFE / fat 0xCAFEBABE) detected in `binary_context.py` early-rejection table. No Mach-O parser or analyzer implemented.

[d] XCOFF analyze: `xcoff32_decompiler.py` provides XCOFF32 pseudo-C. `xcoff_executable_analyzer` (modules/) and `xcoff_loader_symbols` (modules/) extend coverage. No taint tracker for XCOFF content.

[e] XCOFF64 disassembly: `xcoff_executable_analyzer` (modules/) may handle; confirmed for XCOFF32 only via `xcoff32_decompiler.py`.

[f] COFF-M88K analyze: `M88kDecoder.function_starts()` (BSR/BSR.N scan) + `string_refs()` (ORU+OR 32-bit constant loads). No taint/CFG/analysis engine. Triadic ops (0x3A–0x3C) partially decoded.

[g] Win16 NE/LE/MZ formats: sweep drivers exist (`win16_ne_sweep.py`, `win16_le_vxd_sweep.py`, `win16_mz_dos_sweep.py`) providing heuristic scoring. LE/VxD has VMM service resolution (100+ entries). No taint analysis.

[h] DEX/ArkTS/Java: lifters produce pseudo-code. No taint tracker for JVM/Dalvik/ARK bytecode ISAs.

[i] BFF extraction leads to XCOFF32/XCOFF64 which then uses the XCOFF analysis path.

[j] FortiOS/VMDK: extraction produces ELF binaries; full ELF analysis pipeline runs downstream.

[k] PEF-MacPPC: `pef_binary_analyzer.py` parses Classic Mac PEF for PPC. `pef_abi_clobber_scanner.py` detects ABI clobber patterns. No taint tracker for PEF-wrapped code.

[l] PS3 SELF extraction: `ps3_self_decryptor.py` handles SELF→ELF decryption. `binary_context.py` notes PS3 SELF→ELF case where shstrtab may be zeroed.

[m] PS3 SELF analysis: `ps3_opd_vtable_scanner.py` handles Cell BE vtable via .opd (PPC64 function-descriptor pattern). `spu_disassembler.py` (modules/) covers SPU code.

[n] TI-COFF: `ti_coff_loader.py` extracts symbols (C_UEXT weak-symbol equivalents). `ti_nnc_scanner.py` detects TVM override risk. Instruction decode for C28x uses `ecu_c28x_decoder.py` from raw bytes, not TI COFF parsing.

[o] BEAM analyze: `BeamContext` provides module-level summary (no VA space). `BEAMLifter` produces pseudo-C. Sweep driver `sweep_beam_dir()` with obfuscation detection. Architecture tier = Module summary (no taint, no CFG).

[p] AR archive: `ar_archive_scanner.py` + `aix_big_ar_extractor.py` extract member ELFs which are then analyzed via the full ELF pipeline.

[q] Flat ROM: `ecu_arch_detector` identifies ISA (8 discriminators: arm_cm, tricore, m68k, ppc32, ppc_vle, sh2a, m32r, c166). `ecu_rom_layout_analyzer` segments into CODE/CALIBRATION/ERASED regions. `flat_binary_func_start_scanner` finds function entries. ISAs with `from_bytes()` taint support: V850, RH850, TriCore.

---

## Matrix 3 — Taint Tracker Detail

**Total: 24 files in `ablation/analyzers/`, 0 in `modules/`**

| # | architecture | file | location | status | key_limitations |
|:--|:-------------|:-----|:---------|:-------|:----------------|
| 1 | x86-64 (legacy base) | `taint_tracker.py` | analyzers/ | implemented | intraprocedural only; no built-in sources; no `from_path()`/`from_context()`; superseded by #2; naming collision |
| 2 | x86-64 (full interprocedural) | `taint_tracker_x86.py` | analyzers/ | implemented | interprocedural depth=4; 17 sources; ~35 sinks; direct constructor (no `from_context()`); naming collision with #1 |
| 3 | x86-64 (labeled/stream) | `taint_tracker_x86_labeled.py` | analyzers/ | implemented | stream-based only; labeled bounds; Mode.X64/X86; `from_listing()`/`from_objdump()`/`from_capstone()` input |
| 4 | x86-32 / i386 (production) | `taint_tracker_x86_32.py` | analyzers/ | implemented | CDECL32 only; `from_context()` present; PIC and non-PIC PLT stubs; 17 sources; confirmed on Acronis True Image 2018 |
| 5 | i386 (legacy/simple) | `taint_tracker_i386.py` | analyzers/ | implemented | intraprocedural only; no `from_path()`/`from_context()`; non-PIE base auto-detection; no identified test file |
| 6 | AArch64 | `taint_tracker_arm64.py` | analyzers/ | implemented | labeled/bounded via inner `TaintEngine`; no policy override; `from_path()`, `from_path_full()`, `from_path_ko()`, `from_context()`; interprocedural depth=4 |
| 7 | ARM32 / Thumb | `taint_tracker_arm32.py` | analyzers/ | implemented | AAPCS; `from_context()`; interprocedural max_funcs=5000; 18 sources; no stack taint; no loop fixpoint |
| 8 | ARM32 / Thumb (labeled) | `taint_tracker_arm32_labeled.py` | analyzers/ | implemented | stream-based; Mode.ARM / Mode.THUMB; VFP s/d lane model; IT-block path-insensitive join |
| 9 | ARC EM/HS | `taint_tracker_arc.py` | analyzers/ | implemented (partial) | pure-Python ARCDecoder (no Capstone ARC in CS5); DSP/EM extension coverage incomplete; `from_context()`; no stack taint |
| 10 | ARC EM/HS (labeled) | `taint_tracker_arc_labeled.py` | analyzers/ | implemented | stream-based; BMSK bounds tracking; BLINK RA tracking; ENTER/LEAVE code-density; JLI/PCL-relative loads |
| 11 | LoongArch64 | `taint_tracker_loongarch64.py` | analyzers/ | implemented | labeled `Taint(labels,bound)`; userspace + kernel sources/sinks (copy_from_user family); `from_context()`; LP64D ABI |
| 12 | MIPS32 | `taint_tracker_mips.py` | analyzers/ | implemented | O32 ABI; `from_path()` only — no `from_context()`; default `endian='little'`; delay slots consumed; no stack taint; no loop fixpoint |
| 13 | MIPS64 | `taint_tracker_mips64.py` | analyzers/ | implemented | N64 ABI; `from_context()` present; default `endian='big'`; DADD/DADDU/64-bit shifts; MFHI/MFLO clears taint; no stack taint |
| 14 | MIPS32/64 (labeled) | `taint_tracker_mips_labeled.py` | analyzers/ | implemented | stream-based; Mode.MIPS32 / Mode.MIPS64; branch-likely slots path-insensitively joined |
| 15 | nanoMIPS | `taint_tracker_nanomips.py` | analyzers/ | implemented (partial) | full decode requires Capstone 6.x; CS5 fallback: conservative ($a0–$a3 all tainted after source call); no `from_context()`; P48 not tracked |
| 16 | PPC32 | `taint_tracker_ppc32.py` | analyzers/ | implemented | GOT2 PIC resolver for Huawei bootloaders; `from_context()`; bi-endian; no stack taint; no loop fixpoint |
| 17 | PPC64 | `taint_tracker_ppc64.py` | analyzers/ | implemented | boolean taint `Dict[str,bool]` only — NOT labeled (`ppc64-taint-analysis.md` doc incorrectly claims labeled model); `from_context()`; ELFv1/ELFv2 |
| 18 | PPC32/64 (labeled) | `taint_tracker_ppc_labeled.py` | analyzers/ | implemented | stream-based; Mode.PPC32 / Mode.PPC64; LMW/STMW/ISEL/CR-logic/SPR-moves/FP-loads; no reference doc |
| 19 | RH850 | `taint_tracker_rh850.py` | analyzers/ | implemented | extends V850TaintTracker; flat ROM via `from_bytes()`; GHS CC-RH/IAR ABI; `double_is_32bit` flag; GHS old-style symbol normalization |
| 20 | RISC-V (labeled/TaintEngine) | `taint_tracker_riscv.py` | analyzers/ | implemented | stream-based (`TaintEngine` class); Width.RV32 / Width.RV64; provides `TaintState` for `analysis_riscv.py` integration |
| 21 | RISC-V 32 | `taint_tracker_riscv32.py` | analyzers/ | implemented | RV32GC; ilp32/ilp32d ABI; `from_context()`; Capstone 5.x+ required; HiSilicon WS63 custom opcodes via `ext_decoder`; no stack taint |
| 22 | RISC-V 64 | `taint_tracker_riscv64.py` | analyzers/ | implemented | RV64GC; lp64/lp64d ABI; `from_context()`; `*w` arithmetic sign-extends tracked conservatively; no stack taint |
| 23 | TriCore TC1.6x | `taint_tracker_tricore.py` | analyzers/ | implemented | FCALL/FRET leaf-function convention; D[]/A[] register duality; SSOV/SAT/MOV suffix variants; flat ROM via `from_bytes()` |
| 24 | V850 / RH850 | `taint_tracker_v850.py` | analyzers/ | implemented | labeled `Taint(labels,bound)` model; `prepare`/`dispose` save-LP-slot tracking; flat ROM via `from_bytes()`; andi zero-extends and bounds |

### Taint tracker count summary

| Category | Count |
|:---------|------:|
| `taint_tracker*.py` in `ablation/analyzers/` | **24** |
| `taint_tracker*.py` in `ablation/modules/` | **0** |
| **Grand total** | **24** |
| Binary-path trackers (#2,4,5,6,7,9,11,12,13,15,16,17,19,21,22,23,24) | 17 |
| Labeled/stream trackers (#3,8,10,14,18,20) | 6 |
| Legacy base (#1) | 1 |

README count of "18 taint trackers" = 17 binary-path + legacy base #1; the 6 labeled/stream variants are excluded from that count.

---

## Summary statistics

| Metric | Count |
|:-------|------:|
| ISAs with any analyzer support | 21 |
| ISAs with full insn_model + isa_model + CFG + analysis_engine stack | 10 |
| ISAs with taint support | 16 |
| ISAs with SAC (SinkArgClassifier) | 8 |
| `taint_tracker*.py` files total | 24 |
| Binary formats with any support (parse ✓ or ~) | 29 |
| Binary formats with full analyze support | 10 |

**ISAs with taint (16):** AArch64, ARC EM/HS, ARM32/Thumb, LoongArch64, MIPS32, MIPS64, nanoMIPS (~), PPC32, PPC64, RISC-V 32, RISC-V 64, RH850, TriCore, V850, x86-32/i386, x86-64

**ISAs with SAC (8):** x86-64, x86-32/i386, ARM32/Thumb, MIPS32 (+ N32 partial), PPC32, PPC64 (ELFv1/ELFv2/generic), s390/s390x

**Binary formats with analyze=✗ but parse=✓:** CRAMFS, SquashFS, Guardian-PAK, BV41, VxWorks-archive, MZ/DOS, LE/VxD, NE (~), MicroPython .mpy (~)

---

## Retained: Detailed ISA Coverage (from prior unit notes A01, C01, M01–M04, S01)

See the pre-A02 version of this file for the extended ISA matrix (with Decode/Disassemble/CFG/Lift-to-IR/Taint/Vuln-scanners columns) and the Vulnerability Class Coverage matrix — those sections include data from M01–M04 unit notes (enum modules, crypto/AI/MCP scanners) not covered in the A02–A10 source notes for this revision.
