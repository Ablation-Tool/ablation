<img src="assets/branding/woven-diamond/repo/logo.png" width="160" alt="Ablation GEM woven diamond">

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey) [![NIST SP 800-218](https://img.shields.io/badge/NIST%20SP%20800--218-SSDF-grey)](docs/standards-ablation.md) [![CISA Secure by Design](https://img.shields.io/badge/CISA-Secure%20by%20Design-grey)](docs/standards-ablation.md) [![MIL-HDBK-115C](https://img.shields.io/badge/MIL--HDBK--115C-Compliant-grey)](docs/standards-ablation.md)

ABL∀TION is an AI-assisted reverse engineering (AIARE) framework.

---

![GEM native workbench demo](assets/demos/gem-workbench-demo.gif)

## Ablation + GEM (Graphics Environment Manager)

**Ablation + GEM (Graphics Environment Manager) is one product and one default download.** Ablation supplies the required CLI, analysis framework, artifact parsers, reverse-engineering tools, target context, and evidence model. GEM (Graphics Environment Manager) is the native UI for that framework, with the shared investigation Lab, embedded AI Agent, Spatial IR, graphical execution, deterministic verification, and replayable visual evidence.

Ablation can operate CLI-only. GEM's complete investigation workflows require Ablation. The default installation includes both; **CLI Only** remains available for users who do not want a graphical environment. The former GUIAI is obsolete, not an alternate interface or supported alias.

![Unified Memory Architecture: human, AI Agent, Ablation, and GEM](assets/demos/gem-unified-memory-architecture.png)

The Lab and AI Agent share the same workspace. The agent reads `gem state`, begins exact selected work with `gem begin`, performs real analysis through Ablation, and records evidence-backed results with `gem emit` or `gem emit-many`. It does not need to infer the Lab from screenshots. Investigation events remain authoritative; Spatial IR, Cairo scenes, VDI commands, and layouts are derived views. Geometric passes are tool evidence, not human confirmation or proof of reverse-engineering coverage. See the [GEM guide](gem-lab/GEM.md) for implementation details and the visual demonstrations below.

## Capabilities

<details>
<summary>ABL∀TION's Default GEM</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**a11y Optimization**](gem-lab/README.md) | [1](gem-lab/gem/app.py)&nbsp;[2](gem-lab/gem/gtk_app.py) | Auto-detects & merges your accessibility settings & tools into the GUI |
| [**Accessible Volume**](docs/reference-modules/accessible-volume.md) | [1](gem-lab/gem/accessible_volume.py)&nbsp;[2](gem-lab/gem/cli.py) | Measures and records next-token forecast breadth with a local model |
| [**Agent Bridge**](gem-lab/README.md) | [1](gem-lab/gem/environment.py)&nbsp;[2](gem-lab/metrix/desktop.py) | Embeds your AI Agent into the GEM |
| [**Debug Diagnostics**](gem-lab/README.md) | [1](gem-lab/gem/app.py)&nbsp;[2](gem-lab/gem/gtk_app.py) | Shows dependency and terminal diagnostics before requesting troubleshooting permission |
| [**Evidence Integrity**](gem-lab/README.md) | [1](gem-lab/gem/events.py)&nbsp;[2](gem-lab/gem/cli.py)&nbsp;[3](gem-lab/gem/app.py) | Tracks reviews and validates evidence targets |
| [**GEM Verification**](gem-lab/GEM.md) | [1](gem-lab/gem/model.py)&nbsp;[2](gem-lab/gem/geometry.py)&nbsp;[3](gem-lab/gem/runner.py) | Verifies and replays spatial investigation evidence |
| [**Lab Navigation**](gem-lab/README.md) | [1](gem-lab/gem/events.py)&nbsp;[2](gem-lab/gem/map_view.py)&nbsp;[3](gem-lab/metrix/cli.py) | Searches and visualizes discoveries while restoring sessions, agents, and preferences |
| [**OS Optimization**](gem-lab/README.md) | [1](gem-lab/gem/app.py)&nbsp;[2](gem-lab/gem/gtk_app.py) | Recognizes the operating system in use and adapts GEM to that environment |
| [**OS Support**](gem-lab/README.md) | [1](gem-lab/gem/launcher.py)&nbsp;[2](gem-lab/packaging/forall.py)&nbsp;[3](gem-lab/packaging/install_linux.sh) | Supports Linux, Windows, macOS, adaptive presentation, and safe installation |

</details>

<details>
<summary>Decompilers, Disassemblers & Analyzers</summary>

**Native CPUs**

| ISA | Variants |
|---|---|
| [**Alpha AXP**](docs/reference-modules/taint-tracker-alpha.md) | Alpha 21064 · 21164 · 21264 · ECOFF · ELF |
| [**ARC**](docs/reference-modules/binary-lifter.md) | ARC EM · ARC HS |
| [**ARM**](docs/reference-modules/binary-lifter.md) | ARM-32 · ARM-64 · Thumb |
| [**Intel MCS**](docs/reference-modules/isa-8051.md) | 8051 / MCS-51 · CC254x |
| [**LoongArch**](docs/reference-modules/loongarch.md) | LoongArch64 · [KASAN/KCOV V2](docs/reference-modules/loongarch64-v2.md) |
| [**MIPS**](docs/reference-modules/mips.md) | MIPS-32 · [nanoMIPS](docs/reference-modules/nanomips.md) · MIPS-64 |
| [**PowerPC**](docs/reference-modules/ppc32-taint-tracker.md) | PPC-32 · PPC-64 · [VLE](docs/reference-modules/ecu-vle-decoder.md) · [PPC476 Book E](docs/reference-modules/ppc476-lifter.md) · [XCOFF32 / AIX](docs/reference-modules/xcoff32-decompiler.md) |
| [**RISC-V**](docs/reference-modules/risc-v.md) | RV32 · RV64 · [HiSilicon ext](docs/reference-modules/hisi-rv32-ext.md) |
| [**S/390**](docs/reference-modules/s390.md) | Big-endian S/390 · z/Arch subset · LE/C++ PPA · XPLINK · BFP · Pseudo-C |
| [**x86**](docs/reference-modules/x86.md) | x86-32 · x86-64 |
| [**Xilinx**](docs/reference-modules/microblaze-decoder.md) | MicroBlaze · [Versal PDI/CDO](docs/reference-modules/versal-pdi.md) · [ZynqMP BOOT.BIN](docs/reference-modules/zynqmp-boot-image.md) |

**Automotive ECUs**

| ISA | Variants |
|---|---|
| [**Infineon**](docs/reference-modules/tricore-taint-tracker.md) | TriCore TC1.6x |
| [**Infineon C166**](docs/reference-modules/c166-c167-decoding.md) | C166 · C167 |
| [**Motorola**](docs/reference-modules/ecu-m68k-decoder.md) | M68K / CPU32 · [MC88100](docs/reference-modules/m88k-decoder.md) |
| [**Renesas SH**](docs/reference-modules/binary-lifter-sh2a.md) | SH-2A |
| [**TI DSP**](docs/reference-modules/ecu-c28x-decoder.md) | TMS320C28x |
| [**V850/RH850**](docs/reference-modules/v850-rh850.md) | V850-32 · RH850 |

**VMs & Runtimes**

| ISA | Variants |
|---|---|
| [**ARK**](docs/reference-modules/harmonyos.md) | ArkTS |
| [**BEAM**](docs/reference-modules/beam.md) | Erlang BEAM bytecode |
| [**DEX**](docs/reference-modules/android-cross-layer.md) | Dalvik · ART · Java-like pseudocode · JNI |
| [**Java**](docs/reference-modules/java-class-jar-parsing.md) | .class · JAR |
| [**MicroPython**](docs/reference-modules/micropython.md) | .mpy v6 |
| [**Python**](docs/reference-modules/python-pyc-scanning.md) | .pyc (3.8–3.12) |

</details>

<details>
<summary>Core Engine</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**ABI Models**](docs/reference-modules/isa-models.md) | [1](ablation/analyzers/insn_x86.py)&nbsp;[2](ablation/analyzers/isa_x86.py) | Normalizes x86 instructions and models register aliases, calling conventions |
| [**Analysis Caching**](docs/reference-modules/on-demand-analysis.md) | [1](ablation/analyzers/binary_context.py)&nbsp;[2](ablation/analyzers/xref_graph.py) | Reuses analysis results and session state across runs |
| [**Architecture DSL**](docs/reference-modules/encoding-dag.md) | [1](ablation/analyzers/encoding_dag.py) | Describes ISA encodings and semantics as reusable graphs |
| [**Argument Tracking**](docs/reference-modules/call-argument-annotation.md) | [1](ablation/analyzers/reg_annotator.py)&nbsp;[2](ablation/analyzers/arm32_reg_annotator.py) | Tracks registers and sink arguments across calls |
| [**ARM Disassembly**](docs/reference-modules/streaming-and-windowed-disassembly.md) | [1](ablation/core/disasm_engine.py)&nbsp;[2](ablation/analyzers/window_analyzer.py) | Provides targeted disassembly and dataflow analysis |
| [**ARM64 Slicing**](docs/reference-modules/arm64-symbolic-slicing.md) | [1](modules/sse_slicer.py)&nbsp;[2](modules/arm64_global_tracker.py) | Traces ARM64 store addresses backward |
| [**Binary Parsing**](docs/reference-modules/binary-format-and-platform-identification.md) | [1](ablation/core/binary_parser.py)&nbsp;[2](ablation/core/elf_parser.py) | Parses ELF, PE, and Mach-O metadata and inspects ELF hardening |
| [**Cryptographic Analysis**](docs/reference-modules/cryptographic-analysis.md) | [1](modules/crypto_audit.py)&nbsp;[2](ablation/analyzers/xor_solver.py) | Detects cipher implementations, recovers XOR and affine keys |
| [**Data-Flow Analysis**](docs/reference-modules/control-flow-graph-construction.md) | [1](ablation/analyzers/dataflow_engine.py)&nbsp;[2](ablation/analyzers/structurizer.py) | Builds control-flow graphs, propagates dataflow facts |
| [**Entropy Mapping**](docs/reference-modules/entropy-mapper.md) | [1](ablation/analyzers/entropy_mapper.py) | Locates compressed and encrypted regions using entropy |
| [**Expression Analysis**](docs/reference-modules/expr-lifter.md) | [1](ablation/analyzers/expr_lifter.py) | Converts instructions into typed expressions and merges computations |
| [**Function Discovery**](docs/reference-modules/stripped-function-discovery.md) | [1](ablation/analyzers/arm32_function_scanner.py)&nbsp;[2](ablation/analyzers/static_elf32_func_start_scanner.py) | Recovers function entries from stripped binaries and ROMs |
| [**Function Emulation**](docs/reference-modules/dynamic-sandbox.md) | [1](ablation/analyzers/dynamic_sandbox.py) | Emulates ARM64 and x86-64 leaf functions |
| [**Function Prioritization**](docs/reference-modules/single-function-profiling.md) | [1](ablation/analyzers/func_profiler.py)&nbsp;[2](ablation/analyzers/func_reachability.py) | Profiles calls and filters findings in functions |
| [**Intermediate Representation**](docs/reference-modules/binary-lifting.md) | [1](ablation/analyzers/binary_lifter.py) | Lifts machine code into shared intermediate representations |
| [**Knowledge Graph**](docs/reference-modules/knowledge-graph.md) | [1](ablation/analyzers/knowledge_graph.py)&nbsp;[2](sweeps/build_ablation_graph.py) | Combines knowledge graphs with agent-driven retrieval |
| [**SSA Modeling**](docs/reference-modules/ssa.md) | [1](ablation/analyzers/ssa.py)&nbsp;[2](ablation/analyzers/ir.py) | Models register definitions using static single assignment |
| [**Symbol Recovery**](docs/reference-modules/debug-metadata-recovery.md) | [1](ablation/analyzers/i386_absolute_xref_scanner.py)&nbsp;[2](ablation/analyzers/dwarf_loongarch64.py) | Recovers ELF function addresses and names from unwind metadata, DWARF |

</details>

<details>
<summary>ReAct (Reasoning + Acting)</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**AI-Guided Analysis**](docs/reference-modules/llm-analyst-loop.md) | [1](ablation/analyzers/llm_analyst/agent_loop.py)&nbsp;[2](ablation/analyzers/llm_analyst/rag_retriever.py) | Pre-fetches function context for LLM analysis |
| [**Approximate Matching**](docs/reference-modules/sax-approximate-indexing.md) | [1](ablation/analyzers/sax_index.py)&nbsp;[2](ablation/analyzers/subsequence_searcher.py) | Indexes opcode sequences for approximate matching |
| [**Cross-Target Learning**](docs/reference-modules/flywheel.md) | [1](ablation/analyzers/pattern_library.py)&nbsp;[2](ablation/analyzers/finding_registry.py) | Reuses findings and vendor sink patterns |
| [**Evidence Validation**](docs/reference-modules/evidence-scoring-and-probe-ranking.md) | [1](ablation/analyzers/probe_ranker.py)&nbsp;[2](ablation/analyzers/probe_adapters.py) | Ranks probes by expected information gain and executes approved adapters |
| [**Function Identification**](docs/reference-modules/function-identity-database.md) | [1](ablation/analyzers/corpus_builder.py)&nbsp;[2](ablation/analyzers/func_id_db.py) | Names known functions and preserves analyst names |
| [**Hypothesis Tracking**](docs/reference-modules/hypothesis-engine-2.md) | [1](ablation/analyzers/hypothesis_engine.py) | Ranks and preserves vulnerability hypotheses |
| [**Pattern Mining**](docs/reference-modules/corpus-mining-cve-patterns.md) | [1](sweeps/corpus_miner.py)&nbsp;[2](modules/cve_byte_patterns.py) | Mines CWE patterns and scans binaries |
| [**Semantic Search**](docs/reference-modules/semantic-code-search.md) | [1](ablation/analyzers/semantic_search.py) | Ranks functions using natural-language embeddings |

</details>

<details>
<summary>Security Research</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Attack-Surface Detection**](docs/reference-modules/network-sink-finder.md) | [1](ablation/analyzers/network_sink_finder.py) | Prioritizes network-reachable propagated-argument sinks |
| [**Bounds Checking**](docs/reference-modules/length-underflow.md) | [1](ablation/analyzers/length_underflow.py)&nbsp;[2](modules/chunk_walker_validator.py) | Detects underflows and validates chunk bounds |
| [**Call Classification**](docs/reference-modules/sink-arg-classifier.md) | [1](ablation/analyzers/sink_arg_classifier.py)&nbsp;[2](ablation/analyzers/sink_arg_classifier_arm32.py)&nbsp;[3](ablation/analyzers/sink_arg_classifier_loongarch64.py) | Classifies sink arguments and filters constant-format calls |
| [**Call Wrappers**](docs/reference-modules/transitive-sink-wrapper-discovery.md) | [1](ablation/analyzers/sink_propagator.py)&nbsp;[2](ablation/analyzers/sanitizer_detector.py) | Discovers sink wrappers and profiles sanitization coverage |
| [**Compiler Hardening**](docs/reference-modules/compiler-defects.md) | [1](ablation/analyzers/loongarch64_max_not_min_scanner.py)&nbsp;[2](ablation/analyzers/compiler_security_gate.py) | Detects miscompilations and inconsistent binary hardening |
| [**Driver Vulnerabilities**](docs/reference-modules/kernel-drivers.md) | [1](ablation/analyzers/kernel_driver_analyzer.py)&nbsp;[2](ablation/analyzers/byovd_detector.py) | Ranks BYOVD primitives and identifies unsafe IOCTL handlers |
| [**Engine Analysis**](docs/reference-modules/engine-pattern-library.md) | [1](ablation/analyzers/engine_pattern_library.py) | Identifies game engines and RCE surfaces |
| [**Exploit Scoring**](docs/reference-modules/shellcode-templates.md) | [1](ablation/core/shellcode_utils.py)&nbsp;[2](modules/bare_adapter.py) | Builds shellcode and computes cyclic offsets |
| [**Extension Security**](docs/reference-modules/browser-extension-auditing.md) | [1](ablation/analyzers/browser_extension_auditor.py) | Detects insecure externally connectable browser extensions |
| [**Format-String Vulnerabilities**](docs/reference-modules/format-string-scanner.md) | [1](ablation/analyzers/format_string_scanner.py) | Finds non-constant format arguments with provenance |
| [**Fortinet Surfaces**](docs/reference-modules/apache-module-analysis.md) | [1](ablation/analyzers/apache_module_analyzer.py)&nbsp;[2](ablation/analyzers/cmdb_surface_mapper.py) | Reconstructs Apache handlers and Fortinet execution sinks |
| [**Function Checks**](docs/reference-modules/scanf-family-overflow-candidates.md) | [1](ablation/analyzers/sscanf_sink_classifier.py)&nbsp;[2](ablation/analyzers/deprecated_func_scanner.py) | Classifies risky calls and deprecated functions |
| [**Heap Vulnerabilities**](docs/reference-modules/heap-vulnerability-scanner.md) | [1](ablation/analyzers/heap_vuln_scanner.py)&nbsp;[2](modules/heap_uaf_scanner.py) | Detects allocation overflows, use-after-free, double-free |
| [**Injection Analysis**](docs/reference-modules/sql-injection-scanner.md) | [1](ablation/analyzers/sql_sink_scanner.py)&nbsp;[2](ablation/analyzers/lua_injection_analyzer.py) | Classifies SQL and Lua injection provenance |
| [**KASAN Validation**](docs/workflows/kasan-oracle.md) | [1](ablation/analyzers/loongarch_decoder_v2.py) | Verifies KASAN candidates in stripped binaries |
| [**Path Validation**](docs/reference-modules/finding-validation.md) | [1](modules/path_solver.py)&nbsp;[2](ablation/analyzers/finding_registry.py) | Checks path feasibility and stores reviewed findings |
| [**Source Analysis**](docs/reference-modules/source-code-auditing.md) | [1](ablation/analyzers/source_audit_compressor.py)&nbsp;[2](ablation/analyzers/source_taint_tracker.py) | Profiles sources and traces dangerous sinks |
| [**Taint Analysis**](docs/reference-modules/taint-analysis.md) | [1](ablation/analyzers/taint_tracker.py)&nbsp;[2](ablation/analyzers/taint_tracker_arm64.py)&nbsp;[3](ablation/analyzers/cross_layer_taint.py) | Traces attacker-controlled data across architectures |
| [**Unauthenticated Exposure**](docs/reference-modules/preauth-exposure.md) | [1](ablation/analyzers/preauth_route_auditor.py) | Maps unauthenticated routes and reachable sinks |
| [**Vulnerability Sweeps**](docs/reference-modules/multi-phase-vulnerability-sweeps.md) | [1](sweeps/base_sweep.py)&nbsp;[2](sweeps/fortinet_sweep.py) | Runs resumable pre-filtering, sink classification, and taint analysis |

</details>

<details>
<summary>Firmware Analysis</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Architecture Detection**](docs/reference-modules/ecu-architecture-detector.md) | [1](ablation/analyzers/ecu_arch_detector.py)&nbsp;[2](ablation/analyzers/ecu_rom_layout_analyzer.py) | Identifies ROM architectures and classifies regions |
| [**bFLT Loader**](docs/reference-modules/bflt.md) | [1](ablation/parsers/bflt.py)&nbsp;[2](ablation/analyzers/bflt_arm32.py)&nbsp;[3](ablation/analyzers/bflt_context.py) | Loads bFLT executables and applies ARM32 relocations |
| [**C166 Toolkit**](docs/reference-modules/c166-cfg.md) | [1](ablation/analyzers/c166_cfg.py)&nbsp;[2](ablation/analyzers/c166_execution.py) | Analyzes C166 control flow and CAN updates |
| [**CAEN Containers**](docs/reference-modules/caen-ascii-hex.md) | [1](ablation/parsers/caen_hex.py) | Decodes CAEN firmware and verifies additive checksums |
| [**ECU Calibration**](docs/reference-modules/calibration-parsers.md) | [1](ablation/analyzers/ecu_xdf_parser.py)&nbsp;[2](ablation/analyzers/ecu_a2l_parser.py) | Parses ECU calibration and scaling metadata |
| [**ECU Security**](docs/reference-modules/ecu-security-access-scanner.md) | [1](ablation/analyzers/ecu_security_access_scanner.py)&nbsp;[2](ablation/analyzers/taint_tracker_tricore.py) | Detects predictable seeds and traces diagnostic writes |
| [**Embedded Decoding**](docs/reference-modules/c166-c167-decoding.md) | [1](ablation/analyzers/ecu_c166_decoder.py)&nbsp;[2](ablation/analyzers/ecu_c28x_decoder.py) | Decodes C166 and C28x instructions |
| [**Firmware Steganography**](docs/reference-modules/proto-fsm.md) | [1](ablation/analyzers/lsb_stego_extractor.py) | Extracts cryptographic material from firmware images |
| [**Firmware Triage**](docs/reference-modules/firmware-signature-and-secret-triage.md) | [1](ablation/core/firmware_analyzer.py)&nbsp;[2](ablation/analyzers/firmware_container.py) | Scans firmware and extracts vendor partitions |
| [**Fortinet**](docs/reference-modules/firmware-extraction.md) | [1](ablation/analyzers/fortios_firmware_extractor.py)&nbsp;[2](ablation/analyzers/firmware_container_key_extractor.py) | Recovers FortiOS keys and firmware containers |
| [**JFFS2 Recovery**](docs/reference-modules/jffs2.md) | [1](ablation/parsers/jffs2.py) | Reconstructs little-endian JFFS2 files with CRC and extent validation |
| [**Juniper**](docs/reference-modules/junos.md) | [1](ablation/core/junos_package.py)&nbsp;[2](ablation/core/junos_signature.py)&nbsp;[3](ablation/analyzers/junos_function_diff.py)&nbsp;[4](ablation/analyzers/gencfg.py)&nbsp;[5](ablation/analyzers/mips_ownership.py)&nbsp;[6](ablation/analyzers/gencfg_provenance.py)&nbsp;[7](ablation/analyzers/mips_message_provenance.py) | Verifies Junos packages and analyzes MIPS functions |
| [**Legacy Formats**](docs/reference-modules/motorola-88000-bcs-coff.md) | [1](ablation/core/coff_m88k_parser.py)&nbsp;[2](ablation/core/guardian_pak_extractor.py) | Parses M88K COFF and Guardian PAK archives |
| [**Texas Instruments**](docs/reference-modules/texas-instruments-firmware.md) | [1](ablation/analyzers/ti_coff_loader.py)&nbsp;[2](ablation/analyzers/ti_nnc_scanner.py) | Parses TI COFF2 symbols and embedded models |
| [**TIMI Saves**](docs/reference-modules/ibm-timi.md) | [1](ablation/ibm_timi/savf.py)&nbsp;[2](ablation/ibm_timi/catalogue.py)&nbsp;[3](ablation/ibm_timi/program.py)&nbsp;[4](ablation/ibm_timi/cli.py) | Verifies QSYS SAVF records and extracts objects |
| [**WDB Reader**](docs/reference-modules/xilinx-wdb.md) | [1](ablation/analyzers/xilinx_wdb.py) | Streams Xilinx waveform events with bounded memory |

</details>

<details>
<summary>Platform & Runtime Analysis</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Android Cross-Layer**](docs/reference-modules/android-cross-layer.md) | [1](ablation/core/android_package.py)&nbsp;[2](ablation/analyzers/dex_decompiler.py)&nbsp;[3](ablation/analyzers/elf_disassembler.py)&nbsp;[4](ablation/analyzers/apk_jni_mapper.py)&nbsp;[5](ablation/analyzers/cross_layer_taint.py) | Analyzes Android packages, JNI bindings, and native sinks |
| [**C++ Calls**](docs/reference-modules/cpp-vtable-reconstructor.md) | [1](modules/cpp_vtable_reconstructor.py)&nbsp;[2](ablation/analyzers/vtable_resolver.py) | Reconstructs C++ hierarchies and virtual call graphs |
| [**Erlang/MicroPython**](docs/reference-modules/beam.md) | [1](ablation/analyzers/beam_context.py)&nbsp;[2](modules/mpy_lifter.py) | Lifts BEAM bytecode and flags dynamic operations |
| [**Go Binaries**](docs/workflows/go-binaries.md) | [1](ablation/analyzers/go_pclntab.py)&nbsp;[2](modules/go_binary_re.py) | Recovers Go names, handlers, and message framing |
| [**HarmonyOS Apps**](docs/reference-modules/harmonyos.md) | [1](ablation/analyzers/abc_parser.py)&nbsp;[2](ablation/analyzers/abc_disasm.py)&nbsp;[3](ablation/analyzers/abc_decompiler.py) | Reconstructs ArkTS pseudocode and embedded endpoints |
| [**IBM AIX**](docs/reference-modules/aix-xcoff32-64-analysis.md) | [1](ablation/core/xcoff_parser.py)&nbsp;[2](ablation/core/bff_extractor.py) | Parses XCOFF sections and BFF archives |
| [**IBM z/OS**](docs/reference-modules/ibm-zos.md) | [1](ablation/ibm_zos/netdata.py)&nbsp;[2](ablation/ibm_zos/loadmodule.py)&nbsp;[3](ablation/ibm_zos/relocation.py)&nbsp;[4](ablation/ibm_zos/callgraph.py)&nbsp;[5](ablation/ibm_zos/decompiler.py)&nbsp;[6](ablation/ibm_zos/sid.py)&nbsp;[7](ablation/ibm_zos/compare.py) | Decode z/OS binaries and compare builds |
| [**Java/Spring**](docs/reference-modules/java-class-jar-parsing.md) | [1](modules/java_re.py)&nbsp;[2](modules/java_decompiler.py) | Parses Java artifacts and detects deserialization gadgets |
| [**LoongArch/nanoMIPS**](docs/reference-modules/loongarch64-2.md) | [1](ablation/analyzers/loongarch_decoder.py)&nbsp;[2](ablation/analyzers/nanomips_decoder.py)&nbsp;[3](ablation/analyzers/sink_arg_classifier_loongarch64.py) | Decodes and analyzes LoongArch and nanoMIPS |
| [**PowerPC Calls**](docs/reference-modules/ppc32-got2-resolver.md) | [1](modules/ppc32_got2_resolver.py)&nbsp;[2](ablation/analyzers/ppc32_plt_tracer.py)&nbsp;[3](ablation/analyzers/ppc64_vmx_density.py) | Resolves PowerPC indirect calls and trampolines |
| [**Runtime Security**](docs/reference-modules/python-pyc-scanning.md) | [1](ablation/analyzers/pyc_bytecode_scanner.py)&nbsp;[2](ablation/analyzers/perl_taint_scanner.py)&nbsp;[3](ablation/analyzers/electron_security_scanner.py) | Audits Python, Perl, and Electron code |
| [**VPI Bridge**](docs/reference-modules/mixed-hdl-vpi-bridge.md) | [1](/media/cowboy/research/CERN/analysis/mixed-hdl/ablation_vpi_bridge.c)&nbsp;[2](/media/cowboy/research/CERN/analysis/mixed-hdl/run_mixed_bridge.py) | Links VHDL and Verilog simulators |
| [**Windows Binaries**](docs/reference-modules/windows-pe.md) | [1](sweeps/pe_sweep.py)&nbsp;[2](ablation/analyzers/cfg_bypass_detector.py)&nbsp;[3](ablation/analyzers/seh_chain_analyzer.py)&nbsp;[4](ablation/analyzers/com_attack_surface_mapper.py)&nbsp;[5](ablation/analyzers/etw_provider_extractor.py)&nbsp;[6](ablation/analyzers/rpc_server_analyzer.py) | Detects Windows CFG bypasses and COM hijacks |

</details>

<details>
<summary>Protocol Analysis</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Agent Security**](docs/reference-modules/inference-endpoint-enumeration.md) | [1](modules/llm_enum.py)&nbsp;[2](ablation/analyzers/mcp_tool_taint_scanner.py) | Audits AI endpoints and trust chains |
| [**API Security**](docs/reference-modules/unknown-http-api-mapping.md) | [1](modules/api_re.py) | Discovers APIs and tests transport weaknesses |
| [**CAN Decoding**](docs/reference-modules/calibration-parsers.md) | [1](modules/can_dbc_parser.py) | Maps CAN frames using DBC metadata |
| [**Nginx Security**](docs/reference-modules/nginx-fingerprinting-and-exposure.md) | [1](modules/nginx_enum.py) | Fingerprints Nginx and probes exposed endpoints |
| [**SPECS Verifier**](docs/reference-modules/specs-protocol.md) | [1](/media/cowboy/research/CERN/analysis/specs-protocol/run_rtl_boundaries.py)&nbsp;[2](/media/cowboy/research/CERN/analysis/specs-protocol/rtl_boundary_tb.sv) | Verifies all 256 SPECS read counts |
| [**State Machines**](docs/reference-modules/proto-fsm.md) | [1](modules/proto_fsm.py) | Reconstructs ARM64 protocol state machines |
| [**TLS Analysis**](docs/reference-modules/tls-certificate-and-protocol-probing.md) | [1](ablation/core/tls_analyzer.py)&nbsp;[2](modules/tls_enum.py) | Audits TLS certificates and downgrade paths |

</details>

<details>
<summary>Live Ecosystems</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Cisco Assessment**](docs/reference-modules/ios-ios-xe-appliance-enumeration.md) | [1](modules/ios_enum.py)&nbsp;[2](modules/nxos_enum.py) | Audits Cisco configurations and trust paths |
| [**Industrial Protocols**](docs/reference-modules/local-network-inventory.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/net_sniffer.py) | Discovers protocols, credentials, and lateral movement |
| [**Kubernetes Security**](docs/reference-modules/docker-inventory-and-posture.md) | [1](modules/docker_enum.py)&nbsp;[2](modules/k8s_enum.py) | Assesses container privilege and metadata risks |
| [**Malware Forensics**](docs/reference-modules/windows-artifact-discovery.md) | [1](modules/forensics_enum.py)&nbsp;[2](modules/physmem_elf_vfs.py) | Collects forensic artifacts and recovers memory binaries |
| [**Privilege Assessment**](docs/reference-modules/host-platform-inventory.md) | [1](modules/process_enum.py)&nbsp;[2](modules/privesc_enum.py) | Inventories hosts and privilege-escalation misconfigurations |
| [**VoIP Security**](docs/reference-modules/sip-service-and-extension-discovery.md) | [1](modules/sip_enum.py) | Enumerates VoIP services and security weaknesses |

</details>

<details>
<summary>DocIN (Documentation + Integrity)</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Finding Export**](docs/reference-modules/yara-json-sarif-export.md) | [1](ablation/core/yara_generator.py)&nbsp;[2](ablation/export/json_export.py)&nbsp;[3](ablation/export/sarif.py) | Exports findings as YARA, SARIF, and JSON |
| [**FORGE Gate**](docs/reference-modules/forge.md) | [1](ablation/analyzers/forge.py) | Blocks commits with high-risk audit findings |
| [**Ninja Plugin**](docs/reference-modules/binary-ninja-plugin.md) | [1](ablation/integrations/binja_plugin.py) | Annotates Binary Ninja with analysis findings |
| [**Patch Tracking**](docs/workflows/cross-version.md) | [1](ablation/analyzers/version_delta.py) | Matches functions and reports patch changes |
| [**Sequence Matching**](docs/reference-modules/dtw-matrix-profile-similarity.md) | [1](ablation/analyzers/dtw_matcher.py)&nbsp;[2](ablation/analyzers/matrix_profile_diff.py) | Matches functions and localizes patched windows |
| [**Structural Matching**](docs/reference-modules/structural.md) | [1](modules/structural_sim.py) | Matches functions using control-flow topology |
| [**Supply Chain**](docs/reference-modules/dependency-and-supply-chain-tooling.md) | [1](modules/sbom_extractor.py)&nbsp;[2](modules/third_party_library_identifier.py) | Extracts library provenance into SBOM records |
| [**Threat Classification**](docs/reference-modules/attandck-labeling.md) | [1](ablation/core/attck_tagger.py) | Labels findings with MITRE ATT&CK IDs |

</details>

<details>
<summary>Rubric Library</summary>

| Capability | Description |
|:---|:---|
| [**Index**](docs/prompts/analysis-rubric.md) | Applies versioned LLM behavior specifications to analysis tasks |

</details>


## Setup & About

<details>
<summary>Universal OS Installation Prompt</summary>

```text
Ask me to choose one installation type and wait for my answer before installing anything:

1. GEM — install the standard Ablation CLI and GEM, then launch the workbench with you—the AI Agent I am currently using—embedded in its terminal.
2. CLI Only — install the standard Ablation CLI without GEM.

Do not continue until I explicitly choose GEM or CLI Only.

If I choose GEM:
- Check my operating system and Python first. Native Windows requires Python 3.11 x64 with Tcl/Tk; macOS and Linux require Python 3.10 or newer with Tkinter. Explain missing prerequisites and ask before system changes.
- Download and review https://github.com/Ablation-Tool/ablation/releases/latest/download/forall.py and run it with the checked Python. Use the default full installation, which includes both Ablation and GEM, verifies release checksums, installs GEM's wheels offline, and downloads standard Ablation dependencies from PyPI.
- Open GEM and choose the RE target inside the application; the session is created automatically outside the target. On macOS, open the generated GEM.app. On Windows and macOS, use --toolkit tk when launching through the CLI. Use your actual executable for the embedded AI Agent; if you cannot identify it, ask me instead of substituting another agent.
- Verify ablation --help and gem --help, choose a target in GEM, and confirm that the workbench opens with your real CLI inside it. Select an artifact, ask the agent to begin working on the selected item, and verify that it reads the current GEM selection and records an evidence-backed status update visible in the Lab; do not treat terminal startup alone as proof of integration.
- If I explicitly do not want a Desktop shortcut, use python forall.py --no-desktop-shortcut. Otherwise, confirm that the installed icon opens GEM directly with in-app Open binary and Open directory actions, stable per-target sessions, installed Kimi, Claude, or Codex CLI detection when available, and the GEM session and workspace environment supplied to its embedded terminal. Use gem launch --no-agent only when I explicitly want the investigation tree without an agent. Dropping local files or folders into the embedded CLI inserts quoted paths without pressing Enter; never execute an RE artifact merely to validate it.
- The turned-A logo exposes **a11y Optimization**, **OS Optimization**, and **Debug**. Each provides a read-only audit with visible findings and proposed commands before requesting permission; Deny must do nothing, and Allow may send only the displayed bounded request to the active AI agent. Accessibility includes persistent colorblind-safe and high-contrast palettes, descriptive labels, text alternatives, and keyboard navigation. Do not claim screen-reader or accessibility compliance without testing with the user's assistive technology.

If I choose CLI Only:
- Create a project-local virtual environment and activate it for my operating system. For an existing source checkout, verify its origin and preserve uncommitted changes.
- Install the standard package with python -m pip install ablation-tool, or from a reviewed source checkout with python -m pip install . Do not run forall.py because its default includes GEM.
- Verify ablation --help. Do not launch GEM.

For either choice:
- Preserve my files and local changes. Do not use sudo, overwrite an existing installation, skip failed validation, or bypass my permissions.
- Do not install an AI model, credentials, optional analysis extras, or firmware analysis. Do not execute the RE target.
- Report my selected option, operating system, Ablation and GEM versions when applicable, installation and project paths, validation result, and exact launch command.
```

</details>

<details>
<summary>Acknowledgments</summary>


Ablation couldn't exist without these creative individuals.

Though no code was written by these authors, doctors, and engineers, their work has direct influence on the production of code, and the aesthetics that makes Ablation what it is.

Thank you.

-Nick

**Research Papers**

| Title | Authors |
|---|---|
| [Reverse Compilation Techniques](https://scholar.google.com/citations?view_op=view_citation&hl=en&user=iseZ69MAAAAJ&citation_for_view=iseZ69MAAAAJ:u-x6o8ySG0sC) · [Specifying the Semantics of Machine Instructions](https://ieeexplore.ieee.org/document/693702) · [UQBT: Adaptable Binary Translation at Low Cost](https://ieeexplore.ieee.org/document/825697) · [Machine-Adaptable Dynamic Binary Translation](https://dl.acm.org/doi/10.1145/351397.351414) | [Dr. Cristina Cifuentes](https://scholar.google.com/citations?hl=en&user=iseZ69MAAAAJ) |
| [Design of a Retargetable Decompiler for a Static Platform-Independent Malware Analysis](https://www.researchgate.net/publication/220849941_Design_of_a_Retargetable_Decompiler_for_a_Static_Platform-Independent_Malware_Analysis) | Petr Zemek, Lukáš Ďurfina, Jakub Křoustek, Dušan Kolář, Tomas Hruska, Karel Masařík, Alexander Meduna |
| [Finding Taint-Style Vulnerabilities in Linux-based Embedded Firmware with SSE-based Alias Analysis](https://arxiv.org/abs/2109.12209) | Cheng, Zheng, Liu, Guan, Liu, Li, Zhu, Ye, Sun |
| [iResolveX: Multi-Layered Indirect Call Resolution via Static Reasoning and Learning-Augmented Refinement](https://arxiv.org/abs/2601.17888) | Monika Santra, Bokai Zhang, Mark Lim, [Vishnu Asutosh Dasu](https://github.com/vdasu), Dongrui Zeng, [Gang Tan](https://github.com/gangtan) |
| [Extracting Protocol Format as State Machine via Controlled Static Loop Analysis](https://arxiv.org/abs/2305.13483) | [Qingkai Shi](https://github.com/qingkaishi), Xiangzhe Xu, Xiangyu Zhang |
| [NEMETYL: Message Type Identification of Binary Network Protocols using Continuous Segment Similarity](https://arxiv.org/abs/2002.03391) | [Stephan Kleber](https://github.com/vs-uulm), Rens Wouter van der Heijden, [Frank Kargl](https://github.com/fkargl) |
| [Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice](https://dl.acm.org/doi/10.1145/2810103.2813707) | [David Adrian](https://github.com/dadrian), Karthikeyan Bhargavan, [Zakir Durumeric](https://github.com/zakird), Pierrick Gaudry, Matthew Green, [J. Alex Halderman](https://github.com/jhalderm), [Nadia Heninger](https://github.com/factorable), Drew Springall, Emmanuel Thomé, [Luke Valenta](https://github.com/lukevalenta) |
| [Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS](https://www.usenix.org/conference/woot16/workshop-program/presentation/bock) | [Hanno Böck](https://github.com/hannob), [Aaron Zauner](https://github.com/azet), Sean Devlin, [Juraj Somorovsky](https://github.com/jurajsomorovsky), [Philipp Jovanovic](https://github.com/Daeinar) |
| [Whitening Sentence Representations for Better Semantics and Faster Retrieval](https://arxiv.org/abs/2103.15316) | [Jianlin Su](https://github.com/bojone), [Jiarun Cao](https://github.com/jiaruncao), Weijie Liu, Yangyiwen Ou |
| [Constant Propagation with Conditional Branches](https://dl.acm.org/doi/abs/10.1145/103135.103136) | Mark N. Wegman, F. Kenneth Zadeck |
| [A Simple, Fast Dominance Algorithm](https://www.cs.princeton.edu/techreports/2005/737.pdf) | Cooper, Harvey, Kennedy |
| [libdft: Practical Dynamic Data Flow Tracking for Commodity Systems](https://dl.acm.org/doi/10.1145/2151024.2151042) | [Vasileios P. Kemerlis](https://github.com/vkemerlis), [Georgios Portokalidis](https://github.com/portokalidis), [Kangkook Jee](https://github.com/jikk), Angelos D. Keromytis |

**Books** supplied by [www.oreilly.com](https://www.oreilly.com) | [github.com/oreillymedia](https://github.com/oreillymedia)

| Title | Authors |
|---|---|
| The Art of Software Security Assessment | [Mark Dowd](https://github.com/mdowd79), John McDonald, [Justin Schuh](https://github.com/jschuh) |
| Practical Binary Analysis | [Dennis Andriesse](https://github.com/dennisaa) |
| Practical Malware Analysis | Michael Sikorski, Andrew Honig |
| Practical Reverse Engineering | Bruce Dang, Alexandre Gazet, [Elias Bachaalany](https://github.com/0xeb) |
| Hacking: The Art of Exploitation (2e) | Jon Erickson |
| Learning Linux Binary Analysis | [Ryan O'Neill](https://github.com/elfmaster) |
| Windows Internals Part 1 & 2 | [Pavel Yosifovich](https://github.com/zodiacon), [Mark Russinovich](https://github.com/markrussinovich), David Solomon, [Alex Ionescu](https://github.com/ionescu007), [Andrea Allievi](https://github.com/AaLl86) |
| Rootkits: Subverting the Windows Kernel | Greg Hoglund, Jamie Butler |
| Advanced Compiler Design and Implementation | Steven Muchnick |
| Engineering a Compiler | Keith Cooper, Linda Torczon |
| Practical IoT Hacking | [Fotios Chantzis](https://github.com/ithilgore), Ioannis Stais, Paulino Calderon, Evangelos Deirmentzoglou, Beau Woods |
| Inside the Android OS: Building, Customizing, Managing and Operating Android System Services | [G. Blake Meike](https://github.com/bmeike) |
| Malware Analysis and Detection Engineering | [Abhijit Mohanta](https://github.com/amohanta), Anoop Saldanha |
| Evasive Malware | [Kyle Cucci](https://github.com/d4rksystem) |
| Hacking Cryptography | [Kamran Khan](https://github.com/krkhan), [Bill Cox](https://github.com/waywardgeek) |
| Real-World Cryptography | David Wong |
| Agentic GraphRAG | [Anthony Alcaraz](https://github.com/anthonyalcaraz), [Sam Julien](https://github.com/samjulien) |

**GEM Design and Direction**

[Dr. Helen R Horkan](https://github.com/HorkanHR) contributed ideas and design feedback that helped shape GEM’s development and the direction of its native workbench. I’m grateful for her insight and for the influence it had on the project.

**Honorable Mention**

[Microsoft Excel (Data Analysis ToolPak)](https://support.microsoft.com/en-us/office/use-the-analysis-toolpak-to-perform-complex-data-analysis-6c67ccf0-f4a9-487c-8dec-bdb5a2cefab6). When analyzing closed infrastructure or securing black-box systems, this exact process is called timing analysis or telemetry reverse engineering. Without source code, the Data Analysis ToolPak mathematically deconstructs how an application works on the backend by strictly observing its inputs and outputs.

</details>

<details>
<summary>Real-World Results</summary>

Ablation has been used to analyze production firmware and kernel drivers from Cisco, Fortinet, IBM, Juniper, TencentOS, Huawei, and more.

Following coordinated disclosure, the **Cisco Product Security Incident Response Team (PSIRT)** adopted Ablation for internal vulnerability triage and continues to use it to evaluate ongoing disclosure reports. Cisco Adaptive Security Appliance (ASA) LINA is among the artifacts analyzed, with findings submitted through CERT/CC VINCE.

| CVE | Product | Title | CVSS |
|---|---|---|---|
| [CVE‑2026‑76420](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) | Secure Firewall Management Center (FMC) | Peer Impersonation | **9.0 Critical** |
| [CVE‑2026‑76412](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) | Secure Firewall Management Center (FMC) | Privilege Escalation to root | **8.5 High** |
| [CVE‑2026‑76413](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) | Secure Firewall Management Center (FMC) | Single Sign-On Token Forgery | **8.5 High** |
| [CVE‑2026‑76447](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4) | Identity Services Engine (ISE) | OCSP Responder Authentication Bypass | **5.3 Medium** |
| [CVE‑2026‑20241](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-cert-mE9BD5GO) | Identity Services Engine (ISE) and ISE Passive Identity Connector (ISE-PIC) | Authorization Bypass | **5.3 Medium** |

</details>

<details>
<summary>Demonstrations</summary>

### Ablation + GEM (Graphics Environment Manager) architecture notes

These visual notes explain the naming, framework relationship, shared Lab protocol, and single Ablation + GEM (Graphics Environment Manager) distribution.

<table>
  <tr>
    <td><a href="assets/demos/gem-architecture-01.png"><img src="assets/demos/gem-architecture-01.png" alt="Comparison of the former GUIAI workbench with GEM (Graphics Environment Manager) and its graphical verification capabilities" width="600"></a></td>
    <td><a href="assets/demos/gem-architecture-02.png"><img src="assets/demos/gem-architecture-02.png" alt="GEM (Graphics Environment Manager) naming and architecture layers" width="600"></a></td>
  </tr>
  <tr>
    <td><a href="assets/demos/gem-architecture-03.png"><img src="assets/demos/gem-architecture-03.png" alt="AI Agent interaction with the shared GEM (Graphics Environment Manager) Lab" width="600"></a></td>
    <td><a href="assets/demos/gem-architecture-04.png"><img src="assets/demos/gem-architecture-04.png" alt="Ablation framework dependency and GEM (Graphics Environment Manager) graphical environment" width="600"></a></td>
  </tr>
  <tr>
    <td><a href="assets/demos/gem-architecture-05.png"><img src="assets/demos/gem-architecture-05.png" alt="One Ablation and GEM (Graphics Environment Manager) distribution with a CLI Only option" width="600"></a></td>
  </tr>
</table>

### GEM (Graphics Environment Manager) Workbench

<table>
  <tr>
    <td><a href="assets/demos/gem-demo-01.png"><img src="assets/demos/gem-demo-01.png" alt="Investigation Lab and embedded AI terminal" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-02.png"><img src="assets/demos/gem-demo-02.png" alt="GEM settings controls and optimization buttons" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-03.png"><img src="assets/demos/gem-demo-03.png" alt="Accessibility audit and keyboard navigation options" width="600"></a></td>
  </tr>
  <tr>
    <td><a href="assets/demos/gem-demo-04.png"><img src="assets/demos/gem-demo-04.png" alt="OS Optimization read-only audit with permission controls" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-05.png"><img src="assets/demos/gem-demo-05.png" alt="Debug diagnostics with pass and review findings" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-06.png"><img src="assets/demos/gem-demo-06.png" alt="Node details for an investigation artifact" width="600"></a></td>
  </tr>
  <tr>
    <td><a href="assets/demos/gem-demo-07.png"><img src="assets/demos/gem-demo-07.png" alt="Resizable Lab and embedded terminal panes" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-08.png"><img src="assets/demos/gem-demo-08.png" alt="Full-width Lab with radial chart" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-09.png"><img src="assets/demos/gem-demo-09.png" alt="Treemap visualization of investigation nodes" width="600"></a></td>
  </tr>
  <tr>
    <td><a href="assets/demos/gem-demo-10.png"><img src="assets/demos/gem-demo-10.png" alt="Lab tree and embedded AI terminal layout" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-11.png"><img src="assets/demos/gem-demo-11.png" alt="Treemap chart beside the embedded AI terminal" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-12.png"><img src="assets/demos/gem-demo-12.png" alt="Radial chart beside the embedded AI terminal" width="600"></a></td>
  </tr>
  <tr>
    <td><a href="assets/demos/gem-demo-13.png"><img src="assets/demos/gem-demo-13.png" alt="Expanded embedded AI terminal workspace" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-14.png"><img src="assets/demos/gem-demo-14.png" alt="Workspace layout and terminal preferences" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-15.png"><img src="assets/demos/gem-demo-15.png" alt="Dragging a folder into the embedded AI terminal" width="600"></a></td>
  </tr>
  <tr>
    <td><a href="assets/demos/gem-demo-16.png"><img src="assets/demos/gem-demo-16.png" alt="Investigation review statuses and flagged follow-up" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-17.png"><img src="assets/demos/gem-demo-17.png" alt="Reviewed status filter for Lab nodes" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-18.png"><img src="assets/demos/gem-demo-18.png" alt="Status selection menu for Lab review" width="600"></a></td>
  </tr>
  <tr>
    <td><a href="assets/demos/gem-demo-19.png"><img src="assets/demos/gem-demo-19.png" alt="Teal accent applied to the desktop workbench" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-20.png"><img src="assets/demos/gem-demo-20.png" alt="Teal OS accent color in GEM" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-21.png"><img src="assets/demos/gem-demo-21.png" alt="Green OS accent color in GEM" width="600"></a></td>
  </tr>
  <tr>
    <td><a href="assets/demos/gem-demo-22.png"><img src="assets/demos/gem-demo-22.png" alt="Orange OS accent color in GEM" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-23.png"><img src="assets/demos/gem-demo-23.png" alt="Red OS accent color in GEM" width="600"></a></td>
    <td><a href="assets/demos/gem-demo-24.png"><img src="assets/demos/gem-demo-24.png" alt="Purple OS accent color in GEM" width="600"></a></td>
  </tr>
</table>

</details>

<details>
<summary>Code Standards</summary>

**[NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)**

This defines how software should be built, organized around four practice areas: preparing the development environment, protecting the codebase from unauthorized changes, writing software with security built into every layer, and responding when vulnerabilities surface after release.

What this means for Ablation in practice is a mandatory ten-section security audit on every module before it touches the repository. The audit covers input validation, memory handling, integer safety, error handling, concurrency, dependency security, injection prevention, secrets handling, logging, and residual risks. No module is committed without passing it.

Taint trackers, which are the modules that matter most if they get something wrong, carry an additional requirement: 85% statement coverage enforced by a hard gate in the test suite, verified against byte-exact synthetic instruction sequences that test ABI register behavior, not just whether the code runs without crashing. Dependencies are pinned with exact hashes and scanned weekly for known CVEs.

**[CISA Secure by Design](https://www.cisa.gov/securebydesign)**

CISA asks software manufacturers to commit to three things: take ownership of the security outcomes of the people who rely on the software, be transparent about its limitations, and treat security as a requirement rather than a recommendation.

For a RE framework, taking ownership of security outcomes has a specific meaning. A taint tracker that misses a vulnerability does not just produce a wrong answer. It produces a result someone may act on as evidence the binary is clean. That is why a false negative in any Ablation taint tracker is classified as a CRITICAL defect.

Every tracker ships with a documented known-anomalies file describing the exact conditions under which it can produce false negatives, so a researcher knows when to apply manual verification on top of the automated result. The precommit gate is not advisory. No code enters the repository without passing it.

**[MIL-HDBK-115C](https://www.nsa.gov)**

The US Department of Defense handbook for reverse engineering methodology defines four phases:

* **Phase 1:** Every engagement starts with a session file recording the target description, artifact hash, tool selection, and documentation plan before any analysis runs. The rule that semantic search runs before manual disassembly maps to the following phase.
* **Phase 2:** Requires characterizing a binary at the function level before doing detailed trace work. The `DynamicSandbox` covers the following.
* **Phase 3:** The structured retrospective written at the close of every completed project maps to the final phase.
* **Phase 4:** The standards document tracks 29 specific requirements drawn from all three frameworks. All 29 are met.

</details>

<details>
<summary>Responsible Use & Contact</summary>

**Responsible Use:** Ablation is built for authorized security research. Use it only against systems you own or have explicit written permission to test. Running it against systems without authorization violates computer fraud laws in most jurisdictions. The author is not responsible for misuse.

**Contact:** Feel free to contact me if you have any questions, ideas, complaints, or bugs:
* 📧 ablation@nuclide-research.com
* 𝕏 [@showxlate](https://x.com/showxlate)

</details>
