<img src="assets/branding/ablation-1b-riveted-plate-wordmark-transparent-2560.png" width="520" alt="ABLATION">

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey) [![NIST SP 800-218](https://img.shields.io/badge/NIST%20SP%20800--218-SSDF-grey)](docs/standards-ablation.md) [![CISA Secure by Design](https://img.shields.io/badge/CISA-Secure%20by%20Design-grey)](docs/standards-ablation.md) [![MIL-HDBK-115C](https://img.shields.io/badge/MIL--HDBK--115C-Compliant-grey)](docs/standards-ablation.md) [![Sponsor Me](https://img.shields.io/badge/Sponsor%20Me-%23ea4aaa?logo=githubsponsors&logoColor=white)](docs/SPONSORS.md)

Ablation is an AI-assisted reverse engineering (AIARE) framework.

---

![demo](assets/demos/claude-code-demo.gif)

## Capabilities

<details>
<summary>39 Decompilers</summary>

**Native CPUs**

| ISA | Variants |
|---|---|
| [**x86**](docs/reference-modules/x86.md) | x86-32 · x86-64 |
| [**ARM**](docs/reference-modules/binary-lifter.md) | ARM-32 · ARM-64 · Thumb |
| [**MIPS**](docs/reference-modules/mips.md) | MIPS-32 · [nanoMIPS](docs/reference-modules/nanomips.md) · MIPS-64 |
| [**PowerPC**](docs/reference-modules/ppc32-taint-tracker.md) | PPC-32 · PPC-64 · [VLE](docs/reference-modules/ecu-vle-decoder.md) · [PPC476 Book E](docs/reference-modules/ppc476-lifter.md) · [XCOFF32 / AIX](docs/reference-modules/xcoff32-decompiler.md) |
| [**RISC-V**](docs/reference-modules/risc-v.md) | RV32 · RV64 · [HiSilicon ext](docs/reference-modules/hisi-rv32-ext.md) |
| [**ARC**](docs/reference-modules/binary-lifter.md) | ARC EM · ARC HS |
| [**LoongArch**](docs/reference-modules/loongarch.md) | LoongArch64 · [KASAN/KCOV V2](docs/reference-modules/loongarch64-v2.md) |
| [**Intel MCS**](docs/reference-modules/isa-8051.md) | 8051 / MCS-51 · CC254x |

**Automotive ECUs**

| ISA | Variants |
|---|---|
| [**V850 / RH850**](docs/reference-modules/v850-rh850.md) | V850-32 · RH850 |
| [**Renesas SH**](docs/reference-modules/binary-lifter-sh2a.md) | SH-2A |
| [**Motorola**](docs/reference-modules/ecu-m68k-decoder.md) | M68K / CPU32 · [MC88100](docs/reference-modules/m88k-decoder.md) |
| [**Infineon**](docs/reference-modules/tricore-taint-tracker.md) | TriCore TC1.6x |
| [**TI DSP**](docs/reference-modules/ecu-c28x-decoder.md) | TMS320C28x |
| [**Infineon C166**](docs/reference-modules/c166-c167-decoding.md) | C166 · C167 |

**VMs & Runtimes**

| ISA | Variants |
|---|---|
| [**DEX**](docs/reference-modules/dex.md) | Dalvik · ART |
| [**ARK**](docs/reference-modules/harmonyos.md) | ArkTS |
| [**MicroPython**](docs/reference-modules/micropython.md) | .mpy v6 |
| [**BEAM**](docs/reference-modules/beam.md) | Erlang BEAM bytecode |
| [**Java**](docs/reference-modules/java-class-jar-parsing.md) | .class · JAR |
| [**Python**](docs/reference-modules/python-pyc-scanning.md) | .pyc (3.8–3.12) |

</details>

<details>
<summary>Core Engine</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Agentic GraphRAG**](docs/reference-modules/knowledge-graph.md) | [1](ablation/analyzers/knowledge_graph.py)&nbsp;[2](sweeps/build_ablation_graph.py) | Agentic GraphRAG merges knowledge graphs (structured nodes and edges) with autonomous AI agents and retrieval-augmented generation (RAG). Instead of running rigid, single-step vector lookups, it lets an intelligent agent plan, query, iterate, and correct its path across relational data. |
| [**Binary Context & Session Cache**](docs/reference-modules/on-demand-analysis.md) | [1](ablation/analyzers/binary_context.py)&nbsp;[2](ablation/analyzers/xref_graph.py) | Binary context and session cache mechanisms store and reuse pre-computed data, compiled states, or conversation contexts to eliminate redundant processing and speed up execution. |
| [**Binary Lifting**](docs/reference-modules/binary-lifting.md) | [1](ablation/analyzers/binary_lifter.py) | Binary lifting translates raw machine instructions into an architecture-neutral intermediate representation (IR), a higher-level form like pseudo-C or SSA that analysis tools can reason about without knowing the original ISA. The lift step preserves data flow, memory accesses, and control flow while abstracting away register names and instruction encoding, so taint analysis, symbolic execution, and decompilation can operate on one uniform representation regardless of whether the source was x86, ARM, or MIPS. |
| [**DAG Adapter Language**](docs/reference-modules/encoding-dag.md) | [1](ablation/analyzers/encoding_dag.py) | A DAG Adapter Language defines instruction set architecture (ISA) semantics as a directed acyclic graph of bitfield encodings, operand types, and dataflow edges. Each adapter maps architecture-specific instruction formats to the common graph representation that the core analysis engines consume, so adding a new architecture requires writing an adapter, not modifying shared analysis code. |
| [**CFG, Dataflow & Structuring**](docs/reference-modules/control-flow-graph-construction.md) | [1](ablation/analyzers/dataflow_engine.py)&nbsp;[2](ablation/analyzers/structurizer.py) | A control flow graph (CFG) maps every possible execution path through a function as a directed graph of basic blocks and branch edges. Dataflow analysis propagates facts through that graph iteratively until no further changes occur, uncovering constant values, live variables, and reaching definitions. Structuring recovers high-level constructs like if/else and while loops from raw branch instructions so the binary reads closer to its original source form. |
| [**Expr Lifter & Value Numbering**](docs/reference-modules/binary-lifting.md) | [1](ablation/analyzers/expr_lifter.py) | An expression lifter converts individual machine instructions into typed expression nodes that capture operand types, sizes, and semantics independent of the instruction encoding. Value numbering then assigns a canonical identifier to every expression so that two computations producing the same result collapse to a single form. This eliminates compiler-generated synonyms before taint analysis runs, reducing false positives from redundant assignments that are semantically identical. |
| [**Symbolic Registers & Provenance**](docs/reference-modules/call-argument-annotation.md) | [1](ablation/analyzers/reg_annotator.py)&nbsp;[2](ablation/analyzers/arm32_reg_annotator.py) | Symbolic register analysis propagates symbolic expressions through call sites to track where every register value originated. Provenance assigns a source label to each argument at a call site: network input, file read, or return value from a prior call. At a sink, the full data lineage for each argument is available without running the binary. |
| [**ARM64 Symbolic Slicing**](docs/reference-modules/arm64-symbolic-slicing.md) | [1](modules/sse_slicer.py)&nbsp;[2](modules/arm64_global_tracker.py) | Symbolic slicing computes the backward slice from a target expression to find every statement that determines its value. ARM64 slicing starts from registers x0 through x7 at each call site, following the AAPCS64 calling convention, and walks backward to recover argument origins. Global, BSS, and GOT state is tracked across call boundaries so field writes through struct pointers remain visible throughout the slice. |
| [**Function Profiling & Reachability**](docs/reference-modules/single-function-profiling.md) | [1](ablation/analyzers/func_profiler.py)&nbsp;[2](ablation/analyzers/func_reachability.py) | Function profiling surveys every function in a binary for sink calls and argument patterns. Reachability analysis determines which functions can be reached from network entry points. Functions with no path from attacker-controlled input are excluded before taint runs, eliminating false positives at the source. |
| [**Format Parsers & Hardening**](docs/reference-modules/binary-format-and-platform-identification.md) | [1](ablation/core/binary_parser.py)&nbsp;[2](ablation/core/elf_parser.py) | Format parsers identify the binary format and platform before any analysis runs. They extract section layout, entry points, and import tables for ELF, PE, XCOFF, Mach-O, and APK targets. Hardening checks test for NX, PIE, RELRO, and stack canary presence so missing mitigations are recorded before disassembly starts. |
| [**Disassembly & Profiling**](docs/reference-modules/streaming-and-windowed-disassembly.md) | [1](ablation/core/disasm_engine.py)&nbsp;[2](ablation/analyzers/window_analyzer.py) | Disassembly converts raw binary bytes into assembly instructions using the Capstone engine. Streaming mode processes a function in chunks so large binaries stay out of memory. Windowed mode focuses on a specific address range for targeted inspection. Angr-backed dataflow is available for path-sensitive checks when linear disassembly is not sufficient. |
| [**Instruction & ABI Models**](docs/reference-modules/instruction-stream-import-and-normalization.md) | [1](ablation/analyzers/insn_x86.py)&nbsp;[2](ablation/analyzers/isa_x86.py) | Instruction models normalize Capstone and objdump output to a common type with consistent address and operand fields across all supported architectures. ABI models define calling conventions, register assignments, and syscall tables for x86, ARM, MIPS, PPC, RISC-V, ARC, V850, LoongArch64, and M88K. Analysis tools query the ABI model rather than handling each architecture separately. |
| [**Stripped & Flat-ROM Discovery**](docs/reference-modules/stripped-function-discovery.md) | [1](ablation/analyzers/arm32_function_scanner.py)&nbsp;[2](ablation/analyzers/static_elf32_func_start_scanner.py) | Stripped binaries carry no symbol table, so function entry points must be recovered from prologues, call targets, and alignment patterns. Flat ROMs have no ELF header at all, so entry points are derived from reset vectors and branch targets at known offsets. Both scanners produce a function list that feeds directly into BinaryContext so the rest of the pipeline has a consistent set of func_starts to work from. |
| [**Metadata, DWARF & Demangling**](docs/reference-modules/debug-metadata-recovery.md) | [1](ablation/analyzers/i386_absolute_xref_scanner.py)&nbsp;[2](ablation/analyzers/dwarf_loongarch64.py) | When debug information is present, DWARF and BTF sections contain precise function boundaries, type information, and variable names. This module extracts those boundaries and feeds them into BinaryContext so stripped analysis tools see accurate func_starts rather than prologue guesses. Demangling converts compiler-encoded symbol names back to their source form so C++ and Swift functions are readable without manual lookup. |
| [**Entropy Mapper**](docs/reference-modules/entropy-mapper.md) | [1](ablation/analyzers/entropy_mapper.py) | Entropy measures the randomness of data in a byte region. High entropy indicates compressed, encrypted, or packed content. The entropy mapper computes a sliding-window Shannon entropy score across the binary and marks region boundaries where entropy shifts sharply. Packed or encrypted sections stand out before any unpacking attempt runs. |
| [**Unicorn Dynamic Sandbox**](docs/reference-modules/dynamic-sandbox.md) | [1](ablation/analyzers/dynamic_sandbox.py) | The dynamic sandbox emulates ARM64 or x86-64 leaf functions using the Unicorn engine and captures register and memory writes produced during execution. Behavioral signatures derived from emulation carry an evidence strength of 0.40 to 0.75, so sandbox results confirm static findings rather than replace them. Emulation stops at the first external call because the sandbox has no OS context to resolve it. |
| [**Cryptographic Audit & Key Recovery**](docs/reference-modules/cryptographic-analysis.md) | [1](modules/crypto_audit.py)&nbsp;[2](ablation/analyzers/xor_solver.py) | Cryptographic audit identifies cipher implementations in stripped binaries by matching byte patterns associated with AES, hash functions, and XOR-based encodings. Key recovery attempts to extract repeating-XOR keys and affine cipher mappings directly from the binary. JWT weak secret testing and RSA/ECDSA nonce reuse checks run against live endpoints or captured traffic to confirm exploitability. |

</details>

<details>
<summary>ReAct (Reasoning + Acting)</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**LLM Analyst Loop & RAG**](docs/reference-modules/llm-analyst-loop.md) | [1](ablation/analyzers/llm_analyst/agent_loop.py)&nbsp;[2](ablation/analyzers/llm_analyst/rag_retriever.py) | An LLM analyst loop runs a bounded tool-calling cycle where the model selects an Ablation tool, receives its output, and decides the next step. RAG retrieves relevant context from reference module docs before each tool call so the model reasons from current capability descriptions rather than training weights. The loop names functions, reconstructs struct layouts, and generates vulnerability hypotheses in sequence. |
| [**Semantic Code Search**](docs/reference-modules/semantic-code-search.md) | [1](ablation/analyzers/semantic_search.py) | Semantic code search embeds function descriptions as dense vectors and ranks candidates by similarity to a natural-language query. It uses BAAI/bge-small-en-v1.5 at 384 dimensions via fastembed. Run it before any manual disassembly because it identifies the top candidates across an 885-function binary in 35 seconds. |
| [**Hypothesis Engine**](docs/reference-modules/hypothesis-engine-2.md) | [1](ablation/analyzers/hypothesis_engine.py) | The hypothesis engine stores competing vulnerability explanations and updates each one as new evidence arrives. Hypotheses rank against each other based on accumulated evidence so the weakest candidates are deprioritized before manual trace time is spent. State persists across sessions so an incomplete analysis can resume where it stopped. |
| [**Evidence Scoring & Stage Commitments**](docs/reference-modules/evidence-scoring-and-probe-ranking.md) | [1](ablation/analyzers/probe_ranker.py)&nbsp;[2](ablation/analyzers/probe_adapters.py) | Evidence scoring assigns weights to different finding types based on how reliably each indicates a real vulnerability. The probe ranker dispatches the adapters best suited to collect the next piece of evidence for the current hypothesis. Stage commitments are cryptographically signed so partial results cannot be overwritten between sessions. |
| [**The Flywheel & Cross-Target Learning**](docs/reference-modules/flywheel.md) | [1](ablation/analyzers/pattern_library.py)&nbsp;[2](ablation/analyzers/finding_registry.py) | The flywheel replays confirmed finding descriptions and semantic queries from past engagements against new binaries. Vendor-specific sink patterns confirmed on one target are applied automatically to the next target in the same product family. Patterns that produce no findings are not replayed again, so the query set improves with each engagement. |
| [**Function Identity & Auto-Naming DB**](docs/reference-modules/function-identity-database.md) | [1](ablation/analyzers/corpus_builder.py)&nbsp;[2](ablation/analyzers/func_id_db.py) | The function identity database stores FLIRT-style signatures for known functions and matches them against functions in a new binary at load time. Matched functions are named automatically so `ctx.name(va)` returns a meaningful label from the first session. Analyst-assigned names persist in the registry and survive across binary versions so manual naming work accumulates rather than resets. |
| [**SAX Indexing & Homolog Search**](docs/reference-modules/sax-approximate-indexing.md) | [1](ablation/analyzers/sax_index.py)&nbsp;[2](ablation/analyzers/subsequence_searcher.py) | SAX indexing converts opcode sequences into symbolic strings so approximate function lookups run in milliseconds rather than full embedding comparisons. Homolog search finds the closest matching function across the corpus for any given query function. Functions with no close match in the corpus are flagged as structural orphans, which often marks novel or custom components worth examining first. |
| [**Corpus Mining & CVE Patterns**](docs/reference-modules/finding-corpus-mining.md) | [1](sweeps/corpus_miner.py)&nbsp;[2](modules/cve_byte_patterns.py) | Corpus mining summarizes CWE frequency across a target corpus to show which vulnerability classes appear most often in a given vendor's codebase. CVE byte pattern checks scan each binary for known-vulnerable instruction sequences from published CVEs. Results are cached per binary version so repeated scans of the same firmware build skip the full analysis. |
| [**KASAN-Oracle Workflow**](docs/workflows/kasan-oracle.md) | [1](ablation/analyzers/loongarch_decoder_v2.py) | KASAN instrumentation in a debug build surfaces memory safety violations with precise addresses and stack traces. The oracle workflow takes those candidates and verifies each one in the stripped production binary without debug symbols. Confirmed 11 of 14 candidates in TencentOS kernel 6.6.119. |

</details>

<details>
<summary>Security Research</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Intraprocedural & Interprocedural Taint**](docs/reference-modules/taint-analysis-2.md) | [1](ablation/analyzers/taint_tracker.py)&nbsp;[2](ablation/analyzers/taint_tracker_arm64.py) | Intraprocedural taint tracks data flow from sources to sinks within a single function. Interprocedural taint follows tainted values across call boundaries so an argument that enters one function as network input can be traced through intermediate callees to the sink. Cross-library taint extends this across shared library boundaries so taint does not stop at a .so interface. |
| [**Sink Argument Classifiers**](docs/reference-modules/sink-arg-classifier.md) | [1](ablation/analyzers/sink_arg_classifier.py)&nbsp;[2](ablation/analyzers/sink_arg_classifier_arm32.py) | Classifies each sink call site as RODATA_CONST, SNPRINTF_RODATA, ARG_PROPAGATED, or UNKNOWN across 7 ISA variants. Always call `from_context(ctx)` because `from_path()` returns only ~22 func_starts on stripped binaries. Running this before TaintTracker eliminates roughly 80% of false positives. |
| [**Sanitizer & Wrapper Filtering**](docs/reference-modules/transitive-sink-wrapper-discovery.md) | [1](ablation/analyzers/sink_propagator.py)&nbsp;[2](ablation/analyzers/sanitizer_detector.py) | Traces calls outward from known sinks to find wrapper functions so the full call chain is tainted, not just the inner sink. Distinguishes [socket-originated `fgets` from file-originated `fgets`](docs/reference-modules/file-versus-socket-input-discrimination.md) because only the socket variant carries attacker input. |
| [**Network Sink Finder**](docs/reference-modules/network-sink-finder.md) | [1](ablation/analyzers/network_sink_finder.py) | Walks the callgraph outward from `recv`, `read`, `fgets`, and `accept` and intersects those reachable functions with SinkArgClassifier results. Functions that are both reachable from the network and have a propagated-argument sink become taint candidates. |
| [**Symbolic Finding Validation**](docs/reference-modules/finding-validation.md) | [1](modules/path_solver.py)&nbsp;[2](ablation/analyzers/finding_registry.py) | Solves a bounded x86-64 path in Z3 to confirm a finding is reachable before reporting it. Call `FindingRegistry.register()` once Z3 returns SAT because false positives from pattern-only matches have caused missed bugs in past engagements. |
| [**Format String Scanner**](docs/reference-modules/format-string-scanner.md) | [1](ablation/analyzers/format_string_scanner.py) | Flags printf-family, syslog, and custom logging call sites where the format argument is not a constant so every candidate for triage comes with a concrete call site and provenance trace. |
| [**Heap Vulnerability Scanners**](docs/reference-modules/heap-vulnerability-scanner.md) | [1](ablation/analyzers/heap_vuln_scanner.py)&nbsp;[2](modules/heap_uaf_scanner.py) | Detects allocation overflow, use-after-free, double-free, and off-by-one patterns across x86-64 and LoongArch64. |
| [**Length Underflow & Chunk Walkers**](docs/reference-modules/length-underflow.md) | [1](ablation/analyzers/length_underflow.py)&nbsp;[2](modules/chunk_walker_validator.py) | Detects header-subtraction integer wraps that underflow before a `memcpy` or allocation. A separate [chunk walker](docs/reference-modules/tlv-chunk-alignment-checks.md) verifies TLV alignment so parser loops that skip boundary checks are flagged at the omission point. |
| [**sscanf & Unsafe Import Scanners**](docs/reference-modules/scanf-family-overflow-candidates.md) | [1](ablation/analyzers/sscanf_sink_classifier.py)&nbsp;[2](ablation/analyzers/deprecated_func_scanner.py) | Finds unbounded `sscanf` specifiers and deprecated imports like `gets` and `mktemp`. Also catches [ARM32 multiply-into-alloc arithmetic overflows](docs/reference-modules/arm32-allocation-arithmetic-overflow.md) and [PPC32 fixed-slot heap overflows](docs/reference-modules/ppc32-heap-slot-overflow.md) because these patterns do not match a standard format-string scan. |
| [**Pre-Authentication Exposure**](docs/reference-modules/preauth-exposure.md) | [1](ablation/analyzers/preauth_route_auditor.py) | Recovers route dispatch structures and auth wrapper patterns so endpoints reachable before login can be identified and traced to sinks. |
| [**Web Module & CMDB Surface**](docs/reference-modules/apache-module-analysis.md) | [1](ablation/analyzers/apache_module_analyzer.py)&nbsp;[2](ablation/analyzers/cmdb_surface_mapper.py) | Inspects APR and Apache hook registration to surface the active request handler chain. Maps [Fortinet CMDB exec calls](docs/reference-modules/cmdb-to-sink-mapping.md) to their sinks and checks [firmware flasher](docs/reference-modules/firmware-flasher-trust-checks.md) signature verification paths. |
| [**SQL, Lua & Setuid Auth**](docs/reference-modules/sql-injection-scanner.md) | [1](ablation/analyzers/sql_sink_scanner.py)&nbsp;[2](ablation/analyzers/lua_injection_analyzer.py) | Traces formatted query strings into MySQL and SQLite C APIs. Also detects [Python-to-Lua injection paths](docs/reference-modules/lua-injection-analyzer.md) and non-PAM auth oracles that check the shadow file directly rather than delegating to PAM. |
| [**Compiler Defects & VxWorks**](docs/reference-modules/compiler-defects.md) | [1](ablation/analyzers/loongarch64_max_not_min_scanner.py)&nbsp;[2](ablation/analyzers/compiler_security_gate.py) | Detects LoongArch64 min/max miscompilations confirmed in TencentOS 6.6.119, post-link compiler security gate failures, and [VxWorks PPC32 static archive patterns](docs/reference-modules/vxworks-archive-scanner.md). |
| [**Windows Kernel & BYOVD**](docs/reference-modules/kernel-drivers.md) | [1](ablation/analyzers/kernel_driver_analyzer.py)&nbsp;[2](ablation/analyzers/byovd_detector.py) | Ranks BYOVD exploitation primitives by impact and identifies METHOD_NEITHER IOCTL handlers where the kernel passes raw user-space pointers directly to the driver. |
| [**Source Repository Auditing**](docs/reference-modules/source-code-auditing.md) | [1](ablation/analyzers/source_audit_compressor.py)&nbsp;[2](ablation/analyzers/source_taint_tracker.py) | Ingests a source repository and classifies every route handler as authenticated, pre-auth, or unknown. Reports dangerous sinks reachable from unauthenticated paths and flags tenant isolation gaps. |
| [**Exploit Dev, ROP & BARE**](docs/reference-modules/shellcode-templates.md) | [1](ablation/core/shellcode_utils.py)&nbsp;[2](modules/bare_adapter.py) | Generates x86, x64, and ARM64 shellcode with [bad-byte filtering and XOR encoding](docs/reference-modules/payload-formatting.md). Includes [cyclic offset calculation and ROP chain building](docs/reference-modules/crash-offset-and-rop-helpers.md). Ranks findings against BARE to produce Metasploit module severity scores. |

</details>

<details>
<summary>Firmware Analysis</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Fortinet Firmware & Key Corpus**](docs/reference-modules/firmware-extraction.md) | [1](ablation/analyzers/fortios_firmware_extractor.py)&nbsp;[2](ablation/analyzers/firmware_container_key_extractor.py) | Decrypts FortiOS partitions and extracts FortiMail OVF and VMDK keys. Fingerprints certificate key families across firmware versions so key reuse across build tracks is visible. |
| [**Firmware Triage & Vendor FS**](docs/reference-modules/firmware-signature-and-secret-triage.md) | [1](ablation/core/firmware_analyzer.py)&nbsp;[2](ablation/analyzers/firmware_container.py) | Locates format signatures and secrets in a firmware image, extracts partition tables, and identifies MMIO hardware roots. Unpacks AMI BMC CramFS, Huawei SquashFS/XZ, and [Apple bv41 LZ4](docs/reference-modules/apple-bv41-decompression.md) without external tools. |
| [**IBM AIX: BFF, XCOFF & W-Code**](docs/reference-modules/aix-xcoff32-64-analysis.md) | [1](ablation/core/xcoff_parser.py)&nbsp;[2](ablation/core/bff_extractor.py) | Parses XCOFF32/64 binaries and resolves symbols standalone without requiring the original AIX toolchain. Also reads [IBM XLC W-Code IR](docs/reference-modules/ibm-w-code-parsing.md), plain and compressed BFF archives, and AIX bigaf libraries. |
| [**ECU Architecture & ROM Layout**](docs/reference-modules/ecu-architecture-detector.md) | [1](ablation/analyzers/ecu_arch_detector.py)&nbsp;[2](ablation/analyzers/ecu_rom_layout_analyzer.py) | Scores candidate ISAs for a raw ECU dump using reset vector patterns so the correct decoder is selected before disassembly starts. Classifies ROM regions as code, calibration, or interrupt vectors. |
| [**ECU Decoders & Embedded ISAs**](docs/reference-modules/c166-c167-decoding.md) | [1](ablation/analyzers/ecu_c166_decoder.py)&nbsp;[2](ablation/analyzers/ecu_c28x_decoder.py) | Decodes C166/C167, TI C28x DSP, M68K/CPU32, Renesas SH-2A, PowerPC VLE, and HiSilicon RISC-V extension instructions. The [8051 decoder](docs/reference-modules/8051-isa-modeling.md) uses `IntelHexLoader` for Intel HEX files and `Cc254xBankResolver` for CC254x bank switching. |
| [**ECU Taint & SecurityAccess**](docs/reference-modules/ecu-security-access-scanner.md) | [1](ablation/analyzers/ecu_security_access_scanner.py)&nbsp;[2](ablation/analyzers/taint_tracker_tricore.py) | Fingerprints UDS and KWP2000 static-seed SecurityAccess patterns to detect predictable seed algorithms. Runs source-to-sink taint on [Infineon TriCore](docs/reference-modules/tricore-taint-tracker.md) and [Renesas RH850](docs/reference-modules/rh850-taint-analysis.md) to trace attacker input from diagnostic sessions to memory writes. |
| [**Calibration & CAN DBC Parsers**](docs/reference-modules/calibration-parsers.md) | [1](ablation/analyzers/ecu_xdf_parser.py)&nbsp;[2](ablation/analyzers/ecu_a2l_parser.py) | Parses TunerPro XDF, ASAM A2L, RomRaider, and Conescan calibration formats along with CAN DBC bus definitions. Interprets axis and scaling data so calibration values are readable and handles relocated open_damos tables. |
| [**TI SDK, COFF2 & NNC Artifacts**](docs/reference-modules/ti-coff-archive-loading.md) | [1](ablation/analyzers/hisi_rv32_ext.py)&nbsp;[2](modules/isa_8051.py) | Parses TI COFF2 objects and archives from the TI SDK. Also reads TVM and NNC neural-network inference artifacts so embedded model weights and operator schedules are visible. |
| [**Legacy Mainframe, Workstation & DOS/Win16**](docs/reference-modules/motorola-88000-bcs-coff.md) | [1](ablation/core/coff_m88k_parser.py)&nbsp;[2](ablation/core/guardian_pak_extractor.py) | Parses Motorola M88K BCS COFF, Tandem NonStop Guardian PAK, Classic Mac PEF/CFM and AppleDouble resource forks, Win16 NE and LE/VxD binaries, MS-DOS MZ executables, and PS3 SELF containers. Also extracts installer payloads from BitRock, NSIS, and UPX wrappers. |

</details>

<details>
<summary>Multi-Architecture Analysis Matrix</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Android APK, DEX, Binder & JNI**](docs/reference-modules/android-apk-analysis.md) | [1](ablation/core/apk_parser.py)&nbsp;[2](ablation/analyzers/dex_analyzer.py) | Parses APK and AXML manifests and lifts DEX bytecode to smali and pseudo-Java. Reconstructs the Binder IPC surface and JNI bridge so native code entry points are visible alongside the Java call chain. |
| [**HarmonyOS / ArkTS Bytecode**](docs/reference-modules/harmonyos.md) | [1](ablation/analyzers/abc_parser.py)&nbsp;[2](ablation/analyzers/abc_disasm.py) | Parses Ark .abc bytecode, enumerates classes, methods, and strings, and lifts the result to JavaScript-like pseudocode. |
| [**Go Binary Reverse Engineering**](docs/workflows/go-binaries.md) | [1](ablation/analyzers/go_pclntab.py)&nbsp;[2](modules/go_binary_re.py) | Recovers pclntab metadata in stripped and garbled Go binaries so function names and boundaries are usable without debug symbols. Also maps `os/exec` subprocess calls and builds a [dangerous-call graph](docs/reference-modules/go-dangerous-call-graph.md) so command injection paths surface automatically. |
| [**Java, JAR & Spring Analysis**](docs/reference-modules/java-class-jar-parsing.md) | [1](modules/java_re.py)&nbsp;[2](modules/java_decompiler.py) | Parses Java constant pools and JARs and scans for deserialization, XXE, JNDI, and SSRF patterns. Reports Spring Actuator endpoints that expose heap dumps or environment properties. |
| [**Erlang BEAM & MicroPython .mpy**](docs/reference-modules/beam.md) | [1](ablation/analyzers/beam_context.py)&nbsp;[2](modules/mpy_lifter.py) | Lifts Erlang BEAM bytecode and scans imported atoms for dangerous OS and eval calls. Parses [MicroPython .mpy v6 bytecode](docs/reference-modules/micropython-mpy-lifter.md) and lifts it to readable pseudocode. |
| [**Python .pyc, Perl, Electron & Extensions**](docs/reference-modules/python-pyc-scanning.md) | [1](ablation/analyzers/pyc_bytecode_scanner.py)&nbsp;[2](ablation/analyzers/perl_taint_scanner.py) | Audits compiled .pyc code objects for dangerous patterns and runs command-injection taint on Perl scripts. Also inspects [Electron IPC handlers](docs/reference-modules/electron-application-auditing.md) and [browser extension manifest permissions](docs/reference-modules/browser-extension-auditing.md). |
| [**LoongArch64 & nanoMIPS Pipelines**](docs/reference-modules/loongarch64-2.md) | [1](ablation/analyzers/loongarch_decoder.py)&nbsp;[2](ablation/analyzers/nanomips_decoder.py) | Runs the CFG, lifting, and taint pipeline on LoongArch64 and nanoMIPS binaries. nanoMIPS uses a dedicated decoder because the variable instruction width breaks standard Capstone disassembly. |
| [**C++ Vtable & Virtual Dispatch**](docs/reference-modules/cpp-vtable-reconstructor.md) | [1](modules/cpp_vtable_reconstructor.py)&nbsp;[2](ablation/analyzers/vtable_resolver.py) | Recovers C++ vtables from ELF binaries and resolves ARM64 BLR virtual calls and x86-64 RELA relocations to concrete targets. Also parses PS3 Cell OPD vtables so virtual dispatch is traceable on that architecture. |
| [**PowerPC GOT2, ELFv1 & AltiVec**](docs/reference-modules/ppc32-got2-resolver.md) | [1](modules/ppc32_got2_resolver.py)&nbsp;[2](ablation/analyzers/ppc32_plt_tracer.py) | Resolves stripped PPC32 PIC BCTRL jump targets so GOT2-relative calls produce named destinations. Also traces [PPC64 ELFv1 OPD stubs and glink trampolines](docs/reference-modules/ppc64-elfv1-resolution.md) and ranks VMX/AltiVec instruction density to identify signal-processing routines. |
| [**Windows PE, CFG, SEH & COM**](docs/reference-modules/windows-pe.md) | [1](sweeps/pe_sweep.py)&nbsp;[2](ablation/analyzers/cfg_bypass_detector.py) | Sweeps PE binaries for CFG bypass patterns, SEH chain integrity gaps, and COM registration hijacking surfaces. Extracts [ETW provider GUIDs](docs/reference-modules/etw-provider-extraction.md) and [RPC server interfaces](docs/reference-modules/rpc-server-analyzer.md) and can inject [PDB symbol information](docs/reference-modules/pdb-integration.md) for annotated output. |

</details>

<details>
<summary>Protocol Analysis</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Protocol FSM & Stego Extractors**](docs/reference-modules/proto-fsm.md) | [1](modules/proto_fsm.py)&nbsp;[2](ablation/analyzers/lsb_stego_extractor.py) | Infers ARM64 protocol state machines from BSS access patterns, including MMTLS variants. The [BMP LSB extractor](docs/reference-modules/lsb-stego-extractor.md) recovers keys hidden in firmware images where crypto material is embedded in image pixels. |
| [**TLS Probing & Downgrade Analysis**](docs/reference-modules/tls-certificate-and-protocol-probing.md) | [1](ablation/core/tls_analyzer.py)&nbsp;[2](modules/tls_enum.py) | Probes live TCP/TLS connections and inspects certificates and DH parameters. Reports HSTS, mTLS, and CT policy gaps and identifies session resumption configurations that allow protocol downgrade. |
| [**HTTP/GraphQL/gRPC API Auditing**](docs/reference-modules/unknown-http-api-mapping.md) | [1](modules/api_re.py) | Discovers unknown API schemas and tests each endpoint for BOLA, BFLA, injection, and SSRF. Covers REST, GraphQL, gRPC, SOAP, and WebSocket transports and audits JWT, OAuth, and PKCE authentication flows. |
| [**Nginx Exposure & Config Probes**](docs/reference-modules/nginx-fingerprinting-and-exposure.md) | [1](modules/nginx_enum.py) | Fingerprints Nginx status and debug endpoints and checks for alias traversal, proxy SSRF, and request smuggling. Maps the detected version to known CVEs. |
| [**AI, LLM & MCP Security Scanners**](docs/reference-modules/inference-endpoint-enumeration.md) | [1](modules/llm_enum.py)&nbsp;[2](ablation/analyzers/mcp_tool_taint_scanner.py) | Enumerates Ollama, LM Studio, and vLLM inference endpoints and probes them for prompt injection and model agency exposure. Audits MCP and A2A agent protocols for tool taint paths and RAG vector-store exposure using [Atheris grammar-based fuzzing](docs/reference-modules/mcp-grammar-fuzzer.md). |

</details>

<details>
<summary>Live Ecosystems</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Host, Process & Privilege Triage**](docs/reference-modules/host-platform-inventory.md) | [1](modules/process_enum.py)&nbsp;[2](modules/privesc_enum.py) | Inventories OS and kernel security configuration, maps process memory regions, and traces syscalls via strace and ptrace. Detects process hollowing and persistence mechanisms on Linux and Windows and identifies privilege escalation paths on both platforms. |
| [**Forensics, Memory & Malware Triage**](docs/reference-modules/windows-artifact-discovery.md) | [1](modules/forensics_enum.py)&nbsp;[2](modules/physmem_elf_vfs.py) | Collects Windows MFT, LNK, Prefetch, and EVTX artifacts alongside Linux volatile /proc state. Checks for timestomping and log anomalies, flags rootkit and bootkit indicators, and recovers ELF binaries from raw physical memory dumps. Labels findings with MITRE ATT&CK technique IDs. |
| [**Network, PCAP & ICS/OT Discovery**](docs/reference-modules/local-network-inventory.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/net_sniffer.py) | Enumerates interfaces and ports, captures raw packets, and inspects PCAPs for credentials and keys. Probes Modbus, MQTT, CoAP, SNMP, BACnet, and EtherNet/IP and flags traffic patterns consistent with C2 or data exfiltration. |
| [**Cisco Appliance & Data Center Fabrics**](docs/reference-modules/ios-ios-xe-appliance-enumeration.md) | [1](modules/ios_enum.py)&nbsp;[2](modules/nxos_enum.py) | Audits IOS and IOS-XE configurations and recovers Type-7 and SNMP secret strings. Covers NX-OS/ACI/APIC fabrics, SD-WAN, Meraki, HyperFlex/UCS/Intersight, and Nexus Dashboard so the full Cisco product footprint is reachable from one scanner. |
| [**Containers, Kubernetes & Cloud**](docs/reference-modules/docker-inventory-and-posture.md) | [1](modules/docker_enum.py)&nbsp;[2](modules/k8s_enum.py) | Assesses Docker posture and container escape surfaces, inventories Kubernetes workloads and RBAC bindings, and checks network policy gaps. Reaches Kafka, RabbitMQ, Prometheus, Grafana, CI/CD pipelines, and Vault from the same session context. |
| [**VoIP & Real-Time Communications**](docs/reference-modules/sip-service-and-extension-discovery.md) | [1](modules/sip_enum.py) | Enumerates SIP extensions and checks SDP, RTP, SRTP, and WebRTC signaling configuration for exposure. Also covers H.323, SCCP, and MGCP gateways and flags patterns associated with toll fraud and DTMF eavesdropping. |

</details>

<details>
<summary>DocIN (Documentation + Integrity)</summary>

| Capability | Code | Description |
|:---|:---|:---|
| [**Version Diffing & Patch Tracking**](docs/workflows/cross-version.md) | [1](ablation/analyzers/version_delta.py)&nbsp;[2](ablation/analyzers/version_tracker.py) | Compares two binary versions and returns the functions where behavior changed. Call `VersionTracker.track()` to follow a specific function across builds and `VersionDelta.changed_functions()` for the full diff. A taint coverage gate rejects comparisons below 85% coverage. |
| [**DTW & Matrix Profile Similarity**](docs/reference-modules/sax-approximate-indexing.md) | [1](ablation/analyzers/dtw_matcher.py)&nbsp;[2](ablation/analyzers/matrix_profile_diff.py) | Scores instruction-sequence similarity between functions using DTW and detects structural changes across builds using matrix-profile diff. Both are used together because DTW catches renamed logic while matrix-profile catches reorganized logic. |
| [**Structural Function Similarity**](docs/reference-modules/structural.md) | [1](ablation/analyzers/structural_sim.py) | Matches functions across binaries using CFG topology so builds without debug symbols can still be compared. |
| [**FORGE Module Quality Gate**](docs/reference-modules/forge.md) | [1](ablation/analyzers/forge.py) | Required pre-commit auditor for every Ablation module. Runs the 10-section Ablation-SAFE CODE review inline, caches the result with a BLAKE2b digest so re-running on an unchanged file is instant, and blocks `git commit` on any unresolved HIGH finding. |
| [**YARA, JSON & SARIF Export**](docs/reference-modules/yara-generator.md) | [1](ablation/analyzers/yara_generator.py)&nbsp;[2](ablation/export/json_export.py) | Generates YARA rules directly from confirmed findings so detection signatures and the analysis that produced them share the same session. Also exports results as [JSON or SARIF 2.1.0](docs/reference-modules/json-and-sarif-export.md) and produces [Markdown research reports](docs/reference-modules/markdown-research-reports.md). |
| [**Multi-Phase Vulnerability Sweeps**](docs/reference-modules/generic-vulnerability-profile-sweeps.md) | [1](sweeps/base_sweep.py)&nbsp;[2](sweeps/fortinet_sweep.py) | Runs multi-phase vulnerability-profile sweeps across a directory. The Fortinet-specific driver covers 8 vulnerability profiles. The semantic pre-filter uses all-MiniLM-L6-v2 to score candidates before any taint runs. |
| [**Game Engine Pattern Library**](docs/reference-modules/engine-pattern-library.md) | [1](ablation/analyzers/engine_pattern_library.py) | Identifies Unreal Engine, Unity, and custom game engine code patterns in stripped binaries so engine-specific sinks and RCE surfaces are recognized automatically. |
| [**ATT&CK Labeling**](docs/reference-modules/attandck-labeling.md) | [1](ablation/analyzers/attck_tagger.py) | Assigns MITRE ATT&CK technique IDs to findings automatically so taint and scanner results map to the ATLAS/ATT&CK framework without manual tagging. |
| [**SBOM & Supply-Chain Tooling**](docs/reference-modules/dependency-and-supply-chain-tooling.md) | [1](ablation/analyzers/sbom_extractor.py)&nbsp;[2](modules/third_party_lib_scanner.py) | Extracts a software bill of materials from a binary, fingerprints third-party libraries, and checks for dependency confusion patterns. |
| [**Binary Ninja Plugin**](docs/reference-modules/binary-ninja-plugin.md) | [1](ablation/integrations/binja_plugin.py) | Loads BinaryContext data inline in Binary Ninja and annotates disassembly with findings so the full session context is available in the Binary Ninja UI. |

</details>


## Setup & About

<details>
<summary>Install</summary>

```bash
pip install ablation-tool
```

**Requirements:** Python >= 3.10 · `capstone>=4,<5` · `numpy` · `lief` · `fastembed` · `sentence-transformers` · `pyelftools`

</details>

<details>
<summary>Claude Code Configuration</summary>

### 1. Launch Session
```bash
cd ~/ablation && claude
```

### 2. Set Model
```text
/model claude-sonnet-4-6
```
*(or `/model claude-sonnet-4-5`)*

### 3. Define Objective
```text
/goal reverse engineer [target binary, firmware image, or directory]
```

### 4. Check Effort Level
```text
/btw What effort level should we be set on right now?
```

### Recommended Autonomous Configuration (`/config`)
```text
Model                                   claude-sonnet-4-6
Thinking mode                           true
Auto-compact                            true
Continue automatically at usage limit   true
Dynamic workflows                       true
Dynamic workflow size                   unrestricted
Rewind code (checkpoints)               true
Use auto mode during plan               true
Default permission mode                 Manual
Respect .gitignore in file picker       true
Verbose output                          true
Output style                            Explanatory
Question auto-continue timeout          never
```

</details>



<details>
<summary>Acknowledgments</summary>

The code couldn't exist without their ideas. Though no code was written by these authors, doctors, and engineers, their work has direct influence on the production of code that makes Ablation what it is.

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

**Honorable Mention**

[Microsoft Excel (Data Analysis ToolPak)](https://support.microsoft.com/en-us/office/use-the-analysis-toolpak-to-perform-complex-data-analysis-6c67ccf0-f4a9-487c-8dec-bdb5a2cefab6). When analyzing closed infrastructure or securing black-box systems, this exact process is called timing analysis or telemetry reverse engineering. Without source code, the Data Analysis ToolPak mathematically deconstructs how an application works on the backend by strictly observing its inputs and outputs.

</details>

<details>
<summary>Real-World Results</summary>

Ablation has been used to analyze production firmware and kernel drivers from Cisco, IBM, TencentOS, Huawei, Fortinet, and more.

Following coordinated disclosure, the **Cisco Product Security Incident Response Team (PSIRT)** adopted Ablation for internal vulnerability triage and continues to use it to evaluate ongoing disclosure reports. Cisco Adaptive Security Appliance (ASA) LINA is among the artifacts analyzed, with findings submitted through CERT/CC VINCE.

| CVE | Product | Title | CVSS |
|---|---|---|---|
| [CVE‑2026‑76420](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) | Secure Firewall Management Center (FMC) | Peer Impersonation | **9.0 Critical** |
| [CVE‑2026‑76412](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) | Secure Firewall Management Center (FMC) | Privilege Escalation to root | **8.5 High** |
| [CVE‑2026‑76413](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) | Secure Firewall Management Center (FMC) | Single Sign-On Token Forgery | **8.5 High** |
| [CVE‑2026‑76447](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4) | Identity Services Engine (ISE) | OCSP Responder Authentication Bypass | **5.3 Medium** |

</details>

<details>
<summary>Demonstrations</summary>

### Ablation in Action

![Ablation in Action](assets/demos/Ablation-In-Action-01.gif)

### How to Use Ablation

![How to Use Ablation](assets/demos/How-To-Use-Ablation.gif)

### Learn as You RE

![Learn as You RE](assets/demos/Learn-As-You-RE.gif)

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
