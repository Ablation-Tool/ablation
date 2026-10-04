# Ablation Document Library

Semantic firmware analysis for vulnerability researchers.

---

## Getting Started

| Document | Description |
|---|---|
| [Getting Started](getting-started.md) | Install, first binary, first sweep -- 15 minutes |
| [Understanding Ablation](understanding-ablation.md) | Architecture, analysis model, limitations, and Codex workflow |

---

## Workflows

Step-by-step guides for common research tasks.

| Document | Description |
|---|---|
| [Vulnerability Hunting](workflows/vuln-hunting.md) | Full loop: sweep to confirmed finding to disclosure |
| [Cross-Version Diffing](workflows/cross-version.md) | Track a function across firmware patch releases |
| [Go Binary RE](workflows/go-binaries.md) | Stripped Go binaries: pclntab recovery, garbled builds |
| [Crypto Analysis](workflows/crypto.md) | Encrypted firmware, XOR key recovery, JWT cracking |
| [Source Code Audit](workflows/source-code-audit.md) | Compress a repo → rank files → confirm findings; full worked example |
| [KASAN-Oracle](workflows/kasan-oracle.md) | Scan KASAN debug build first; verify candidates in stripped production build |

---

## Source Code Audit

Audit any large codebase for security vulnerabilities, faster than reading it linearly and without missing coverage.

| Document | Covers |
|---|---|
| [Source Analyzers](module-reference/source-audit.md) | SourceContext, SourceAuditCompressor, SourceEntryClassifier, SourceSinkScanner, SourceIsolationChecker, SourceTaintTracker |
| [Source Code Audit Workflow](workflows/source-code-audit.md) | Clone → compress → priority reads → batch close → log findings |

---

## Module Reference

| Document | Covers |
|---|---|
| [Core Analyzers](module-reference/core.md) | BinaryContext, XRefGraph, CFGBuilder, TaintTracker, ARM64TaintTracker, PathSolver, CrossBinaryTaintTracker; StaticELF32FuncStartScanner (x86_32 stripped static func_starts); I386AbsoluteXrefScanner (x86_32 absolute-address string xref — 26× improvement over RIP-relative scanner) |
| [Encoding DAG](module-reference/encoding-dag.md) | EncodingDAG: ISA-agnostic bitfield template framework; round-trip encode/decode between raw bytes (RGB-integer packing), Encoding DAG (named fields), and Semantic DAG (SemanticOp/SemanticBlock/DataflowEdge); ISA-24 bundled 24-bit toy ISA |
| [PPC32 Taint Tracker](module-reference/ppc32-taint-tracker.md) | PPC32TaintTracker: GOT2 PIC (Huawei/embedded Linux), crclr ABI, per-function r30 map, Huawei secure-string sinks |
| [PPC32 GOT2 Resolver](module-reference/ppc32-got2-resolver.md) | PPC32GOT2Resolver: resolve 15k+ indirect BCTRL calls in stripped GOT2-PIC binaries; 98.6% resolution on S6720EI bootload |
| [PPC32 PLT Tracer](module-reference/ppc32-plt-tracer.md) | PPC32PLTTracer: verified import caller finder for PPC32 BE .so files; r30 cross-check eliminates cross-CU false positives; batch_scan + PPC32ELF helper |
| [HiSilicon RV32 Extension](module-reference/hisi-rv32-ext.md) | HiSiliconRV32ExtDecoder: 6-opcode-space + uxtb/uxth decoder for HiSilicon riscv31 (WS63/Hi3863/BS21); ldmia/stmia (0x0b), uxtb/uxth (16-bit), l.li (0x1f 6-byte), muliadd/addshf/branches |
| [Semantic Search](module-reference/semantic-search.md) | SemanticSearcher, CorpusBuilder, PatternLibrary |
| [Vulnerability Scanners](module-reference/vuln-scanners.md) | FormatStringScanner, HeapVulnScanner (INT_OVERFLOW, UAF, double-free, off-by-one), SqlSinkScanner (mysql_query/sqlite3 injection), GoSubprocessScanner (Go os/exec injection; x86-64 full / arm64 call-site detection) |
| [CMDB Surface Mapper](module-reference/cmdb-surface-mapper.md) | CMDBSurfaceMapper: forward-taint CMDB table→exec-sink surface map for FortiWeb/FortiOS; Phase 0.5 of Fortinet RE methodology; co-location triage before TaintTracker |
| [PE32 Sweep](module-reference/pe-sweep.md) | pe_sweep.py: Windows PE32 (i386) semantic vulnerability sweep; IAT call resolution; QuickTime/Win32 profiles |
| [Windows Kernel Drivers](module-reference/kernel-drivers.md) | KernelDriverAnalyzer, ByovdDetector: IOCTL surface, 8 capability classes |
| [Erlang / BEAM](module-reference/beam.md) | BeamContext: exports, imports, atoms, literals, dangerous import sweep |
| [Signature Matching](module-reference/sig-library.md) | SigLibrary, auto-naming fn_0x* functions |
| [Export Formats](module-reference/export.md) | SARIF 2.1.0, JSON, GitHub Code Scanning |
| [Registry](module-reference/registry.md) | NameRegistry, FindingRegistry, `export_patterns()`, `ingest_from_registry()` flywheel |
| [Crypto](module-reference/crypto.md) | CryptoAudit, XorSolver, EntropyMapper, HashAlgoDiscriminator, CustomCBCDetector |
| [Structural](module-reference/structural.md) | VtableResolver (ARM64), VersionDelta, StructuralSim |
| [x86-64 Vtable Analysis](module-reference/vtable-x86-64.md) | ELFVtableReconstructor (.rela.dyn slot reconstruction), VtableDispatchScanner (dead/live method detection) |
| [Firmware Containers](module-reference/firmware-containers.md) | FirmwareContainer (partitioned image parser + payload detection), VideoContainerAnalyzer (MP4/MKV/AVI forensics) |
| [Android / APK](module-reference/android.md) | APKParser (AXML+DEX), DexAnalyzer, JniBridgeScanner (JNI_OnLoad/Java_*/opaque peer), BinderScanner (exported services, AIDL Stubs, onTransact), LibraryInventory (native .so scanner: arch, exports, JNI count, PLT hook detection, security score, classify_internals) |
| [SPU Disassembler](module-reference/spu-disassembler.md) | Cell BE SPU (PS3) instruction decoder: all formats (RRR/RI18/RI16/RI10/RR/RI7), confirmed opcode table, frequency/coverage report, embedded SPU ELF extraction |
| [HarmonyOS / ArkTS](module-reference/harmonyos.md) | ABCParser (Ark Bytecode v9–v13+): header, class walk, method iteration, CodeItem (ULEB128), native/string queries; ARKDisasm: 324-opcode ISA, smali output, call/string-load queries; ABCDecompiler: JS-like pseudocode, accumulator tracking, property/global name resolution via method_idx |
| [LLM Analyst](module-reference/llm.md) | LlmAnalyst ReAct agent loop |
| [LoongArch64](module-reference/loongarch64.md) | LoongArch64TaintTracker (`from_path` / `from_path_full`), LoongArchDecoder, ISA model, CFG builder, DWARF/BTF enrichment, syscall tracking, kernel escalation — TencentOS 4.6 / Loongson 3A5000 |

---

## Integrations

| Document | |
|---|---|
| [Claude Code](integrations/claude-code.md) | Using Ablation inside a Claude Code session |
| [Binary Ninja](integrations/binja.md) | Plugin installation and commands |

---

## Release Notes

See [CHANGELOG.md](../CHANGELOG.md) for full version history.

| Version | Summary |
|---|---|
| v2.39.0 | WindowAnalyzer: PPC32/PPC64 big-endian support — `_elf_arch()` respects EI_DATA byte order; `_cs()` emits Capstone PPC decoder; `_build_plt_ppc32_bss()` recovers BSS PLT stub→symbol map via BL scan + `.rela.plt` index correlation |
| v2.38.0 | PPC32PLTTracer: SYSV PIC BSS PLT support — `_is_bss_plt()` detection, `bss_plt_stub_map()` with cached stub map, `_find_callers_bss_plt()` direct BL scan path; GOT2-PIC path unchanged |
| v2.37.0 | PPC32TaintTracker: `_load_plt_from_dynsym_raw()` now gated by `if not self._plt:` — prevents BSS PLT SYSV PIC binaries from having their correct LIEF-populated PLT map corrupted by zero st_value dynsym entries |
| v2.36.0 | PPC32GOT2Resolver: two hardening fixes — per-function r30 floor (`fn_starts` param) + GOT2 range validation (`got2_va`/`got2_size`); both backward-compatible |
| v2.35.0 | PPC32GOT2Resolver: resolve indirect BCTRL calls in GOT2-PIC stripped binaries; 15120/15339 (98.6%) on S6720EI bootload; handles LWZ/LWZU/LWZX/direct patterns; zero unknowns |
| v2.34.0 | PPC32TaintTracker: GOT2 PIC support (Huawei/embedded Linux) — r30 map, crclr ABI fix, LIEF vendor-reloc bypass, LWZ stale-taint fix, 8 new sinks |
| v2.15.0 | HashAlgoDiscriminator and CustomCBCDetector: ARM32 hash-algorithm identification and hand-rolled CBC detection from disassembly |
| v2.14.3 | `BinaryContext` kernel-space VA fix: `_va_to_i64()` / `_va_arr_to_i64()` ctypes bit-cast helpers; 6 call sites fixed |
| v2.14.1–2 | FindingRegistry/PatternLibrary flywheel hardening: 13 bugs fixed (thread safety, lock upgrade, tag filter, double-save, Unicode edge cases) |
| v2.13.0 | ZIM-BERT distillation: teacher-student fine-tuning for cross-version binary similarity |
| v2.12.0 | ELFVtableReconstructor (.rela.dyn slot reconstruction), VtableDispatchScanner (dead/live virtual method detection) |
| v2.11.0 | BmpKeyExtractor: BMP LSB steganography, Lagrange secret sharing key recovery |
| v2.10.0 | DEXLifter: pseudo-Java IR lifter with type inference, field dot-notation, invoke formatting, if/else labels |
| v2.9.0 | DEXDisasm: all 17 DEX instruction formats, smali output, full reference annotation from DEX flat tables |
| v2.8.0 | SqlSinkScanner: MySQL C API / SQLite3 SQL injection detection in ELF binaries |
| v2.7.0 | APKParser (AXML+DEX+ACC_NATIVE), JniBridgeScanner (JNI_OnLoad/Java_*/opaque peer), BinderScanner (exported services, AIDL Stubs, onTransact), android_sweep.py |
| v2.6.0 | FirmwareContainer partitioned image parser, VideoContainerAnalyzer MP4/MKV/AVI forensics |
| v2.5.0 | FormatStringScanner fortify variants, IoctlAttackSurfaceGenerator, CrossBinaryTaintTracker, BYOVDDetector PDB fingerprints |
| v2.4.0 | MIPS32TaintTracker, HeapVulnScanner (INT_OVERFLOW/UAF/double-free/off-by-one) |
| v2.3.0 | BYOVDDetector 8-path scoring, SSDT/CR0/CR4/token-steal/APC primitives |
| v2.0.0 | KernelDriverAnalyzer: IRP/IOCTL dispatch, 40+ API risk classes, SMEP/CR0 scan |
| v1.8.0 | NameRegistry overlay, FindingRegistry, PatternLibrary self-improvement loop |
| v1.7.0 | LlmAnalyst ReAct agent, TaintTracker x86-64, PathSolver |
| v1.6.0 | VtableResolver ARM64, VersionDelta CFG shape diffing |
| v1.5.0 | BERT semantic search (SemanticSearcher), CorpusBuilder |
| v1.4.0 | XRefGraph, vectorized RIP-relative xref index in BinaryContext |
| v1.3.0 | Installable package (ablation.analyzers.*), BinaryContext SHA256 cache |
