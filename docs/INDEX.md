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
| [Fortinet Firmware](workflows/fortinet-firmware.md) | Two-layer decryption, shared key corpus, and semantic sweep for Fortinet `.out` images |

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
| [Core Analyzers](module-reference/core.md) | BinaryContext, XRefGraph, CFGBuilder, TaintTracker, ARM64TaintTracker, PathSolver, CrossBinaryTaintTracker; StaticELF32FuncStartScanner (x86_32 stripped static func_starts); I386AbsoluteXrefScanner (x86_32 absolute-address string xref: 26× improvement over RIP-relative scanner) |
| [Encoding DAG](module-reference/encoding-dag.md) | EncodingDAG: ISA-agnostic bitfield template framework; round-trip encode/decode between raw bytes (RGB-integer packing), Encoding DAG (named fields), and Semantic DAG (SemanticOp/SemanticBlock/DataflowEdge); ISA-24 bundled 24-bit toy ISA |
| [PPC32 Taint Tracker](module-reference/ppc32-taint-tracker.md) | PPC32TaintTracker: GOT2 PIC (Huawei/embedded Linux), crclr ABI, per-function r30 map, Huawei secure-string sinks |
| [x86-32 Taint Tracker](module-reference/x86-32-taint-tracker.md) | X86_32TaintTracker: i386 CDECL32; PIC+non-PIC PLT stub resolution; push-based call-site arg tracking; Acronis rescue env (asamba, product.bin) |
| [PPC32 GOT2 Resolver](module-reference/ppc32-got2-resolver.md) | PPC32GOT2Resolver: resolve 15k+ indirect BCTRL calls in stripped GOT2-PIC binaries; 98.6% resolution on S6720EI bootload |
| [PPC32 PLT Tracer](module-reference/ppc32-plt-tracer.md) | PPC32PLTTracer: verified import caller finder for PPC32 BE .so files; r30 cross-check eliminates cross-CU false positives; batch_scan + PPC32ELF helper |
| [PEF ABI Clobber Scanner](module-reference/pef-abi-clobber-scanner.md) | PEFABIClobberScanner: PPC32 PEF ABI register clobber detector for Mac OS 8/9 CFM binaries; backward-walk from sink BL; built on encoding_dag Templates; fixes ori RA-field, addic opcode 12, b/ba boundary bugs |
| [HiSilicon RV32 Extension](module-reference/hisi-rv32-ext.md) | HiSiliconRV32ExtDecoder: 6-opcode-space + uxtb/uxth decoder for HiSilicon riscv31 (WS63/Hi3863/BS21); ldmia/stmia (0x0b), uxtb/uxth (16-bit), l.li (0x1f 6-byte), muliadd/addshf/branches |
| [Semantic Search](module-reference/semantic-search.md) | SemanticSearcher.from_context(ctx) scopes corpus to one binary (26x faster first build); CorpusBuilder, PatternLibrary |
| [Vulnerability Scanners](module-reference/vuln-scanners.md) | FormatStringScanner, HeapVulnScanner (INT_OVERFLOW, UAF, double-free, off-by-one), SqlSinkScanner (mysql_query/sqlite3 injection), GoSubprocessScanner (Go os/exec injection; x86-64 full / arm64 call-site detection) |
| [Sink Arg Classifier](module-reference/sink-arg-classifier.md) | SinkArgClassifier: exec-sink argument provenance (RODATA_CONST/SNPRINTF_RODATA/ARG_PROPAGATED/UNKNOWN); x86-64 classification + ARM32/ARM64 batch_plt_intersect triage; GAP-002 GCC packed-string fix |
| [CMDB Surface Mapper](module-reference/cmdb-surface-mapper.md) | CMDBSurfaceMapper: forward-taint CMDB table→exec-sink surface map for FortiWeb/FortiOS; Phase 0.5 of Fortinet RE methodology; co-location triage before TaintTracker |
| [PE Sweep](module-reference/pe-sweep.md) | pe_sweep.py: Windows PE i386+AMD64 semantic vulnerability sweep; IAT call resolution; RIP-relative x64 resolution; QuickTime/Win32 profiles; GAP-015 FirmwareAuthBypassProfile (unsigned-flasher CWE-347 detector); GAP-016 BorlandVCLStringIndex (.data fallback for BCC32/VCL targets) |
| [Windows Kernel Drivers](module-reference/kernel-drivers.md) | KernelDriverAnalyzer, ByovdDetector: IOCTL surface, 8 capability classes |
| [Erlang / BEAM](module-reference/beam.md) | BeamContext: exports, imports, atoms, literals, dangerous import sweep |
| [Signature Matching](module-reference/sig-library.md) | SigLibrary, auto-naming fn_0x* functions |
| [Export Formats](module-reference/export.md) | SARIF 2.1.0, JSON, GitHub Code Scanning |
| [Registry](module-reference/registry.md) | NameRegistry, FindingRegistry, `export_patterns()`, `ingest_from_registry()` flywheel |
| [Crypto](module-reference/crypto.md) | CryptoAudit, XorSolver, EntropyMapper, HashAlgoDiscriminator, CustomCBCDetector |
| [Structural](module-reference/structural.md) | VtableResolver (ARM64), VersionDelta, StructuralSim |
| [x86-64 Vtable Analysis](module-reference/vtable-x86-64.md) | ELFVtableReconstructor (.rela.dyn slot reconstruction), VtableDispatchScanner (dead/live method detection) |
| [C++ Vtable Reconstructor](module-reference/cpp-vtable-reconstructor.md) | CppVtableReconstructorAnalyzer: any-arch vtable extraction (RELA + byte scan), slot naming via exports/string-xref/callees, x86-64 + ARM64 call-site tracing, IDAPython set_type script emitter |
| [PS3 OPD Vtable Scanner](module-reference/ps3-opd-vtable-scanner.md) | PS3OPDVtableScanner: PPC64 ABI v1 OPD two-level indirection (vtable_ptr→OPD→code_va); dense-run scan; dual-TOC support via explicit toc=; inject_into_context; string-proximity class hints |
| [Firmware Containers](module-reference/firmware-containers.md) | FirmwareContainer (partitioned image parser + payload detection), VideoContainerAnalyzer (MP4/MKV/AVI forensics) |
| [Huawei Squashfs Extractor](module-reference/huawei-squashfs-extractor.md) | HuaweiSquashfsExtractor: pure-Python squashfs v4 XZ reader; ARM64 BCJ filter bypass via FORMAT_RAW; Huawei VRP V600R024+ (S6750-H confirmed) |
| [Android / APK](module-reference/android.md) | APKParser (AXML+DEX), DexAnalyzer, JniBridgeScanner (JNI_OnLoad/Java_*/opaque peer), BinderScanner (exported services, AIDL Stubs, onTransact), LibraryInventory (native .so scanner: arch, exports, JNI count, PLT hook detection, security score, classify_internals) |
| [SPU Disassembler](module-reference/spu-disassembler.md) | Cell BE SPU (PS3) instruction decoder: all formats (RRR/RI18/RI16/RI10/RR/RI7), confirmed opcode table, frequency/coverage report, embedded SPU ELF extraction |
| [HarmonyOS / ArkTS](module-reference/harmonyos.md) | ABCParser (Ark Bytecode v9–v13+): header, class walk, method iteration, CodeItem (ULEB128), native/string queries; ARKDisasm: 324-opcode ISA, smali output, call/string-load queries; ABCDecompiler: JS-like pseudocode, accumulator tracking, property/global name resolution via method_idx |
| [LLM Analyst](module-reference/llm.md) | LlmAnalyst ReAct agent loop |
| [LoongArch64](module-reference/loongarch64.md) | LoongArch64TaintTracker (`from_path` / `from_path_full`), LoongArchDecoder, ISA model, CFG builder, DWARF/BTF enrichment, syscall tracking, kernel escalation; TencentOS 4.6 / Loongson 3A5000 |
| [Scan Result Version Cache](module-reference/scan-result-version-cache.md) | ScanResultVersionCache: wraps any scanner with `from_path(path).scan()`; caches results by (scanner source hash, file mtime, size, sha256 prefix); cache hit uses stat only, no file read; invalidates automatically on scanner or file change |
| [Kernel Module Subsystem Classifier](module-reference/kernel-module-subsystem-classifier.md) | KernelModuleSubsystemClassifier: infers attack surface from .ko file path in standard `lib/modules/<version>/kernel/` layout; returns PROXIMITY/NETWORK/NETWORK-cluster/LOCAL-USB/LOCAL-HARDWARE-*/LOCAL-DEV-ACCESS; 26 rules, most-specific first |
| [FORGE](module-reference/forge.md) | FORGE.audit_module(path): cache hit returns ForgeReport instantly; cache miss raises ForgeAuditRequired: perform 10-section SAFE CODE audit inline as Claude Code, then call FORGE.record_result() to cache; no subprocess, no API key; gate_passed=False blocks on any HIGH/CRITICAL |
| [CFG Bypass Detector](module-reference/cfg-bypass-detector.md) | CFGBypassDetector: reads IMAGE_LOAD_CONFIG GuardFlags + CFG function table; cross-references exports against table; flags cfg_disabled (HIGH), no_export_suppression (MEDIUM), export_not_in_table (MEDIUM per export); x86+x64 PE |
| [SEH Chain Analyzer](module-reference/seh-chain-analyzer.md) | SEHChainAnalyzer: x86-32 PE only; reads SafeSEH handler table; scans code for push-handler/push-FS:[0] SEH frame setup; cross-references handlers against SafeSEH table; safesh_disabled (HIGH), handler_not_in_table (MEDIUM) |
| [ETW Provider Extractor](module-reference/etw-provider-extractor.md) | ETWProviderExtractor: finds EventRegister call sites; extracts provider GUIDs (RCX/LEA for x64, push for x86); cross-references against 15 known security providers; detection gap when zero EventWrite sites found |
| [RPC Server Analyzer](module-reference/rpc-server-analyzer.md) | RPCServerAnalyzer: finds RpcServerRegisterIf* call sites; reads RPC_SERVER_INTERFACE struct for interface UUID + transfer syntax; extracts auth level from RegisterIfEx; flags RPC_C_AUTHN_LEVEL_NONE as HIGH (CWE-306); extracts endpoint strings |
| [COM Attack Surface Mapper](module-reference/com-attack-surface-mapper.md) | COMAttackSurfaceMapper: detects COM server exports (DllGetClassObject); scans data sections for CLSID GUIDs; finds CoCreateInstance call sites with resolved CLSIDs; flags COM hijacking risk (MEDIUM, CWE-426); detects marshaling + IDispatch |
| [PDB Symbol Integrator](module-reference/pdb-symbol-integrator.md) | PDBSymbolIntegrator: reads CodeView RSDS debug entry for PDB GUID+age; fetches PDB from Microsoft symbol server; parses MSF 7.0 container + public symbols stream (S_PUB32); injects names into BinaryContext via set_name(source='pdb') |
| [Windows Pool Taint Tracker](module-reference/windows-pool-taint-tracker.md) | WindowsPoolTaintTracker: finds ExAllocatePool* call sites; extracts size arg (RDX in x64 fastcall); finds RtlCopyMemory/memmove copy sinks; pairs alloc+copy sites sharing same size register; flags unvalidated propagation as HIGH (CWE-122) |
| [BinaryContext](module-reference/binary-context.md) | BinaryContext: pre-computed context cache (PLT/IAT, exports, strings, func_starts, call_edges) for ELF and Windows PE; load_or_build() auto-detects format; every Ablation tool works on PE/.sys without code changes; callers_of()/callees_of()/strings_in_func() all populated for PE |
| [ECU Calibration Parsers](module-reference/ecu-cal-parsers.md) | EcuXDFParser (TunerPro XDF XML), EcuOpenDamosParser (open_damos.json with fingerprint relocation), CalibrationTable/CalibrationAxis shared dataclasses; label_map() for BinaryContext injection; tested on BMW N54 MSD80 (755 tables) and Bosch EDC16C34 PSA diesel |
| [ECU M68K Decoder](module-reference/ecu-m68k-decoder.md) | EcuM68kDecoder: M68K/CPU32 Capstone wrapper with function_starts() for GM P-series ECU ROMs; LINK.W A6,#-N prologue scan; M68kInsn with insn_type/target; CPU32 is 68020 subset; confirmed on GM P01/P04/P05/P08/P10/P11/P59 corpus |
| [PS3 SELF Decryptor](module-reference/ps3-self-decryptor.md) | PS3SELFDecryptor: decrypt PS3 SELF (Signed ELF, SCE magic 0x53434500) to plain ELF inside a Python pipeline; 3-stage AES (256-CBC metadata_info + 128-CTR headers + 128-CTR per section); auto-detect keyset from key_rev field; `decrypt_to_tmp()` → path for BinaryContext.load_or_build(); `from_key_rev(rev)` for explicit keyset; replaces manual scetool invocation; GoldenEye 007 Reloaded (BLUS30755) validated |
| [ECU SH-2A Decoder](module-reference/ecu-sh2a-decoder.md) | EcuSH2aDecoder: Renesas SH-2A (SH7058/SH7059) pure-Python decoder; 16-bit SH-2 base ISA + 32-bit SH-2A extensions (MOVI20/MOVI20S/MOV12/BIT); length discrimination from first halfword; function_starts() via STS.L PR,@-R15 (0x4F22) + leaf STS PR,Rn; STORE/LOAD tagging for MOV.L Rm,@-R15 / MOV.L @R15+,Rn; BSR/JSR/BRA/BT/BF branches; PC-relative loads; Honda CBR250RR validated; Capstone has no SH-2A support |
| [ECU VLE Decoder](module-reference/ecu-vle-decoder.md) | EcuVLEDecoder: PPC VLE / SE16 instruction decoder for NXP e200z4/z6/z7 ECU ROMs (GM E39a/E54/E92); 16-bit SE and 32-bit VLE instruction decoding; CIA-relative branch targets; function_starts() via e_stwu r1,-N(r1) and se_mflr r0 prologue scanning; Capstone does not decode VLE; validated on GM E39a MPC5566 corpus |
| [ECU ROM Layout Analyzer](module-reference/ecu-rom-layout-analyzer.md) | EcuROMLayoutAnalyzer: entropy-based arch-agnostic ROM region classifier; four-variable decision (entropy + fill ratio + entropy floor + PPC density); ERASED/CODE/CALIBRATION/MIXED/PADDING; `is_calibration_only()` detects OBD cal-only dumps (EDC16C34 confirmed); validated on GM E38 PCM (PPC32) and Bosch EDC16C34 |
| [ECU Security Access Scanner](module-reference/ecu-security-access-scanner.md) | EcuSecurityAccessScanner: static-seed SecurityAccess handler fingerprinter; M68K/CPU32 pattern (move.b #$67 + 2x clr.b) and PPC32 pattern (li rX,0x67 + stb + 2x zero li+stb); confirmed GM P01/P04/P05/P08/P10/P11/P59 (CPU32) and GM E38 (PPC32) |
| [ECU RomRaider Parser](module-reference/ecu-romraider-parser.md) | EcuRomRaiderParser: RomRaider ECU definition XML parser; two-pass base+variant inheritance model; identify_rom() with ±32-byte window + hex-address fallback + false-positive table-count filter; 14 scaling expression forms; BMW Siemens MS43/MS45 (MPC555 PPC32) + Subaru SH705x; self-contained ROM support for Subaru 5EAT TCU M32R (273 tables, 160 MAP) |
| [ECU Conescan Parser](module-reference/ecu-conescan-parser.md) | EcuConescanParser: ConnorRigby conescan XML parser for Mazda SH705x/SH7055 ECUs; single-ROM format with global named scaling dictionary; identify_rom() by internalidstring search; is_float propagation for float32 storagetype; 507 tables from MX5 LFG2EE |
| [ECU A2L Parser](module-reference/ecu-a2l-parser.md) | EcuA2LParser: ASAM/ASAP2 A2L calibration definition parser; Latin-1 text; RAT_FUNC/LINEAR/IDENTICAL COMPU_METHOD coefficient reduction; RECORD_LAYOUT type resolution; A2ML and IF_DATA block stripping; 11,427 tables from Bosch EDC16U34; 26,016 tables from Bosch EDC17CP46; byte order auto-detected from BYTE_ORDER keyword |
| [ECU Nissan Parser](module-reference/ecu-nissan-parser.md) | EcuNissanParser: Pytrex Nissan ECU definition parser; three-level inheritance (ScalingData.xml library + A2L.xml structure + variant address overlays); child-first chain resolution; tolerant XML parsing for truncated ScalingData.xml; 273 scalings, 188 variants (350Z/G35/Altima/Maxima/Sentra/Skyline + 12 more models); per-table X/Y Axis address overrides |
| [CAN DBC Parser](module-reference/can-dbc-parser.md) | CanDbcParser: CAN DBC signal database parser (Vector/PEAK format); 11-bit standard + 29-bit extended frames (J1939); two-pass: BO_/SG_ message+signal definitions, then CM_/VAL_ comments+value tables; `CANSignal.decode(raw)` for physical conversion; find_signals() substring search; BMW E39/E90 + SAE J1939 validated |

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
| v2.60.0 | PS3SELFDecryptor: PS3 SELF (Signed ELF) decryptor; 3-stage AES pipeline (256-CBC metadata_info, 128-CTR metadata+headers, 128-CTR per-section); key_rev auto-detect; decrypt_to_tmp() feeds BinaryContext.load_or_build(); from_key_rev() for explicit keyset; GoldenEye BLUS30755 (key_rev=0x0016) validated; replaces manual scetool invocation in RE pipeline |
| v2.59.0 | EcuSH2aDecoder: Renesas SH-2A (SH7058/SH7059) pure-Python decoder; 16-bit SH-2 base + 32-bit SH-2A extensions (MOVI20/S, MOV d12, BIT ops); length discrimination; function_starts() via STS.L PR,@-R15 + leaf STS PR,Rn; PUSH/POP stack ops tagged STORE/LOAD; BSR/JSR/BRA/BT/BF; PC-relative loads; Honda CBR250RR validated; FORGE: 4 HIGH/MEDIUM findings fixed (2 wrong bit masks, 1 missing SH2aInsn field, 1 wrong register extraction), 1 LOW dead variable |
| v2.58.0 | EcuM68kDecoder: M68K/CPU32 Capstone wrapper; function_starts() via LINK.W A6,#-N prologue scan; M68kInsn insn_type/target; CPU32 = 68020 subset; GM P01/P04/P05/P08/P10/P11/P59 corpus validated |
| v2.58.0 | PS3OPDVtableScanner: PS3 Cell PPU PPC64 ABI v1 OPD two-level vtable scanner; dense-run scan in data segment; OPD→code_va resolution; RTTI header detection; string-proximity class hints; inject_into_context; find_by_method_name; dual-TOC documented; FORGE: 2 findings fixed (dead NULL_TOC_TOLERANCE attr removed; report() null-slot filter corrected to slot-index) |
| v2.57.0 | EcuVLEDecoder: NXP e200z4/z6/z7 PPC VLE/SE16 pure-Python decoder; length discrimination via (byte0 & 0x90)==0x10; SE16 coverage (se_blr/mflr/mtlr/b/bl/bc/li/lwz/stw + SD4 + SE_R/RR/IM5); 32-bit VLE (e_stwu, e_b/bl, e_lwz/stw/lbz/stb/lha/lhz, e_add16i, e_li LI20, e_stmw/lmw); CIA-relative branch targets; function_starts() (e_stwu + se_mflr dual pattern); GM E39a MPC5566 validated |
| v2.56.0 | EcuSecurityAccessScanner: M68K/CPU32 and PPC32 static-seed SA handler fingerprinter; confirmed GM P01/P04/P05/P08/P10/P11/P59 (CPU32) and GM E38 (PPC32); ROMLayout.is_calibration_only() OBD cal-only dump guard (EDC16C34 confirmed) |
| v2.55.0 | CanDbcParser: CAN DBC signal database parser; 11-bit standard + 29-bit extended frames (J1939 bit-31 detection); two-pass parsing for CM_ comments and VAL_ value tables; CANSignal.decode() for raw-to-physical; BMW E39/E90 + SAE J1939 validated (250.0 rpm EEC1 EngineSpeed confirmed) |
| v2.54.0 | EcuNissanParser: Pytrex Nissan three-level ECU definition parser; ScalingData.xml (273 scalings) + A2L.xml structure + variant address overlays; child-first chain resolution; tolerant XML recovery for truncated ScalingData.xml; 188 variants across 18 models; per-table X/Y Axis address overrides from CD415-style variants |
| v2.53.0 | EcuRomRaiderParser: self-contained ROM support via _maybe_synthesize_self_variant(); synthesizes a pseudo-variant from the base when all tables carry inline storageaddress; covers Subaru 5EAT TCU M32R (273 tables, 160 MAP, 42 CURVE); hex internalidaddress fix in _parse_variant() |
| v2.52.0 | EcuA2LParser: ASAM/ASAP2 A2L parser for Bosch EDC16/EDC17 and any A2L-compliant definition file; RAT_FUNC COEFFS reduction to scale/bias; RECORD_LAYOUT type resolution; A2ML + IF_DATA block stripping; byte order from BYTE_ORDER keyword; 11,427 tables from EDC16U34, 26,016 from EDC17CP46 |
| v2.51.0 | EcuConescanParser: single-ROM conescan XML parser for Mazda SH705x/SH7055 ECUs (507 tables, MX5 + RX8); global named scaling dictionary; identify_rom() by internalidstring; is_float propagation; FORGE hardening across all 5 ECU analyzers: eval() removed from eval_math_equation(), float struct format fix, stale relocated_address reset, skip counter in EcuXDFParser, axis_little_endian rename |
| v2.50.0 | EcuRomRaiderParser: two-pass RomRaider XML parser; identify_rom() with hex-address fallback + table-count false-positive filter; 14 scaling expression forms; BMW MS43/MS45 + Subaru SH705x; `Optional` import fix in EcuROMLayoutAnalyzer |
| v2.49.0 | ECU calibration analysis: EcuXDFParser (TunerPro XDF), EcuOpenDamosParser (open_damos.json + fingerprint relocation), EcuROMLayoutAnalyzer (entropy+fill+PPC-density four-variable ROM classifier), CalibrationTable/CalibrationAxis shared dataclasses |
| v2.46.0 | BinaryContext PE support: load_or_build() works on .exe/.dll/.sys; _build_pe() + _detect_arch_pe() + 7 helper methods; IAT as PLT; prologue scan for func_starts; vectorized 0xe8 call graph; RIP-relative xref index; ELF path unchanged |
| v2.45.0 | BinaryLifter: 13 new ISA decompiler backends (x86_32, arm32, mips32/64, nanomips, ppc32/64, rv32/64, arc, v850, la64, beam); _walk_ablation_cfg() shared BFS helper |
| v2.44.0 | Windows PE security suite: CFGBypassDetector (GuardFlags + export table cross-reference), SEHChainAnalyzer (x86 SafeSEH table + frame scan), ETWProviderExtractor (provider GUIDs + detection gap), RPCServerAnalyzer (interface UUID + auth level + endpoint strings), COMAttackSurfaceMapper (server detection + CLSID scan + hijack risk), PDBSymbolIntegrator (MSF parser + msdl fetch + NameRegistry injection), WindowsPoolTaintTracker (ExAllocatePool size → RtlCopyMemory taint) |
| v2.43.0 | FORGE: result cache (sha256-keyed, ~/.ablation/forge_cache.json, instant hit); ForgeAuditRequired exception replaces subprocess: audits run inline as Claude Code, no subprocess, no API key; FORGE.record_result() stores inline results; removed dead Anthropic SDK path |
| v2.42.0 | ScanResultVersionCache: scanner result cache keyed on source hash + file fingerprint; fast stat-only hit path; KernelModuleSubsystemClassifier: attack surface from .ko path (26 rules: PROXIMITY/NETWORK-cluster/LOCAL-USB/etc.) |
| v2.41.0 | CppVtableReconstructorAnalyzer: any-arch vtable extraction (RELA + byte scan), slot naming (export/string-xref/callee), x86-64 + ARM64 call-site tracing, IDAPython set_type script emitter |
| v2.39.0 | WindowAnalyzer: PPC32/PPC64 big-endian support; `_elf_arch()` respects EI_DATA byte order; `_cs()` emits Capstone PPC decoder; `_build_plt_ppc32_bss()` recovers BSS PLT stub→symbol map via BL scan + `.rela.plt` index correlation |
| v2.38.0 | PPC32PLTTracer: SYSV PIC BSS PLT support; `_is_bss_plt()` detection, `bss_plt_stub_map()` with cached stub map, `_find_callers_bss_plt()` direct BL scan path; GOT2-PIC path unchanged |
| v2.37.0 | PPC32TaintTracker: `_load_plt_from_dynsym_raw()` now gated by `if not self._plt:`: prevents BSS PLT SYSV PIC binaries from having their correct LIEF-populated PLT map corrupted by zero st_value dynsym entries |
| v2.36.0 | PPC32GOT2Resolver: two hardening fixes; per-function r30 floor (`fn_starts` param) + GOT2 range validation (`got2_va`/`got2_size`); both backward-compatible |
| v2.35.0 | PPC32GOT2Resolver: resolve indirect BCTRL calls in GOT2-PIC stripped binaries; 15120/15339 (98.6%) on S6720EI bootload; handles LWZ/LWZU/LWZX/direct patterns; zero unknowns |
| v2.34.0 | PPC32TaintTracker: GOT2 PIC support (Huawei/embedded Linux); r30 map, crclr ABI fix, LIEF vendor-reloc bypass, LWZ stale-taint fix, 8 new sinks |
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
