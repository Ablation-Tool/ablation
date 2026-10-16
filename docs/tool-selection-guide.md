# Ablation — Tool Selection Guide

Task-to-tool lookup. For constructor patterns and key methods, see `docs/module-reference/`.

**Ordering:** BinaryContext → SemanticSearcher (new binary/vuln class) → FuncProfiler (candidate) → **SinkArgClassifier** (eliminate RODATA_CONST first) → TaintTracker (ARG_PROPAGATED/UNKNOWN sinks only) → PathSolver (confirm feasibility). Manual capstone only when TaintTracker has no configured sink. For targets with a Perl scripting layer, run `PerlTaintScanner` in parallel with TaintTracker — it is independent of BinaryContext.

---

## Core context + search

| Task | First reach |
|---|---|
| "What does this function call?" | `ctx.callees_of(va)` |
| "What calls this symbol?" | `ctx.callers_of('symbol')` or `ctx.callers_of(va)` |
| "What strings does this function reference?" | `ctx.strings_in_func(va)` |
| "Which functions reference this string?" | `ctx.funcs_referencing_string(string_va)` |
| "strings_in_func() returns almost nothing on a stripped i386 ELF32" | `I386AbsoluteXrefScanner.from_context(ctx).inject(ctx)` |
| "What is this function?" | `ctx.name(va)` |
| "Show disassembly around address" | `WindowAnalyzer.dump_text(va, window=1536)` |
| "Find functions matching vulnerability pattern" | `SemanticSearcher.query(description)` (ALWAYS first on new binary) |
| "Binary not in func_id.db (SemanticSearcher slow/global fallback)" | `SemanticSearcher.ingest_binary(ctx)` — auto-called by `from_context` on miss; or call manually with `product=`, `arch=`, `version=` metadata |
| "What values are passed to this sink?" | `FuncProfiler.profile(va).fmt()` |
| "Trace taint from network recv to sink" | `TaintTracker.run_interprocedural()` |

---

## Arch-specific taint trackers

| Task | First reach |
|---|---|
| "ARM32: trace recv to malloc/strcpy/system" | `ARM32TaintTracker.from_context(ctx).run_interprocedural()` |
| "ARM32: find function starts in stripped ELF without .eh_frame" | `ARM32FunctionScanner.from_path(elf).inject_into_context(ctx)` |
| "ARM32: find MUL before malloc without bounds check" | `ARM32IntOverflowScanner.from_context(ctx).scan()` |
| "ARM64: trace recv to malloc/strcpy/system" | `ARM64TaintTracker.from_path_full(elf).run_interprocedural()` |
| "MIPS32: trace recv to system/strcpy/sprintf" | `MIPS32TaintTracker.from_path(elf).run_interprocedural()` |
| "MIPS32: big-endian RouterOS or little-endian CPE" | `MIPS32TaintTracker.from_path(elf, endian='big')` |
| "MIPS64: trace recv (Cisco IOS/OCTEON big-endian)" | `MIPS64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "MIPS64: little-endian RouterOS 64" | `MIPS64TaintTracker.from_path(elf, endian='little').run_interprocedural()` |
| "nanoMIPS: trace recv to system/popen/sprintf" | `NanoMIPSTaintTracker.from_path(elf, endian='little').run_interprocedural(depth=4)` |
| "PPC32: trace recv (Cisco IOS 7200, VxWorks)" | `PPC32TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "PPC32 PEF: detect ABI register clobber at OTStrCat/OTMemcpy call sites" | `PEFABIClobberScanner.from_bytes(code, base_va).scan(sink_vas, check_regs=[4])` |
| "PPC32: resolve indirect BCTRL calls in GOT2-PIC stripped binary" | `PPC32GOT2Resolver.from_path(elf).resolve()` |
| "PPC32 .so: find every BL call site calling an imported symbol" | `PPC32PLTTracer.from_path(elf).find_callers('system')` |
| "PPC32 XCOFF/ELF: detect heap slot overflow (mulli+malloc+strcpy, no size check)" | `PPC32HeapSlotScanner(binary_path).scan()` |
| "VxWorks static archive: scan all .o files for stack-frame strcpy patterns" | `VxWorksArchiveScanner(archive_path).scan_strcpy_in_frame()` |
| "Scan binary for unpatched CVE byte patterns (bundled libxml2, etc.)" | `CVEScanner(binary_path).scan()` |
| "PPC64le ELF V2: get PLT stub VAs and symbol names" | `BinaryContext.load_or_build(elf).plt` (auto-decoded via `_extract_plt_ppc64le`; clear `~/.ablation/ctx_*` if binary was previously cached) |
| "PPC64 BE ELFv1: ctx.plt empty, func_starts are OPD VAs (IBM POWER Linux, LoadLeveler)" | `Ppc64ElfV1Resolver.from_path(elf).resolve()` then `res.patch_context(ctx)` — fixes plt stub map and resolves OPD entry VAs to code VAs |
| "PPC64 BE ELFv1: decode a BL instruction target" | `info.bl_target(src_va, file_data)` from a resolved `Ppc64ElfV1Info` |
| "PPC64 BE ELFv1: find all callers of an imported symbol" | `Ppc64ElfV1Resolver.from_path(elf).find_all_bl_callers()` → `{'strcpyx': [va, ...], ...}` |
| "PPC64 BE ELFv1: classify r3/r4 sources at every BL-to-sink site (IBM POWER Linux)" | `Ppc64BeSinkClassifier.from_path(elf).classify_all()` → `List[Ppc64SinkSite]`; filter `s.interesting` for ARG_PROPAGATED+STACK_DEST pairs — the cross-arch replacement for `SinkArgClassifier` on ELFv1 targets |
| "PPC64: trace recv (IBM POWER, AIX)" | `PPC64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "ARC: trace recv (ARC HS IoT, Marvell, Seagate)" | `ARCTaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 32: trace recv" | `RISCV32TaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 32 with HiSilicon WS63/Hi3863 riscv31 custom opcodes" | `HiSiliconRV32ExtDecoder` — pass as `ext_decoder=` to `RISCV32TaintTracker.from_path()` |
| "RISC-V 64: trace recv" | `RISCV64TaintTracker.from_path(elf).run_interprocedural()` |
| "V850: trace recv (RH850/G3M ECU)" | `V850TaintTracker.from_path(elf).run_interprocedural()` |
| "RH850 GHS/IAR ABI: trace taint through CAN/SecurityAccess" | `RH850TaintTracker.from_bytes(data, base_va).scan_function(func_va, func_end, init_labels={'can_payload'})` |
| "TriCore AURIX: trace taint through SecurityAccess / CAN handler" | `TriCoreTaintTracker.from_bytes(data, base_va).scan_function(func_va, func_end, init_labels={'sa_seed'})` |
| "TriCore: find shared epilogue blocks creating phantom taint paths" | `EpilogueShareScanner.from_context(ctx).scan()` |
| "x86-32/i386: trace recv to system/execv/snprintf" | `X86_32TaintTracker.from_path(elf).run_interprocedural()` |
| "LoongArch64: trace recv (TencentOS 4.6)" | `LoongArch64TaintTracker.from_path(elf).run_interprocedural()` |
| "LoongArch64: find GCC 12.3.1.7 max-not-min bug in ELF" | `LA64MaxNotMinScanner.from_path(elf).scan()` |
| "LoongArch64: find GCC 12.3.1.7 max-not-min bug in UEFI PE32+" | `LA64MaxNotMinScanner.from_pe32plus(data).scan()` |
| "LoongArch64: find integer overflow before malloc" | `LA64HeapVulnScanner.from_path(elf).scan()` |

---

## Scanners

| Task | First reach |
|---|---|
| "Find printf/syslog with non-literal format string" | `FormatStringScanner.from_context(ctx).scan()` |
| "Scan for heap integer overflow / UAF / double-free" | `HeapVulnScanner.from_context(ctx).scan()` |
| "Find gets/mktemp/tmpnam/getwd in PLT (CWE-242/121/377)" | `DeprecatedFuncScanner.from_context(ctx).scan()` |
| "Find setuid shadow password oracle (CWE-307) + weak PRNG OTP (CWE-338)" | `SetuidAuthOracleScanner.from_path(elf).scan()` |
| "Where did this command string come from?" | `SinkArgClassifier.from_path(elf).classify_all()` (x86-64/ARM32/ARM64) |
| "MIPS32 O32: classify exec-sink arguments on BE or LE MIPS firmware" | `SinkArgClassifierMIPS.from_context(ctx).classify_all()` — add vendor sinks with `clf.add_sink(name, arg_pos)` |
| "Does sscanf/scanf/fscanf format string have unbounded %s?" | `SscanfSinkClassifier.from_path(elf).classify_all()` — RODATA_SAFE=eliminated, RODATA_UNSAFE=HIGH, DYNAMIC_FMT=verify snprintf template manually |
| "Find wrappers around system/popen/exec* (multi-level injection chains)" | `SinkPropagator.from_context(ctx).propagate()` |
| "Register vendor-specific sinks + known-safe patterns" | `VendorProfile.from_vendor('fortinet').apply_to(clf)` |
| "Map CMDB table IDs to exec-sink reach (FortiWeb/FortiOS)" | `CMDBSurfaceMapper.from_path(elf).map()` |
| "Batch triage all .so files in a dir" | `LibraryInventory.from_dir('/tmp/target/lib/').scan()` |
| "Which libs in a rootfs dir have exec-class PLT imports?" | `batch_plt_intersect('/tmp/fad_root/lib/')` |
| "Detect allowlist byte-validators in stripped binary (x86-64 loop pattern)" | `SanitizerDetector.from_path(elf).detect()` |
| "Audit a specific function for shell metacharacter coverage (any arch incl. PPC64)" | `audit_coverage(elf, va, CS_ARCH_PPC, CS_MODE_64\|CS_MODE_BIG_ENDIAN)` → `SanitizerCoverageReport` |
| "Post-process ARG_PROPAGATED results: downgrade sanitizer-gated exec sinks to SANITIZER_VALIDATED" | `SinkSanitizerFilter.from_path(elf).apply(clf.classify_all())` — run after `SinkArgClassifier.classify_all()`; eliminates manual disasm for structurally safe ARG_PROPAGATED sites |
| "Classify fork() callers as worker/exec/exit" | `ForkExecClassifier.from_path(elf).classify()` |
| "Find pre-auth routes in flatui firmware" | `PreAuthRouteAuditor.run(route_init_va, factory_va)` |
| "Find encrypted/packed sections in binary" | `EntropyMapper.scan()` |
| "Find CFG bypass targets in a Windows PE" | `CFGBypassDetector.from_path(pe).scan()` |
| "Check SafeSEH status and SEH frame installations in x86 PE" | `SEHChainAnalyzer.from_path(x86_pe).scan()` |
| "Extract ETW provider GUIDs and detect detection gaps" | `ETWProviderExtractor.from_path(pe).scan()` |
| "Find RPC server interfaces and check auth levels" | `RPCServerAnalyzer.from_path(pe).scan()` |
| "Map COM attack surface" | `COMAttackSurfaceMapper.from_path(pe).scan()` |
| "Load PDB symbols into BinaryContext" | `PDBSymbolIntegrator.from_path(pe).inject_into_context(ctx)` |
| "Find unvalidated ExAllocatePool size → RtlCopyMemory taint in kernel driver" | `WindowsPoolTaintTracker.from_path(driver_sys).scan()` |
| "Detect BYOVD capability classes in a signed Windows kernel driver" | `ByovdDetector.from_path(driver_path).detect()` |
| "Analyze a Windows kernel .sys driver" | `KernelDriverAnalyzer.from_path(path).analyze()` |
| "Decode a Windows IOCTL CTL_CODE value" | `decode_ioctl_code(value)` |
| "Find JNI bridge surface in Android APK" | `JniBridgeScanner.from_path(apk).scan()` |
| "Map Binder service surface in Android APK" | `BinderScanner.from_path(apk).scan()` |
| "Find 'safe now catastrophic later' rendering architecture risk" | `SourceArchRiskScanner.from_context(ctx).scan()` |
| "Detect Python→Lua code injection" | `LuaInjectionAnalyzer.from_path(root).scan()` |
| "Scan MCP server Python source for credential exposure, prompt injection, transport exposure, auth bypass" | `McpToolTaintScanner.from_path(root).scan()` |
| "Scan Electron app JS (extracted asar) for nodeIntegration, IPC no-sender-check, TLS bypass, openDevTools in prod" | `ElectronSecurityScanner.from_path(app_src).scan()` |
| "Audit Chrome/Edge/Firefox extension for externally_connectable exposure, pre-auth message handlers, DOM hooks, WebSocket bus" | `BrowserExtensionAuditor.from_path(ext_dir).scan()` |
| "Analyze Apache C module .so for handler registration, Cookie→session taint, skip-flag bypass surface" | `ApacheModuleAnalyzer.from_path(mod_so).analyze()` |
| "Find shell injection in Perl .pm/.pl (qx//, backtick, system with $var)" | `PerlTaintScanner.from_path(dir).scan()` |
| "Confirm Perl sink is sanitized vs. injectable (quotemeta, single-quote wrap)" | `PerlTaintScanner.from_files([pm, pl]).scan()` → check `hit.verdict` |
| "Scan MCP server code for BIND_WIDE / EXEC_IN_ALLOWED / NO_AUTH" | `MCPToolTaintScanner.from_path(root).scan()` |
| "Detect TI NNC (Apache TVM) inference artifacts" | `TiNNCScanner.from_path(path).scan()` |
| "Scan MP4/MKV/AVI for forensic anomalies" | `VideoContainerAnalyzer.from_path(path).scan()` |
| "Post-linker security gate on compiled binary" | `CompilerSecurityGate.from_path(elf).scan()` |
| "Pre-commit gate on staged .py files" | `FORGE.audit_module(path)` — gate_passed=False blocks commit |
| "Check README/doc text for white-bronco prose violations" | `python3 -m ablation.core.prose README.md` |
| "Scan a flat ECU ROM for function starts (arch-agnostic)" | `FlatBinaryFuncStartScanner(rom, base_va=0).scan()` |
| "Fingerprint ISA of unknown flat ECU ROM" | `EcuArchDetector(rom_bytes).detect()` |
| "Classify ECU ROM into CODE/CALIBRATION/IVT/PADDING regions" | `EcuROMLayoutAnalyzer.from_path(rom).analyze()` |
| "Label stripped PC game binary as engine code" | `EnginePatternLibrary.default().label_binary(ctx, xg)` |
| "Find math/physics/renderer functions on PPC64 Cell PPU" | `VMXDensityScanner.from_context(ctx).scan(threshold=5)` |
| "Classify PPC64 Cell PPU functions as dynamic data structure traversal" | `DynDSClassifier.from_context(ctx).classify()` |
| "Cache any scanner's results across sessions" | `ScanResultVersionCache.for_scanner(ScannerClass).get_or_scan(path)` |
| "Classify Linux .ko attack surface from kernel source tree path" | `KernelModuleSubsystemClassifier().classify(ko_path)` |

---

## Decoders / lifters / parsers

| Task | First reach |
|---|---|
| "nanoMIPS: walk frame boundaries" | `NanoMIPSDecoder(endian='little').decode_frames(data, base_addr)` |
| "Decode Renesas SH-2A ECU firmware" | `EcuSH2aDecoder(rom, base_va=0x400000).disassemble(start, end)` |
| "Decode TMS320C28x firmware" | `EcuC28xDecoder(data, base_va=0).disassemble(start, end)` |
| "Parse Go pclntab and enumerate functions" | `GoBinaryRE.parse_pclntab()` |
| "Find Go subprocess/exec injection sites" | `GoSubprocessScanner.scan()` |
| "Stripped x86-64 Go binary: BinaryContext has only 3 func_starts — recover all from pclntab" | `GoX86StripScanner.from_context(ctx).patch_context(ctx)` — recovers function VAs (and partial names) from .gopclntab embedded in .rodata; works for Go 1.2+ incl. stripped -ldflags=-s -w binaries |
| "Stripped x86-64 Go binary: detect and get pclntab scan result" | `GoX86StripScanner.from_path(elf).scan()` → `GoScanResult` with `.funcs` dict (VA→name), `.func_starts` list, `.go_version` |
| "Lift a PPC476 function to pseudo-C IR (IBM PPC476 Book E, glibc-2.15 sysroot)" | `Ppc32Lifter.from_context(ctx).lift(func_va, n_insn=150)` — tracks r3-r10 args, resolves PLT stubs (requires _extract_plt_ppc32be fix), decodes lis/addi/lwz GOT loads, annotates bctr indirect calls; see docs/module-reference/ppc476-lifter.md |
| "Lift a native function to pseudo-C IR (18 ISA variants)" | `BinaryLifter.from_path(elf, arch='arm64').lift_function(va)` |
| "Lift a SH-2A ECU function from flat ROM to pseudo-C IR" | `BinaryLifter.from_path(rom, arch='sh2a').lift_function(va)` |
| "Disassemble a DEX method to smali" | `DEXDisasm(dex).disasm_method('Lcom/foo/Bar;', 'methodName')` |
| "Lift a DEX method to pseudo-Java" | `DEXLifter(dex).lift_method('Lcom/foo/Bar;', 'methodName')` |
| "Lift a MicroPython .mpy v6 module to pseudo-Python" | `MpyLifter.from_path(mpy).lift_module()` |
| "Scan Python .pyc bytecode in firmware for dangerous shell/eval calls (no source needed)" | `PycBytecodeScanner().scan_raw(raw, magic=PYC_MAGICS['3.4'])` |
| "Decode a Cell SPU ELF (PS3 co-processor)" | `SPUDisassembler.dump_spu_elf(path, start_va, limit)` |
| "Decrypt a PS3 SELF (Signed ELF) to plain ELF" | `PS3SELFDecryptor.from_path(eboot_bin).decrypt_to_tmp(eboot_bin)` |
| "Find C++ vtables in PS3 Cell PPU (PPC64 ABI v1) binary" | `PS3OPDVtableScanner.from_context(ctx).scan(min_slots=3)` |
| "Resolve C++ vtable indirect calls (ARM64)" | `VtableResolver.extract_vtable_regions()` + `resolve_blr_sites()` |
| "Reconstruct ET_DYN vtable slots from .rela.dyn (x86-64)" | `ELFVtableReconstructor.from_path(elf).reconstruct_class('ClassName')` |
| "Extract C++ vtables from any ELF" | `CppVtableReconstructorAnalyzer.from_path(elf).scan()` |
| "Parse a PowerPC PEF (CFM) binary" | `PEFBinaryAnalyzer.from_path(pef).stubs()` |
| "Extract key material from BMP LSB steganography" | `BmpKeyExtractor('/path/to/keys.bmp').extract('seed')` |
| "Parse TunerPro XDF calibration file" | `EcuXDFParser.from_file(xdf_path)` |
| "Parse open_damos.json and locate calibration tables" | `EcuOpenDamosParser.from_file(json_path)` |
| "Parse RomRaider ECU definition XML" | `EcuRomRaiderParser.from_file(xml_path)` |
| "Parse conescan ECU definition XML (Mazda SH705x)" | `EcuConescanParser.from_file(xml_path)` |
| "Parse ASAM/ASAP2 A2L ECU calibration definition" | `EcuA2LParser.from_file(a2l_path)` |
| "Parse Pytrex NissanDefinitions" | `EcuNissanParser.from_dir(defs_dir)` |
| "Parse CAN DBC signal database file" | `CanDbcParser.from_file(path)` |
| "Parse AppleDouble wrapper from unar-extracted .rsrc file" | `AppleDoubleExtractor.from_path(rsrc_path).resource_fork()` |
| "Parse TI COFF2 object files and AR archives" | `TiCoffLoader.from_path(path)` |
| "Parse Motorola 88K BCS COFF executable (magic 0x016D, DG AViiON / DG/UX)" | `from ablation.core.coff_m88k_parser import parse; b = parse(path)` |
| "Disassemble MC88100 instructions / find function starts on 88K binary" | `M88kDecoder(b).disassemble_va(va)` / `.function_starts()` / `.string_refs()` |

---

## Firmware extraction

| Task | First reach |
|---|---|
| "Extract a specific firmware partition by name" | `FirmwareContainer.from_path(fw).extract('bin', out_path)` |
| "Extract files from AIX backup-by-name (BFF) archive" | `from ablation.core.bff_extractor import iter_entries; [e for e in iter_entries(data)]` |
| "Open a BFF archive that may be compressed (Huffman 0x0C or LZW 0x0E)" | `BFFDecompressor.open(path)` — raises `BFFCompressedError` with remediation text |
| "Detect BFF compression type before parsing" | `from modules.bff_decompressor import detect; detect(data)` |
| "Extract XCOFF members from AIX big archive (<bigaf>: libc.a, libm.a, libpthreads.a)" | `from ablation.analyzers.aix_big_ar_extractor import AixBigArExtractor; members = AixBigArExtractor.from_path(path)` |
| "Parse an AIX XCOFF32/XCOFF64 binary" | `from ablation.core.xcoff_parser import parse; parse(path)` |
| "XCOFF32/64 exports, imports, function starts, section lookup (analyzer interface)" | `XCOFFExecutableAnalyzer.from_path(path).exports_table()` |
| "XCOFF loader symbol quick lookup without full parse" | `from modules.xcoff_loader_symbols import loader_symbols; loader_symbols(data)` |
| "XCOFF loader import table" | `from modules.xcoff_loader_symbols import loader_imports; loader_imports(data)` |
| "Extract files from a Tandem NonStop Guardian PAK archive" | `from ablation.core.guardian_pak_extractor import iter_files; list(iter_files(Path('patch.zip').read_bytes()))` |
| "Build BinaryContext from an AIX XCOFF binary" | `BinaryContext.load_or_build(path)` (auto-detects XCOFF magic 0x01DF/0x01EF) |
| "Extract files from Huawei VRP squashfs v4 XZ image" | `HuaweiSquashfsExtractor(sqfs_path).extract(inner_path)` |
| "Extract files from AMI BMC CramFS firmware" | `AmiCramFSExtractor.from_image(ima_path, offset).extract_file('/path')` |
| "Extract FortiOS hardware firmware (.out file)" | `FortiOSHardwareExtractor.from_path(fw).extract_to(outdir)` |
| "Recover inner partition key from FortiOS hardware .out firmware" | `FirmwareContainerKeyExtractor.from_path(fw)` |
| "Extract PKI keys from FortiMail VM OVF zip or VMDK image" | `FortiMailVmdkExtractor.from_zip(zip_path)` or `.from_vmdk(vmdk_path)` |
| "Batch-fingerprint cert keys in FortiGate OVF firmware ZIPs" | `FortiGateCertKeyScanner.batch_scan(dir)` |
| "Scan bare FortiGate QCOW2/VHD disk image for cert keys" | `FortiGateCertKeyScanner.from_disk(path)` |
| "Predict cert key set from firmware filename alone" | `FortiBuildTrackClassifier.classify(filename)` |
| "Crack XOR-encrypted firmware section" | `XorSolver.solve(ciphertext_path)` |
| "Decode an IBM W-Code binary builtin record" | `WCodeParser.decode_record(data, offset)` |
| "Hash an IBM builtin name for WCB table lookup" | `WCodeParser.name_hash(name)` |
| "Load WCB builtin catalog from xlCentry binary" | `WCodeBuiltinCatalog.from_binary(xlcentry_path)` |
| "Scan a byte stream for W-Code IR records" | `WCodeParser(xlcentry_path).scan(data)` |
| "Identify POWER generation required by a W-Code builtin" | `catalog.arch_mask_to_name(entry.arch_mask)` |

---

## Hypothesis engine / dynamics

| Task | First reach |
|---|---|
| "Seed and score competing RE hypotheses" | `HypothesisEngine.from_binary(elf, arch='arm64', ctx=ctx)` |
| "Auto-execute a probe and feed evidence back" | `engine.with_context(ctx).step(approved=True)` |
| "Execute a leaf function in Unicorn sandbox" | `DynamicSandbox.from_context(ctx).run_function(va, args={'x0': 0x10})` |
| "Check if function is safe to run in sandbox" | `LeafFunctionChecker.from_path(elf).is_leaf(va, ctx)` |
| "Score evidence for a hypothesis" | `EvidenceScorer().score(hypothesis, evidence_items)` |
| "Rank analysis probes by expected information gain" | `ProbeRanker().plan_report(hypotheses, top_n=5)` |
| "Confirm taint path is reachable" | `PathSolver.solve_path(func_va, target_va)` |
| "Trace an arg across 3 library hops" | `IPRegAnnotator.annotate_chain(va, max_hops=3)` |
| "Which library exports this symbol?" | `LibGraph.defined_in('symbol')` |
| "Is this the same function as in v7.4?" | `DTWMatcher.score_functions(va_a, va_b)` |
| "Where did this function change across versions?" | `MatrixProfileDiff.diff_functions(va_v1, va_v2)` |
| "Find confirmed similar findings from past engagements" | `FindingRegistry.find_similar(embedding)` |
| "Sync confirmed findings into PatternLibrary (flywheel)" | `PatternLibrary.ingest_from_registry(reg)` |
| "Auto-name stripped functions via LLM" | `LlmAnalyst.FunctionNamer(ctx).run(va)` |
| "Compress N-file source audit to M profile buckets" | `SourceAuditCompressor.from_context(ctx).compress()` |
| "Generate PoC curl commands" | `PocGenerator.generate_all(preauth_routes)` |
| "Analyze JWT token" | `CryptoAudit.analyze_jwt(token)` |
| "Sweep a Windows PE for vulns" | `python3 sweeps/pe_sweep.py <target.exe> --vendor <v>` |
| "Build engine signature corpus for a new engine" | `lib.add_signature(EngineSignature(...))` then `lib.save()` |
| "Feed game RE findings back into engine library (flywheel)" | `lib.ingest_from_findings(registry.confirmed(), engine='unreal')` |
| "Track RE session state across stages with schema validation" | `WorkflowDocument.for_re_session(vendor, target)` |
| "Audit finding provenance and detect cross-session tampering" | `StageCommitment.verify(stage_name, instance)` |
