# Ablation: Tool Selection Guide

Task-to-tool lookup. For constructor patterns and key methods, see `docs/reference-modules/`.

**Ordering:** BinaryContext → SemanticSearcher new binary/vuln class → FuncProfiler candidate → **SinkArgClassifier** eliminate RODATA_CONST first → TaintedStringTracker → SnprintfVariableFilter → **NetworkSinkFinder** (networked binaries only) → TaintTracker ARG_PROPAGATED/UNKNOWN sinks only → PathSolver confirm feasibility. Manual capstone only when TaintTracker has no configured sink. For targets with a Perl scripting layer, run `PerlTaintScanner` in parallel with TaintTracker, it is independent of BinaryContext.

---

## Core context + search

| Task | First reach |
|---|---|
| "What does this function call?" | `ctx.callees_of(va)` |
| "What calls this symbol?" | `ctx.callers_of('symbol')` or `ctx.callers_of(va)` |
| "What strings does this function reference?" | `ctx.strings_in_func(va)` |
| "Which functions reference this string?" | `ctx.funcs_referencing_stringstring_va` |
| "strings_in_func() returns almost nothing on a stripped i386 ELF32" | `I386AbsoluteXrefScanner.from_context(ctx).inject(ctx)` |
| "What is this function?" | `ctx.name(va)` |
| "Show disassembly around address" | `WindowAnalyzer.dump_text(va, window=1536)` |
| "Disassemble the function containing a CALL site fixes garbled backward-scan output" | `WindowAnalyzer.from_path(elf).dump_caller_contextcall_site_va`: searches backward for ENDBR64/push-rbp prologue, disassembles forward to the call; fixes alignment issues in stripped binaries; see docs/reference-modules/window-analyzer-alignment.md |
| "Find function prologue before a call site stripped binary, no symbols" | `WindowAnalyzer.from_path(elf).align_to_func_start(call_site_va, search_back=512)` → VA of nearest ENDBR64 or push-rbp; fallback = call_site_va - search_back |
| "Find functions matching vulnerability pattern" | `SemanticSearcher.querydescription` ALWAYS first on new binary |
| "Binary not in func_id.db (SemanticSearcher slow/global fallback)" | `SemanticSearcher.ingest_binary(ctx)`: auto-called by `from_context` on miss; or call manually with `product=`, `arch=`, `version=` metadata |
| "What values are passed to this sink?" | `FuncProfiler.profile(va).fmt()` — native x86-64, ARM32, and ARM64 argument annotation; ARM64 uses `ARM64RegAnnotator` |
| "Filter SAC results to network-reachable sinks (networked daemon)" | `NetworkSinkFinder.from_context(ctx).find(depth=3)` — run after SAC, before TaintTracker; skip for local-only binaries |
| "Trace taint from network recv to sink" | `TaintTracker.run_interprocedural()` |

---

## Arch-specific taint trackers

| Task | First reach |
|---|---|
| "ARM32: trace recv to malloc/strcpy/system" | `ARM32TaintTracker.from_context(ctx).run_interprocedural()` |
| "ARM32: find function starts in stripped ELF without.eh_frame" | `ARM32FunctionScanner.from_path(elf).inject_into_context(ctx)` |
| "ARM32: find MUL before malloc without bounds check" | `ARM32IntOverflowScanner.from_context(ctx).scan()` |
| "ARM64: trace recv to malloc/strcpy/system" | `ARM64TaintTracker.from_path_full(elf).run_interprocedural()` |
| "MIPS32: trace recv to system/strcpy/sprintf" | `MIPS32TaintTracker.from_path(elf).run_interprocedural()` |
| "MIPS32: big-endian RouterOS or little-endian CPE" | `MIPS32TaintTracker.from_path(elf, endian='big')` |
| "MIPS64: trace recv Cisco IOS/OCTEON big-endian" | `MIPS64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "MIPS64: little-endian RouterOS 64" | `MIPS64TaintTracker.from_path(elf, endian='little').run_interprocedural()` |
| "nanoMIPS: trace recv to system/popen/sprintf" | `NanoMIPSTaintTracker.from_path(elf, endian='little').run_interprocedural(depth=4)` |
| "PPC32: trace recv (Cisco IOS 7200, VxWorks)" | `PPC32TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "PPC32 PEF: detect ABI register clobber at OTStrCat/OTMemcpy call sites" | `PEFABIClobberScanner.from_bytescode, base_va.scan(sink_vas, check_regs=[4])` |
| "PPC32: resolve indirect BCTRL calls in GOT2-PIC stripped binary" | `PPC32GOT2Resolver.from_path(elf).resolve()` |
| "PPC32.so: find every BL call site calling an imported symbol" | `PPC32PLTTracer.from_path(elf).find_callers('system')` |
| "PPC32 XCOFF/ELF: detect heap slot overflow mulli+malloc+strcpy, no size check" | `PPC32HeapSlotScannerbinary_path.scan()` |
| "VxWorks static archive: scan all.o files for stack-frame strcpy patterns" | `VxWorksArchiveScannerarchive_path.scan_strcpy_in_frame()` |
| "Scan binary for unpatched CVE byte patterns bundled libxml2, etc." | `CVEScannerbinary_path.scan()` |
| "PPC64le ELF V2: get PLT stub VAs and symbol names" | `BinaryContext.load_or_build(elf).plt` (auto-decoded via `_extract_plt_ppc64le`; clear `~/.ablation/ctx_*` if binary was previously cached) |
| "PPC64 BE ELFv1: ctx.plt empty, func_starts are OPD VAs (IBM POWER Linux, LoadLeveler)" | `Ppc64ElfV1Resolver.from_path(elf).resolve()` then `res.patch_context(ctx)`: fixes plt stub map and resolves OPD entry VAs to code VAs |
| "PPC64 BE ELFv1: decode a BL instruction target" | `info.bl_targetsrc_va, file_data` from a resolved `Ppc64ElfV1Info` |
| "PPC64 BE ELFv1: find all callers of an imported symbol" | `Ppc64ElfV1Resolver.from_path(elf).find_all_bl_callers()` → `{'strcpyx': [va,...],...}` |
| "PPC64 BE ELFv1: classify r3/r4 sources at every BL-to-sink site IBM POWER Linux" | `Ppc64BeSinkClassifier.from_path(elf).classify_all()` → `List[Ppc64SinkSite]`; filter `s.interesting` for ARG_PROPAGATED+STACK_DEST pairs: the cross-arch replacement for `SinkArgClassifier` on ELFv1 targets |
| "PPC64 BE ELFv1 stripped: find all BL call sites targeting a PLT stub call graph too weak for callers_of" | `PPC64BECallScanner.from_path(elf).scan_calls_to(plt_va)` → `List[int]` of call-site VAs; brute-force 4-byte-aligned BL opcode sweep; see docs/reference-modules/ppc64-be-call-scanner.md |
| "PPC64: trace recv IBM POWER, AIX" | `PPC64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "ARC: trace recv (ARC HS IoT, Marvell, Seagate)" | `ARCTaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 32: trace recv" | `RISCV32TaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 32 with HiSilicon WS63/Hi3863 riscv31 custom opcodes" | `HiSiliconRV32ExtDecoder`: pass as `ext_decoder=` to `RISCV32TaintTracker.from_path()` |
| "RISC-V 64: trace recv" | `RISCV64TaintTracker.from_path(elf).run_interprocedural()` |
| "V850: trace recv RH850/G3M ECU" | `V850TaintTracker.from_path(elf).run_interprocedural()` |
| "RH850 GHS/IAR ABI: trace taint through CAN/SecurityAccess" | `RH850TaintTracker.from_bytesdata, base_va.scan_function(func_va, func_end, init_labels={'can_payload'})` |
| "TriCore AURIX: trace taint through SecurityAccess / CAN handler" | `TriCoreTaintTracker.from_bytesdata, base_va.scan_function(func_va, func_end, init_labels={'sa_seed'})` |
| "TriCore: find shared epilogue blocks creating phantom taint paths" | `EpilogueShareScanner.from_context(ctx).scan()` |
| "x86-32/i386: trace recv to system/execv/snprintf" | `X86_32TaintTracker.from_path(elf).run_interprocedural()` |
| "LoongArch64: trace recv (TencentOS 4.6)" | `LoongArch64TaintTracker.from_path(elf).run_interprocedural()` |
| "LoongArch64: find GCC 12.3.1.7 max-not-min bug in ELF" | `LA64MaxNotMinScanner.from_path(elf).scan()` |
| "LoongArch64: find GCC 12.3.1.7 max-not-min bug in UEFI PE32+ (all JIRL sites)" | `LA64MaxNotMinScanner.from_pe32plus(data).scan()` — reports `"<indirect>"` for any JIRL where the result is live; does not distinguish AllocatePool vs other calls |
| "LoongArch64: find GCC 12.3.1.7 max-not-min bug in UEFI AllocatePool/AllocatePages" | `UEFISinkClassifierLA64.from_path(path).scan()` — resolves gBS dispatch sites (ld.d+jirl at gBS offsets 0x18/0x30), checks correct arg register per sink; lower FP rate than from_pe32plus |
| "LoongArch64: find GCC 12.3.1.7 max-not-min bug in Linux kernel (vmlinux)" | `LA64MaxNotMinScanner.from_system_map('vmlinux', 'System.map').scan()` — System.map provides VA→name mapping for internal kernel sinks (kmalloc, vmalloc, kzalloc, __kmalloc); kernel modules (.ko ET_REL) use `from_path()` instead |
| "LoongArch64: find integer overflow before malloc" | `LA64HeapVulnScanner.from_path(elf).scan()` |
| "Alpha AXP ECOFF: scan exec-class (system/popen/execve) call sites" | `AlphaEcoffScanner(binary).scan()` → `List[AlphaExecFinding]`; byte-verified BSR targets; call `trace_arg(f.caller_va)` on each finding to classify the argument |
| "Alpha AXP: build per-function CFG from raw ECOFF binary" | `AlphaCFGBuilder(data, sections, gp_value).build(func_va)` → `Dict[va, BasicBlock]`; BFS from entry; handles BR/Bcc/RET/JMP/BSR |
| "Alpha AXP: trace return value of a function (for BSR_RETVAL from trace_arg)" | `AlphaCFGBuilder(data, sections, gp_value).trace_return_value(cfg, ret_reg=0)` → `List[ReturnTrace]`; one result per RET block; closes BSR_RETVAL from trace_arg |
| "Alpha AXP: build SSA form for a function (correct reaching-def across blocks)" | `SSABuilder(cfg, AlphaAXPConfig()).build()` → `SSAForm`; `ssa.reaching_def('r0', ret_va)` replaces trace_arg() linear scan; `ssa.defs_of(name)` / `ssa.uses_of(name)` for def-use chains |
| "Alpha AXP: CFG-fixpoint taint (crosses basic blocks, models callee return values)" | `AlphaTaintTracker.from_path(binary).run_interprocedural(depth=3)` → `List[AlphaTaintFinding]`; replaces linear-scan trace_arg for multi-block functions |
| "Alpha AXP: CFG-fixpoint taint single function" | `AlphaTaintTracker.from_path(binary).scan_function(func_va, init_taint={'r16': frozenset([TaintLabel('argv')])})` |
| "x86-64 / Alpha AXP: lift function to IR node tree" | `AlphaIRLifter(data, sections, gp).lift_cfg(cfg)` / `X86_64IRLifter().lift_cfg(cfg)` → `IRIG`; use `PseudoCEmitter(irig).emit()` for pseudo-C |
| "Recover struct field layout from IRIG load/store patterns" | `StructLayoutAnalyzer(irig).analyze()` → `List[StructDef]`; pass to `PseudoCEmitter(irig, structs=structs)` to get `ctx->field_18` instead of `*(r1+0x18)` |
| "IR-backed pseudo-C lift with struct annotation (Alpha AXP or x86-64)" | `BinaryLifter(binary, arch='alpha').lift_function_ir(va)` → str; drives full pipeline: CFG → IR → struct recovery → pseudo-C |

---

## Scanners

| Task | First reach |
|---|---|
| "Find printf/syslog with non-literal format string (x86-64)" | `FormatStringScanner.from_context(ctx).scan()` |
| "Find printf/syslog with non-literal format string (LoongArch64)" | `FormatStringScannerLA64.from_context(ctx).scan()` — LA64 uses pcaddu12i+addi.d for .rodata refs; add firmware wrappers with `scanner.add_extra_sink(name, arg_pos)` |
| "Scan for heap integer overflow / UAF / double-free" | `HeapVulnScanner.from_context(ctx).scan()` |
| "Find gets/mktemp/tmpnam/getwd in PLT CWE-242/121/377" | `DeprecatedFuncScanner.from_context(ctx).scan()` |
| "Find setuid shadow password oracle (CWE-307) + weak PRNG OTP (CWE-338)" | `SetuidAuthOracleScanner.from_path(elf).scan()` |
| "Where did this command string come from?" | `SinkArgClassifier.from_path(elf).classify_all()` x86-64; use `sac_for_path(elf)` for any arch |
| "Which C++ struct field (base_reg+offset) was read to populate another struct field, via c_str/assign? x86-64 stripped PIE C++" | `CppStructFieldTracker.from_context(ctx, c_str_va=X, assign_va=Y).find_flows()`: auto-detects PLT stubs when VAs omitted; returns FieldFlow list with src/dst offsets, carrier reg, call VAs; use `flows_to_offset(N)` to filter by known sink field offset; see docs/reference-modules/cpp-struct-field-tracker.md |
| "Auto-dispatch to the right SAC for any ELF architecture i386/ppc32/s390x/arm32/arm64/x86-64" | `sac_for_path(elf).classify_all()`: reads e_machine from ELF header; returns SinkArgClassifierARM64 (aarch64), SinkArgClassifierARM32 (arm32), SinkArgClassifierX86_32, SinkArgClassifierPPC32, SinkArgClassifierS390, or SinkArgClassifier (x86_64); import from `ablation.analyzers.sink_arg_classifier`; see docs/reference-modules/sac-arch-dispatch.md |
| "Dispatch to arch-specific SAC from a pre-loaded BinaryContext avoid double-parse" | `sac_for_context(ctx).classify_all()`: same dispatch as `sac_for_path`; dispatches on `ctx.arch` in ('arm64','aarch64') or ('arm32','arm'); import from `ablation.analyzers.sink_arg_classifier` |
| "AArch64 stripped ELF: classify exec-sink arguments (Versal, HiSilicon, RPi, ATLAS GEP)" | `SinkArgClassifierARM64.from_context(ctx).classify_all()`: AAPCS64 x0-x7; handles ADRP+ADD, ADRP+LDR, ADR, MOV, MOVZ, literal pool (IMM operand), and stack slot patterns; closes ARM64-SAC-GAP-001; see docs/reference-modules/sac-arm64.md |
| "Find exec-class sinks in a statically linked binary (BTT, VE/UninstallAssistantLinux, IBM POWER tools): SAC returns 0 because there is no PLT" | `StaticLinkSinkScanner.from_context(ctx).scan_exec_sinks()`: locates system() impl via /bin/sh LEA xref scan, finds CALL sites, classifies arg0, byte-verifies; import from `ablation.analyzers.static_link_sink_scanner`; Gap IDs: SAC-STATIC-001/002/003 |
| "Upgrade SAC SNPRINTF_RODATA verdicts where snprintf format args are tainted SAC-FORMAT-001" | `TaintedStringTracker.from_context(ctx).upgrade_snprintf_rodatasac_results`: backward-scans snprintf rcx/r8/r9 (x86_64) at each SNPRINTF_RODATA site; returns TaintedFormatResult list with upgraded ARG_PROPAGATED verdicts; import from `ablation.analyzers.tainted_string_tracker` |
| "SNPRINTF_RODATA format string contains %s — is the shell command still injectable? x86-64 C++ stripped PIE" | `SnprintfVariableFilter.from_context(ctx).apply(sac_results)`: post-filters SAC results, re-classifies SNPRINTF_RODATA as SNPRINTF_RODATA_VARIABLE when format string contains %s/%S/%n; severity upgraded to HIGH; import from `ablation.analyzers.snprintf_variable_filter`; see docs/reference-modules/snprintf-variable-filter.md |
| "Print pseudo-C call expressions from a WindowAnalyzer window register state lifter" | `wa.dump_pseudo_c(va, window=1536)`: tracks rdi/rsi/rdx/rcx/r8/r9 forward through annotated dump lines, emits one pseudo-C expression per CALL; or `wa.dump_pseudo_c_text(va)` for a single string; single-BB only |
| "i386 ELF reports plt=0 despite exec/net imports: check for R_386_PC32 in .rel.dyn IBM EVF, liblinux.so" | `RelDynPc32Scanner.from_path(elf).scan()`: parses .rel.dyn directly (no LIEF/BinaryContext), returns list of Pc32Hit(r_offset, sym_name, family='EXEC'|'NET', call_va); import from `ablation.analyzers.rel_dyn_pc32_scanner`; run BEFORE declaring plt=0 safe on any i386 shared object |
| "i386 / x86-32 cdecl: classify exec-sink arguments (DOORS, TestMate, Tau, RoseRT, BTT)" | `SinkArgClassifierX86_32.from_path(elf).classify_all()` or `sac_for_path(elf)`: stack-push trace, tracks last push before CALL as arg0; see docs/reference-modules/sac-i386.md |
| "ppc32 BE: classify exec-sink arguments: callers_of() returns nothing on ppc32 HACMP, RMC, DCV, cd7200" | `SinkArgClassifierPPC32.from_path(elf).classify_all()` or `sac_for_path(elf)`: r3 as first arg, 32-bit instruction decode; see docs/reference-modules/sac-ppc32-be.md |
| "MIPS32 O32: classify exec-sink arguments on BE or LE MIPS firmware" | `SinkArgClassifierMIPS.from_context(ctx).classify_all()`: add vendor sinks with `clf.add_sinkname, arg_pos` |
| "s390/s390x IBM Z Linux: classify exec-sink arguments: BinaryContext returns plt=0 S390-GAP-001" | `SinkArgClassifierS390.from_path(elf).classify_all()`: use `from_path()` not `from_context()` to bypass BinaryContext's s390 PLT parse gap; `is_s390(path)` detects e_machine=0x0016 |
| "ppc64/ppc64le IBM POWER Linux ABIv2: classify exec-sink arguments: ARCH-GAP-PPC64LE" | `SinkArgClassifierPPC64.from_context(ctx).classify_all()`: handles both LE and BE via EI_DATA detection; resolves TOC-relative addis-r2+addi/ld address patterns; r3-r10 argument registers; see docs/reference-modules/ppc64-le-sink-classifier.md |
| "LoongArch64 LA64: classify exec-sink arguments: Alpine musl and LoongOS; BinaryContext returns plt=0 for large GOT: use this module not sac_for_path" | `SinkArgClassifierLA64.from_context(ctx).classify_all()`: uses LoongArchDecoderV2 for call site discovery and backward trace; no Capstone; PLT resolved via raw ELF byte decode; $a0-$a7 arg registers; add execline wrappers with `clf.add_sink('xexec_ae', 0)` etc; sac_for_context() dispatches here automatically for arch='loongarch64'; ground truth: mqtt-exec 0.7.1 and execline 2.9.9.1 Alpine 3.24.3 LA64 |
| "Does sscanf/scanf/fscanf format string have unbounded %s?" | `SscanfSinkClassifier.from_path(elf).classify_all()`: RODATA_SAFE=eliminated, RODATA_UNSAFE=HIGH, DYNAMIC_FMT=verify snprintf template manually |
| "Find wrappers around system/popen/exec* multi-level injection chains" | `SinkPropagator.from_context(ctx).propagate()` |
| "Register vendor-specific sinks + known-safe patterns" | `VendorProfile.from_vendor('fortinet').apply_to(clf)` |
| "Map CMDB table IDs to exec-sink reach (FortiWeb/FortiOS)" | `CMDBSurfaceMapper.from_path(elf).map()` |
| "Batch triage all.so files in a dir" | `LibraryInventory.from_dir('/tmp/target/lib/').scan()` |
| "Which libs in a rootfs dir have exec-class PLT imports?" | `batch_plt_intersect('/tmp/fad_root/lib/')`: now strips @GLIBC versioning suffixes; exact match only no substring FPs |
| "Extract ELFs from nested archives tar→RPM→ELF, zip→tar→ELF, tar.gz→ELF, tar.Z→ELF" | `NestedArchiveScanner('/path/to/dir').scan()` → Iterator[real_path, virtual_path]; or `NestedArchiveScanner.collect_elfs(archive, max_elfs=30)` → [virtual_path, bytes]; handles .rpm via rpm2cpio, up to 4 levels deep; see docs/reference-modules/nested-archive-scanner.md |
| "Extract ELF .o members from Unix ar (.a) static library + run exec-class scan on each" | `ArArchiveScanner.from_path(path).scan_exec_class()` or `ArArchiveScannerbytes_data.scan_exec_class()`; dispatches SinkArgClassifierI386 for i386, SinkArgClassifier for all others; see docs/reference-modules/ar-archive-scanner.md |
| "Parse ELF32 relocatable .o file (VxWorks PPC32, static library member): get functions, calls, imports, disasm" | `ReloObjectContext.from_path(path)` → `.functions()`, `.calls_in(fn_name)`, `.imports()`, `.disasm(fn_name)`, `.functions_calling(sym)`; handles bctrl+RELA call pattern, no PLT, section-relative only; see docs/reference-modules/relo-object-context.md |
| "Classify exec-sink argument provenance in ELF32 relocatable .o (VxWorks PPC32): detect strcpy/strcat/system bctrl call sites via rela_map" | `ReloSinkArgClassifier.from_context(roc).classify_fn(fn_name)` or `.classify_all()`; needs ReloObjectContext; rodata detection uses rela annotation not VA ranges; see docs/reference-modules/relo-sink-arg-classifier.md |
| "Cross-object query across Unix ar (.a) archive: find functions calling both sym_a and sym_b (read+strcpy pattern), find all callers of a symbol, find symbol definitions" | `ArchiveContext.from_path(path).co_reference_scan(sym_a, sym_b)` → `[(obj, fn)]`; also `.find_callers(sym)`, `.find_definitions(sym)`, `.get(member_name)` → ReloObjectContext; ELF32 only; see docs/reference-modules/archive-context.md |
| "Check OS/2 NE/LX binary for DosExecPgm/DosStartSession exec-class imports" | `NEFormatParser.from_path(path).parse()` → NEFormatResult; check `r.exec_imports`; handles NE OS/2-1.x, LE/LX OS/2-2.x, PE (Win32); see docs/reference-modules/ne-format-parser.md |
| "Detect allowlist byte-validators in stripped binary x86-64 loop pattern" | `SanitizerDetector.from_path(elf).detect()` |
| "Audit a specific function for shell metacharacter coverage any arch incl. PPC64" | `audit_coverage(elf, va, CS_ARCH_PPC, CS_MODE_64\|CS_MODE_BIG_ENDIAN)` → `SanitizerCoverageReport` |
| "Post-process ARG_PROPAGATED results: downgrade sanitizer-gated exec sinks to SANITIZER_VALIDATED" | `SinkSanitizerFilter.from_path(elf).apply(clf.classify_all())`: run after `SinkArgClassifier.classify_all()`; eliminates manual disasm for structurally safe ARG_PROPAGATED sites |
| "Filter dead-code ARG_PROPAGATED findings: check if function has runtime callers" | `FuncReachabilityAnalyzer.from_context(ctx).filter_unreachablefindings`: removes findings in unreachable functions; check() returns REACHABLE/UNREACHABLE_DEBUG/UNREACHABLE_NOREF/REACHABLE_VIA_PTR |
| "Trace what callers pass for an ARG_PROPAGATED function argument i386 cdecl" | `CallerArgResolver.from_context(ctx).resolvefunc_va, func_arg_pos` or `resolve_from_classification(sc)`: classifies each caller as CONST_NULL/CONST_NONZERO/ARG_PROPAGATED/STACK_LOCAL/RODATA_CONST/UNKNOWN |
| "Classify exec-sink arguments in i386 ELF using forward register-state tracking handles long-range register persistence beyond backward-scan lookback" | `SinkArgClassifierI386.from_path(elf).classify_all()`: forward pass builds reg_state; handles [ebp+N]/register aliases/push+sub-esp calling conventions; use when x86_32 module returns UNKNOWN due to lookback limit; see docs/reference-modules/sink-arg-classifier-i386.md |
| "Multi-level call chain ascent for i386: trace ARG_PROPAGATED through callers to network source or static ceiling" | `I386CallChainResolver.from_context(ctx).resolve_chain(func_va, func_arg_pos, max_depth=8)`: traverses multiple levels, resolves struct pointer derefs [*reg] → [ebp+N]/network recv/global, returns CONFIRMED/SAFE/STATIC_CEILING with full chain; use after CallerArgResolver returns UNKNOWN on struct derefs; see docs/reference-modules/i386-call-chain-resolver.md |
| "Classify fork() callers as worker/exec/exit" | `ForkExecClassifier.from_path(elf).classify()` |
| "SETUID binary calls setuid(0)+fork+exec: confirm privilege escalation CWE-269, asmmenu pattern" | `SetuidBeforeForkAnalyzer.from_path(elf).scan()`: detects literal-0 setuid arg before fork+exec; import from `ablation.analyzers.setuid_before_fork`; verdicts: CONFIRMED/PLAUSIBLE; Gap: HMC-GAP-001 |
| "SETUID binary drops root via setuid(getuid()) or setreuid(-1,getuid()) before exec: confirm NOT_EXPLOITABLE rnvi pattern" | `PrivilegeDropBeforeExecAnalyzer.from_path(elf).scan()`: clears SAC UNKNOWN exec sinks in SETUID wrappers that drop back to calling user; verdict NOT_EXPLOITABLE requires no re-escalation between drop and exec; import from `ablation.analyzers.priv_drop_before_exec` |
| "SETUID binary uses getpwnam('root') to obtain pw_uid then setuid+fork+exec: upgrade SetuidBeforeForkAnalyzer PLAUSIBLE to CONFIRMED hscdc pattern" | `SetuidObfuscatedExecDetector.from_path(elf).scan()`: resolves getpwnam('root')->pw_uid→setuid chain; invariant: root pw_uid==0 always; also catches obfuscated/decode paths before exec; verdict CONFIRMED when getpwnam arg is 'root'; import from `ablation.analyzers.setuid_obfuscated_exec` |
| "SETUID binary builds command in malloc'd buf via strcat(argv[i]) loop then system(): SAC returns UNKNOWN ldapsearch/chhmc pattern" | `ArgvBuildToSinkClassifier.from_path(elf).scan()`: detects alloc→strcat-loop→system/exec; scores gate automatically (no-gate=HIGH, root/role-gate=LOW/MEDIUM); complements SAC for UNKNOWN system() sinks with dynamic buf; import from `ablation.analyzers.argv_build_to_sink` |
| "Find pre-auth routes in flatui firmware" | `PreAuthRouteAuditor.runroute_init_va, factory_va` |
| "Find encrypted/packed sections in binary" | `EntropyMapper.scan()` |
| "Find CFG bypass targets in a Windows PE" | `CFGBypassDetector.from_path(pe).scan()` |
| "Check SafeSEH status and SEH frame installations in x86 PE" | `SEHChainAnalyzer.from_path(x86_pe).scan()` |
| "Extract ETW provider GUIDs and detect detection gaps" | `ETWProviderExtractor.from_path(pe).scan()` |
| "Find RPC server interfaces and check auth levels" | `RPCServerAnalyzer.from_path(pe).scan()` |
| "Map COM attack surface" | `COMAttackSurfaceMapper.from_path(pe).scan()` |
| "Load PDB symbols into BinaryContext" | `PDBSymbolIntegrator.from_path(pe).inject_into_context(ctx)` |
| "Find unvalidated ExAllocatePool size → RtlCopyMemory taint in kernel driver" | `WindowsPoolTaintTracker.from_pathdriver_sys.scan()` |
| "Detect BYOVD capability classes in a signed Windows kernel driver" | `ByovdDetector.from_pathdriver_path.detect()` |
| "Analyze a Windows kernel.sys driver" | `KernelDriverAnalyzer.from_path(path).analyze()` |
| "Decode a Windows IOCTL CTL_CODE value" | `decode_ioctl_code(value)` |
| "Find JNI bridge surface in Android APK" | `JniBridgeScanner.from_path(apk).scan()` |
| "Map Binder service surface in Android APK" | `BinderScanner.from_path(apk).scan()` |
| "Find 'safe now catastrophic later' rendering architecture risk" | `SourceArchRiskScanner.from_context(ctx).scan()` |
| "Detect Python→Lua code injection" | `LuaInjectionAnalyzer.from_path(root).scan()` |
| "Scan MCP server Python source for credential exposure, prompt injection, transport exposure, auth bypass" | `McpToolTaintScanner.from_path(root).scan()` |
| "Scan Electron app JS extracted asar for nodeIntegration, IPC no-sender-check, TLS bypass, openDevTools in prod" | `ElectronSecurityScanner.from_path(app_src).scan()` |
| "Audit Chrome/Edge/Firefox extension for externally_connectable exposure, pre-auth message handlers, DOM hooks, WebSocket bus" | `BrowserExtensionAuditor.from_path(ext_dir).scan()` |
| "Analyze Apache C module.so for handler registration, Cookie→session taint, skip-flag bypass surface" | `ApacheModuleAnalyzer.from_path(mod_so).analyze()` |
| "Scan binary rodata for hardcoded API keys, AWS credentials, JWT tokens, PEM private keys, passwords" | `HardcodedCredentialScanner.from_context(ctx).scan()` |
| "Find shell injection in Perl.pm/.pl qx//, backtick, system with $var" | `PerlTaintScanner.from_path(dir).scan()` |
| "Confirm Perl sink is sanitized vs. injectable quotemeta, single-quote wrap" | `PerlTaintScanner.from_files[pm, pl].scan()` → check `hit.verdict` |
| "Scan MCP server code for BIND_WIDE / EXEC_IN_ALLOWED / NO_AUTH" | `MCPToolTaintScanner.from_path(root).scan()` |
| "Detect TI NNC Apache TVM inference artifacts" | `TiNNCScanner.from_path(path).scan()` |
| "Scan MP4/MKV/AVI for forensic anomalies" | `VideoContainerAnalyzer.from_path(path).scan()` |
| "Post-linker security gate on compiled binary" | `CompilerSecurityGate.from_path(elf).scan()` |
| "Pre-commit gate on staged.py files" | `FORGE.audit_module(path)`: gate_passed=False blocks commit |
| "Check README/doc text for white-bronco prose violations" | `python3 -m ablation.core.prose README.md` |
| "Scan a flat ECU ROM for function starts arch-agnostic" | `FlatBinaryFuncStartScanner(rom, base_va=0).scan()` |
| "Fingerprint ISA of unknown flat ECU ROM" | `EcuArchDetectorrom_bytes.detect()` |
| "Classify ECU ROM into CODE/CALIBRATION/IVT/PADDING regions" | `EcuROMLayoutAnalyzer.from_path(rom).analyze()` |
| "Label stripped PC game binary as engine code" | `EnginePatternLibrary.default().label_binary(ctx, xg)` |
| "Find math/physics/renderer functions on PPC64 Cell PPU" | `VMXDensityScanner.from_context(ctx).scan(threshold=5)` |
| "Classify PPC64 Cell PPU functions as dynamic data structure traversal" | `DynDSClassifier.from_context(ctx).classify()` |
| "Cache any scanner's results across sessions" | `ScanResultVersionCache.for_scanner(ScannerClass).get_or_scan(path)` |
| "Classify Linux.ko attack surface from kernel source tree path" | `KernelModuleSubsystemClassifier().classify(ko_path)` |
| "Find Q-shell / dispatch-table command handlers in ELF data segment (IBM Sentinel, server firmware)" | `CommandTableScanner.from_context(ctx).scan()` → list of CommandTable; each entry has name, handler_va, entry_va; see docs/reference-modules/command-table-scanner.md |
| "Flag pthread_once() lazy-init wrappers misidentified as auth checks in stripped non-PIE ELF" | `PthreadOnceDetector.from_context(ctx).detect()` → list of PthreadOnceResult with verdict LAZY_INIT/POSSIBLE_AUTH/UNKNOWN; see docs/reference-modules/pthread-once-detector.md |

---

## Decoders / lifters / parsers

| Task | First reach |
|---|---|
| "Parse Intel HEX with strict checksum and overlap checks" | `IntelHexImage.from_path(path)`; use `.to_sparse()` for spans or `.to_bytes(fill=0xFF, base=0)` for bounded absolute images; see `docs/reference-modules/intel-hex.md` |
| "Decode CAEN ASCII-hex firmware and verify its trailer" | `CaenHexFirmware.from_path(path)`; validates the LF-excluding additive checksum; see `docs/reference-modules/caen-ascii-hex.md` |
| "Load a bFLT v4 embedded-Linux executable" | `BfltImage.from_path(path)`; use `.text_bytes`, `.data_bytes`, and bounded `.read_memory()`; see `docs/reference-modules/bflt.md` |
| "Recover files from a little-endian JFFS2 image without mounting" | `Jffs2Image.from_path(path).read_file('/path')`; validates node, filename, inode, and stored-payload CRCs; see `docs/reference-modules/jffs2.md` |
| "Decode C166/C167 flat or boot-loaded firmware" | `EcuC166Decoder(data, base_pa=...)`; use `parse_ivt(start_pa=...)`, `disassemble()`, and explicit DPP helpers for data references; see `docs/reference-modules/c166-c167-decoding.md` |
| "nanoMIPS: walk frame boundaries" | `NanoMIPSDecoder(endian='little').decode_framesdata, base_addr` |
| "Disassemble Xilinx MicroBlaze / Versal PLM firmware" | `MicroBlazeDecoder(data, base_va=..., byte_order='little').disassemble()`; extract PDI load bytes first with `VersalPdi.dma_write_segments()` |
| "Recover MicroBlaze CFG / separate reachable code" | `recover_cfg(decoder, entries=[...])`; validate bounded indirect tables with `resolve_jump_tables()`; see `docs/reference-modules/microblaze-decoder.md#recursive-cfg-recovery` |
| "Recover MicroBlaze direct-call arguments" | `call_arguments(function, call_site)`; bounded same-block constants with delay-slot support; see `docs/reference-modules/microblaze-decoder.md#call-argument-recovery` |
| "Find MicroBlaze absolute-address references" | `direct_memory_references(recovery, start, end)` and `reference_neighbors()`; layout candidates, not type proof; see `docs/reference-modules/microblaze-decoder.md#direct-memory-references` |
| "Lift MicroBlaze CFG to structural pseudo-C" | `MicroBlazeLifter(recovery).lift_function(entry)`; unresolved indirect targets stay explicit; see `docs/reference-modules/microblaze-decoder.md#structural-pseudo-c-lifting` |
| "Decode Renesas SH-2A ECU firmware" | `EcuSH2aDecoder(rom, base_va=0x400000).disassemblestart, end` |
| "Decode TMS320C28x firmware" | `EcuC28xDecoder(data, base_va=0).disassemblestart, end` |
| "Parse Go pclntab and enumerate functions" | `GoBinaryRE.parse_pclntab()` |
| "Find Go subprocess/exec injection sites" | `GoSubprocessScanner.scan()` |
| "Stripped x86-64 Go binary: BinaryContext has only 3 func_starts: recover all from pclntab" | `GoX86StripScanner.from_context(ctx).patch_context(ctx)`: recovers function VAs and partial names from.gopclntab embedded in.rodata; works for Go 1.2+ incl. stripped -ldflags=-s -w binaries |
| "Stripped x86-64 Go binary: detect and get pclntab scan result" | `GoX86StripScanner.from_path(elf).scan()` → `GoScanResult` with `.funcs` dict (VA→name), `.func_starts` list, `.go_version` |
| "Lift a PPC476 function to pseudo-C IR IBM PPC476 Book E, glibc-2.15 sysroot" | `Ppc32Lifter.from_context(ctx).lift(func_va, n_insn=150)`: tracks r3-r10 args, resolves PLT stubs requires _extract_plt_ppc32be fix, decodes lis/addi/lwz GOT loads, annotates bctr indirect calls; see docs/reference-modules/ppc476-lifter.md |
| "Lift a native function to pseudo-C IR 18 ISA variants" | `BinaryLifter.from_path(elf, arch='arm64').lift_function(va)` |
| "Lift a SH-2A ECU function from flat ROM to pseudo-C IR" | `BinaryLifter.from_path(rom, arch='sh2a').lift_function(va)` |
| "Disassemble a DEX method to smali" | `DEXDisasm(dex).disasm_method('Lcom/foo/Bar;', 'methodName')` |
| "Lift a DEX method to pseudo-Java" | `DEXLifter(dex).lift_method('Lcom/foo/Bar;', 'methodName')` |
| "Lift a MicroPython.mpy v6 module to pseudo-Python" | `MpyLifter.from_path(mpy).lift_module()` |
| "Scan Python.pyc bytecode in firmware for dangerous shell/eval calls no source needed" | `PycBytecodeScanner().scan_raw(raw, magic=PYC_MAGICS['3.4'])` |
| "Decode a Cell SPU ELF PS3 co-processor" | `SPUDisassembler.dump_spu_elfpath, start_va, limit` |
| "Decrypt a PS3 SELF Signed ELF to plain ELF" | `PS3SELFDecryptor.from_patheboot_bin.decrypt_to_tmpeboot_bin` |
| "Find C++ vtables in PS3 Cell PPU PPC64 ABI v1 binary" | `PS3OPDVtableScanner.from_context(ctx).scan(min_slots=3)` |
| "Resolve C++ vtable indirect calls (ARM64)" | `VtableResolver.extract_vtable_regions()` + `resolve_blr_sites()` |
| "Reconstruct ET_DYN vtable slots from.rela.dyn (x86-64)" | `ELFVtableReconstructor.from_path(elf).reconstruct_class('ClassName')` |
| "Extract C++ vtables from any ELF" | `CppVtableReconstructorAnalyzer.from_path(elf).scan()` |
| "Recover all vtable layouts from PIE x86-64 ELF, find which vtable(s) contain a function — virtual callers invisible to call_edges" | `VtableDispatchMapper.from_context(ctx).callers_via_vtable(func_va)` → `List[VtableSlot]`; groups R_X86_64_RELATIVE relocs by 8-byte stride in .rela.dyn; import from `ablation.analyzers.vtable_dispatch_mapper`; see docs/reference-modules/vtable-dispatch-mapper.md |
| "Function has zero call_edges callers in binary A but is called from companion binary (daemon+helper pattern)" | `CrossBinaryExportDetector.from_context(ctx).detect(vtable_mapper=mapper)` → `List[CrossBinaryExport]`; heuristic: zero callers + not in vtable + stack canary + source-path xref; import from `ablation.analyzers.cross_binary_export_detector`; see docs/reference-modules/cross-binary-export-detector.md |
| "Parse a PowerPC PEF (CFM) binary" | `PEFBinaryAnalyzer.from_path(pef).stubs()` |
| "Extract key material from BMP LSB steganography" | `BmpKeyExtractor('/path/to/keys.bmp').extract('seed')` |
| "Parse TunerPro XDF calibration file" | `EcuXDFParser.from_filexdf_path` |
| "Parse open_damos.json and locate calibration tables" | `EcuOpenDamosParser.from_filejson_path` |
| "Parse RomRaider ECU definition XML" | `EcuRomRaiderParser.from_filexml_path` |
| "Parse conescan ECU definition XML Mazda SH705x" | `EcuConescanParser.from_filexml_path` |
| "Parse ASAM/ASAP2 A2L ECU calibration definition" | `EcuA2LParser.from_filea2l_path` |
| "Parse Pytrex NissanDefinitions" | `EcuNissanParser.from_dirdefs_dir` |
| "Parse CAN DBC signal database file" | `CanDbcParser.from_file(path)` |
| "Parse AppleDouble wrapper from unar-extracted.rsrc file" | `AppleDoubleExtractor.from_pathrsrc_path.resource_fork()` |
| "Parse TI COFF2 object files and AR archives" | `TiCoffLoader.from_path(path)` |
| "Parse Motorola 88K BCS COFF executable (magic 0x016D, DG AViiON / DG/UX)" | `from ablation.core.coff_m88k_parser import parse; b = parse(path)` |
| "Disassemble MC88100 instructions / find function starts on 88K binary" | `M88kDecoder(b).disassemble_va(va)` / `.function_starts()` / `.string_refs()` |
| "Locate MetaKit VFS appended to a TclKit binary (BitRock installer, embedded appliance)" | `MetaKitParser.from_path(path)` → `.found`, `.mk_start`, `.schema` |
| "Extract all files from a TclKit MetaKit VFS" | `parser.iter_files()` → yields `(label, bytes)` per zlib blob |
| "Get BitRock file manifest from MetaKit (lists installed files + LZMA chunk offsets)" | `parser.get_manifest()` → bytes of the first large text blob |
| "Extract ELF .so binaries embedded in MetaKit (tbcload, lzmadec, cookfs...)" | `parser.find_embedded_elfs()` → `{label: bytes}` — feed each to `BinaryContext` |
| "Extract Tcl scripts and TclPro ByteCode blobs from MetaKit" | `parser.find_tcl_scripts()` → `{label: bytes}` |
| "Decode TclPro ByteCode 1.3/1.7 to instructions and literal strings" | `TclProDecoder.from_bytes(blob)` → `.disassemble()`, `.get_strings()`, `.report()` |
| "Find all TclPro ByteCode streams inside a binary blob" | `TclProDecoder.find_all_in_blob(data)` → list of decoders |
| "Screen TclPro bytecodes for exec/network/install security patterns" | `dec.security_strings()` / `dec.has_eval_stk()` |
| "Full disassembly with literal annotations for TclPro bytecodes" | `dec.dump()` |

---

## IoT firmware + CGI surface

| Task | First reach |
|---|---|
| "Inventory an artifact collection and RE coverage" | `scan_artifacts(root, records, hash_files=True)` and `scan_nested_artifacts()` for tar/ZIP members; literal evidence matching and JSON/Markdown matrices; see `docs/reference-modules/artifact-inventory.md` |
| "Extract structurally valid embedded ELF payloads" | `find_embedded_elf(data)` or `VersalPdi.embedded_elf()`; strict table/load bounds, no magic-only acceptance; see `docs/reference-modules/embedded-elf.md` |
| "Parse raw WIC/img disk image, navigate filesystem without mounting (ext4/FAT)" | `DiskImageExtractor.from_path(image, partition_index=1).read_path('/etc/shadow')`: wraps Sleuth Kit fls/icat; auto-detects partition table via fdisk; `list_path(dir)`, `path_exists(p)`, `find_suid()`; closes DISK-IMG-GAP-001; see docs/reference-modules/disk-image-extractor.md |
| "Security scan an embedded Linux rootfs (PetaLinux, OpenWRT, Yocto) from WIC image or directory" | `EmbeddedRootfsScanner.from_dir(rootfs_dir).scan()` or `.from_image(wic_path)`: checks credentials (shadow/passwd), inetd services, systemd autostart units, SSH config, IPBus shims, SUID binaries; returns `List[RootfsFinding]`; see docs/reference-modules/embedded-rootfs-scanner.md |
| "Parse IPBus XML address table (facility/ATLAS/EMP firmware) into structured register map" | `IPBusAddrParser.from_file(xml).parse()` → `IPBusRegisterMap`; `.writable()` lists all r/w registers; `.lookup_addr(word_addr)` maps raw address to symbolic name; handles nested nodes, bitmasks, permission inheritance; closes IPBUS-ADDR-TABLE-GAP-001; see docs/reference-modules/ipbus-addr-parser.md |
| "Identify IoT firmware container format without extracting" | `IoTFirmwareUnpacker.probe(fw_path)` → `FirmwareInfo(format, encrypted, inner_offset)`; detects 15+ formats; returns early with error hint on OpenSSL AES encrypted images |
| "Extract IoT firmware: strip VIVOTEK 49-byte header / uImage 64-byte header, decompress, unpack squashfs/cpio/tar" | `IoTFirmwareUnpacker.unpack(fw_path, outdir)` → `UnpackResult(format_chain, rootfs_path, inventory, error)` |
| "Map HTTP CGI attack surface of a firmware rootfs: classify handlers as shell vs ELF, run ShellSinkClassifier on all shell CGIs, return sorted findings table" | `CGISurfaceMapper.from_rootfs(rootfs_path).map()` → `CGISurface`; `CGISurfaceMapper.report(surface)` for formatted output |
| "Get only risky CGI handlers (ARG_PROPAGATED / EVAL_SINK / UNKNOWN)" | `surface.risky` — list of `CGIHandler` with worst-case verdicts first |
| "Get ELF CGI handlers for binary RE queue" | `surface.elf_handlers` → `[CGIHandler]`; pass `h.abs_path` to `BinaryContext.load_or_build()` |
| "Classify exec sinks in a single shell script or CGI handler" | `ShellSinkClassifier.from_path(path).classify()` → `List[ShellSinkResult]`; use `ShellSinkClassifier.report(results)` for formatted output |
| "Sweep all shell scripts in a directory for exec sinks" | `ShellSinkClassifier.from_dir(dir, exts={'.sh','.cgi'}).classify()` |

---

## Firmware extraction

| Task | First reach |
|---|---|
| "Extract a specific firmware partition by name" | `FirmwareContainer.from_path(fw).extract('bin', out_path)` |
| "Extract files from AIX backup-by-name (BFF) archive" | `from ablation.core.bff_extractor import iter_entries; [e for e in iter_entries(data)]` |
| "Open a BFF archive that may be compressed (Huffman 0x0C or LZW 0x0E)" | `BFFDecompressor.open(path)`: raises `BFFCompressedError` with remediation text |
| "Detect BFF compression type before parsing" | `from modules.bff_decompressor import detect; detect(data)` |
| "Extract XCOFF members from AIX big archive <bigaf>: libc.a, libm.a, libpthreads.a" | `from ablation.analyzers.aix_big_ar_extractor import AixBigArExtractor; members = AixBigArExtractor.from_path(path)` |
| "Decompile an AIX PPC32 XCOFF32 function to C-like pseudocode descriptor resolution + TOC naming" | `Xcoff32Decompiler.from_context(ctx).decompile(func_va)` → pseudocode string; see `docs/reference-modules/xcoff32-decompiler.md` |
| "Parse an AIX XCOFF32/XCOFF64 binary" | `from ablation.core.xcoff_parser import parse; parse(path)` |
| "XCOFF32/64 exports, imports, function starts, section lookup analyzer interface" | `XCOFFExecutableAnalyzer.from_path(path).exports_table()` |
| "XCOFF loader symbol quick lookup without full parse" | `from modules.xcoff_loader_symbols import loader_symbols; loader_symbols(data)` |
| "XCOFF loader import table" | `from modules.xcoff_loader_symbols import loader_imports; loader_imports(data)` |
| "Extract files from a Tandem NonStop Guardian PAK archive" | `from ablation.core.guardian_pak_extractor import iter_files; list(iter_files(Path('patch.zip').read_bytes()))` |
| "Build BinaryContext from an AIX XCOFF binary" | `BinaryContext.load_or_build(path)` (auto-detects XCOFF magic 0x01DF/0x01EF) |
| "One-shot: extract all XCOFF binaries from an AIX installp .bff package" | `AixBffExtractor.from_pathbff_path` → `[name, xcoff_bytes, ...]`; uses `bff_extractor.iter_entries` with magic-scan fallback |
| "Find AIX PPC32 external-call stub VAs for system()/popen()/exec*() in XCOFF32" | `XCOFF32Info.from_path(path).import_stubs()` → `{'.system': va, '.popen': va, ...}`; searches COFF symtab (inline) then stub pattern lwz r12+stw r2 |
| "Find all callers of an AIX PPC32 import stub" | `XCOFF32Info.from_path(path).callers_of(stub_va)` → `[call_va, ...]`; exhaustive bl scan of .text |
| "Triage dangerous imports + stub VAs + caller count in one call AIX XCOFF32" | `XCOFF32Info.from_path(path).summary()` |
| "AIX XCOFF32: stride BL scan — all call sites, immune to embedded trap/NULL-word tables in .text" | `from ablation.analyzers.xcoff32_call_scanner import XCOFF32CallScanner; s = XCOFF32CallScanner.from_binary(binary); s.named_calls()` → `{import_name: [caller_vas]}`; `s.calls_to(stub_va)` for one target; `s.scan_all()` for full {target: [callers]} map; see docs/reference-modules/xcoff32-call-scanner.md |
| "AIX XCOFF32: classify TOC slots from LDREL — identify function import stubs vs data pointers" | `from ablation.core.xcoff_parser import classify_toc_slots; slots = classify_toc_slots(binary)` → `{toc_offset: XcoffTocSlot}`; kind = FUNC_IMPORT/DATA_PTR/SECTION_REF/UNKNOWN; use after parse() to map TOC[N] to import names without manual LDSYM counting |
| "Extract files from Huawei VRP squashfs v4 XZ image" | `HuaweiSquashfsExtractorsqfs_path.extractinner_path` |
| "Extract files from AMI BMC CramFS firmware" | `AmiCramFSExtractor.from_imageima_path, offset.extract_file('/path')` |
| "Extract FortiOS hardware firmware .out file" | `FortiOSHardwareExtractor.from_path(fw).extract_to(outdir)` |
| "Recover inner partition key from FortiOS hardware.out firmware" | `FirmwareContainerKeyExtractor.from_path(fw)` |
| "Extract PKI keys from FortiMail VM OVF zip or VMDK image" | `FortiMailVmdkExtractor.from_zipzip_path` or `.from_vmdkvmdk_path` |
| "Batch-fingerprint cert keys in FortiGate OVF firmware ZIPs" | `FortiGateCertKeyScanner.batch_scan(dir)` |
| "Scan bare FortiGate QCOW2/VHD disk image for cert keys" | `FortiGateCertKeyScanner.from_disk(path)` |
| "Predict cert key set from firmware filename alone" | `FortiBuildTrackClassifier.classifyfilename` |
| "Crack XOR-encrypted firmware section" | `XorSolver.solveciphertext_path` |
| "Decode an IBM W-Code binary builtin record" | `WCodeParser.decode_recorddata, offset` |
| "Hash an IBM builtin name for WCB table lookup" | `WCodeParser.name_hash(name)` |
| "Load WCB builtin catalog from xlCentry binary" | `WCodeBuiltinCatalog.from_binaryxlcentry_path` |
| "Scan a byte stream for W-Code IR records" | `WCodeParserxlcentry_path.scan(data)` |
| "Identify POWER generation required by a W-Code builtin" | `catalog.arch_mask_to_nameentry.arch_mask` |

---

## Hypothesis engine / dynamics

| Task | First reach |
|---|---|
| "Seed and score competing RE hypotheses" | `HypothesisEngine.from_binary(elf, arch='arm64', ctx=ctx)` |
| "Auto-execute a probe and feed evidence back" | `engine.with_context(ctx).step(approved=True)` |
| "Execute a leaf function in Unicorn sandbox" | `DynamicSandbox.from_context(ctx).run_function(va, args={'x0': 0x10})` |
| "Check if function is safe to run in sandbox" | `LeafFunctionChecker.from_path(elf).is_leaf(va, ctx)` |
| "Score evidence for a hypothesis" | `EvidenceScorer().scorehypothesis, evidence_items` |
| "Rank analysis probes by expected information gain" | `ProbeRanker().plan_report(hypotheses, top_n=5)` |
| "Confirm taint path is reachable" | `PathSolver.solve_pathfunc_va, target_va` |
| "Trace an arg across 3 library hops" | `IPRegAnnotator.annotate_chain(va, max_hops=3)` |
| "Which library exports this symbol?" | `LibGraph.defined_in('symbol')` |
| "Is this the same function as in v7.4?" | `DTWMatcher.score_functionsva_a, va_b` |
| "Where did this function change across versions?" | `MatrixProfileDiff.diff_functionsva_v1, va_v2` |
| "Find confirmed similar findings from past engagements" | `FindingRegistry.find_similarembedding` |
| "Sync confirmed findings into PatternLibrary flywheel" | `PatternLibrary.ingest_from_registry(reg)` |
| "Auto-name stripped functions via LLM" | `LlmAnalyst.FunctionNamer(ctx).run(va)` |
| "Compress N-file source audit to M profile buckets" | `SourceAuditCompressor.from_context(ctx).compress()` |
| "Generate PoC curl commands" | `PocGenerator.generate_allpreauth_routes` |
| "Analyze JWT token" | `CryptoAudit.analyze_jwt(token)` |
| "Sweep a Windows PE for vulns" | `python3 sweeps/pe_sweep.py <target.exe> --vendor <v>` |
| "Build engine signature corpus for a new engine" | `lib.add_signature(EngineSignature(...))` then `lib.save()` |
| "Feed game RE findings back into engine library flywheel" | `lib.ingest_from_findings(registry.confirmed(), engine='unreal')` |
| "Track RE session state across stages with schema validation" | `WorkflowDocument.for_re_sessionvendor, target` |
| "Audit finding provenance and detect cross-session tampering" | `StageCommitment.verifystage_name, instance` |


---

## FPGA firmware / hardware RE

| Task | First reach |
|---|---|
| "Parse a Xilinx .bit file header (design, part, date, bitstream)" | `XilinxBitfile.from_path(path).summary()` |
| "Extract embedded strings from an uncompressed FPGA bitstream" | `XilinxBitfile.from_path(path).extract_strings(min_len=6)` |
| "Get IDCODE from an uncompressed 7-series bitfile" | `XilinxBitfile.from_path(path).idcode_candidate()` |
| "Check if a bitfile was compressed by Vivado" | `XilinxBitfile.from_path(path).is_compressed()` |
| "Batch-parse all .bit files in a directory" | `scan_directory('/path/to/dir', '*.bit')` |
| "Map known Xilinx device IDCODEs" | `from ablation.analyzers.xilinx_bitfile import XILINX_IDCODES` |
| "Decode Xilinx config packets from an uncompressed bitstream (7-series, Spartan-6)" | `XilinxFrameDecoder.from_bitfile(bf).summary()` |
| "Extract all Type1/Type2 packets from a Xilinx bitfile" | `XilinxFrameDecoder.from_bitfile(bf).packets()` |
| "Get final register values written during FPGA configuration" | `XilinxFrameDecoder.from_bitfile(bf).config_registers()` |
| "Compare frame data between two FPGA firmware versions (word-level diff)" | `dec_a.frame_diff(dec_b)` |
| "Extract raw frame bytes for version comparison (Spartan-6 / Spartan-3AN)" | `XilinxFrameDecoder.from_bitfile(bf).heuristic_frame_bytes()` |
| "Extract text, register tables, and constants from a .docx ASIC specification" | `DocxReExtractor.from_path(path).register_tables()` |
| "Get all tables from a .docx spec as structured row/cell data" | `DocxReExtractor.from_path(path).tables()` |
| "Get full plain text from a .docx ASIC spec" | `DocxReExtractor.from_path(path).text()` |
| "Extract architecture parameters (speed, depth, count) from a LaTeX TDR or spec" | `LatexReExtractor.from_tar(tar, member).parameters()` or `from_path(tex).parameters()` |
| "Extract \\newcommand / \\def constant definitions from a LaTeX document" | `LatexReExtractor.from_path(tex).commands()` |
| "Extract tabular register-map tables from a LaTeX spec" | `LatexReExtractor.from_path(tex).tables()` |
| "Navigate section hierarchy of a LaTeX spec" | `LatexReExtractor.from_path(tex).sections()` |
| "Extract \\textbf{label}: description pairs from LaTeX itemize lists" | `LatexReExtractor.from_path(tex).labeled_items()` |
| "Parse a Xilinx Versal PDI firmware image (pld or boot type)" | `VersalPdi.from_path(path).report()` |
| "Determine PDI type (pld/boot) and extract sync word count" | `vp.result.pdi_type`, `vp.result.sync_word_count` |
| "Extract git commit hash from a Versal PDI (works for both pld and boot)" | `VersalPdi.from_path(path).git_hash()` — recovers from image header OR XILPDI CDO command |
| "List all CDO sections in a PDI and their command counts" | `VersalPdi.from_path(path).cdo_sections()` — each `CdoSection` has `.offset`, `.length_words`, `.commands` |
| "Extract all NPI register writes from a PDI's CDO sections" | iterate `cdo.commands` filtering `cmd.npi_addr is not None` |
| "Find all CFICDR/PL partitions (bitstream) in a PDI" | `[ph for ph in vp.partitions() if ph.is_pl]` |
| "Batch-parse all .pdi files in a directory for build provenance" | `VersalPdi.scan_directory(dir, '*.pdi')` — each result has `.git_hash()` |
| "Scan an arbitrary CDO blob for CDO sections (no MetaHeader)" | `VersalPdi.from_bytes(data).cdo_sections()` — scanner works even when pdi_type = 'unknown' |
| "Decode LCB downlink byte buffer (L0A triggers, BCR, CMD frames)" | `LcbDecoder.decode_stream(data)` — returns `List[LcbFrame]` with frame_type, l0a_map, bcr, tag |
| "Encode/decode SPECS frames or parse simulation headers" | `encode_frame()` / `decode_frame()` from `ablation.analyzers.specs_protocol`; use `parse_simulation_headers(text)` for archived vectors and explicit 128/129 long-frame behavior |
| "Decode STAR FLINK 4-bit nibble uplink (PR/LP events with L0ID)" | `StarFlinkDecoder.decode_stream(nibbles)` — returns `List[StarFlinkEvent]` with l0id |
| "Decode HCC 8B/10B uplink bit stream" | `decode_8b10b_stream(bits)` — returns `[(offset, byte, is_k)]` per codeword |
| "Decode single LCB 6B/8B codeword byte" | `decode_6b8b(byte)` → `(6bit_value, is_k)` or `None` if invalid |
| "Decode single 10-bit 8B/10B word (HCC uplink)" | `decode_8b10b(word10)` → `(byte, is_k)` or `None` if invalid |
| "Extract VHDL/Verilog source from HDL Designer HTML exports (*.htm ContentFrame files)" | `HdlHtmlExtractor.from_directory(htm_dir).to_semantic()` |
| "Get clean source text from an HDL Designer HTML export file" | `HdlHtmlExtractor.from_directory(htm_dir).text('module.vhd')` |
| "Write clean .vhd/.v files from HDL Designer HTML export (for HDLVersionDiff input)" | `HdlHtmlExtractor.from_directory(htm_dir).write_vhd(output_dir)` |
| "Extract constants from Verilog/VHDL source (parameters, defines, VHDL constants)" | `VerilogSemantic.from_directory(src_dir).constants()` |
| "Extract FSM state encodings from Verilog/VHDL" | `VerilogSemantic.from_directory(src_dir).state_encodings()` |
| "Search Verilog/VHDL source for a protocol pattern" | `VerilogSemantic.from_directory(src_dir).query('opcode broadcast reset')` |
| "List all module/entity names in a source tree" | `VerilogSemantic.from_directory(src_dir).modules()` |
| "Get port bit widths from Verilog/VHDL" | `VerilogSemantic.from_directory(src_dir).port_widths()` |
| "Classify the dominant analog topology in a SPICE netlist" | `SpiceAnalyzer.from_path(path).classify()` |
| "Count transistors by type in a SPICE file" | `SpiceAnalyzer.from_path(path).transistors_by_type()` |
| "Find current mirrors, diff pairs, LVDS structures in a SPICE netlist" | `SpiceAnalyzer.from_path(path).known_structures()` |
| "Extract supply voltages from a SPICE netlist" | `SpiceAnalyzer.from_path(path).supply_rails()` |
