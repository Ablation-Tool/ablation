# Ablation: Claude Operational Reference

## What this tool is

Binary RE toolkit for stripped firmware. No symbols. No source.

**Version:** 2.57.0 — `pip install -e ~/ablation/` (editable install, already done)
**GitHub:** `Ablation-Tool/ablation` — all repo ops via `gh` CLI. `mcp__github` is BANNED.

---

## Package layout

```
ablation/
  core/          # Low-level parsers + platform detection (not for direct use in RE work)
                 #   binary_parser.py, elf_parser.py, pe_parser.py, pe_analyzer.py
                 #   platform_detect.py, disasm_engine.py, tls_analyzer.py, macho_analyzer.py
  analyzers/     # All analysis tools — this is the RE surface (see "Which tool" table below)
  profiles/      # Vendor-specific sink/safe-pattern YAML (fortinet.yaml, etc.)
  data/          # Packaged JSON data (engine patterns, etc.)
  export/        # Report export helpers
  integrations/  # External tool bridges
sweeps/          # Standalone sweep scripts (pe_sweep.py, fortinet_sweep.py)
modules/         # Shared utility modules (NOT for target-specific findings)
re/         # Per-target RE modules — LOCAL ONLY, never committed to GitHub
  <vendor>/      # e.g. re/fortinet/, re/dahua/, re/huawei/
    <target>_re.py          # All findings go here
    SESSION_<target>.md     # Per-target session state
docs/            # Module reference + getting-started guides
tests/           # Test suite
```

**Key separation:**
- `ablation/analyzers/` = tools and scanners → committed, public
- `re/<vendor>/` = findings and session state → LOCAL ONLY, gitignored, never pushed to GitHub
- `modules/` = shared utilities → committed, vendor-neutral only

---

## Active session state

Read `SESSION.md` (root) before any work — it is the authoritative index of all active targets,
confirmed findings, and next steps. Per-target detail is in `re/<vendor>/SESSION_<target>.md`.

**Currently active (2026-10-04):**
- Apple QuickTime for Windows RE (`re/apple/`) — 3 candidates pending manual trace
- AlphaSmart Dana RE (`re/alphasmart/`) — WSCONV-001 CONFIRMED HIGH; AILERON-001 PLAUSIBLE
- IBM HPS 02BP235 (`re/ibm/`) — F-001 CONFIRMED; ValidateConnection pre-auth trace pending
- HPE MSA DHFlash (`re/hpe/`) — 5 confirmed findings; Telnet fallback + ARM RE pending
- FortiSOAR 7.6.7 (`re/fortinet/`) — 30 confirmed findings; dynamic confirms only remaining

**Pending ablation improvements (from SESSION.md):**
- `InstallerBinaryAnalyzer` module (self-extractor format, shell header scan)
- `_build_string_xref_index_ppc64_array` (CryEngine indirect TOC access pattern)
- README vendor list: add "Microsoft Windows"

---

## Session start: run this every time

```python
from ablation.analyzers.binary_context import BinaryContext

# 1. Read SESSION.md (root) + re/<vendor>/SESSION_<target>.md
# 2. Load context (0.5s first run, 110ms from cache)
ctx = BinaryContext.load_or_build('/path/to/target.so')
print(ctx.summary())

# 3. Surface all confirmed function names before anything else
if ctx.names_count():
    print(ctx.names_table())

# RULE: ctx.name(va) everywhere. Never raw hex in display contexts.
# ctx.set_name(0x17b660, "ips_diameter_parse_message", source="confirmed")
```

SESSION.md convention: root index at `~/ablation/SESSION.md`; per-target state at `re/<vendor>/SESSION_<target>.md`. Read before touching any binary. Update at end of each session.

---

## Which tool for which task?

| Task | First reach |
|---|---|
| "What does this function call?" | `ctx.callees_of(va)` |
| "What calls this symbol?" | `ctx.callers_of('symbol')` or `ctx.callers_of(va)` |
| "What strings does this function reference?" | `ctx.strings_in_func(va)` |
| "Which functions reference this string?" | `ctx.funcs_referencing_string(string_va)` |
| "strings_in_func() returns almost nothing on a stripped i386 ELF32 (static wsconv, legacy x86 IoT)" | `I386AbsoluteXrefScanner.from_context(ctx).inject(ctx)` — populates ctx._str_xref_idx and ctx._func_str_idx with absolute-imm32 xrefs; BinaryContext auto-calls this for x86_32 ELF, but call manually if ctx was loaded from cache before the scanner existed; ELF32 only, not PE32 |
| "What is this function?" | `ctx.name(va)` |
| "Show disassembly around address" | `WindowAnalyzer.dump_text(va, window=1536)` |
| "Find functions matching vulnerability pattern" | `SemanticSearcher.query(description)` (ALWAYS first on new binary) |
| "What values are passed to this sink?" | `FuncProfiler.profile(va).fmt()` |
| "Trace taint from network recv to sink" | `TaintTracker.run_interprocedural()` |
| "ARM32: trace recv to malloc/strcpy/system" | `ARM32TaintTracker.from_context(ctx).run_interprocedural()` |
| "ARM32: find MUL before malloc without bounds check" | `ARM32IntOverflowScanner.from_context(ctx).scan()` |
| "ARM64: trace recv to malloc/strcpy/system (Dahua, HiSilicon)" | `ARM64TaintTracker.from_path_full(elf).run_interprocedural()` — use `from_path_full` for stripped binaries (injects eh_frame func starts + PLT stub VAs); `from_path` only works when binary has symbols |
| "MIPS32: trace recv to system/strcpy/sprintf" | `MIPS32TaintTracker.from_path(elf).run_interprocedural()` |
| "MIPS32: big-endian RouterOS or little-endian CPE" | `MIPS32TaintTracker.from_path(elf, endian='big')` |
| "MIPS64: trace recv (Cisco IOS/OCTEON big-endian)" | `MIPS64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "MIPS64: little-endian RouterOS 64" | `MIPS64TaintTracker.from_path(elf, endian='little').run_interprocedural()` |
| "nanoMIPS: walk frame boundaries" | `NanoMIPSDecoder(endian='little').decode_frames(data, base_addr)` |
| "nanoMIPS: trace recv to system/popen/sprintf (Ingenic X-series, MediaTek Helio embedded)" | `NanoMIPSTaintTracker.from_path(elf, endian='little').run_interprocedural(depth=4)` — two-path: Capstone 6.x full decode or conservative O32 ABI fallback; P32/P16 BALC target resolution; 12-byte PLT stub unwrap |
| "PPC32: trace recv (Cisco IOS 7200, VxWorks)" | `PPC32TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "PPC32 PEF: detect ABI register clobber at OTStrCat/OTStrCopy/OTMemcpy call sites (Mac OS 8/9 CFM binaries)" | `PEFABIClobberScanner.from_bytes(code, base_va).scan(sink_vas, check_regs=[4])` — built on encoding_dag Templates; fixes ori RA-field, addic opcode 12, b/ba boundary bugs; `check_regs=[4,5]` for OTMemcpy; see `pef_abi_clobber_scanner` |
| "PPC32: resolve indirect BCTRL calls in GOT2-PIC stripped binary (Huawei VRP, embedded Linux)" | `PPC32GOT2Resolver.from_path(elf).resolve()` — returns `GOT2ResolveResult`; `.resolved` list has `.target`/`.name`; feed named symbols into `ctx.set_name(r.target, r.name)` |
| "PPC32 .so: find every BL call site that calls an imported symbol (system/popen/execl/execve) — verified, no false positives" | `PPC32PLTTracer.from_path(elf).find_callers('system')` — r30 cross-check per caller eliminates cross-CU false positives; `batch_scan(dir, sinks)` for full directory sweep; `PPC32ELF` helper for disasm/plt_slot; see `ppc32_plt_tracer` |
| "PPC64: trace recv (IBM POWER, AIX)" | `PPC64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "ARC: trace recv (ARC HS IoT, Marvell, Seagate)" | `ARCTaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 32: trace recv (SiFive, Allwinner D1)" | `RISCV32TaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 32 with HiSilicon WS63/Hi3863/BS21 riscv31 custom opcodes (0x0b/0x1b/0x1f/0x3b/0x5b/0x7b + uxtb/uxth)" | `HiSiliconRV32ExtDecoder` — `hisi_rv32_ext`; handles all 6 HiSilicon opcode spaces + 2 16-bit extensions; `ldmia`/`stmia` (0x0b) = multi-reg load/store, clears taint (memory not tracked); do NOT gate 0x0b dispatch on `(b0 & 0x80)==0` — bit7 is ra bitmap slot, not rd lsb; `uxtb`/`uxth` = 16-bit `(insn & 0xFC5F)==0x9C01`, clears taint (bounds value); `l.li` (0x1f) = 6 bytes (not 4); `muliadd` (0x5b) propagates taint from rs1+rs2; `addshf` (0x1b) propagates taint from rs1+rs2; `beqi/bnei` (0x3b) = branch, no data taint; `scan_all_custom(code, base_va)` for full inventory; pass as `ext_decoder=` to `RISCV32TaintTracker.from_path()` |
| "RISC-V 64: trace recv (VisionFive 2, SiFive Unmatched)" | `RISCV64TaintTracker.from_path(elf).run_interprocedural()` |
| "V850: trace recv (RH850/G3M ECU)" | `V850TaintTracker.from_path(elf).run_interprocedural()` |
| "RH850 GHS/IAR ABI: trace taint through CAN handler / SecurityAccess (flat ROM or ELF, Denso/Bosch)" | `RH850TaintTracker.from_bytes(data, base_va=0x0).scan_function(func_va, func_end, init_labels={'can_payload'})` — ELF: `.from_path(elf).run_interprocedural(depth=4)`; GHS CC-RH ABI (R6-R9 args, R10 return, R31=LP); `double_is_32bit=True` (GHS default, §2.7); GHS old-style mangling resolved (`__ct`/`__dt`/`__vtbl`/`_foo`); BFS uses deque; see `rh850-taint-tracker` |
| "TriCore AURIX: trace taint through SecurityAccess / CAN handler (flat ROM)" | `TriCoreTaintTracker.from_bytes(data, base_va=0x80000000).scan_function(func_va, func_end, init_labels={'sa_seed'})` — ELF path: `.from_path(elf).run_interprocedural()`; CSA-aware (upper context preserved across CALL; lower context d0-d7/a2-a7/a11 clobbered); FCALL/FRET leaf pattern handled; mode default = TC1.6.2 (AURIX); see `tricore-taint-tracker` |
| "x86-32/i386: trace recv to system/execv/snprintf (asamba, product.bin, Acronis rescue env, legacy x86 IoT)" | `X86_32TaintTracker.from_path(elf).run_interprocedural()` — CDECL32 stack args; PIC+non-PIC PLT; `from_context(ctx)` to inherit func_starts; `custom_sinks={'wrapper': {0: 0}}` for logging wrappers |
| "LoongArch64: trace recv (TencentOS 4.6, Loongson 3A5000/3C5000)" | `LoongArch64TaintTracker.from_path(elf).run_interprocedural()` |
| "LoongArch64: find GCC 12.3.1.7 max-not-min bug in ELF (kernel module, shared lib, executable)" | `LA64MaxNotMinScanner.from_path(elf).scan()` — 4-insn sltu/masknez/maskeqz/or sequence; checks or-result flows into named PLT sink within 20 insns |
| "LoongArch64: find GCC 12.3.1.7 max-not-min bug in UEFI PE32+ DXE module" | `LA64MaxNotMinScanner.from_pe32plus(data).scan()` — no PLT/GOT; reports arg-register feed at BL/<indirect> call sites; 63 findings across 26 modules in TencentOS EDK2 UEFI |
| "LoongArch64: find integer overflow before malloc/calloc/realloc/kmalloc (mul.w/sll.w/add.w/addi.w → size arg without bounds check)" | `LA64HeapVulnScanner.from_path(elf).scan()` — 32-bit overflow path; pure-Python no capstone; handles ET_DYN/ET_EXEC/ET_REL; HIGH=mul.w/sll.w, MEDIUM=add.w/addi.w |
| "Cache any scanner's results across sessions; auto-invalidate when scanner source or target file changes" | `ScanResultVersionCache.for_scanner(ScannerClass)` → `cache.get_or_scan(path)` → `list[dict]`; `scan_batch(paths)` → `dict[abspath, list[dict]]`; call `cache.save()` after batch; cache at `~/.ablation/cache/scan_results/<ClassName>.json`; key = (scanner_source_sha256, file_mtime_ns, file_size, file_sha256_prefix); stale on any scanner or file change |
| "Classify a Linux .ko file's attack surface from its kernel source tree path (PROXIMITY/NETWORK/LOCAL-USB/etc.)" | `KernelModuleSubsystemClassifier().classify(ko_path)` → `KernelModuleClassification`; fields: `attack_surface`, `subsystem`, `network_reachable`, `confidence`, `rule_matched`; `classify_batch(paths)` + `report(results)` for full sweeps; see `kernel-module-subsystem-classifier` doc for rule table |
| "Post-linker security gate: run full detector suite on compiled binary before it ships (all archs)" | `CompilerSecurityGate.from_path(elf).scan()` — taint (all archs) + format string + heap + length underflow (x86_64); findings include SemanticBlock DAG per taint path; `gate.check()` → exit code for CI/make; `gate.check(strict=True)` blocks on any severity; `python -m ablation.analyzers.compiler_security_gate <binary> [--strict] [--quiet]` |
| "Find printf/syslog with non-literal format string" | `FormatStringScanner.from_context(ctx).scan()` |
| "Scan for heap integer overflow / UAF / double-free" | `HeapVulnScanner.from_context(ctx).scan()` |
| "Where did this command string come from? (system/popen/execve)" | `SinkArgClassifier.from_path(elf).classify_all()` — verdicts: RODATA_CONST/SNPRINTF_RODATA/ARG_PROPAGATED/UNKNOWN |
| "Register vendor-specific sinks + known-safe patterns" | `VendorProfile.from_vendor('fortinet').apply_to(clf)` — loads profiles/fortinet.yaml; zero-caller sinks auto-ELIMINATED |
| "Map CMDB table IDs to exec-sink reach in FortiWeb/FortiOS binary (Phase 0.5 forward taint)" | `CMDBSurfaceMapper.from_path(elf).map()` — enumerates `cmf_query_create()` call sites, extracts table_id from rdi, flags callers that co-locate exec sinks; `extra_sinks=`, `extra_tables=`, `verbose=`; report warns co-location ≠ verified data flow; x86-64 ET_DYN only |
| "Batch triage all .so files in a dir — size/arch/exports/JNI/security strings" | `LibraryInventory.from_dir('/tmp/target/lib/arm64-v8a/').scan()` — returns `List[LibInventoryEntry]`; sorted by security_score; `report(entries)` prints table; `security_entries(entries, min_score=3)` filters hits |
| "Which libs in a rootfs dir have exec-class PLT imports?" | `batch_plt_intersect('/tmp/fad_root/lib/')` — returns {path:[sinks]}; omitted=auto-CLEAN; run FIRST, audit only the hits |
| "Detect allowlist byte-validators in stripped binary" | `SanitizerDetector.from_path(elf).detect()` — SHELL_SAFE/SHELL_UNSAFE/UNKNOWN per charset |
| "Classify fork() callers as worker/exec/exit" | `ForkExecClassifier.from_path(elf).classify()` — WORKER/EXEC_AFTER_FORK/EXIT_IN_CHILD |
| "Find 'safe now catastrophic later' rendering architecture risk (TS/JS/Python)" | `SourceArchRiskScanner.from_context(ctx).scan()` — tags: unsafe_render/type_dispatch/string_selector/registry_lookup/shared_module; HIGH=score≥3 or known combo |
| "Compress N-file source audit to M profile buckets (40x read reduction)" | `SourceAuditCompressor.from_context(ctx).compress()` — 5-bit profile per file; profile 0=batch-CLEAN; profiles 8-31=individual reads; .compression_ratio() gives % reads saved |
| "Audit a new ablation module before committing (SAFE CODE 10-section + DEV & TEST PLAN)" | `FORGE.audit_module('/path/to/module.py')` — returns cached ForgeReport instantly on hit; raises ForgeAuditRequired on miss (do audit inline, call FORGE.record_result() to cache); no subprocess, no API key; gate_passed=False on any HIGH/CRITICAL |
| "Audit any source codebase for vulnerabilities (no LLM)" | `FORGE.audit_source('/path/to/repo')` — runs SourceEntryClassifier+SourceSinkScanner+SourceAuditCompressor; returns ForgeReport with sink findings + priority read list |
| "Pre-commit gate on staged .py files" | Run `FORGE.audit_module(path)` for each staged .py; gate_passed=False blocks commit |
| "Trace an arg across 3 library hops" | `IPRegAnnotator.annotate_chain(va, max_hops=3)` |
| "Which library exports this symbol?" | `LibGraph.defined_in('symbol')` |
| "Is this the same function as in v7.4?" | `DTWMatcher.score_functions(va_a, va_b)` |
| "Where did this function change across versions?" | `MatrixProfileDiff.diff_functions(va_v1, va_v2)` |
| "Confirm taint path is reachable" | `PathSolver.solve_path(func_va, target_va)` |
| "Find pre-auth routes in flatui firmware" | `PreAuthRouteAuditor.run(route_init_va, factory_va)` |
| "Generate PoC curl commands" | `PocGenerator.generate_all(preauth_routes)` |
| "Analyze JWT token" | `CryptoAudit.analyze_jwt(token)` |
| "Crack XOR-encrypted firmware section" | `XorSolver.solve(ciphertext_path)` |
| "Extract FortiOS hardware firmware (.out file)" | `FortiOSHardwareExtractor.from_path(fw).extract_to(outdir)` |
| "Recover inner partition key from FortiOS hardware .out firmware and decrypt inner gzip partitions (cert keys, rootfs)" | `FirmwareContainerKeyExtractor.from_path(fw)` — outer XOR via FortiOSHardwareExtractor, then PKCS#1 v1.5 block scan for embedded RC4 key, then KPA on gzip magic to confirm; `result.datafs_path` set when cert key partition decrypted; `override_key=bytes.fromhex(...)` for known key |
| "Batch-fingerprint cert keys in FortiGate OVF firmware ZIPs against known key family table" | `FortiGateCertKeyScanner.from_path(ovf_zip)` or `FortiGateCertKeyScanner.batch_scan(dir)` — extracts fgt_512.key/fgt2.key/fgt.key, compares MD5 to KNOWN_KEY_FAMILIES, flags UNKNOWN family; results cached by file mtime; requires qemu-img + debugfs on PATH |
| "Scan a bare FortiGate KVM QCOW2 / Hyper-V VHD / VHDX disk image for cert keys (no OVF ZIP wrapper)" | `FortiGateCertKeyScanner.from_disk(path)` — detects format from extension (.qcow2/.vhd/.vhdx/.vmdk), converts to raw via qemu-img, extracts P1 at LBA 2048; returns error for FAZ/FMG images (no datafs.tar.gz at LBA 2048) |
| "Predict cert key set for a Fortinet firmware image from filename alone (no disk I/O)" | `FortiBuildTrackClassifier.classify(filename)` → `BuildTrackResult`; `build_track` M/F, `expected_keys` list, `key_generation` Gen1/Gen2; `discrepancy(actual_keys)` for anomaly detection vs scanner results; see `fortibuild-track-classifier` |
| "Find encrypted/packed sections in binary" | `EntropyMapper.scan()` |
| "Resolve C++ vtable indirect calls (ARM64)" | `VtableResolver.extract_vtable_regions()` + `resolve_blr_sites()` |
| "Reconstruct ET_DYN vtable slots from .rela.dyn (x86-64)" | `ELFVtableReconstructor.from_path(elf).reconstruct_class('ClassName')` — type-8+type-1 reloc scan; returns `VtableMap` with slot→function mapping; use `reconstruct(vtable_va)` when VA is known |
| "Determine which vtable methods are dead (never dispatched) in x86-64 binary" | `VtableDispatchScanner.from_path(elf).scan(slot_map)` — full encoding coverage (REX.B, disp8/32, SIB r12); `report.dead()` = unreachable methods, `report.live()` = call site list |
| "Extract C++ vtables from any ELF, name slots, and emit a type-annotation script for the full producer→consumer chain" | `CppVtableReconstructorAnalyzer.from_path(elf).scan()` — RELA reloc-based vtable extraction (any arch, dynamic ELF) + code-pointer byte scan fallback (static/non-PIE); slot naming via export symbols + BinaryContext string-xref + callee names; x86-64 + ARM64 full + all other arches via pointer literal scan; `emit_ida_script(result.vtables, result.propagation)` → type-annotation + comment script for full producer→consumer chain; use `from_context(ctx)` for BinaryContext-enhanced naming; see `cpp-vtable-reconstructor` |
| "Decrypt a PS3 SELF (Signed ELF) file to plain ELF for analysis — lief/BinaryContext reject SCE magic" | `PS3SELFDecryptor.from_path(eboot_bin).decrypt_to_tmp(eboot_bin)` → ELF path for BinaryContext.load_or_build(); `from_key_rev(0x0016)` explicit keyset; `decrypt(src, dst)` → DecryptResult(decrypted_sections, section_count); auto-detects keyset from key_rev bytes[6:8]; see `ps3-self-decryptor` |
| "Find C++ vtables in a PS3 Cell PPU (PPC64 ABI v1) binary — resolves OPD two-level indirection (vtable_ptr → OPD entry → code_va)" | `PS3OPDVtableScanner.from_context(ctx).scan(min_slots=3)` → `List[OPDVtable]`; each vtable: `va`, `slots`, `method_vas`, `null_slots`, `rtti_offset`, `class_hint`; `inject_into_context(vtables, ctx)` → injects `vtbl_<va>_sN` names; `find_by_method_name(vtables, name, ctx)` → locate which class owns a named method; dual-TOC binaries: pass `toc=` explicitly and call twice (once per module); `from_path(elf)` for no-ctx use; see `ps3-opd-vtable-scanner` |
| "Detect TI NNC (Apache TVM) inference artifacts in ARM ELF or C28x COFF firmware — tvmgen_* symbols, weak normalization override risk, NPU async hazard, multi-model contention" | `TiNNCScanner.from_path(path).scan()` — ELF (lief) + TI COFF2/AR (TiCoffLoader); no disassembly; 4 finding classes: TINCC-001 (HIGH weak norm override), TINCC-002 (MEDIUM NPU ordering), TINCC-003 (MEDIUM multi-model NPU), TINCC-004 (INFO skip-normalize); targets: Cortex-M33/M4/R5/M0+, C29x ELF, C28x F28P55x COFF; `TiNNCScanner.report(result)` for ASCII table; see `ti-nnc-scanner` |
| "Parse TI COFF2 object files and AR archives (cl2000, c29clang output) — extract symbol table with storage class (C_UEXT=weak)" | `TiCoffLoader.from_path(path)` → iterate `.symbols()` for `CoffSymbol` list; `sym.is_weak` = True when `storage_class==C_UEXT` (19); `sym.is_global` for C_EXT; `loader.objects()` for per-member detail; raises `FileNotFoundError` on missing file (caller catches); see `ti-coff-loader` |
| "Scan a flat ECU ROM for function starts without knowing the ISA (arch-agnostic)" | `FlatBinaryFuncStartScanner(rom, base_va=0).scan()` → `FuncStartResult`; `.function_starts` = sorted union of call targets + prologue hits; `.call_targets` = BFS from reset vector following direct calls; `.prologue_hits` = ISA prologue byte scan; `.arch`/`.confidence` from `EcuArchDetector`; `scan(arch='sh2a')` to force ISA; `from_path(p)` / `from_bytes(b)` wrappers; `max_call_depth` caps BFS; see `flat-binary-func-start-scanner` |
| "Fingerprint the ISA of an unknown flat ECU ROM image (no ELF/IHEX wrapper)" | `EcuArchDetector(rom_bytes).detect()` → `ArchDetectResult`; `.arch` = `arm_cm/tricore/m68k/ppc32/ppc_vle/sh2a/unknown`; `.confidence` = `HIGH/MEDIUM/LOW`; `.score` 0.0–1.0; `.reason` one-sentence; `.candidates` all hypotheses sorted by score; `.is_confident` = True for HIGH/MEDIUM; `from_path(p)` / `from_bytes(b)` wrappers; `sample_size=0` to scan full image; TriCore discriminator always scans full image (startup density too low in first 4 KB); see `ecu-arch-detector` |
| "Decode Renesas SH-2A (SH7058/SH7059) ECU firmware — Capstone has no SH-2A support" | `EcuSH2aDecoder(rom, base_va=0x400000).disassemble(start, end)` → `List[SH2aInsn]`; `function_starts()` → VAs of stack-saving + leaf prologues; `decode_one(offset)` → single insn; `SH2aInsn`: `mnemonic`, `insn_type` (CALL/BRANCH/RETURN/LOAD/STORE/LR_SAVE/MISC), `rd/rs/imm/target/raw`; 32-bit SH-2A: MOVI20/MOVI20S + MOV12 + BIT ops; `from_path(p)` / `from_bytes(b)` wrappers; see `ecu-sh2a-decoder` |
| "Decode TMS320C28x (F28x-series MCU) firmware — Capstone has no C28x support; used in EV traction-inverter and motor-drive ECUs" | `EcuC28xDecoder(data, base_va=0).disassemble(start, end)` → `List[C28xInsn]`; `function_starts()` → word-VAs of direct call targets (LC/LCR/FFC); `decode_one(byte_off)` → single insn; `C28xInsn`: `mnemonic`, `insn_type` (BRANCH/CALL/RETURN/LOOP/MISC), `word_va`, `target` (word-addr), `cond`, `imm`, `raw`; 3 calling conventions: LC/LRET (stack), LCR/LRETR (RPC register), FFC (XAR7); `base_va` is a word address; byte offsets for `disassemble`/`decode_one`; `from_path(p)` / `from_bytes(b)` wrappers; see `ecu-c28x-decoder` |
| "Parse Go pclntab and enumerate functions" | `GoBinaryRE.parse_pclntab()` |
| "Find Go subprocess/exec injection sites" | `GoSubprocessScanner.scan()` |
| "Auto-name stripped functions via LLM" | `LlmAnalyst.FunctionNamer(ctx).run(va)` |
| "Find confirmed similar findings from past engagements" | `FindingRegistry.find_similar(embedding)` |
| "Export confirmed findings as PatternLibrary query dicts" | `FindingRegistry.export_patterns()` — returns `[{query, tag}]`; one per unique (title, description); CWE auto-tagged |
| "Sync all confirmed findings into PatternLibrary (flywheel)" | `PatternLibrary.ingest_from_registry(reg)` — idempotent; call at engagement start before `sweep()` |
| "Write a new scanner for an undetected vuln class" | See **Custom scanner workflow** below |
| "Decode a Cell SPU ELF (PS3 co-processor)" | `SPUDisassembler.dump_spu_elf(path, start_va, limit)` — `frequency_report(text, base)` for gap analysis; `extract_spu_text_from_elf(data)` for raw bytes extraction |
| "Sweep a Windows PE i386 or AMD64 (.exe/.dll) for vulns (QuickTime, Win32 media codecs)" | `python3 sweeps/pe_sweep.py <target.exe> --vendor <v> --product <p> --version <v>` — IAT call resolution; i386: CS_MODE_32 + 55 8B EC prologues; AMD64: CS_MODE_64 + RIP-relative IAT resolution + LEA string refs; Qt/Win32 profiles; no taint |
| "Analyze a Windows kernel .sys driver" | `KernelDriverAnalyzer.from_path(path).analyze()` |
| "Find CFG bypass targets in a Windows PE (disabled CFG, missing export suppression, exports not in CFG table)" | `CFGBypassDetector.from_path(pe).scan()` — reads `IMAGE_LOAD_CONFIG.GuardFlags` + CFG function table; cross-references exports; entry stride = `4 + (GuardFlags >> 28)`; HIGH=cfg_disabled/cfg_table_absent, MEDIUM=no_export_suppression/export_not_in_table; `det.cfg_config()` for raw config |
| "Check SafeSEH status and find SEH frame installations in an x86 PE" | `SEHChainAnalyzer.from_path(x86_pe).scan()` — x86-32 only (raises ValueError on x64); reads SafeSEH handler table from IMAGE_LOAD_CONFIG; scans code for push-handler/push-FS:[0] sequences; HIGH=safesh_disabled, MEDIUM=handler_not_in_table |
| "Extract ETW provider GUIDs and detect detection gaps in a Windows PE" | `ETWProviderExtractor.from_path(pe).scan()` — finds EventRegister call sites; extracts GUIDs (RCX/LEA for x64, push for x86); cross-references against 15 known security providers; MEDIUM=detection gap (providers registered, zero EventWrite sites) |
| "Find RPC server interfaces and check auth levels in a Windows PE" | `RPCServerAnalyzer.from_path(pe).scan()` — finds RpcServerRegisterIf* call sites; reads RPC_SERVER_INTERFACE struct for interface UUID + transfer syntax; extracts auth level from RegisterIfEx; HIGH=RPC_C_AUTHN_LEVEL_NONE (CWE-306); `ana.endpoint_strings()` for named pipes/ports |
| "Map COM attack surface: COM server detection, CLSID inventory, COM hijacking risk" | `COMAttackSurfaceMapper.from_path(pe).scan()` — detects DllGetClassObject exports; scans .rdata/.data for {GUID} strings; finds CoCreateInstance call sites with resolved CLSIDs; MEDIUM=com_hijack_risk (CWE-426), com_marshal (CWE-502) |
| "Load PDB symbols for a Windows PE binary into BinaryContext" | `PDBSymbolIntegrator.from_path(pe).inject_into_context(ctx)` — reads CodeView RSDS debug entry; fetches PDB from msdl.microsoft.com; parses MSF 7.0 + S_PUB32 records; calls ctx.set_name(va, name, source='pdb'); `integrator.pdb_info()` for GUID+URL |
| "Find unvalidated ExAllocatePool size → RtlCopyMemory taint in a Windows kernel driver" | `WindowsPoolTaintTracker.from_path(driver_sys).scan()` — finds ExAllocatePool* + RtlCopyMemory/memmove sites; pairs allocation-size register with copy-size register; HIGH=unvalidated propagation (CWE-122); complement with KernelDriverAnalyzer for full driver triage |
| "Decode a Windows IOCTL CTL_CODE value" | `decode_ioctl_code(value)` from `kernel_driver_analyzer`; rejects printable-ASCII 4-byte values (pool tags / format strings that pass other checks) |
| "Detect vtable in writable PE section (write primitive → IRP dispatch hijack)" | `KernelDriverAnalyzer` — `report.dangerous_patterns` includes `WRITABLE_VTABLE_IN_DATA` entries when 3+ aligned code pointers appear in a writable `.data` section |
| "Detect METHOD_NEITHER IOCTLs with no ProbeForRead/ProbeForWrite (CWE-822 unvalidated kernel arb-read)" | `KernelDriverAnalyzer` — `report.dangerous_patterns` includes `NEITHER_IOCTL_NO_PROBE` when METHOD_NEITHER IOCTLs exist and neither probe function appears in IAT or UTF-16LE strings |
| "Detect dangerous API surface in a zero-IAT driver (MmGetSystemRoutineAddress-resolved, no import table)" | `KernelDriverAnalyzer` — falls back to UTF-16LE string scan when IAT returns zero findings; results tagged `dll='[dynamic-resolve]'` in `report.kernel_apis` |
| "Detect BYOVD capability classes in a signed Windows kernel driver (PHYS_MEM_RW, TOKEN_STEAL, DKOM, CALLBACK_REMOVE, PROCESS_KILL, DRIVER_LOAD, APC_INJECT, MSR_WRITE)" | `ByovdDetector.from_path(driver_path).detect()` → `ByovdReport`; `report.is_byovd_capable`; `report.capabilities`; compose with KDA to avoid re-parsing: `ByovdDetector(path, kda_report=existing_report).detect()`; see `kernel-drivers` doc |
| "Parse and extract partitions from a partitioned firmware container image" | `FirmwareContainer.from_path(fw).dump_partitions()` |
| "Extract a specific firmware partition by name" | `FirmwareContainer.from_path(fw).extract('bin', out_path)` |
| "Extract files from Huawei VRP squashfs v4 XZ image (ARM64 BCJ filter, V600R024+)" | `HuaweiSquashfsExtractor(sqfs_path).extract(inner_path)` → bytes; `ext.list_files()` to enumerate; use `with` for auto-close; see `huawei-squashfs-extractor` doc |
| "Scan MP4/MKV/AVI for forensic anomalies (polyglot, trailer data, atom overflow)" | `VideoContainerAnalyzer.from_path(path).scan()` |
| "Find JNI bridge surface in Android APK (RegisterNatives vs canonical, opaque peer)" | `JniBridgeScanner.from_path(apk).scan()` — HIGH=dynamic reg or opaque peer; MEDIUM=Java_* canonical |
| "Map exported Binder service surface in Android APK (Services, Stubs, onTransact)" | `BinderScanner.from_path(apk).scan()` — HIGH=exported service or raw onTransact; MEDIUM=AIDL Stub |
| "Disassemble a DEX method to smali (all 17 instruction formats, annotated refs)" | `DEXDisasm(dex).disasm_method('Lcom/foo/Bar;', 'methodName')` — full smali with method sigs, field descriptors, string literals |
| "Disassemble all methods in a DEX class" | `DEXDisasm(dex).disasm_class('Lcom/foo/Bar;')` — iterates every non-native method with code |
| "Lift a native function to pseudo-C IR across 18 ISA variants (arm64, x86-64, x86-32, arm32, thumb, mips32, mips64, nanomips, ppc32, ppc64, rv32, rv64, arc, v850, la64, sh2a, beam, erlang)" | `BinaryLifter.from_path(elf, arch='arm64').lift_function(va)` — all native ISAs (arm64, x86-64, x86-32, arm32/thumb, mips32/64, nanomips, ppc32/64, rv32/64, arc, v850, la64, sh2a) emit full NativeVal pseudo-C IR with typed register tracking, arg seeding, load/store dereferences, and resolved call sites; `.with_taint(findings)` propagates taint into all ISAs (not ARM64 only); ARC/V850 require `arc-elf32-objdump`/`v850-elf-objdump` in PATH; BEAM emits function-level pseudo-IR (call/move/gc_bif/send/try/catch decoded via `BEAMLifter`); pass `va=0` for full module IR |
| "Lift a Renesas SH-2A (SH7058/SH7059) ECU function from flat ROM to pseudo-C IR" | `BinaryLifter.from_path(rom, arch='sh2a').lift_function(va)` — flat ECU ROM: VA==file offset (base_va=0); ELF also supported; `arch='sh-2a'` and `arch='sh2'` are aliases; dispatches on `SH2aInsn.insn_type` (pre-decoded by `EcuSH2aDecoder`); R4-R7=args, R0=return; taint via `_taint_map`; truncates at RETURN+delay-slot; see `binary-lifter-sh2a` doc |
| "Seed and score competing RE hypotheses (source-to-sink, indirect call, function entry)" | `HypothesisEngine.from_binary(elf, arch='arm64', ctx=ctx)` — seed/add_evidence/plan/report; CONFIRMED requires structural+data_flow evidence; REJECTED on hard contradiction; sessions persist to ~/.ablation/sessions/; pass `ctx=` to enable auto-execution |
| "Auto-execute a probe (Milestone 3) and feed evidence back" | `engine.with_context(ctx).step(approved=True)` — runs adapter (disassembly/cfg/xref/lifter/taint/semantic/version), returns EvidenceRecord list, updates hypothesis confidence in place |
| "Execute a probe directly outside the engine" | `execute_probe(probe_record, ctx, session)` — dispatches to correct ProbeAdapter by kind; returns List[EvidenceRecord]; never raises |
| "Execute a leaf function in Unicorn sandbox (Phase 3)" | `DynamicSandbox.from_context(ctx).run_function(va, args={'x0': 0x10})` → SandboxResult; `.probe_multiple(va, input_sets)` for multi-run behavioral fingerprinting; PLT calls abort cleanly |
| "Check if function is safe to run in sandbox (no PLT callees)" | `LeafFunctionChecker.from_path(elf).is_leaf(va, ctx)` — False if any callee is in .plt range; probe returns partial result (strength 0.40) if aborted |
| "Score evidence for a hypothesis with family deduplication" | `EvidenceScorer().score(hypothesis, evidence_items)` → (confidence, state, contradiction_notes); families: behavioral(1.0)→data_flow(0.9)→structure(0.75)→semantic(0.25) |
| "Rank analysis probes by expected information gain" | `ProbeRanker().plan_report(hypotheses, top_n=5)` — eig = disagreement × observability / cost; probe kinds: disassembly/cfg/lifter/taint/semantic/version/manual |
| "Label stripped PC game binary as engine code (UE4/id Tech/Unity/Source2/CryEngine)" | `EnginePatternLibrary.default().label_binary(ctx, xg)` — 3-pass: string_marker → string_pattern → semantic; returns `{va: EngineLabel}`; `.strip_report(labels, total_funcs)` gives coverage; `.unlabeled(func_starts, labels)` = human RE target |
| "Find math/physics/renderer functions on PPC64 Cell PPU (PS3) by VMX instruction density" | `VMXDensityScanner.from_context(ctx).scan(threshold=5)` → `List[VMXFunctionResult]`; O(N log F) numpy path; labels: vector_heavy(≥30%)/vector_math(≥15%)/vector_light(≥5%)/vector_trace; `scanner.report(results, name_fn=ctx.name)` for table; `density_histogram(results)` for bucket view; use when 100K+ functions have no string xrefs |
| "Classify PPC64 Cell PPU functions as dynamic data structure traversal / manipulation (BST, C-tree, BLL, coroutine iterator)" | `DynDSClassifier.from_context(ctx).classify()` → `List[DynDSFinding]`; O(N log F) numpy; patterns: bst_traversal/ctree_traversal/bll_traversal/coroutine_iter/bll_append; no string xrefs needed; `clf.report(findings, name_fn=ctx.name)` for grouped table; `clf.by_pattern(findings)['bst_traversal']` for subset; combine with VMXDensityScanner to cover both math-heavy and pointer-heavy residuals |
| "Build engine signature corpus for a new engine" | `lib.add_signature(EngineSignature(sig_id, engine, category, name, description, string_markers, string_patterns))` — then `lib.save()` to `~/.ablation/engine_patterns.json` |
| "Feed game RE findings back into engine library (flywheel)" | `lib.ingest_from_findings(registry.confirmed(), engine='unreal', category='gameplay')` — turns confirmed FindingRegistry hits into new EngineSignatures |
| "Lift DEX method to pseudo-Java (field access, method calls, if/else, types)" | `DEXLifter(dex).lift_method('Lcom/foo/Bar;', 'methodName')` — readable Java-like IR with type-inferred registers |
| "Lift all non-native methods in a DEX class to pseudo-Java" | `DEXLifter(dex).lift_class('Lcom/foo/Bar;')` — full class pseudo-Java; detect obfuscation patterns instantly |
| "Lift a MicroPython .mpy v6 module to pseudo-Python (ESP32/STM32/CC13xx firmware)" | `MpyLifter.from_path(mpy).lift_module()` — decodes prelude + bytecode to readable pseudo-Python; `lifter.imports()` lists all imported modules; `lifter.dangerous_calls()` flags exec/eval/os.system/machine.mem32/socket imports; same format works for CircuitPython; `MpyLifter.report(findings)` for ASCII table; see `mpy-lifter` |
| "Extract key material from BMP LSB steganography (Lagrange secret sharing)" | `BmpKeyExtractor('/path/to/keys.bmp').extract('seed')` — per-component hex + raw_key_hex; matches imath LE+reverse-TC byte order |
| "Parse TunerPro XDF calibration definition file and inject table labels into BinaryContext" | `EcuXDFParser.from_file(xdf_path)` — `label_map()` → `{file_offset: name}`; `calibration_tables()` → `List[CalibrationTable]`; handles DALINK shared axes, linear MATH equations, BASEOFFSET; 755 tables parsed from BMW N54 MSD80 XDF in under 1s; see `ecu-cal-parsers` |
| "Parse open_damos.json and locate calibration tables in any ROM variant via fingerprint relocation" | `EcuOpenDamosParser.from_file(json_path)` — `locate_in_rom(rom)` → `{name: file_offset}`; encodes physical axis breakpoints (RPM, load %) as raw integer bytes and byte-searches ROM; correct for any firmware variant, not just the definition baseline; handles Bosch EDC16C34/39, EDC17C42/49/50; `label_map(rom)` injects relocated addresses; see `ecu-cal-parsers` |
| "Classify an ECU ROM image into ERASED/CODE/CALIBRATION/MIXED/PADDING regions before any scanner" | `EcuROMLayoutAnalyzer.from_path(rom).analyze()` → `ROMLayout`; `.calibration_regions()` feeds EcuCalibrationTableScanner bounds; `.code_regions()` feeds disasm pipeline; four-variable classifier: entropy + fill ratio + entropy floor (4.8 bits) + PPC instruction density (0.20 threshold); validated on GM E38 PCM (PPC32, 1520 KB code) and Bosch EDC16C34 (calibration-only, zero false CODE regions); see `ecu-rom-layout-analyzer` |
| "Parse a RomRaider ECU definition XML and auto-identify a ROM variant, then inject table labels into BinaryContext" | `EcuRomRaiderParser.from_file(xml_path)` — `identify_rom(rom)` → `xmlid` (searches ±32-byte window around internalidaddress, with hex-address fallback); `calibration_tables(variant_id)` → `List[CalibrationTable]`; `label_map(variant_id)` → `{file_offset: name}`; 14 scaling expression forms parsed including `(x-offset)*k`; covers BMW Siemens MS43/MS45 (MPC555 PPC32), Subaru Denso SH705x, Subaru 5EAT TCU M32R (self-contained format, 273 tables); self-contained ROMs (all addresses inline in base) automatically synthesize a pseudo-variant so calibration_tables(base_xmlid) works without a separate overlay; false-positive filter: candidate must resolve ≥min(20, base_defs//5) tables; see `ecu-romraider-parser` |
| "Parse a conescan ECU definition XML (Mazda SH705x/SH7055 MX5/RX8) and inject table labels into BinaryContext" | `EcuConescanParser.from_file(xml_path)` — single-ROM format (no base/variant split); `identify_rom(rom)` → `bool` (searches ±32-byte window around internalidaddress for internalidstring); `calibration_tables()` → `List[CalibrationTable]`; `label_map()` → `{file_offset: name}`; is_float propagated for float32 storagetype; 507 tables from MX5 LFG2EE; degenerate 3D tables (missing axis child) silently skipped; see `ecu-conescan-parser` |
| "Parse an ASAM/ASAP2 A2L ECU calibration definition file (Bosch EDC16, EDC17, MED17, Continental, Delphi, any OEM A2L)" | `EcuA2LParser.from_file(a2l_path)` — Latin-1 encoding; A2ML + IF_DATA blocks stripped; RAT_FUNC COEFFS reduced to scale=b/f, bias=c/f; RECORD_LAYOUT type resolution (SWORD/UWORD/FLOAT32_IEEE/etc.); byte order from BYTE_ORDER keyword (MSB_FIRST=big, MSB_LAST=little); `calibration_tables()` → `List[CalibrationTable]`; `label_map()` → `{file_offset: name}`; 11,427 tables from Bosch EDC16U34; 26,016 from EDC17CP46; see `ecu-a2l-parser` |
| "Parse Pytrex NissanDefinitions and inject calibration table labels for Nissan SH705x ECUs (350Z, G35, Altima, Maxima, Sentra, Skyline, 12+ models)" | `EcuNissanParser.from_dir(defs_dir)` — loads ScalingData.xml (273 scalings, tolerant XML for truncated file) + A2L.xml (188 table defs) + all variant XMLs in subdirs; `variants()` → list of 188 xmlids; `calibration_tables(variant_id)` → `List[CalibrationTable]` (chain-resolved: child overrides ancestor); `identify_rom(rom)` → xmlid by internalidstring match; `label_map(variant_id)` → `{file_offset: name}`; per-table X/Y Axis address overrides from CD415-style variants; see `ecu-nissan-parser` |
| "Parse a CAN DBC signal database file (CANdb++, SavvyCAN, Wireshark, cantools format); extract message/signal definitions, value tables, and comments" | `CanDbcParser.from_file(path)` — `messages()` → list; `message(can_id)` → CANMessage; `find_signals(pattern)` → [(msg, sig)]; `standard_messages()` / `extended_messages()` split; `CANSignal.decode(raw)` → physical; 29-bit extended frame detection (bit 31 in raw DBC ID); two-pass: BO_/SG_ first, then CM_ comments + VAL_ value tables; BMW E39/E90 + SAE J1939 validated; see `can-dbc-parser` |

**Ordering rule:** BinaryContext (always) -> SemanticSearcher (new binary/vuln class) -> FuncProfiler (candidate) -> TaintTracker (sinks known) -> PathSolver (confirm feasibility). Manual capstone only when TaintTracker has no configured sink.

---

## Module quick-reference

All modules under `ablation.analyzers.*`. Construction pattern: `ClassName.from_context(ctx)` or `ClassName.from_path('/path/to/binary')`.

**BinaryContext** — `from ablation.analyzers.binary_context import BinaryContext`
Core: `load_or_build(path)`, `summary()`, `names_table()`, `name(va)`, `set_name(va, name, source)`, `callers_of()`, `callees_of()`, `strings_in_func(va)`, `funcs_referencing_string(va)`. Cache at `~/.ablation/cache/`; name overlay at `~/.ablation/function_names.json`.

**SemanticSearcher** — `from ablation.analyzers.semantic_search import SemanticSearcher`
`SemanticSearcher.from_context(ctx)` — primary constructor; resolves binary from `ctx.sha256`, scopes corpus to that binary's VAs, pre-builds (~549s first run, 0.1s cache hit). Then `query(description, top_k=10)`. Calling the bare constructor without `from_context` will warn and encode all functions in func_id.db (slow).

**TaintTracker (x86-64)** — `from ablation.analyzers.taint_tracker_x86 import TaintTracker`
`TaintTracker(path, xref=xg, custom_sinks={'sink': [arg_idx]})`. Modes: `run_on_function(va)`, `run_interprocedural()`, `run_on_function_seeded(va, seed_arg_indices=[1])`.

**Arch taint trackers** — all follow `ClassName.from_path(elf[, endian='big'|'little'][, custom_sinks={}]).run_interprocedural()`:
- `ARM32TaintTracker` — `taint_tracker_arm32`; Thumb binaries: `ARM32TaintTracker(path, thumb=True)`
- `ARM64TaintTracker` — `taint_tracker_arm64`; `from_path(elf)` or `from_context(ctx)`
- `MIPS32TaintTracker` — `taint_tracker_mips32`
- `MIPS64TaintTracker` — `taint_tracker_mips64`
- `NanoMIPSTaintTracker` — `taint_tracker_nanomips`; two-path: Capstone 6.x or conservative O32 ABI fallback; `has_full_decode` flag
- `PPC32TaintTracker` — `taint_tracker_ppc32`
- `PPC64TaintTracker` — `taint_tracker_ppc64`
- `ARCTaintTracker` — `taint_tracker_arc`; check `ARCDecoder().has_full_decode` for capstone next
- `RISCV32TaintTracker` — `taint_tracker_riscv32`
- `RISCV64TaintTracker` — `taint_tracker_riscv64`
- `V850TaintTracker` — `taint_tracker_v850`; endian auto-detected via lief
- `X86_32TaintTracker` — `taint_tracker_x86_32`; i386 CDECL32; PIC+non-PIC PLT; `from_path(elf)` or `from_context(ctx)`; custom_sinks={name:{arg_idx:min_len}}

**DisasmEngine** — `from ablation.analyzers.disasm_engine import DisasmEngine`
`DisasmEngine(arch='mips32'|'mips64'|'ppc32'|'ppc64'|'arc'|'riscv32'|'riscv64'|'v850'[, endian='big'])`. Arch decoders: `NanoMIPSDecoder`, `ARCDecoder`, `V850Decoder` all follow `decode_frames(data, base_addr)`.

**FuncProfiler** — `from ablation.analyzers.func_profiler import FuncProfiler`
`from_context(ctx)`. `profile(va).fmt()`. `profile.sink_calls`. Default sinks: strcpy/strcat/sprintf/vsprintf/system/popen/execv*/Tcl_Eval/fm_exec_cli.

**PatternLibrary** — `from ablation.analyzers.pattern_library import PatternLibrary`
`pl.sweep(searcher)`, `pl.record_hit(tag, binary, va, confirmed=True)`, `pl.add(query, tag=)`.
Flywheel: `pl.ingest_from_registry(reg)` — pulls confirmed findings from FindingRegistry, deduplicates, saves. Call once at engagement start before `sweep()`. Thread-safe (RLock).

**FindingRegistry** — `from ablation.analyzers.finding_registry import FindingRegistry`
`reg.register(vendor, product, version, title, description, cwe_class, severity, embedding, func_addr, binary)`. `find_similar(embedding, top_k=8, min_sim=0.60)`. Storage: `~/.ablation/findings.db`.
Flywheel: `reg.export_patterns()` → `[{query, tag}]`; one per unique (title, description); CWE→tag via `_CWE_TAG_MAP`.

**LibGraph** — `from ablation.analyzers.lib_graph import LibGraph`
`LibGraph.from_dir('/path/rootfs/lib/')`. `callers_of(sym)`, `defined_in(sym)`, `call_chain(binary, sym)`.

**IPRegAnnotator** — `from ablation.analyzers.ipreg_annotator import IPRegAnnotator`
`annotate_chain(entry_va, max_hops=3)`. `chain.sink_report(SINKS)`.

**PathSolver** — `from ablation.analyzers.path_solver import PathSolver`
`solve_path(func_va, target_va, constraints=[MemoryConstraint(reg='rsi', min_len=256)])`. `result.sat`.

**WindowAnalyzer** — `from ablation.analyzers.window_analyzer import WindowAnalyzer`
`dump_text(va, window=1536)`. `calls_in_window(va, window)`.

**CryptoAudit** — `from ablation.analyzers.crypto_audit import CryptoAudit, forge_jwt`
`analyze_jwt(token)`, `analyze_tls(host)`, `scan_key_material(['/etc/'])`.
`forge_jwt({'sub': 'admin', 'role': 'superuser'}, secret='', alg='none')`.

**FortiOSHardwareExtractor** — `from ablation.analyzers.fortios_firmware_extractor import FortiOSHardwareExtractor`
`FortiOSHardwareExtractor.from_path(fw).extract_to(outdir)`. 64-byte XOR key; NAND 0xFF assumption for FortiWiFi/FortiGate appliances; pass `plaintext_assumption=0x00` for x86-64 sparse images.

**FirmwareContainerKeyExtractor** — `from ablation.analyzers.firmware_container_key_extractor import FirmwareContainerKeyExtractor`
`FirmwareContainerKeyExtractor.from_path(fw)` — outer XOR via FortiOSHardwareExtractor, PKCS#1 v1.5 block scan, RC4 KPA against gzip magic. `result.datafs_path` set when cert partition decrypted. `override_key=bytes` for known keys.

**FortiGateCertKeyScanner** — `from ablation.analyzers.fortigate_cert_key_scanner import FortiGateCertKeyScanner`
`FortiGateCertKeyScanner.from_path(ovf_zip)` or `.from_disk(bare_disk_path)` or `.batch_scan(dir)`. Extracts fgt_512.key/fgt2.key/fgt.key MD5s, classifies against `KNOWN_KEY_FAMILIES`, flags `family='UNKNOWN'` as new finding candidate. `from_disk()` handles `.qcow2/.vhd/.vhdx/.vmdk` directly. Cache at `~/.ablation/cache/fortigate_cert_key_scanner.json`.

**FortiBuildTrackClassifier** — `from ablation.analyzers.fortibuild_track_classifier import FortiBuildTrackClassifier`
`FortiBuildTrackClassifier.classify(filename)` → `BuildTrackResult`. Parses Fortinet filename → `build_track` (M/F), `expected_keys` list, `key_generation` (Gen1/Gen2), `version`, `build_number`. No disk I/O. `result.discrepancy(actual_keys_set)` detects anomalies vs `FortiGateCertKeyScanner` results. `batch_classify([filenames])` + `report(results)` for directory sweeps.

**KernelDriverAnalyzer** — `from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer, decode_ioctl_code`
`KernelDriverAnalyzer.from_path(path).analyze()`. Key: `report.ioctl_codes`, `report.dangerous_patterns`, `report.is_signed`. `decode_ioctl_code(val).is_neither()` true = raw user pointer, no kernel buffer copy; trace `InputBufferLength` via TaintTracker with `ExAllocatePoolWithTag`/`RtlCopyMemory` sinks. `report.dangerous_patterns` now includes `WRITABLE_VTABLE_IN_DATA` (vtable in writable section — any kernel write converts to IRP dispatch hijack) and `NEITHER_IOCTL_NO_PROBE` (METHOD_NEITHER IOCTLs with no ProbeForRead/Write anywhere in binary — CWE-822). Zero-IAT drivers (import_directory_rva=0, MmGetSystemRoutineAddress-resolved) produce `[dynamic-resolve]` tagged entries in `report.kernel_apis` via UTF-16LE string fallback. `decode_ioctl_code` rejects printable-ASCII 4-byte values (pool tag false positives).

**DTWMatcher** — `from ablation.analyzers.dtw_matcher import DTWMatcher`
`score_functions(va_a, va_b)`. Verdicts: same_era (>=0.85), patched (0.45-0.85), rewritten (0.20-0.45).

**MatrixProfileDiff** — `from ablation.analyzers.matrix_profile_diff import MatrixProfileDiff`
`diff_functions(va_v1, va_v2)`. Use `discord_threshold=0.5` for categorical sequences (default 1.5 too high).

**SinkArgClassifier** — `from ablation.analyzers.sink_arg_classifier import SinkArgClassifier` — `from_path(elf).classify_all()`. `add_sink('fadcsystem', arg_pos=0)` for vendor sinks. Verdicts: RODATA_CONST/SNPRINTF_RODATA/ARG_PROPAGATED/UNKNOWN. Handles `__snprintf_chk` r8=fmt + callee-saved buffer patterns. Zero-caller filter: sinks with 0 PLT callers go to `_dead_sinks` (ELIMINATED before BFS). `_count_plt_callers(binary, data)` exported for standalone use. `batch_plt_intersect(directory, sinks=None)` → {path:[sink_names]}; omitted files = auto-CLEAN. Report warns when ARG_PROPAGATED/UNKNOWN results exist but SanitizerDetector has not been applied. **GAP-002 fix (2026-10-06):** `_scan_immediate_slot_write` resolves stack slots written by GCC's packed-string optimisation — `movabs reg, <imm64>` + `mov [rbp+disp], reg` — to RODATA_CONST. Also handles direct `mov [rbp+disp], <imm32>`. Full-function-body scan (not limited to snprintf search window). Verified on Huawei VRP x86_64 firmware (44 UNKNOWN → RODATA_CONST on libosu_sysdiag.so). Known limitation: stack slots written as two separate 4-byte movabs pairs remain UNKNOWN.
**SanitizerDetector** — `from ablation.analyzers.sanitizer_detector import SanitizerDetector` — `from_path(elf).detect(min_score=4)`. Scores: byte-load density + RC (cmp_same_reg_ratio) + dual-return + no-calls gate. Reports SHELL_SAFE/SHELL_UNSAFE/UNKNOWN.
**ForkExecClassifier** — `from ablation.analyzers.fork_exec_classifier import ForkExecClassifier` — `from_path(elf).classify()`. BFS 32-block child walk. EXEC_AFTER_FORK = investigate; WORKER/EXIT_IN_CHILD = ELIMINATED. v2: je/jz child-entry detection (Clang), child_entry_va backward-branch threshold, _MAX_DIRECT_EXIT_BLOCKS=12 depth gate.
**VendorProfile** — `from ablation.analyzers.vendor_profile import VendorProfile` — `VendorProfile.from_vendor('fortinet')`. `profile.apply_to(classifier)` registers vendor sinks. `profile.safe_pattern_for_exec(unsetenv_strings)` matches known-safe re-exec fingerprints. Profiles: `ablation/profiles/<vendor>.yaml`. Current: `fortinet` (fadcsystem/fadcpopen/sys_vdom_exec/sys_vdom_exec_safe/fadcsystemf; haproxy_mworker_reexec + nginx_worker_respawn safe patterns; is_valid_host_name sanitizer).
**LibraryInventory** — `from ablation.analyzers.library_inventory import LibraryInventory`
`from_dir(path)`, `from_paths([list])`, `scan_one(elf_path)`. Returns `List[LibInventoryEntry]`: `size_kb`, `arch`, `exports`, `internal` (ARM64 BL-target count), `jni`, `has_jni_on_load`, `security_score` (0-10), `security_strings`, `plt_hooks` (critical PLT labels: `[TLS-KEYLOG]`, `[PLT-HOOK]`). `report(entries)` → ASCII table (shows hook labels inline). `security_entries(entries, min_score=3)` → filtered list. `report_strings(entry)` → per-lib credential/crypto string dump. `classify_internals(elf_path)` → `{label: [va, ...]}` ARM64 internal function taxonomy by PLT call signature.

**DynDSClassifier** — `from ablation.analyzers.ppc64_dynds_classifier import DynDSClassifier, DynDSFinding`
`from_context(ctx)` (ppc64/ppc32) or `from_path(elf)`. `classify(min_insns=4)` → `List[DynDSFinding]` sorted by VA. Patterns: `bst_traversal` (≥2 self-calls + null-check + 0 loops), `ctree_traversal` (recursive + ≥1 loop), `bll_traversal` (≥2 loops + ptr-self-load, no recursion), `coroutine_iter` (≥3 BLR + LI r,0 + LI r,1), `bll_append` (small + alloc + ptr-self-load). `report(findings, name_fn, top_n=80)` → pattern-grouped ASCII table. `by_pattern(findings)` → dict. `summary(findings)` → one-line count. O(N log F) numpy; pure-Python fallback. Use after EnginePatternLibrary to label AI/physics/entity-list traversal functions.

**VMXDensityScanner** — `from ablation.analyzers.ppc64_vmx_density import VMXDensityScanner, VMXFunctionResult`
`from_context(ctx)` (ppc64/ppc32 arch only) or `from_path(elf_path)`. `scan(threshold=5, min_insns=8, min_density=0.0)` → `List[VMXFunctionResult]` sorted by vmx_count desc. Each result: `.va`, `.total_insns`, `.vmx_count`, `.density`, `.label`. Numpy path: O(N log F) via `searchsorted`+`bincount`. Pure-Python fallback when numpy unavailable. Labels: `vector_heavy`(≥30%), `vector_math`(≥15%), `vector_light`(≥5%), `vector_trace`(any). `report(results, name_fn, top_n=60)` → ASCII table. `density_histogram(results)` → 10-bucket ASCII chart. Use after EnginePatternLibrary to label residual unlabeled math/physics/render functions.

**FormatStringScanner** — `from ablation.analyzers.format_string_scanner import FormatStringScanner`
**HeapVulnScanner** — `from ablation.analyzers.heap_vuln_scanner import HeapVulnScanner`
**LengthUnderflowScanner** — `from ablation.analyzers.length_underflow import LengthUnderflowScanner` — C12-class
**ChunkWalkerValidator** — `from ablation.analyzers.chunk_walker_validator import ChunkWalkerValidator` — C13-class
**LA64MaxNotMinScanner** — `from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner`
ELF: `from_path(elf)`. PE32+ (UEFI): `from_pe32plus(data, image_base=0)`. Both return the same scanner; `scan()` → `List[LA64MaxNotMinFinding]`. Each finding: `pattern_va`, `result_reg`, `result_name`, `sink_va`, `sink_name`, `sink_arg`. ELF mode resolves PLT sink names (memcpy/malloc/etc.); PE32+ mode cannot resolve names and reports `sink_name="<direct>"/"<indirect>"` with `sink_arg` = arg-register ABI name. Handles both OR operand orderings (GCC may emit either commuted form). Confirmed corpus: TencentOS libstd (ELF, 5 confirmed findings F-030..F-034), TencentOS EDK2 UEFI (PE32+, 63 findings across 26 modules, TlsDxe highest risk). False-positive class: Rust Vec-append with `bltu remaining_cap` guard — needs manual verification.

**ScanResultVersionCache** — `from ablation.analyzers.scan_result_version_cache import ScanResultVersionCache`
`ScanResultVersionCache.for_scanner(ScannerClass)`. `get_or_scan(path, force=False)` → `list[dict]` (findings as dicts). `scan_batch(paths)` → `dict[abspath, list[dict]]`. `save()` persists to `~/.ablation/cache/scan_results/<ClassName>.json`. `is_cached(path)` checks without scanning. `evict(path)` removes entries for a file. `cache_stats()` + `report(stats)` for diagnostics. Cache key = (scanner source SHA-256[:16], file abspath, mtime_ns, size, sha256 prefix[:16]); auto-invalidates on scanner source change or file change. Wraps any scanner with `from_path(path).scan()` interface.

**KernelModuleSubsystemClassifier** — `from ablation.analyzers.kernel_module_subsystem_classifier import KernelModuleSubsystemClassifier, KernelModuleClassification`
`KernelModuleSubsystemClassifier().classify(ko_path)` → `KernelModuleClassification`. Fields: `attack_surface` (PROXIMITY/NETWORK/NETWORK-cluster/LOCAL-USB/LOCAL-HARDWARE-*/LOCAL-DEV-ACCESS/LOCAL), `subsystem` (canonical path label), `network_reachable` (bool), `confidence` (HIGH/MEDIUM/LOW), `rule_matched` (the prefix that matched). `classify_batch(paths)` → list. `report(results)` → ASCII table. Works on any path containing a `/kernel/` component (standard `lib/modules/<version>/kernel/` layout). Extend by adding entries to `_SUBSYSTEM_RULES` in the module, most-specific first.

**ARM32IntOverflowScanner** — `from ablation.analyzers.intoverflow_scanner_arm32 import ARM32IntOverflowScanner`
**PreAuthRouteAuditor** — `from ablation.analyzers.preauth_route_auditor import PreAuthRouteAuditor` — FortiManager flatui; update VA constants per version
**EntropyMapper** — `from ablation.analyzers.entropy_mapper import EntropyMapper` — `scan().high_entropy`
**XorSolver** — `from ablation.analyzers.xor_solver import XorSolver` — `solve()` auto; `kpa_attack(crib=b'\x7fELF')`
**VtableResolver** — `from ablation.analyzers.vtable_resolver import extract_vtable_regions, resolve_blr_sites` — ARM64
**GoSubprocessScanner** — `from ablation.analyzers.go_subprocess_scanner import GoSubprocessScanner`
**LlmAnalyst** — `from ablation.analyzers.llm_analyst.tasks.function_namer import FunctionNamer` — ReAct loop; `namer.run(va)`.
**SAXIndex** — `from ablation.analyzers.sax_index import SAXIndex` — approximate NN over function opseq corpus
**VersionTracker** — `from ablation.analyzers.version_delta import VersionTracker` — cross-version homolog tracking
**CorpusBuilder** — `from ablation.analyzers.corpus_builder import CorpusBuilder, build_fortios_corpus`

**FirmwareContainer** — `from ablation.analyzers.firmware_container import FirmwareContainer`
`FirmwareContainer.from_path(path)`. Key attrs: `.magic`, `.fw_version`, `.vendor`, `.product`, `.partitions` (list of `FirmwarePartition`). Methods: `dump_partitions()`, `get_partition(name)`, `read_partition(name)` → bytes, `extract(name, out_path)`, `extract_all(out_dir)`. Each `FirmwarePartition`: `.index`, `.name`, `.offset`, `.size`, `.destpath`, `.payload_type` (gzip/xz/ext2/3/4/elf/cpio_newc/unknown). CLI: `python3 -m ablation.analyzers.firmware_container <image.BIN> [extract <outdir>]`.

**HuaweiSquashfsExtractor** — `from ablation.analyzers.huawei_squashfs_extractor import HuaweiSquashfsExtractor`
`HuaweiSquashfsExtractor(sqfs_path)`. `extract(inner_path)` → bytes; `list_files()` → generator of path strings. Use as context manager (`with HuaweiSquashfsExtractor(path) as ext:`). Handles ARM64 BCJ filter (xz filter ID 0x0A) via FORMAT_RAW fallback. Squashfs v4 XZ only; validates magic + major + comp_id at open. Decompression-bomb guard: 8 MB per metadata block, 512 MB per file. Not thread-safe.

**BmpKeyExtractor** — `from ablation.analyzers.lsb_stego_extractor import BmpKeyExtractor`
`BmpKeyExtractor(bmp_path).extract(seed)` → `StegoKeyResult`. `.components` = per-component hex list; `.raw_key_hex` = concatenated. Low-level: `LSBStegoReader(pixel_data)`, `LagrangeKeyExtractor(primes=None)`.

**DEXLifter** — `from ablation.analyzers.dex_lifter import DEXLifter`
`DEXLifter(dex)`. `lift_method(class_name, method_name)` → pseudo-Java str. `lift_class(class_name)` → all methods. `DEXLifter.report(dex, class, method)` convenience. Handles: field get/put as dot notation, invoke-* as method calls with typed args, const-string inline, new-instance, if-*/if-*z as labelled conditionals, goto/back-edges, unary/binary arithmetic, array access. Type inference propagates through move-result, iget/sget, check-cast.

**DEXDisasm** — `from ablation.analyzers.dex_disasm import DEXDisasm, DEXInstruction, decode_code_item`
`DEXDisasm(dex)`. `disasm_method(class_name, method_name)` → smali str. `disasm_class(class_name)` → all methods. `list_methods(class_name)` → sorted method names. `DEXDisasm.report(dex, class_name, method_name)` one-call convenience. Covers all 17 DEX instruction formats; resolves method/field/type/string refs from DEX flat tables. `decode_code_item(dex, code_off)` → `(registers, ins_size, outs_size, List[DEXInstruction])`.

**JniBridgeScanner** — `from ablation.analyzers.jni_bridge_scanner import JniBridgeScanner, JniBridgeFinding`
`JniBridgeScanner.from_path(apk_path).scan()`. Reconstructs Java↔native boundary from DEX + ELF dynsym. HIGH=dynamic registration (JNI_OnLoad present; RegisterNatives; symbols arbitrary) or opaque peer (long field holding raw native pointer). MEDIUM=canonical Java_* exports (recoverable class+method from symbol name). INFO=loadLibrary call site count. No androguard dependency.

**BinderScanner** — `from ablation.analyzers.binder_scanner import BinderScanner, BinderFinding`
`BinderScanner.from_path(apk_path).scan()`. Maps Binder IPC surface from DEX ClassDef superclass + MethodRef + manifest cross-reference. HIGH=exported Service or raw Binder onTransact override. MEDIUM=AIDL-generated $Stub class or unexported Service subclass. INFO=Messenger usage. Works on any APK.

**VideoContainerAnalyzer** — `from ablation.analyzers.video_container import VideoContainerAnalyzer`
`VideoContainerAnalyzer.from_path(path)`. `scan()` → list of `VideoFinding`. `report(findings)` → str. Formats: MP4/MOV, MKV/WebM, AVI. Checks: polyglot header collisions, appended trailer data, atom size overflow, EBML length abuse, RIFF chunk miscount.

---

## RE workflow

**New binary, initial triage:**

1. Read `SESSION.md` (root) + `re/<vendor>/SESSION_<target>.md`
2. `BinaryContext.load_or_build()` + `ctx.summary()` + `ctx.names_table()`
3. `CorpusBuilder.build()` if no prior coverage
4. `SemanticSearcher.query()`: sweep ALL vuln classes before touching disasm
5. `PatternLibrary.sweep()`: replay confirmed patterns from prior engagements
6. `FuncProfiler.profile()` on top candidates
7. `TaintTracker` if sinks are standard
8. `IPRegAnnotator` for cross-library call chains
9. `WindowAnalyzer.dump_text()` for manual disasm only when automated tools don't have the sink

**Confirming a finding:**

0. **Byte-verify every VA in the code trace.** Before writing `status: "CONFIRMED"` anywhere, read the raw bytes at each documented address and confirm they match the instruction. `data = open(binary,'rb').read(); off = va - base; assert data[off:off+n] == expected_bytes`. No exceptions. C16 (FGT7K engagement) was carried as CONFIRMED HIGH for six sessions on pattern-match alone — the bytes were wrong.
1. `PathSolver.solve_path()` for feasibility
2. `ctx.set_name(va, name, source="confirmed")`
3. `PatternLibrary.record_hit(confirmed=True)`
4. `FindingRegistry.register()`
5. Write finding to `re/<vendor>/<target>_re.py` (NOT into ablation itself)
6. Update `re/<vendor>/SESSION_<target>.md`

**Custom scanner workflow:**

1. Confirm SemanticSearcher has no existing pattern (run a query first)
2. Create `ablation/analyzers/<scanner_name>.py`; follow `length_underflow.py` as template
3. Wire: `from_context(ctx)` classmethod, `scan()` -> findings list, `report(findings)` -> str
4. Run on a known-positive binary first
5. Analyze FPs: cross-basic-block register clobber? Data network-facing or from trusted DB? Callee actually reads the register?
6. Document: raw hits -> filtered -> confirmed after FP analysis
7. Add to "Which tool for which task?" table above
8. Add usage example to README.md
9. Write `docs/module-reference/<module>.md` — open with `## Why this exists` as a numbered list:
   **"N things that weren't possible before in Ablation"** — each item names the specific gap,
   what you got instead (the painful status quo), and why it mattered. Prose summary of what
   the module does goes *after* the gap list, not instead of it.

**Cross-version patch analysis:**

1. `DTWMatcher.score_functions()`: same era?
2. `MatrixProfileDiff.diff_functions()`: what changed?
3. `VersionTracker.find_homolog()`: where did it move?

---

## Hard rules

- **GitHub:** active account is `Ablation-Tool`. ALL repo ops via `gh` CLI. `mcp__github` is BANNED.
- **Push:** after every commit: `env HOME=/home/cowboy GIT_LFS_SKIP_SMUDGE=1 git push origin main`
- **Edits:** main session only. Never fork or delegate ablation work.
- **Repo integrity:** `~/ablation/` is never deleted, moved, or destructively modified.
- **No findings in repo:** reports, disclosures, and write-ups never go into the ablation repo.
- **No Ghidra:** ever.
- **Semantic sweep first:** before ANY manual disasm on a new binary or new vuln class.
- **Gaps become modules:** every missing sink, scanner pattern, or analysis gap -> new ablation module. Never a workaround script.
- **Findings go in RE modules:** `re/<vendor>/<target>_re.py`. Nowhere else. NOT `modules/`.
- **Name everything:** `ctx.set_name()` the moment a function is confirmed. `ctx.name(va)` everywhere.
- **Session files:** update `re/<vendor>/SESSION_<target>.md` at end of each session. Update root `SESSION.md` if active target changes.
