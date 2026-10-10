# Changelog

---

## v2.61.0

**FlatBinaryFuncStartScanner: arch-agnostic function-start scanner for flat ECU ROMs.**  Combines
call-target harvesting (BFS from the reset vector following direct call instructions) and ISA-specific
prologue pattern scanning.  Uses `EcuArchDetector` internally — HIGH/MEDIUM confidence selects one ISA
catalog, LOW confidence unions all five.

- `FlatBinaryFuncStartScanner`: `scan(arch=None)` → `FuncStartResult`; `arch` override skips detection
- `FuncStartResult`: `arch`, `confidence`, `function_starts` (sorted union), `call_targets`, `prologue_hits`, `detect_result`
- Call harvesting: Thumb2 BL/BLX (ARM Cortex-M), BSR.W/BSR.L (M68K), BL (PPC32/VLE), BSR (SH-2A); stops at return instruction or 512 instructions
- Prologue scan: Thumb2 PUSH+LR (`0xB5xx`), LINK.W A6 (`0x4E56`+neg), MFLR r0 (`7C0802A6`), e_stwu r1 (`0x1C21`+neg D8), STS.L PR (`0x4F22`) + leaf STS PR
- `from_path()` / `from_bytes()` wrappers; `max_call_depth` caps BFS recursion
- 27 tests; FORGE gate: PASSED (0 findings)

---

## v2.60.0

**EcuArchDetector: ISA fingerprinter for unknown flat ECU ROM images.** Five discriminators
identify the instruction set of a raw binary with no ELF/IHEX wrapper, returning a HIGH/MEDIUM/LOW
confidence verdict and the best-match ISA token, enabling automatic decoder selection before any
disassembly step.

- `EcuArchDetector`: `detect()` → `ArchDetectResult`; `candidates()` → `list[ArchCandidate]` sorted by score
- `ArchDetectResult`: `arch`, `confidence` (HIGH/MEDIUM/LOW), `score`, `reason`, `candidates`, `is_confident`
- `ArchCandidate`: `arch`, `score`, `reason`
- ARM Cortex-M: LE vector table — MSP in SRAM `0x20000000–0x3FFFFFFF` + Thumb reset handler; score 0.90 (both) / 0.55 (MSP only)
- M68K/CPU32: BE reset vector in-range + LINK.W A6, #-N prologue density; score 0.85 / 0.70 / 0.35
- PPC32 Book E: primary opcode density (0x08-0x0F, 0x38-0x3F, 0x80-0x9F ranges); fires at ≥ 35% density
- PPC VLE: `(byte0 & 0x90) == 0x10` halfword density; score = `min(density * 2.5, 0.92)` at ≥ 15% density
- SH-2A: BE reset vector at offset 4 + STS.L PR (0x4F22) density + RTS (0x000B) density; score 0.88/0.75/0.60/0.40
- `from_path()` / `from_bytes()` convenience wrappers; `sample_size=0` scans full image
- 31 tests; FORGE gate: PASSED (0 findings)

---

## v2.59.0

**EcuSH2aDecoder: Renesas SH-2A decoder for Honda/Subaru ECU firmware.** Pure-Python decoder
for the SH-2A ISA (Renesas SH7058/SH7059).  Capstone 5.0.7 has no SH-2A support; this module
closes the gap and enables BinaryContext, WindowAnalyzer, and manual RE on Honda CBR250RR and
Subaru (SH7058S, EcuFlash corpus) ECU ROMs.

- `EcuSH2aDecoder`: `disassemble()`, `decode_one()`, `function_starts()`, `insn_length()`
- `SH2aInsn`: `offset`, `is_32bit`, `mnemonic`, `insn_type`, `raw`, `target`, `rd`, `rs`, `imm`
- `insn_type`: RETURN, BRANCH, CALL, LR_SAVE, LR_RESTORE, LOAD, STORE, MISC
- 32-bit SH-2A discrimination: four `0xF00F` masks per Renesas SH2A HW Manual Rev.2.00; MOWI20 uses `0xF00F == 0x0005` (not `0xF0FF`) because imm[19:16] occupies bits[7:4] and varies
- `function_starts()` primary: `STS.L PR, @-R15` (0x4F22); secondary: `STS PR, Rn` leaf prologue with preceding-STS.L suppression
- Branch targets include SH-2 delay slot: `target = VA + 4 + disp * 2`
- PC-relative load: `(VA + 4 & ~3) + disp * 4` (4-byte aligned PC)
- `from_path()` / `from_bytes()` convenience wrappers; `FileNotFoundError` wrapped with context
- 69 tests; FORGE gate: PASSED (0 findings)

---

## v2.58.0

**EcuM68kDecoder: M68K/CPU32 decoder for GM P-series ECU firmware.** Wraps Capstone
(CS_ARCH_M68K / CS_MODE_M68K_020) with ECU-specific prologue scanning and pipeline-compatible
M68kInsn dataclass.  CPU32 is a 68020 derivative; Capstone 5.0.7 has no CS_MODE_M68K_CPU32 but
020 mode decodes the GM P-series instruction set correctly.

- `EcuM68kDecoder`: `disassemble()` (Capstone-backed), `decode_one()`, `function_starts()` (pure scan), `insn_length()`
- `M68kInsn`: `offset`, `mnemonic`, `op_str`, `insn_type`, `raw`, `size`, `target`
- `function_starts()` primary signal: `LINK.W A6, #-N` (`0x4E56` + negative 16-bit displacement); secondary: `MOVEM.L regs, -(SP)` (`0x48E7`) when not immediately after a LINK
- `insn_type`: RETURN (rts/rtd/rte/rtr), BRANCH (bra/b*/jmp), CALL (jsr/bsr), PROLOGUE (link.w A6 neg), MISC
- Branch targets strip Capstone `.w`/`.l` size suffix from `$addr.w` format
- `disassemble()`/`decode_one()` raise `ImportError` with install instructions when Capstone missing; `function_starts()` and `insn_length()` are pure-Python (no Capstone)
- Cs() constructed at `__init__` time (not lazily) to eliminate thread-safety race
- 26 tests; FORGE gate: PASSED (0 findings)

---

## v2.57.0

**EcuVLEDecoder: PPC VLE / SE16 decoder for NXP e200-class ECU firmware.** Decodes the PowerPC
Variable Length Encoding ISA used by GM E39a (MPC5566 e200z6), E54, and E92 PCMs. Capstone 5.0.7
does not implement VLE; this module closes that gap with a pure-Python decoder covering the
security-relevant instruction subset.

- `EcuVLEDecoder`: pure-Python VLE decoder; `disassemble()` walks a ROM region instruction by
  instruction; `decode_one()` decodes a single instruction; `function_starts()` returns probable
  function-entry VAs for taint-tracker seeding
- `VLEInsn` dataclass: `offset` (VA), `is_16bit`, `mnemonic`, `insn_type`, `raw`, `target`,
  `rd`, `rs`, `ra`, `imm`
- Length discrimination: `(byte0 & 0x90) == 0x10` → 32-bit; else 16-bit SE; sourced from NXP
  e200 VLE Reference Manual and verified against binutils ppc-opc.c macro table
- SE 16-bit coverage: `se_blr/blrl`, `se_mflr/mtlr`, `se_li`, `se_b/bl/bc`, `se_lwz/stw`,
  `se_lbz/stb/lhz/sth`, plus SE_R / SE_RR / SE_IM5 arithmetic and compare forms
- 32-bit VLE coverage: `e_stwu`, `e_b/bl`, `e_lwz/stw/lbz/stb/lha/lhz`, `e_add16i`, `e_li`,
  `e_stmw/lmw`; unrecognized opcodes decode as `vle32_opN` (MISC) without crashing
- `function_starts()` primary signal: `e_stwu r1, -N(r1)` (exact VUP/RS/RA/D8 check);
  secondary signal: `se_mflr r0` for leaf functions; scan avoids mflr false positives by
  checking whether the preceding 4 bytes are already an e_stwu prologue
- CIA-relative branch targets: `se_b/se_bc` use `CIA + exts(BD8) * 2`; `e_b/e_bl` use
  `CIA + BD24` where BD24 is the raw bits[24:1] signed displacement (CIA-relative, not NIA)
- `_compact_reg_4bit()`: translates 4-bit compact VLE register fields (0-7 → GPR0-7;
  8-15 → GPR24-31); applied to `se_li` IM7 form; SE_R instructions (mflr/mtlr) use direct
  GPR mapping (no translation)
- 51 tests covering: length discrimination, all SE/32-bit mnemonics, branch targets (forward and
  backward), function_starts (primary/secondary/false-positive suppression), e_li 20-bit
  immediate assembly, compact register translation, FileNotFoundError wrapping
- FORGE gate: PASSED (4 LOW, 0 MEDIUM, 0 HIGH, 0 CRITICAL)

---

## v2.56.0

**EcuSecurityAccessScanner: static-seed SecurityAccess handler fingerprinter for M68K/CPU32 and
PPC32 ECU ROMs.** Detects the `move.b #$67 + 2x clr.b` pattern (M68K/CPU32) and
`li rX,0x67 + stb + 2x(li rY,0 + stb)` pattern (PPC32). Confirmed across the full GM P-series
CPU32 family (P01/P04/P05/P08/P10/P11/P59) and the GM E38 PCM PPC32 region.

- `EcuSecurityAccessScanner`: two-architecture scanner; `scan()` returns `list[SecurityAccessFinding]`
- M68K fingerprint: `(byte[0] & 0xF0) == 0x10` and `(byte[1] & 0x3F) == 0x3C` and
  `byte[2:4] == 0x00 0x67`; covers all M68K destination addressing modes in one mask
- PPC32 fingerprint: `(word & 0xFC1FFFFF) == 0x38000067` for `li rX, 0x67`; `(word >> 26) == 38`
  for `stb`; same masks for the confirming zero pairs
- `window` parameter (default 256) applies uniformly to both architectures; eliminates earlier
  inconsistency where M68K and PPC32 used separate hidden constants
- `SecurityAccessFinding`: offset, arch, pattern, evidence bytes, note; `__str__` for CLI output
- 30 tests (21 for scanner, 9 for `is_calibration_only`)

**ROMLayout.is_calibration_only(): OBD calibration-only dump detector.** Returns
`(True, "OBD cal-only dump, program flash absent")` when the layout contains zero CODE regions
and at least one active region. Confirmed on Bosch EDC16C34 PSA Berlingo corpus image
(1792 KB ERASED + 184 KB CALIBRATION/PADDING, zero CODE regions). Added as 4th gap in
`ecu-rom-layout-analyzer.md`.

---

## v2.48.0

**BEAMLifter: function-level BEAM bytecode decompiler.** Upgrades `_lift_beam()`
from a module-level summary to a full pseudo-IR decompiler that decodes every
function in the BEAM Code chunk.

- `_ct_read()`: compact-term decoder covering all seven standard tags (u/i/a/x/y/f/h)
  and all six Z-extended subtypes (float, list, float-register, allocation-list,
  literal, typed-register)
- `_BEAM_OPS`: opcode dispatch table covering 80 entries; opcodes 1–78 are stable
  across OTP 18–26; entries above 78 cover R7B–OTP 26 additions with OTP 18/19
  numbering
- `_BEAMTerm.fmt()`: resolves atom indices against the AtU8/Atom table, literal
  indices against the LitT table, and renders X/Y registers, labels, characters,
  and Z-extended floats into readable form
- `BEAMLifter._decode()`: scans the instruction stream for `label/1` + `func_info/3`
  pairs to build the function table without requiring LocT; sets `_partial=True`
  when an unknown opcode halts decode
- `BEAMLifter._emit()`: 60-opcode dispatch: call/tailcall with resolved import
  names, gc_bif1/2/3 arithmetic with resolved BIF names, move/swap, list/tuple
  constructors, comparison tests with goto targets, exception handling
  (try/catch/raise), send, loop_rec, and select_val with branch tables
- `put_tuple + put...` sequences are collapsed into a single tuple literal in `lift()`
- Falls back to module-level summary if Code chunk is absent or decode fails
- `_BEAM_ARITH`, `_BEAM_CMP`, `_BEAM_TYPES`: module-level constants (hoisted from
  per-call dict literals per FORGE audit finding)
- FORGE: gate_passed=True, 3 LOW findings

---

## v2.47.0

**BinaryLifter: full decompiler parity across all native ISAs.** Replaces the
v2.45.0 structural skeleton emitters with full NativeVal register-tracking state
machines. Every native ISA now produces the same quality of pseudo-C IR as ARM64
and x86-64: typed variable declarations, resolved load/store dereferences with
pointer casts, call sites with per-ISA argument lists, taint propagation, and
branch conditions with inlined comparison operands.

- `_ARM32State`: AAPCS r0–r3 params; `.cond` attribute threading for conditional
  execution; writeback load/store (`ldr r0, [r1], #4`)
- `_MIPSState`: o32 `$4`–`$7` / n64 `$4`–`$11` params; $0 zero guard; branch
  comparison operands embedded per-instruction (beq/bne/blt/bltz/etc.)
- `_PPCState`: SysV/ELFv2 r3–r10 params; update-form load/store writeback;
  signed vs. unsigned compare flag for blt/bgt branch generation
- `_RISCVState`: psABI a0–a7 params; ret / jalr ra, 0 return detection;
  C-extension compressed insns (c.lw, c.sw, c.mv, c.j, c.li)
- `_LA64State`: lp64 $a0–$a7 params; jirl $zero, $ra, 0 return detection;
  bl call detection; lu12i.w/lu32i.d immediate reconstruction
- `_ARCState`: r0–r7 params; blink return; br-form branches with embedded
  register comparison operands
- `_V850State`: CC-RH r6–r9 params; r10 return; jmp lp return detection;
  subr (reverse-subtract) operand ordering
- `_NanoMIPSState`: regex operand parsing (NanoFrame has no structured .ops);
  ABI name → canonical numeric mapping; beqc/bnec two-register branches
- `_ablation_mem_addr()`: shared helper that resolves `.disp` or `.offset`
  transparently across all ISA Mem object styles
- `_taint_map` now threads taint into all 8 new state machines, not ARM64 only

---

## v2.46.0

**BinaryContext: full Windows PE support.** `BinaryContext.load_or_build()` now works on `.exe`, `.dll`, and `.sys` files. Every Ablation analysis tool that depends on `BinaryContext` — `SemanticSearcher`, `TaintTracker`, `WindowAnalyzer`, `FuncProfiler`, `callers_of()`, `callees_of()`, `strings_in_func()` — now functions on Windows PE binaries with no changes to calling code.

- `_detect_arch_pe()` maps PE `MACHINE_TYPES` to Ablation arch strings (`x86_64`, `x86_32`, `arm64`, `arm32`)
- `_extract_plt_pe()` builds `{absolute_va: import_name}` from the IAT (the PE equivalent of ELF PLT stubs)
- `_extract_exports_pe()` populates `exports` from the PE export directory
- `_extract_strings_pe()` scans `.rdata` and `.data` sections
- `_extract_func_starts_pe()` seeds from exports, then prologue-scans executable sections (x86_64: `sub rsp`, `push rbx`, `endbr64`; x86_32: `push ebp; mov ebp, esp`)
- `_build_call_graph_pe()` vectorized numpy `0xe8` scan on all `IMAGE_SCN_MEM_EXECUTE` sections; Capstone fallback when numpy is unavailable
- `_build_string_xref_index_pe()` RIP-relative scan (x86_64) or absolute scan (x86_32) to populate `strings_in_func()` and `funcs_referencing_string()`
- `BinaryContext` doc added: `docs/module-reference/binary-context.md`
- MZ magic removed from `_NON_ELF` warn list (PE files now build a real context instead of warning and returning empty)

---

## v2.45.0

**BinaryLifter: 13 new ISA decompiler backends.** `BinaryLifter` now supports all 17
ISA variants shown in the README architecture table. ARM64 and x86-64 remain full
(register-tracking state machines). 13 new structural backends emit call/return/branch
as resolved pseudocode and arithmetic as comments.

- `x86_32` / `i386`: Capstone CS_MODE_32, CDECL (stack args, eax return), `_X86_32State`
- `arm32` / `arm`: insn_arm32 + cfg_arm32; AAPCS r0–r3
- `thumb` / `thumb2`: insn_arm32 Thumb mode
- `mips32`, `mips32el`: insn_mips + cfg_mips; o32 $a0–$a3; LE/BE variants
- `mips64`, `mips64el`: insn_mips + cfg_mips; n64 $a0–$a7
- `nanomips`: NanoMIPSDecoder linear walk; o32 ABI
- `ppc32` / `ppc`: insn_ppc + cfg_ppc; SysV32 r3–r10
- `ppc64`: insn_ppc + cfg_ppc; ELFv2 r3–r10
- `rv32` / `riscv32`: insn_riscv + cfg_riscv; psABI a0–a7
- `rv64` / `riscv64`: insn_riscv + cfg_riscv; psABI a0–a7
- `arc` / `arcem` / `archs`: requires `arc-elf32-objdump` in PATH; degrades gracefully if absent
- `v850` / `rh850`: requires `v850-elf-objdump` in PATH; degrades gracefully if absent
- `la64` / `loongarch64`: LoongArchDecoder + cfg_loongarch64; lp64 $a0–$a7 (replaces stub)
- `beam` / `erlang` / `elixir`: BeamContext module summary (exports, dangerous imports, atoms); no VA space

Shared `_walk_ablation_cfg()` BFS helper eliminates code duplication across all 9
CFG-backed backends. `_make_*_emit()` factory closures encapsulate per-ISA call/return/branch
detection without full register state machines.

---

## v2.44.0

Windows PE security analysis suite. Seven new modules covering the full attack surface
of Windows PE binaries from control flow integrity to kernel pool allocation.

- **CFGBypassDetector** (`ablation/analyzers/cfg_bypass_detector.py`): Control Flow Guard
  bypass analysis. Reads `IMAGE_LOAD_CONFIG.GuardFlags` for CFG enabled/disabled, function
  table presence, and export suppression flag. Reads the CFG function table (entry stride =
  `4 + (GuardFlags >> 28)` bytes). Cross-references the PE export table against the CFG table
  when export suppression is enabled to find exports that slip through as valid indirect call
  targets. Counts indirect call/jmp sites in code sections. Flags: cfg_disabled (HIGH),
  cfg_table_absent (HIGH), no_export_suppression (MEDIUM), export_not_in_table (MEDIUM).

- **SEHChainAnalyzer** (`ablation/analyzers/seh_chain_analyzer.py`): x86-32 Structured
  Exception Handler chain analysis. Reads `IMAGE_LOAD_CONFIG.SEHandlerTable` and
  `SEHandlerCount` for SafeSEH status and handler RVAs. Scans code sections for SEH frame
  installation sequences (`push handler; push FS:[0]; mov FS:[0], esp`) using Capstone.
  Cross-references discovered handlers against the SafeSEH table. Rejects x64 PE input
  (table-based EH applies there; SafeSEH does not). Flags: safesh_disabled (HIGH),
  handler_not_in_table (MEDIUM).

- **ETWProviderExtractor** (`ablation/analyzers/etw_provider_extractor.py`): ETW provider
  and event extraction. Builds IAT map for `EventRegister`, `EventWrite*`, `EventUnregister`.
  Finds `EventRegister` call sites and extracts provider GUIDs from the first argument (RCX
  via LEA/MOV for x64; first push for x86). Cross-references GUIDs against 15 known Windows
  security providers including Security-Auditing, PowerShell, Antimalware-Engine, RPC, DCOM.
  Counts `EventWrite*` call sites. Flags a detection gap when providers register but never
  write events.

- **RPCServerAnalyzer** (`ablation/analyzers/rpc_server_analyzer.py`): Windows RPC server
  endpoint analysis. Finds `RpcServerRegisterIf*` call sites. Reads `RPC_SERVER_INTERFACE`
  struct at the first argument to extract interface UUID and transfer syntax UUID. Extracts
  auth level from `RpcServerRegisterIfEx` second argument. Finds `RpcServerUseProtseqEp*`
  call sites and reads endpoint strings (UTF-16LE + ASCII). Flags unauthenticated interfaces
  (RPC_C_AUTHN_LEVEL_NONE) as HIGH with CWE-306.

- **COMAttackSurfaceMapper** (`ablation/analyzers/com_attack_surface_mapper.py`): COM attack
  surface analysis. Detects COM server DLLs via `DllGetClassObject` export. Scans `.rdata`
  and `.data` for GUID strings in `{...}` format. Finds `CoCreateInstance*` call sites and
  extracts CLSID arguments. Detects COM marshaling imports (`CoMarshalInterface*`) and
  IDispatch automation (`Invoke`/`GetIDsOfNames`). Flags COM servers with CLSID references
  as hijacking surface (MEDIUM, CWE-426); marshaling as deserialization risk (MEDIUM, CWE-502).

- **PDBSymbolIntegrator** (`ablation/analyzers/pdb_symbol_integrator.py`): PDB symbol file
  parser and NameRegistry integrator. Reads `IMAGE_DEBUG_TYPE_CODEVIEW` entry to extract
  RSDS record (PDB GUID, age, filename). Builds Microsoft symbol server URL. Fetches PDB via
  `urllib.request` with caching. Parses MSF 7.0 container: superblock, stream directory
  reconstruction, DBI stream for public symbols stream index, `S_PUB32` CodeView records for
  `{offset: name}` mappings. `inject_into_context(ctx)` calls `ctx.set_name(va, name, source='pdb')`.

- **WindowsPoolTaintTracker** (`ablation/analyzers/windows_pool_taint_tracker.py`): kernel
  pool allocation taint tracking. Finds `ExAllocatePool*` call sites (8 variants including
  `ExAllocatePool2`/`ExAllocatePool3`). Extracts size argument (RDX in x64 fastcall).
  Finds `RtlCopyMemory`, `memmove`, `memcpy`, `RtlMoveMemory` copy sinks. Pairs allocation
  sites with copy sites where the same register carries the size to both without an intervening
  comparison. Flags unvalidated pairs as HIGH with CWE-122.

---

## v2.43.0

- **FORGE** (`ablation/analyzers/forge.py`): redesigned audit gate — no subprocess, no API key.
  - **Result cache** (`_ForgeCache`): persists audit results to `~/.ablation/forge_cache.json`.
    Key is `sha256(system_prompt)[:16] + ":" + sha256(file_bytes)[:16]`. Cache hit on an
    unchanged module returns the `ForgeReport` instantly. Any change to the SOP file or the
    module source invalidates the entry. Lazy load on first use. Atomic writes via `.tmp` rename.
  - **ForgeAuditRequired exception**: `audit_module()` raises this on cache miss instead of
    calling `claude --print` in a subprocess. The audit runs inline in the Claude Code session —
    read the file, apply the 10-section SAFE CODE review, call `FORGE.record_result()` to cache.
    No subprocess, no backgrounding, no Anthropic API key.
  - **FORGE.record_result(path, findings, summary)**: new classmethod. Stores the result of an
    inline audit in the cache. `findings` accepts `list[ForgeFinding]` or `list[dict]`. Future
    `audit_module()` calls return the cached result instantly.
  - **Removed dead SDK path and streaming path**: the `anthropic` SDK branch, `subprocess` import,
    `_STREAM_PATH`, and `_run_via_claude_cli` are gone. Removed dead helper functions
    `_parse_json_findings`, `_parse_prose_findings`, `_extract_summary` (no callers after redesign).
  - CLI `module` and `register` commands now print a clear how-to message on `ForgeAuditRequired`
    (exit code 2) instead of an unformatted traceback.
  - `_extract_subsystem_path` in `kernel_module_subsystem_classifier.py`: fixed first-vs-last
    "kernel" component bug — now uses `indices[-1]` instead of `next(...)` so paths like
    `/home/kernel/linux/.../kernel/net/mac80211/mac80211.ko` classify correctly.

---

## v2.42.0

- **ScanResultVersionCache** (`ablation/analyzers/scan_result_version_cache.py`): version-aware
  persistent cache for any ablation scanner that implements `from_path(path).scan()`.
  - Cache key: (scanner source SHA-256[:16], file abspath, mtime_ns, size, sha256 prefix[:16]).
    Invalidates automatically when the scanner source changes or the target file changes.
    No manual version bumping required.
  - Fast path on cache hit uses stat only (mtime_ns + size prefix scan). A batch of 1096
    cached `.ko` files costs 1096 stat calls, not 1096 file reads.
  - Atomic writes via `.tmp` rename. Cache file at
    `~/.ablation/cache/scan_results/<ClassName>.json`.
  - `get_or_scan(path, force=False)`, `scan_batch(paths)`, `is_cached(path)`, `evict(path)`,
    `cache_stats()`, `report(stats)`. Works with any scanner.
  - Fixes the stale-result class: kernel module sweeps produced silently wrong results after
    scanner updates (S35 discovery — 23 modules missed because sweep_kernel_modules_results.json
    predated the sltui variant and OR commutativity fix).

- **KernelModuleSubsystemClassifier** (`ablation/analyzers/kernel_module_subsystem_classifier.py`):
  infers attack surface from a Linux kernel module's path in the standard
  `lib/modules/<version>/kernel/` layout.
  - 26 rules, most-specific first. Returns `KernelModuleClassification` with `attack_surface`,
    `subsystem`, `network_reachable`, `confidence`, and `rule_matched`.
  - Surfaces: PROXIMITY (mac80211, wireless), NETWORK-cluster (dlm), NETWORK (net/), LOCAL-USB,
    LOCAL-HARDWARE-ISDN, LOCAL-HARDWARE-MEDIA, LOCAL-HARDWARE-SAS, LOCAL-HARDWARE-SCSI,
    LOCAL-DRM, LOCAL-DEV-ACCESS (sound/), LOCAL-HARDWARE, LOCAL.
  - `classify(path)`, `classify_batch(paths)`, `report(results)`.
  - Fixes manual attack surface annotation for every kernel module finding. Before this module,
    every `.ko` finding required looking up the kernel source tree manually (S35: 28 findings
    across 20 modules, all annotated by hand).

## v2.40.0

- **CMDBSurfaceMapper** (`ablation/analyzers/cmdb_surface_mapper.py`): forward-taint
  CMDB attack surface mapper for x86-64 FortiWeb/FortiOS binaries.
  - Phase 0.5 of the Fortinet RE methodology: enumerate `cmf_query_create()` call sites,
    extract table_id from rdi (supports `mov edi/rdi, imm` and `xor edi, edi`),
    then flag functions that co-locate CMDB access and exec-sink calls.
  - Correct VA→file-offset mapping via lief section table; validates x86-64 `e_machine`
    at entry; fails fast on non-CMDB binaries (cmf_query_create absent from PLT).
  - Single-pass disassembly per function (create + field reads + exec sinks collected
    simultaneously); window bounded by next function start, capped at 8192 bytes.
  - `from_path(elf, extra_sinks=, extra_tables=, verbose=)` and
    `from_context(ctx)` constructors.
  - Report explicitly marks all exec-reach flags as co-location only; directs analyst
    to SinkArgClassifier + TaintTracker for confirmed data-flow verification.
  - 19 unit + integration tests; integration baseline: cmdbsvr 7.4.3 → 19 tables,
    libcmdb_plugin.so 7.4.3 → exec-reach present (FWB-KRB-1 origin signal).
  - Origin: FWB-KRB-1 CONFIRMED (FortiWeb 7.4.3, CVSS 7.2) — backward TaintTracker
    missed this because the CMDB abstraction blocked the trace; forward mapper found
    the exec-reach table in the first run.

## v2.39.0

- **I386AbsoluteXrefScanner** (`ablation/analyzers/i386_absolute_xref_scanner.py`): i386
  absolute-address string xref scanner for ELF32 binaries.
  - x86-32 encodes data references as 4-byte LE absolute immediates; the existing RIP-relative
    scanner produces near-zero results on i386 (21 pairs on a 675KB binary vs 548 correct).
  - Same numpy stride-trick window scan as the x86-64 scanner; target VA = raw u32 value
    (no displacement arithmetic).
  - `from_path(path)` / `from_context(ctx)` construction; `scan_full()` → `XrefResult`;
    `inject(ctx)` populates `ctx._str_xref_idx` and `ctx._func_str_idx` in-place.
  - `BinaryContext._build_string_xref_index` now dispatches to this scanner for `x86_32` arch.
  - Pure-Python fallback when NumPy is unavailable.
  - ELF32 only (PE32 excluded — too many false positives from vtable/jump-table entries).
  - Validated on wsconv (AlphaSmart Dana): 934 string VAs, 548 xref pairs, 153 unique functions.
  - Docs: `docs/module-reference/core.md` (new I386AbsoluteXrefScanner section).

## v2.38.0

- **pe_sweep.py** (`sweeps/pe_sweep.py`): Windows PE32 (i386) semantic vulnerability sweep.
  - IAT extraction via lief PE parser as PLT equivalent (`_build_iat`).
  - x86-32 prologue detection: MSVC `55 8B EC` and GCC `55 89 E5` patterns.
  - Capstone `CS_MODE_32` function extraction with per-function string and call lists.
  - `.rdata`-only string index (prevents noise from writable `.data` segment).
  - Regex handles both `dword ptr [0xXXXX]` and `dword ptr ds:[0xXXXX]` IAT call forms.
  - 8 Windows/QuickTime-specific vulnerability profiles: `qt_heap_atom_parse`,
    `qt_rtsp_recv_overflow`, `qt_registry_plugin_load`, `qt_path_string_overflow`,
    `win_cmd_exec`, `win_format_string`, `qt_codec_intovf`, `qt_com_stream_overflow`.
  - CLI: single binary or directory scan; outputs `reports/sweep_pe_*.md`.
  - Docs: `docs/module-reference/pe-sweep.md`.
  - Validated on `PlugInHelper.exe` (Apple QuickTime, 2002): 23 functions, 94 IAT entries,
    9 profiles hit above 0.30 including integer overflow and path string candidates.

## v2.37.0

- **PPC32PLTTracer** (`ppc32_plt_tracer.py`): verified import caller finder
  for PPC32 BE `.so` files.
  - `PPC32PLTTracer.find_callers(sym)` returns only call sites whose active
    r30 matches the `implied_r30 = plt_slot(sym) - thunk_disp` — eliminates
    the cross-compilation-unit false positive class where shared thunk VAs
    route to different PLT slots from different r30 contexts.
  - `batch_scan(directory, sinks)` runs the verified scan over every ELF in
    a directory; returns `{filename: {sym: [PLTCallSite]}}`.
  - `batch_sweep(directory, sinks)` quick import-surface scan (no call-site
    detail) — compatible with `SinkArgClassifier.batch_plt_intersect` results.
  - `PPC32ELF` helper: thin lief + capstone wrapper with `disasm`,
    `print_disasm`, `plt_slot`, `find_bl_callers` for workspace use.
  - Validated against CE6810 sessions 28–31: 184 apparent dangerous call
    sites across 7 modules reduced to 8 confirmed by r30 check; all four
    SESSION_28/29 ground-truth entries confirmed exact match.

---

## v2.36.0

- **PPC32GOT2Resolver: three hardening improvements** (`ppc32_got2_resolver.py`)
  - **Fix 1 — per-function r30 floor:** `resolve()` now accepts an optional
    `fn_starts: List[int]` parameter (sorted function entry VAs, e.g. from the
    ELF export table).  When provided, `_r30_at` rejects any BCL setup site
    whose VA precedes the calling function's entry VA, preventing cross-CU r30
    inheritance at function boundaries in stripped binaries.
  - **Fix 2 — GOT2 range validation:** `__init__`, `from_path`, and
    `from_sections` now accept optional `got2_va` / `got2_size` parameters.
    `from_path` extracts `.got2` automatically via lief.  Any resolved
    `entry_va = r30 + disp` that falls outside `[got2_va, got2_va + got2_size)`
    is rejected with reason `entry_va_outside_got2` rather than silently reading
    whatever happens to be at that address.
  - **Fix 3 — generalised r30 setup detection:** `_find_r30_setups` now uses a
    sliding-window scan (up to 16 instructions for MFLR r30, up to 6 more for
    ADDIS, up to 6 more for ADDI) instead of checking fixed offsets.  Handles a
    third compiler-generated variant found in Huawei CE6810 e500mc modules where
    up to 8 frame spills appear between BCL and MFLR r30.  `_is_stw_r1` helper
    removed (superseded by the general `_clobbers_r30` check).
  - All three fixes are backward-compatible.

---

## v2.35.0

- **PPC32TaintTracker: multi-segment `_va_to_slice` fix** (`taint_tracker_ppc32.py`)
  - **Bug**: `_va_to_slice` used a single-segment linear formula
    (`file_off = text_off + (va - text_va)`) which gave file offsets 0x10000 bytes
    too high for any VA in the second LOAD segment (rw-, `.got2`/`.data`). The
    S6720EI binary has two PT_LOAD segments where segment[1] (VA `0x1014b000`,
    file `0x13b000`) has a different VA→file gap than segment[0]. Reads via
    `_va_to_slice(got2_va, 4)` returned garbage from `.data` instead of the
    `.got2` contents.
  - **Fix**: new `_load_segments_raw()` method reads all PT_LOAD entries from raw
    ELF program headers and populates `self._load_segs` as a `[(va, foff, filesz)]`
    list. `_va_to_slice` now searches this list; falls back to the legacy single-
    segment path only when segment parsing fails. Called from `_load_elf()` before
    `_build_got2_resolver()`.
  - **Impact**: `_build_got2_resolver()` was already correct (uses `got2_foff`
    from section headers directly); function disassembly was always correct (all
    code in segment[0]). The bug only affected callers that read GOT2/data VAs
    through `_va_to_slice` — e.g., resolving internal function pointers from the
    second LOAD segment. Internal function targets in `fn@0x10031800` now resolve
    to `0x100540d0`, `0x100526c4`, `0x10052cd0` (previously read as `0x03030000`
    etc.).

## v2.34.0

- **PPC32TaintTracker: GOT2 PIC support for Huawei/embedded Linux** (`taint_tracker_ppc32.py`)
  - **LIEF vendor-reloc bypass**: LIEF discards Huawei relocation type `0x40000054` and
    maps `_plt` to `.plt section` VAs (wrong range). `_load_plt_from_dynsym_raw()` now runs
    unconditionally, loading SHN_UNDEF dynamic symbols directly from raw ELF headers to get
    the correct PLT stub VAs. SHN_UNDEF filter added to exclude internal symbols.
  - **Per-function r30 map**: pre-computes GOT2 PIC base register for all 2241 functions.
    Two bugs fixed: `lr_val` was `mflr_addr + 4` (off-by-4 from bcl mechanics); prologue
    window was 32 bytes (8 instructions), extended to 64 bytes (16 instructions) to cover
    prologues with `stmw`/`stw r30`/`stw r31` before the `bcl`.
  - **677 GOT2 VA→name entries** populated for S6720EI bootloader (previously 0).
  - **`crclr cr1eq` transparent handling**: GCC PPC32 emits this varargs indicator between
    `mtctr` and `bctrl`. The 2-instruction look-back now uses `prev3` to recover the
    `lwz+mtctr` pair when `prev1` is a CR instruction; raises resolved calls from 12/59
    to 45/59 in test function.
  - **LWZ stale-taint fix**: load from a non-tainted base register now explicitly clears
    the destination's taint (was silently preserving prior taint, causing false positives
    when a GOT2 pointer load followed a source call).
  - **New sinks**: `execl`, `execle`, `execlp`, `strcpy_s`, `strcat_s`, `sprintf_s`,
    `snprintf_s`, `memcpy_s` (Huawei secure-string variants, heavily used in Huawei boot ROM).
  - **New doc**: `docs/module-reference/ppc32-taint-tracker.md`

## v2.33.0

- **TencentOS kernel modules sweep: 14 findings across 1096 .ko files** (targets, not in repo)
  - Swept all 1096 kernel modules from `kernel-modules-6.6.119-52.9.tl4` with LA64MaxNotMinScanner + LA64HeapVulnScanner
  - **6 CONFIRMED HIGH** (F-037..F-042): `mlx5_ib_post_send` ×2 (RDMA), `hidp_raw_request` (BT proximity), `tcmu_copy_data` (remote iSCSI), `qedi_ll2_recv_thread` (remote iSCSI), `brcmf_cfg80211_join_ibss` (WiFi + 3× memcpy)
  - **2 PLAUSIBLE** (F-043..F-044): `rds_info_copy` (LOCAL getsockopt), `btusb_setup_qca_download_fw` (USB BT firmware)
  - **3 PLAUSIBLE_LOW** (F-045..F-047): ntb_tool debug ×2, mpt3sas hardware event
  - **3 ELIMINATED** (F-048..F-050): hso_resume (power mgmt), qla2xx sysfs stats, snd-cs46xx audio
  - All 14 patterns byte-verified; all memcpy sinks confirmed via `.rela.text` R_LARCH_B26 entries
  - Fixed ET_REL VA bug: `pattern_va = text_file_off + section_offset`; rela lookup uses section-relative `r_offset`
  - Root cause: same GCC 12.3.1.7-1.tl4 max-not-min codegen bug as F-029..F-034; ring-0 context elevates severity
  - RE module docstring updated to reflect extended status

## v2.32.0

- **TencentOS LoongArch64 RE: full corpus survey complete** (targets, not in repo)
  - `GNU_EFI_ANALYSIS` block added to RE module for gnu-efi-3.0.17-5.tl4 (26 PE32+ EFI app binaries)
  - Classification: PLAUSIBLE_LOW — GCC 12.3.1.7-1.tl4 max-not-min pattern confirmed (same libgnuefi.a CU in all 26 apps); BL target at VA 0xb8763c is an unresolved PE32+ relocation placeholder (outside text section); sink identity unverifiable without runtime relocation; dev-only package (not deployed on production servers)
  - Language-Toolchains survey complete: golang-bin/libgccjit/cargo/rust all swept; clang-analyzer is Python/shell only; libatomic-static 65 object files → 0 findings on both scanners
  - Firmware directory excluded: all packages are peripheral firmware blobs (WiFi, GPU, audio DSP) in non-LoongArch64 ISAs
  - RE module docstring updated: "9 CONFIRMED | 27 ELIMINATED | 1 PLAUSIBLE_LOW"

## v2.31.0

- **`ARM64FgetsFdDiscriminator`: FILE* provenance post-processor for ARM64TaintTracker** (`analyzers/arm64_fgets_fd_discriminator.py`, new)
  - Post-processes `TaintFindingARM64` results to classify `fgets`-sourced findings by whether the FILE* argument (x0) came from a file-open call (`fopen`/`fopen64`/`freopen`/`tmpfile`) or a socket call (`socket`/`accept`/`accept4`).
  - Detection algorithm: lightweight backward slice from func_va to the `bl fgets` site; tracks x0 provenance state through `bl` calls (file-open → `"file"`, socket → `"socket"`, `fdopen` → propagates fd class), `mov` propagation, and SP-relative `ldr`/`str` stack spills. At the fgets call site, resolves x0 class: `"file"` → severity downgraded to `"LOW"`; `"socket"` stays `"HIGH"`; `"unknown"` stays `"HIGH"` (conservative); CLEAN (not modified) → `"file"` (static/global FILE* from init).
  - Returns `FgetsClassifiedFinding` wrapper with `fd_class` and computed `severity` fields; original finding unchanged.
  - Also exports `ARM64TaintTracker` and `TaintFindingARM64` from the analyzers package (were previously only accessible via direct module import).
  - Gap origin: TencentOS ARM64 config-parsing daemons produced 47 fgets findings at HIGH; 41 are file-class FPs. Discriminator recovers true-positive signal.
  - Validation corpus: 94 AArch64 binaries; 41/41 file-class findings confirmed as config-file parsing via manual trace; 0 false network classifications.
  - Docs: `docs/module-reference/vuln-scanners.md` ARM64FgetsFdDiscriminator section added.

## v2.30.0

- **`LA64MaxNotMinScanner`: PE32+ mode and OR commutativity fix** (`analyzers/loongarch64_max_not_min_scanner.py`)
  - `from_pe32plus(data, image_base=0)` classmethod: loads a UEFI PE32+ DXE/PEIM module directly. Parses the PE32+ section table to find the first code section, computes a file-offset bias so the existing `_words_at()` address machinery works without copying section data. No lief dependency for PE32+ path.
  - PE32+ has no PLT/GOT. `_check_lookahead()` enters arg-register feed mode when `self._pe32plus` is True: any `bl` or `jirl $ra,...` call where the max-not-min result is live in `$a0`–`$a7` produces a finding with `sink_name="<direct>"` or `"<indirect>"` and `sink_arg` set to the ABI register name. Confirm callee manually (AllocatePool/CopyMem arrive via EFI Boot Services Table pointers through `jirl`).
  - **OR commutativity fix**: the four-instruction sequence check previously required `or Rout, Rtmp2, Rtmp1` exactly. GCC may also emit `or Rout, Rtmp1, Rtmp2` (commuted). Both encode the same `max(Ra,Rb)`. Changed the check to `{rj, rk} == {rtmp1, rtmp2}` (set equality). This was a silent miss on every binary where GCC chose the commuted ordering — validated on TencentOS EDK2 PE32+ modules.
  - Validation: 87 DXE modules from `edk2-loongarch64-fw` (TencentOS Server 4.6, `QEMU_EFI.fd`). 63 sink-proximate findings across 26 modules. Highest-risk module: TlsDxe (13 findings, network-reachable in PXE/HTTP-boot, no ASLR). ELF regression clean (existing libstd findings unaffected).
  - Docs: `docs/module-reference/vuln-scanners.md` PE32+ mode section added; `CLAUDE.md` tool table and quick-reference updated.

## v2.29.0

- **`loongarch_decoder_v2`: KASAN/KCOV-aware LoongArch64 decoder** (`analyzers/loongarch_decoder_v2.py`, new)
  - `LoongArchDecoderV2` extends `LoongArchDecoder` (V1) with a two-pass semantic layer modeled on the Cifuentes & Sendall 1998 SSL (Semantic Specification Language) idiom-recognition architecture.
  - **Pass 1 — BL tagging**: every `bl` whose resolved target VA appears in the instrumentation VA set gets `is_instrumentation=True`.  The VA set is extracted from kernel `System.map` via `from_system_map(path)`, matching any symbol with prefix `__asan_`, `__kasan_`, or `__sanitizer_cov_`.
  - **Pass 2 — preamble walk**: from each tagged BL, walk backwards up to 6 instructions and tag KASAN shadow-address computation instructions (`srli.d`, `lu12i.w`, `lu52i.d`, `addi.d`, `ld.b`, `andi`, `slti`, `sltui`, `add.d`) as `idiom="kasan_shadow"`.  Stops at calls, branches, stores, or function start.  Recovers the 4–6 instruction KASAN check idiom observed in TencentOS 4.6 kernel 6.6.119-52.9.tl4+debug.
  - `LoongArchFrameV2` extends `LoongArchFrame` with `is_instrumentation: bool` and `idiom: str` fields.
  - `decode_frames_v2()` returns a list (random-access required for pass 2).  `decode_frames_clean()` is the iterator interface that filters `is_instrumentation=True` frames.
  - `count_instrumentation()` returns `{total, instrumentation, real, pct_instrumentation}` — measured ~40% overhead on `kvm_eiointc_write` (208 instructions, 84 ghost calls).
  - Theoretical basis: the V1/V2 split maps onto the UQBT paper (Cifuentes & Van Emmerik 2000): V1 is the SLED pass (instruction encoding → boundary + operands), V2 is the SSL pass (instruction windows → named semantic units).

## v2.28.0

- **`abc_decompiler`: short-circuit evaluation merging** (`_merge_short_circuit`, Cifuentes 1995 Figure 7; Cifuentes/Simon 1998 §5.2)
  - Pre-structuring pass that runs between `_parse_blocks` and `_cfg_emit` inside `_structure_cfg`. Collapses consecutive conditional basic blocks that share the same `goto_tgt` into a single block with a `||`-merged condition.
  - Pattern: `bb[i].term_type == 'cond'` AND `bb[i+1].term_type == 'cond'` AND same `goto_tgt` AND `bb[i+1].label is None` AND `bb[i+1].stmts == []`. The second block must have no label (no external entry) and no stmts (no side effects between the two branch points).
  - Runs iteratively to handle chains of three or more consecutive conditions (e.g. `if(a) goto L; if(b) goto L; if(c) goto L` → single block with `((a) || (b)) || (c)`).
  - After merging, all block indices are recomputed and `lidx` is rebuilt so the existing `_try_while`/`_try_if` patterns receive a clean block list.
  - `_negate` fixed: compound conditions containing `||` or `&&` are now always wrapped in `!()` rather than operator-flipping a sub-expression inside the compound (which produced semantically incorrect negations).
  - Cifuentes/Simon 1998 §5.2 explicitly names short-circuit recovery as a known gap that produces excess `goto` statements; this pass closes that gap for the common same-target pattern generated by ArkTS `&&`/`||`.

## v2.27.0

- **`abc_decompiler`: control flow structuring pass** (`_structure_cfg`, `_BB`, Cifuentes §6.6.1/§6.6.2)
  - Runs after `_propagate_acc` on the flat `label+goto` statement list. Parses the list into `_BB` basic blocks at label and branch boundaries, builds a `label → block_index` map, then applies three structural patterns recursively.
  - **While loop** (§6.6.1): header block has a label, ends with `if (exit_cond) goto L_after`, and some later block ends with `goto L_head` (back-edge detected by position: `label_idx[target] <= source_idx`). The exit condition is negated to produce `while (loop_cond) { body }`. The latching block's terminal goto is suppressed.
  - **If/else** (§6.6.2, Pattern A): conditional block ends with `if (cond) goto L_else`; last then-block ends with `goto L_end`. Emitted as `if (!cond) { then } else { else }`.
  - **Simple if** (§6.6.2, Pattern B): `if (cond) goto L_skip`; fall-through is the then-body. Emitted as `if (!cond) { body }`.
  - `_negate(cond)` flips the operator (`==↔!=`, `<↔>=`, `>↔<=`, strict variants) rather than wrapping in `!(...)` when possible.
  - Condition negation is required because ARK bytecode encodes branches as "jump-if-false" exits: the fall-through path is the then-branch, so the emitted condition is the negation of the jump condition.
  - Unrecognized patterns (exception-handler targets, multi-exit loops, cross-region gotos) fall back to raw `label+goto` output unchanged.
  - Verified on wechat.abc: 867/867 methods OK, 0 errors; 2 while loops structured, 227 if-bodies structured, 154 if/else pairs; 45 residual raw conditional gotos (exception paths and non-reducible patterns).

## v2.26.0

- **`abc_decompiler`: accumulator copy-propagation pass** (`_propagate_acc`, Cifuentes §5.4.6)
  - Post-lift pass over the flat statement list. For each `_acc = EXPR` line: if the next substantive line's rhs does not contain `_acc` (dead assignment), drop the line; if it contains `_acc` exactly once, substitute EXPR inline and drop the line; if it contains `_acc` multiple times, leave both lines.
  - Labels, blank lines, and comment-only lines are transparent for look-ahead purposes.
  - `_paren(expr)` adds parentheses when EXPR contains a binary operator, preserving precedence after inlining.
  - Removed the redundant `// = X` comment from `return _acc` emission — propagation now produces clean `return EXPR` directly.
  - Verified on wechat.abc: `_acc = Row  // global; v6 = _acc` → `v6 = Row  // global`; `_acc = Row.create; v6 = _acc` → `v6 = Row.create`; dead intermediate accumulator assignments eliminated across all 867 methods.
  - Sound within a single basic block. Cross-block propagation requires full ud-chain / liveness analysis (future pass).

## v2.25.0

- **`abc_decompiler`: ARK Bytecode to JavaScript-like pseudocode decompiler** (`analyzers/abc_decompiler.py`, new)
  - `ABCDecompiler.decompile_method(method, code)`: lifts a `CodeItem` to readable JS-like pseudocode via register-state accumulator tracking (Durfina 2012 front-end/IR/back-end pipeline).
  - `decompile_class(class_name)`: decompiles all methods whose class name contains the substring.
  - `decompile_all()`: iterator over every method with code in the file.
  - Register-state machine tracks `_acc` (ARK accumulator) and all virtual registers as expression strings; argument registers seeded as `a0..aN`.
  - Semantic tables covering ~40 instruction categories: binary ops (`add2/sub2/mul2/...`), unary ops (`neg/not/typeof/...`), property access (`ldobjbyname/stobjbyname/...`), global vars (`tryldglobalbyname/stglobalvar/...`), call instructions (`callarg0..callthis3/callrange/...`), object construction, function/class definition, conditional branches, lexical scope, module vars, iterators, generators, async.
  - Branch labels: `_branch_targets()` pre-scans all jumps and inserts `L_XXXX:` labels at target offsets.
  - `ABCParser.resolve_method_idx(n, region=0)` added: resolves property/global name `d`-kind operands through `IndexHeader.method_idx[]`. Property-access instructions (`ldobjbyname`, `stobjbyname`, `tryldglobalbyname`, `stglobalvar`, etc.) encode their operand as an INDEX into `method_idx`, not `class_idx` and not a raw file offset. Prior `_resolve_entity()` called `get_string(val)` directly, which returned "" for any index < 60 (header size). Fix: route all property/global name operands through `resolve_method_idx(val)`.
  - Verified on wechat.abc: string loads resolve correctly (`"L@system.curves;"`); property names (`AudioCapturerManager`, `prototype`) resolve via method_idx.

## v2.24.0

- **`abc_disasm`: ARK Bytecode disassembler** (`analyzers/abc_disasm.py`, new)
  - Full 324-opcode ISA table embedded from ArkCompiler v13.0.0.0 `isa.json` (4 prefix groups: callruntime/deprecated/wide/throw).
  - `ARKDisasm.iter_insns(code)`: yields `ARKInstruction` per instruction; unknown opcodes emitted as single-byte `.data` to preserve alignment.
  - `disasm_method(method, code)`: smali-style text with inline string annotations.
  - `find_calls(code)`: yields all call-site instructions.
  - `find_string_loads(code)`: returns `[(insn, resolved_string), ...]`. Resolves `lda.str N` via `ABCParser.resolve_class_idx(N)` — the 16-bit ID is an INDEX into `IndexHeader.class_idx`, not a raw file offset. Added `ABCParser.resolve_class_idx()` to `abc_parser.py`.
  - Key finding: dual-size opcodes (e.g. `getiterator` at 0x67 vs 0xab) use parallel `opcode_idx[i] ↔ format[i]` arrays in `isa.json`; naive iteration caused 138 false collisions, fixed by pairing arrays.
  - Verified: `func_main_0` in wechat.abc resolves `lda.str 0x21 → "L@system.curves;"` correctly.

## v2.23.0

- **`abc_parser`: HarmonyOS Ark Bytecode (ABC) parser — foundation of the HarmonyOS analysis layer** (`analyzers/abc_parser.py`, new)
  - Parses ABC binary format (ArkCompiler `libpandafile`) for versions v9–v13+, covering both dynamic (ECMAScript/ArkTS runtime) and static dialects.
  - 60-byte header with version-aware literal-array detection: `has_literal_in_header()` returns True for versions ≤ `[12,0,6,0]`.
  - Class body walker: reads MUTF-8 inline name strings, ULEB128 access/field/method counts, `ClassTaggedValues`, `Field12` items, and `MethodItem` records. Entity IDs are absolute file offsets.
  - `get_code(method)`: CodeItem parsing with all-ULEB128 prologue (`register_count + parameter_count + code_size + exception_handler_count`); confirmed from ArkCompiler `ark-rs/src/lowlevel/bytecode.rs`. The fixed u16/u32 layout (often cited in docs) is the static dialect only.
  - Security API: `find_native_methods()`, `find_methods_by_name()`, `find_methods_in_class()`, `find_string_refs_in_code()`, `iter_class_info()`, `summary()`.
  - Verified on wechat.abc v12.0.6.0 (356 KB): 39 classes, 867 methods, all `get_code()` calls succeed.
  - Docs: `docs/module-reference/harmonyos.md` (new); `docs/INDEX.md` updated.

---

## v2.22.0

- **`dwarf_loongarch64`: follow `DW_AT_abstract_origin` / `DW_AT_specification` for LTO-compiled binaries**
  - `extract_debug_funcs()` now builds a flat `{offset: DIE}` map for each ELF and resolves names via `_resolve_name()`, which walks `DW_AT_abstract_origin` and `DW_AT_specification` chains before giving up. GCC LTO emits concrete function instances with no `DW_AT_name`; the name lives in the abstract definition DIE. Without this fix, all LTO-compiled functions returned empty-string names. With fix: all 431 functions in `libtss2-fapi.so.1.0.0` (TencentOS 4.6) now resolve correctly (0 unnamed). Surface exposed by sweeping the TencentOS corpus.

- **LoongArch64 PLT header size fix (`elf_parser.py`, `taint_tracker_loongarch64.py`)**
  - LoongArch64 emits a 2-slot (32-byte) PLT header; `elf_parser.py` and the tracker's pyelftools path both assumed a 1-slot (16-byte) header. This shifted every PLT symbol assignment one position early, causing systematic sink mislabeling (e.g., `fclose` reported as `strcpy`, `__stack_chk_fail` as `execvp`).
  - Fix: `elf_parser.py` `get_plt_got_table()` now starts `plt_idx=2` when `e_machine == EM_LOONGARCH`; tracker pyelftools path changed from `enumerate(start=1)` to `enumerate(start=2)`.
  - Verified via `pcaddu12i` GOT cross-check: `PLT@0x220` → `GOT@0xef2a0` → `rela[0]=fcntl` for all 38 stubs checked. All prior LoongArch64 findings (F-001 through F-006) were false positives from this bug and have been updated to ELIMINATED.

---

## v2.21.0

- **LoongArch64 Steps 8–10: tests, CLI, and package exports**
  - `tests/test_taint_loongarch64.py`: unit tests covering ALU propagation, `andi` bound semantics, `$sp` rebase + load/store roundtrip, syscall source/sink/escalation, `ertn`/`break` termination, two-label union, and callee-saved preservation.
  - `cli.py`: `ablation loongarch64 [--interprocedural] [--depth N] [--full]` and `ablation loongarch64-decode [--frames] [--base N] [--limit N]` subcommands. `--full` selects `from_path_full()` with `.eh_frame`/DWARF/BTF enrichment.
  - `analyzers/__init__.py`: exports `LoongArchDecoder`, `LoongArchFrame`, `LoongArch64TaintTracker`, `TaintFindingLA64`, `LOONGARCH_ESCALATION_NAMES`, `LOONGARCH_SYSCALL_TABLE`, `loongarch_classify_syscall`, `extract_eh_frame_starts`, `extract_debug_funcs`, `extract_btf_funcs`.
  - `docs/INDEX.md`: updated LoongArch64 row description.

---

## v2.20.0

- **LoongArch64 Step 7: syscalls, kernel traps, and exception paths** (`analyzers/syscall_loongarch64.py`, new; `cfg_loongarch64.py`, `taint_tracker_loongarch64.py` updated)
  - `syscall_loongarch64.py`: full asm-generic/unistd.h syscall table (318 entries, Linux 6.6). Three classification tracks: `SYSCALL_SOURCES` (taint `$a0` on return — read/recvfrom/recvmsg/getrandom/etc.), `SYSCALL_SINKS` (CRITICAL/HIGH — execve/execveat/bpf/ptrace/kexec etc.), `SYSCALL_ESCALATION` (setuid/setgid family). Kernel-space function counterparts: `KERNEL_SOURCES` (copy_from_user family), `KERNEL_SINKS`, `KERNEL_ESCALATION` (commit_creds/prepare_kernel_cred).
  - `cfg_loongarch64.py`: `ertn` and `break`/`dbcl` added as no-successor terminators.
  - `taint_tracker_loongarch64.py`: `_SOURCE_NAMES`/`_SINK_NAMES` expanded with kernel-space counterparts; `_ESCALATION_NAMES` frozenset added. `_handle_syscall_frame()` reads `$a7` from constant-folding table for precise source/sink/escalation classification; unknown `$a7` conservatively clobbers caller-saved. Both `_scan_func_binary()` and `run_interprocedural()` handle `syscall`, `ertn`, and `break`/`dbcl` frames.

---

## v2.19.0

- **LoongArch64 Step 6: DWARF, CFI, and BTF function-boundary enrichment** (`analyzers/dwarf_loongarch64.py`, new)
  - `extract_eh_frame_starts(path)` — FDE `initial_location` from `.eh_frame`; present in all GCC-compiled stripped binaries. Recovers leaf functions and tail-call-optimised bodies missed by the `addi.d $sp` prologue heuristic.
  - `extract_debug_funcs(path)` — DW_TAG_subprogram `low_pc`/`high_pc` from `.debug_info`; handles both absolute and relative (byte-count) `high_pc` forms. Returns `{va: (name, end_va)}`.
  - `extract_btf_funcs(path)` — `.BTF` type records + `.BTF.ext` `func_info` section; gives function name→VA for Linux kernel modules that lack `.symtab`.
  - `LoongArch64TaintTracker.from_path_full()` — merges all three sources into `_syms` and stores DWARF end VAs in `tt._dwarf_ends`. Both `run()` and `run_interprocedural()` prefer DWARF `high_pc` over the next-function-start approximation when available.

---

## v2.18.0

- **LoongArch64 Step 5: PLT/GOT resolution + R_LARCH_\* constants**
  - `elf_parser.py`: added `R_LARCH_NONE/32/64/RELATIVE/COPY/JUMP_SLOT/TLS_DTPMOD32/64/TLS_DTPREL32/64/TLS_TPREL32/64/IRELATIVE` constants (psABI v2.30 / binutils loongarch.h).
  - `taint_tracker_loongarch64.py` — `_load_elf()`: fixed three broken attribute accesses in the `ELFParser` branch (`little_endian`→`endian=="<"`, `section_by_name`→`get_section`, `sym.name/value`→`sym["name"]/sym["st_value"]`); the branch now actually runs instead of silently falling through to pyelftools. Both branches now merge PLT stub addresses (VA→imported symbol name) into `syms` from `get_plt_got_table()` / `.rela.plt`, so every `bl <plt_stub>` call resolves to the exact imported function name rather than the ±16-byte `_PLT_TOL` heuristic.

---

## v2.17.1

- **`LibraryInventory` bug fixes** (`analyzers/library_inventory.py`): seven correctness bugs fixed after code review.
  - **`.plt.sec` support**: `classify_internals()` now scans both `.plt` and `.plt.sec`. Android NDK r23+ with BTI places real PLT stubs in `.plt.sec`; previously, `plt_map` was always empty on modern NDK targets and every function clustered as `(pure-internal)` silently.
  - **Wrong delta for same-label symbols**: the scoring loop previously looked up the delta of the first `_PLT_CRITICAL_IMPORTS` entry whose label matched — so `ssl_log_secret` (delta=2) was scored as +3 because `SSL_CTX_set_keylog_callback` (delta=3) shares the `[TLS-KEYLOG]` label. Score bonus is now computed per matched needle during detection and carried forward as `plt_score_bonus`, not re-derived at scoring time.
  - **Multi-symbol additive scoring**: the label deduplication that prevented `SSL_CTX_set_keylog_callback` (+3) and `ssl_log_secret` (+2) from both contributing is replaced by per-needle deduplication. Each distinct matched needle contributes its delta once.
  - **Separated try/except**: the JNI loop and PLT detection loop now each have their own try/except. A None-named symbol causing AttributeError in the JNI loop no longer silently zeroes out `plt_hooks`.
  - **struct bounds guard in BL scan**: `range(0, len(traw), 4)` replaced with `range(0, len(traw) - 3, 4)` to avoid `struct.error` on non-4-byte-aligned content.
  - **IRELATIVE skip in RELA parsing**: entries with `sym_idx == 0` (ifunc resolvers with no symbol) are now skipped; previously, an empty string was written into `got_to_sym`, which could corrupt PLT cluster labels.
  - **text_end clamped to actual content**: `text_end = tv0 + text.size` replaced with `min(text.size, len(traw))` to prevent phantom VAs when `text.size > len(text.content)`.
  - **Exact symbol match**: `needle in sym_name` substring check replaced with `sym_name == needle or sym_name.startswith(needle + '@')` to avoid false positives from wrapper names (e.g., `frida_ssl_log_secret_interceptor`).
  - **Consistent `plt_hooks` formatting** in `report()` high-risk summary: was rendering as Python list repr; now uses `' '.join()` matching the table column format.
- **`docs/INDEX.md`**: added `LibraryInventory` to the Android/APK module row (was missing since v2.16.0).

---

## v2.17.0

- **`LibraryInventory` PLT hook and TLS keylog detection** (`analyzers/library_inventory.py`): adds `plt_hooks: List[str]` field to `LibInventoryEntry`. Six critical symbol patterns are now detected in both dynamic imports and statically-linked re-exports: `SSL_CTX_set_keylog_callback` (`[TLS-KEYLOG]`, +3), `ssl_log_secret` (`[TLS-KEYLOG]`, +2), `ssl_log_rsa_client_key_exchange` (`[TLS-KEYLOG]`, +2), `bytehook_hook_all` (`[PLT-HOOK]`, +2), `bytehook_hook_single` (`[PLT-HOOK]`, +2), `shadowhook_hook_sym_name` (`[PLT-HOOK]`, +2). The score delta from each matching import is added to the security score (capped at 10). `report()` shows detected labels inline per row; the high-risk summary also lists hook labels.

- **`LibraryInventory.classify_internals()`** (`analyzers/library_inventory.py`): new static method. Groups ARM64 internal functions by their PLT call signature (first 6 distinct PLT symbols called, joined with `+`). Returns `{label: [va, ...]}`. Functions with no PLT calls cluster as `(pure-internal)`. Requires `capstone`. Replaces the per-session `defaultdict` cluster scripts written during engagements.

---

## v2.16.0

- **`LibraryInventory`** (`analyzers/library_inventory.py`): batch triage scanner for directories of native ELF `.so` files. `LibraryInventory.from_dir(path).scan()` returns a `List[LibInventoryEntry]` sorted by security score, one entry per library: `size_kb`, `arch`, `exports`, `internal` (ARM64 BL-target count), `jni` (Java_* exports), `has_jni_on_load`, `security_score` (0-10), and a `security_strings` sample. `report(entries)` prints a formatted triage table; `security_entries(entries, min_score=3)` filters to libraries worth detailed review. Security score weights credential-field format strings (+3), credential names (+2), crypto primitive strings (+1), JNI surface size, and internal function density. Replaces the ad-hoc BL-target enumeration loops written per engagement.

---

## v2.15.2

- **`WindowAnalyzer` ARM64 PLT resolver** (`analyzers/window_analyzer.py`): added `_build_plt_arm64()` method that parses ARM64 PLT stubs (`ADRP x16 / LDR x17, [x16, #imm] / ADD x16 / BR x17`, 16-byte entries) and maps each stub VA to its symbol name via `.rela.plt`. Previously, all `bl` instructions on ARM64 binaries produced no PLT annotation; now they resolve inline (e.g., `PLT -> std::string::push_back`). Supports both full 4-instruction stubs and handles the 2-slot trampoline at the PLT start.

---

## v2.15.1

- **`WindowAnalyzer` ARM64 fix** (`analyzers/window_analyzer.py`): use `capstone.CS_ARCH_ARM64` instead of `capstone.CS_ARCH_AARCH64`; the latter was removed in Capstone v5.x. ARM64 disassembly via `WindowAnalyzer.from_path()` now works on Capstone 5.x installs.

---

## v2.15.0

- **`HashAlgoDiscriminator`** (`analyzers/crypto_pattern_detector.py`): identifies hash algorithms from K-table and round-constant values extracted via ARM32 Thumb2 disassembly. Handles MOVW/MOVT pairs and LDR-literal pool loads. Covers MD5 (64-entry K-table), SHA-1 (4 round constants), SHA-256 (8 init + 4 K constants), SHA-512 (unique lower-half constants for disambiguation), and CRC32. Returns per-algorithm confidence scores.

- **`CustomCBCDetector`** (`analyzers/crypto_pattern_detector.py`): detects hand-rolled AES-128-CBC in ARM32 Thumb2 binaries without requiring symbol names or import tables. Scores four signals: BL inside a backward-branch loop (40 pts), 16-byte EOR/VEOR block (30 pts), MOV updating the LDRB base register (20 pts), pre-loop `.rodata` LDR (10 pts). Reports `CBCPattern` with confidence, block function VA, and chaining register when score >= 50.

---

## v2.14.3

- **`BinaryContext` kernel-space VA fix** (`analyzers/binary_context.py`):
  `np.int64(va)` and `np.array([...], dtype=np.int64)` both raise `OverflowError` on kernel-space addresses (VA > 2^63−1, e.g. `0xffffffff81000000`). Added two module-level helpers: `_va_to_i64()` for scalar VAs and `_va_arr_to_i64()` for VA sequences. Both use `ctypes.c_int64` / `uint64.view(int64)` to bit-cast without value conversion. Fixed six call sites across the x86-64 call graph builder, ARM32 call graph builder, and string xref scanner.

---

## v2.14.2

- **Flywheel hardening continued** (3 additional bugs fixed):
  - `PatternLibrary._merge_new_defaults()`: fixed double `save()`. The redundant `if added: self.save()` before the unconditional call caused two disk writes when new defaults were added. Reduced to one unconditional call, which also handles the schema_version bump-only case.
  - `PatternLibrary.list()`: `if tag:` replaced with `if tag is not None:`. Same class of bug as Bug 11 in `sweep()`. `list(tag="")` now filters to untagged patterns instead of showing all.
  - `PatternLibrary.sweep()`: Bug 11 fix verified across 4 scenarios (empty list, None, real tag, nonexistent tag). Concurrent `add()` is GIL-safe in CPython. Lock is released correctly after an `AttributeError` from a duck-typed non-registry.

## v2.14.1

- **Flywheel hardening** (10 bugs fixed via adversarial test suite):
  - `export_patterns()`: whitespace-only title no longer produces a leading `': '` in the query. Title is stripped before building the query string.
  - `export_patterns()`: descriptions made entirely of non-printing Unicode (e.g. zero-width spaces `U+200B`) are rejected. They pass SQLite `TRIM()` and Python `str.strip()` but fail `isprintable()`.
  - `export_patterns()`: `TRIM()` guard added to the WHERE clause so whitespace-only descriptions are excluded at the SQL level.
  - `export_patterns()`: query string is stripped of leading and trailing whitespace.
  - `PatternLibrary._load()`: a non-list `patterns` field no longer crashes on load. It falls back to defaults.
  - `PatternLibrary.save()`: acquires `self._lock`. Without it, an external save call could race with `ingest_from_registry()` and overwrite its in-progress results.
  - `PatternLibrary._lock`: upgraded from `threading.Lock` to `threading.RLock`. `ingest_from_registry()` holds the lock and calls `save()` internally. A plain Lock deadlocks on that path.
  - `FindingRegistry.__init__`: `check_same_thread=False` added to the SQLite connection. `export_patterns()` can now be called from a thread other than the one that created the registry.
  - `PatternLibrary._load()`: one broken pattern entry no longer wipes all valid patterns. Broken entries are skipped one at a time instead of triggering a full reset to defaults.
  - `Pattern.from_dict()`: extra fields in stored `PatternHit` dicts are filtered before construction. An unknown field from a newer version caused an uncaught `TypeError`.
  - `Pattern.from_dict()`: `PatternHit` entries with no `binary` field are skipped instead of crashing the parent `Pattern` load.

## v2.14.0

- **FindingRegistry flywheel** (`analyzers/finding_registry.py`, `analyzers/pattern_library.py`):
  Confirmed findings now feed future sweeps automatically. `FindingRegistry.export_patterns()`
  returns all confirmed findings as `{query, tag}` dicts tagged by CWE class.
  `PatternLibrary.ingest_from_registry(reg)` consumes them, deduplicates, and saves. Call it
  once at engagement start before `sweep()`. Idempotent: subsequent calls only add findings
  registered since the last ingest. No hard coupling between modules; `PatternLibrary` accepts
  any object with `export_patterns()`.

---

## v2.13.0

- **ZIM-BERT distillation** (`analyzers/version_delta_finetune.py`): Teacher-student training
  for cross-version binary similarity. `zimbert_finetune()` uses `all-mpnet-base-v2` as teacher
  and `all-MiniLM-L6-v2` as student. Two auxiliary losses on top of MultipleNegativesRankingLoss:
  L_KL_output (KL divergence on batch pairwise similarity distributions) forces the student's
  similarity structure to match the teacher's; L_value (MSE on value projection vectors across
  paired encoder layers) transfers the teacher's attention routing. Architecture-aware value
  hooks handle both BERT and MPNet attention layouts. Standard fine-tuning entry point
  (`finetune_model()`, `generate_structural_pairs()`) unchanged.

---

## v2.12.0

- **ELFVtableReconstructor** (`analyzers/elf_vtable_reconstructor.py`): Static C++ vtable
  reconstruction for x86-64 ET_DYN ELF files without executing the binary. Reads `.rela.dyn`
  and resolves both R_X86_64_RELATIVE (type 8, in-library function pointers) and R_X86_64_64
  (type 1, exported symbol references) to produce a complete slot→function map. Accepts a
  vtable VA directly or looks up `_ZTV<N><name>` from the symbol table. Returns a `VtableMap`
  with `live_slots()`, `function_at(offset)`, `slot_for_va(fn_va)`, and
  `slot_offset_for_name(fragment)` helpers.

- **VtableDispatchScanner** (`analyzers/vtable_dispatch_scanner.py`): Scans x86-64 ELF
  executable sections for `call [reg+disp]` dispatch instructions. Covers all standard
  encodings: bare register (rax–rdi), REX.B-extended (r8–r15), SIB-based (r12/rsp), and
  both disp8 (0–127) and disp32 forms with full REX prefix variants. Accepts a name→offset
  dict, a `VtableMap` directly, or a list of raw offsets. Returns a `DispatchReport` with
  `.dead()` (zero call sites) and `.live()` (call site list) per slot. Composes with
  `ELFVtableReconstructor`: `scanner.scan(vtable_map)` identifies unreachable virtual methods
  in one call.

---

## v2.11.0

- **BmpKeyExtractor / LSBStegoReader / LagrangeKeyExtractor**
  (`analyzers/lsb_stego_extractor.py`): BMP LSB steganography reader and
  Lagrange polynomial secret-sharing key extractor. Recovers key material
  hidden in BMP pixel LSBs using a Shamir-style scheme over rational arithmetic.
  `LSBStegoReader` reads the per-seed pixel LSB channel (1 bit/pixel, 8 pixels/byte,
  LE bit order, modular wrap-around). `LagrangeKeyExtractor` reconstructs P(0) via
  Lagrange interpolation at x=0 using CRT over multiple 63-bit primes; matches the
  imath `mp_int_to_binary` byte-order: little-endian output, reverse two's complement
  for negative values (carry MSByte to LSByte), extra byte for bit-aligned integers.
  `BmpKeyExtractor` is the high-level entry point: BMP path + seed -> `StegoKeyResult`
  with per-component hex strings and concatenated `raw_key_hex`. Stdlib-only;
  no sympy or scipy dependency.

---

## v2.10.0

- **DEXLifter** (`analyzers/dex_lifter.py`): pseudo-Java IR lifter for DEX bytecode.
  Converts `DEXInstruction` streams to readable Java-like source without SSA
  or external dependencies. Type inference propagates through move-result, iget,
  sget, check-cast, and const opcodes. Renders field access as dot notation,
  invoke-* as typed method calls, if-* as labelled conditionals, backward
  gotos as loop markers. Pending-invoke state correctly handles move-result
  (result assigned to typed variable on the invoke line, not a separate line).
  Handles binary/unary arithmetic, array access, new-instance, instanceof,
  monitor-enter/exit, switch, fill-array-data. Falls back to annotated smali
  comment for any unrecognised opcode so output is always complete.
  Verified on PetTech APK: reveals ByteDance `Tz.a()`/`Tz.b()` anti-tamper
  wrapping pattern and `BWFlashData.c` as the device key storage field.

---

## v2.9.0

- **DEXDisasm** (`analyzers/dex_disasm.py`): DEX bytecode disassembler with
  smali-style output. Covers all 17 instruction formats (`10x` through `51l`).
  Annotates every reference with resolved descriptors from the DEX flat tables:
  full method signatures (class, name, proto), field names and types,
  type names, and string literals. Builds a code_off lookup map at init time
  by walking all `class_data_item` entries. `disasm_method(class, method)`,
  `disasm_class(class)`, `list_methods(class)`, `decode_code_item(dex, off)`.
  53,635 methods decoded in PetTech APK. No external dependencies.

---

## v2.8.0

- **SqlSinkScanner** (`sql_sink_scanner.py`): detect raw SQL injection in C/C++
  ELF binaries using the MySQL C API or SQLite3 directly. Covers
  `mysql_query`/`mysql_real_query`/`sqlite3_exec`/`sqlite3_prepare_v2`. For each
  call site, traces the SQL string argument backward: RODATA literal with `%s` →
  `INJECTABLE_LITERAL`; `snprintf`-built buffer with `%s` format specifier →
  `INJECTABLE`; numeric-only format specifiers → `SAFE_NUMERIC`; entry-register
  propagation → `ARG_PROPAGATED`. Reuses PLT extraction and function-start
  helpers from `SinkArgClassifier`. Dead PLT imports (0 callers) are pre-filtered
  and reported separately. CLI: `python3 -m ablation.analyzers.sql_sink_scanner
  <binary>` exits 2 on HIGH findings.

---

## v2.7.0

- **APKParser** (`apk_parser.py`): zero-dependency APK/XAPK container parser. Binary
  XML (AXML) decoder with `ResXMLTree_attrExt` offset fix. DEX flat-table iteration:
  strings, method refs, field refs, class defs. Handles multi-dex APKs (`classes*.dex`)
  and APKPure XAPK containers transparently. API: `from_path()`, `parse_manifest()`,
  `iter_dex()`, `native_libs()`, `extract_native_lib()`.

- **DEXFile.iter_native_methods()** (`apk_parser.py`): streaming `class_data_item`
  parser for authoritative ACC_NATIVE detection (`0x0100`). Walks `encoded_method`
  ULEB128 arrays with correct running-index reset between `direct_methods` and
  `virtual_methods`. Returns `NativeMethod` dataclass with class name, method name,
  proto shorty, and code_off. Combined with ELF dynsym scan: three-way classification
  — confirmed native, stripped/dynamically registered, ELF-only helper.
  `dump_class_methods()` debug dump produces ASCII table with kind/flags/code_off per
  method.

- **JniBridgeScanner** (`jni_bridge_scanner.py`): JNI bridge RE from DEX + ELF dynsym.
  DEX side: ACC_NATIVE methods via `iter_native_methods()`, opaque peer FieldRef
  (type `J` + peer-like name), `loadLibrary` call sites. ELF side: `JNI_OnLoad` export
  (HIGH — dynamic registration; `RegisterNatives` function pointers not in symbol table)
  vs `Java_*` exports (MEDIUM — canonical naming directly recoverable). No androguard
  dependency. API: `from_path()`, `scan()`, `report()`.
  Docs: `docs/module-reference/android.md`.

- **BinderScanner** (`binder_scanner.py`): Binder IPC surface map from DEX ClassDef
  superclass scan, `onTransact` MethodRef, and manifest exported component cross-reference.
  Detects exported Services (HIGH), raw `onTransact` overrides (HIGH), AIDL-generated
  `$Stub` inner classes (MEDIUM), unexported Service subclasses (MEDIUM), and Messenger
  usage (INFO). AIDL Stub integer transaction code fuzzing noted per finding.
  API: `from_path()`, `scan()`, `report()`.
  Docs: `docs/module-reference/android.md`.

- **android_sweep.py** (`sweeps/android_sweep.py`): orchestration sweep for full APK
  RE pass. Runs manifest analysis, DexAnalyzer, JniBridgeScanner, BinderScanner, and
  native lib ELF security properties in a single call. XAPK containers handled
  transparently.

---

## v2.6.0

- **FirmwareContainer** (`firmware_container.py`): parser for partitioned firmware
  images with a plaintext header and fixed 296-byte partition table records. Detects
  payload type (gzip/xz/zstd/lz4/lzo/cpio/elf/pe/ext2/3/4) per partition. API:
  `from_path()`, `dump_partitions()`, `read_partition(name)`, `extract(name, path)`,
  `extract_all(outdir)`. CLI: `python3 -m ablation.analyzers.firmware_container`.
  Docs: `docs/module-reference/firmware-containers.md`.

- **VideoContainerAnalyzer** (`video_container.py`): forensic scanner for MP4/MOV,
  MKV/WebM, and AVI files. Detects polyglot headers, appended trailer data, atom size
  overflow, EBML unknown-length abuse, and RIFF chunk miscount. API: `from_path()`,
  `scan()`, `report(findings)`. Docs: `docs/module-reference/firmware-containers.md`.

---

## v2.5.0

- **FormatStringScanner** (`format_string_scanner.py`): x86-64 format string
  vulnerability detector. TAOSSA Ch8-grounded. 28 format sinks: printf/fprintf/
  sprintf/snprintf/syslog/err/warn/wprintf family. Backward trace per call site:
  LEA [rip+offset] into .rodata = SAFE; register from function arg / stack slot /
  recv return = VULNERABLE. `verdict` property returns SAFE / VULNERABLE / SUSPICIOUS.
  CLI: `ablation fmtstr <binary> [--json FILE]`.

- **IoctlAttackSurfaceGenerator** (`ioctl_attack_surface.py`): per-IOCTL attack
  surface report for Windows kernel drivers. Wraps KernelDriverAnalyzer output. For
  each IoControlCode: METHOD_NEITHER without ProbeForRead = CRITICAL; allocation
  before InputBufferLength read = HIGH; TYPE3_INPUT_BUFFER direct deref = HIGH.
  Generates Markdown report via `report_markdown()`. CLI: `ablation ioctl-surface`.

- **CrossBinaryTaintTracker** (`cross_binary_taint.py`): LibGraph-backed cross-library
  taint BFS. Extends TaintTracker.run_interprocedural() to follow tainted arguments
  through PLT entries into exporting shared libraries. Resolves PLT symbol to exporting
  binary via LibGraph.defined_in(), spawns a seeded TaintTracker on that binary, and
  continues BFS. Returns TaintChain with full cross-binary hop provenance.

- **ByovdDetector / BYOVDDetector** (`byovd_detector.py`): BYOVD capability detector.
  12 capability classes: PHYS_MEM_RW (MmMapIoSpace), TOKEN_STEAL (PsInitialSystemProcess),
  DKOM (ObReferenceObjectByHandle), APC_INJECT (KeInitializeApc), DRIVER_LOAD,
  CALLBACK_REMOVE, PROCESS_KILL, MSR_WRITE (WRMSR instruction scan), and more.
  Known-driver PDB fingerprints (mhyprot, RTCore64, dbutil, PROCEXP, iqvw64e, cpuz).
  CLI: `ablation byovd <driver.sys>`.

- **MIPS32FuncProfiler** (`mips_analyzer.py`): quick MIPS32 function profiler.
  Complements MIPS32TaintTracker (taint_tracker_mips.py): single-call function
  profile returning call sites + sink flags for MIPS32 binaries. Uses `MIPS32TaintTracker`
  as backend; adds big-endian + little-endian O32 ABI support.

- **HeapUAFScanner** (`heap_uaf_scanner.py`): forward register-state UAF/double-free
  scanner. Complements HeapVulnScanner: simpler single-pass approach tracking ALLOC /
  FREE / UNKNOWN state per register. Compatible with both SysV and Windows x64 ABI
  (`windows_abi=True` flag uses RCX as free arg instead of RDI).

---

## v2.4.0

- **MIPS32TaintTracker** (`taint_tracker_mips.py`): MIPS32 source-to-sink taint
  analysis for embedded firmware (RouterOS, Broadcom CPE, MIPS-based routers).
  O32 ABI register model: $a0-$a3 args, $v0 return, $t0-$t9 caller-saved, $s0-$s7
  callee-saved. Sources: recv/recvfrom/read/fgets/gets/fread. Sinks:
  system/execve/execl/execvp/popen/strcpy/sprintf/memcpy/strcat/snprintf. Load-delay
  slot aware. Big-endian and little-endian support. Intraprocedural + interprocedural
  BFS up to depth 4. CLI: `ablation mips <binary> [--le]`.

- **HeapVulnScanner** (`heap_vuln_scanner.py`): four heap memory corruption classes
  for x86-64 ELF. Grounded in TAOSSA Ch5 (Memory Corruption) and Ch6 (C Language
  Issues): `INT_OVERFLOW_BEFORE_ALLOC` (IMUL/MUL/SHL result fed to allocator without
  overflow check, L6-2/L6-3 patterns); `USE_AFTER_FREE` (freed register dereferenced
  in same function); `DOUBLE_FREE` (same register freed twice without reassignment);
  `OFF_BY_ONE_ALLOC` (strlen result to malloc without +1). CLI: `ablation heap <binary>`.

---

## v2.3.0

- **BYOVDDetector**: BYOVD (Bring Your Own Vulnerable Driver) risk assessment.
  Wraps `KernelDriverAnalyzer` with BYOVD-specific scoring (0-100). Detects 8
  attack paths: `PHYS_MEM_ARBITRARY_RW` (MmMapIoSpace with user-supplied physical
  address), `MDL_KERNEL_WRITE` (IoAllocateMdl + MmProbeAndLockPages +
  MmMapLockedPagesSpecifyCache SSDT-write chain, from PRE ch3 Sample A walk-through),
  `MSR_LSTAR_MANIPULATION` (RDMSR/WRMSR at 0xC0000082), `SSDT_HOOK` (CR0 WP-disable
  combined sequence + KeServiceDescriptorTable), `TOKEN_STEALING_LPE`
  (PsInitialSystemProcess + DKOM), `SMEP_BYPASS` (CR4 combined sequence),
  `APC_KERNEL_INJECTION` (KeInitializeApc/KeInsertQueueApc), `VIRTUAL_MEM_WRITE`
  (ZwWriteVirtualMemory). Signed driver + METHOD_NEITHER IOCTL + attack path =
  BYOVD_CONFIRMED. CLI: `ablation byovd <driver.sys>`.
  Grounded in Practical Reverse Engineering (Dang et al.) ch3 IOCTL walk-throughs.

---

## v2.0.0

- **KernelDriverAnalyzer**: first Windows `.sys` kernel driver RE module. Covers IRP/IOCTL
  dispatch extraction (capstone DriverEntry disassembly), CTL_CODE decoder with METHOD_NEITHER
  flagging, 40+ kernel API risk classifications across 12 classes, 20+ callback registrations
  tagged by edr_like/rootkit_risk/info, pool tag extraction from `41 B8` byte pattern, and a
  dangerous-instruction scanner: CR0/CR4 combined sequences, MSR_LSTAR targeted access,
  SSDT hook combined byte pattern, UTF-16LE `L"KeServiceDescriptorTable"` wide-string scan,
  SMEP-disable CR4 sequence, RDMSR/WRMSR, CLI/STI/HLT, SWAPGS, IRETQ, I/O ports.
  Standalone `decode_ioctl_code()` function. WDM/KMDF/minifilter classification by import
  profile. PDB path extraction (RSDS + NB10), Authenticode signature detection.
  Grounded in Windows Internals Part 1 (Ch5 memory, Ch6 I/O), Windows Kernel Programming,
  and Rootkits: Subverting the Windows Kernel.

---

## v1.8.0

- **NameRegistry**: persistent VA-to-name overlay at `~/.ablation/function_names.json`,
  keyed by binary SHA256. Names auto-load in all sessions and appear in every callee, caller,
  and display context.
- **FindingRegistry**: cross-target confirmed finding store at `~/.ablation/findings.db`.
  BERT embeddings attached to findings seed future sweeps automatically.
- **PatternLibrary**: self-improving pattern corpus. Every confirmed finding registers a
  semantic query that replays on future binaries via `pl.sweep(searcher)`.
- **BinaryContext: discovered-name overlay**: `ctx.name(va)` returns the overlay name when
  set, cascading through export, PLT, and hex. `ctx.set_name()`, `ctx.names_table()`,
  `ctx.names_map()`.
- **Vectorized call graph**: `_build_call_graph` replaced with NumPy `0xe8` opcode scan.
  One broadcast operation extracts all CALL rel32 displacements and resolves all targets.
  Sequential capstone retained as fallback.
- **fortinet_sweep.py rewrite**: modernized to use current ablation.analyzers API; removed
  manual ELF parsing and hardcoded session paths.
- **modules/ migration**: 611 vendor-specific RE modules moved from flat `modules/` to
  `targets/<vendor>/` directories. `modules/` now contains only general-purpose utilities.
- **MCP server removed**: dead code; all functionality available directly via the Python API.
- **Document library**: full external-facing docs: getting started, workflow guides, module
  reference, target notes, pitch document.

---

## v1.7.0

- **LlmAnalyst**: ReAct agent loop (Claude Sonnet 5) for automated function naming and
  vulnerability hypothesis generation. `AgentLoop`, `ToolRegistry`, `ContextBuilder`,
  `RAGRetriever`.
- **TaintTracker (x86-64)**: static intraprocedural taint analysis. libdft taint policy
  adapted for static analysis. Full stack model (rbp-relative and rsp-relative slots).
- **PathSolver**: constraint-based path feasibility. Eliminates TaintTracker false positives
  where the tainted path is unreachable due to contradictory branch constraints.
- **FuncProfiler**: lightweight triage: BB count, edge count, PLT calls, branch density
  classification without full disassembly.

---

## v1.6.0

- **VtableResolver**: ARM64 C++ vtable reconstruction and BLR indirect call resolution.
  Four-phase: vtable extraction, constructor vptr detection, BLR site detection, resolution.
  Primary target: WeChat `libwechatnetwork.so` gILinkKey dispatch.
- **VersionDelta**: cross-version function tracking. Three-stage pipeline: structural
  pre-filter, mnemonic 4-gram Jaccard, BERT tiebreaker. Patch localization via
  `difflib.SequenceMatcher`. Anchor scan for implementation variant classification (validated
  against multiple binary versions).
- **StructuralSim**: five-signal composite similarity (opcode histogram, immediate Jaccard,
  PLT overlap, branch density, size proximity). Works on all functions, not just the ~12%
  with two or more external PLT calls.
- **MatrixProfileDiff**: STOMP-based sequence anomaly detection for binary diffing.

---

## v1.5.0

- **SemanticSearcher**: BERT behavioral fingerprint search over all functions in a binary.
  ~35s for 19,000 functions on CPU. Queries in plain English. Results cached.
- **CorpusBuilder**: builds `func_id.db` behavioral description database for BERT encoding.
  Per-function: PLT calls, strings, exported name, call-graph neighbors, size.
- **EntropyMapper**: sliding-window Shannon entropy scan. Classifies binary regions as
  ENCRYPTED, CODE, SPARSE, or PADDING. Finds encrypted and plaintext transitions.
- **XorSolver**: three-mode automated XOR decryption: KPA (known plaintext), Hamming
  distance key length guesser, frequency analysis and transposition.
- **CryptoAudit**: JWT weak-secret cracking (ordered by production frequency), hardcoded
  key material scan, TLS posture assessment.

---

## v1.4.0

- **XRefGraph**: full cross-reference graph with indirect call resolution.
- **CFGBuilder**: per-function control flow graph via iterative recursive disassembly
  (Andriesse PBA ch. 8.2.4). BasicBlock: start, end, succs, insns.
- **BinaryContext: RIP-relative xref index**: NumPy vectorized displacement scan in
  `_build_string_xref_index`. One O(N) pass over `.text` builds `_str_xref_idx`
  (string_va -> [code_vas]) and `_func_str_idx` (func_va -> [string_vas]).
- **`ctx.strings_in_func(va)`**, **`ctx.string_xrefs(va)`**, **`ctx.funcs_referencing_string(va)`**.

---

## v1.3.0

- **Installable package**: `ablation.analyzers.*` package structure. `pip install -e .`.
  Shims in `modules/` preserve backward compatibility.
- **BinaryContext**: SHA256-keyed JSON cache at `~/.ablation/cache/`. Build once (0.5s),
  reload in 110ms. Captures PLT, exports, strings, func_starts, call_edges.
- **GoFuncTable (GoPclntab)**: pclntab parser. Go 1.12 - 1.20+. All architectures.
  Lifts semantic search accuracy from ~0.20 to ~0.70+ on stripped Go binaries.
- **GoGarbleRe**: garble-obfuscated Go binary RE. Runtime bootstrap tracing, HTTP handler
  pattern detection, VA and file-offset mapping recovery.
- **GoStringResolver**: reconstructs Go string constants from `concatstrings` call sites.
- **GoSubprocessScanner**: finds all `os/exec.Command`, `syscall.Exec`, SYS_EXECVE sites.
- **GoDangerousCallers**: Go-specific dangerous caller sweep.
