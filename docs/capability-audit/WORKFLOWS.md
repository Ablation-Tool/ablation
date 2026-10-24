# WORKFLOWS.md — Ablation Capability Audit

Covers all 10 sweep drivers and 7 workflow guides. For each, the goal, phases,
analyzers chained, inputs, outputs, architecture coverage, status, and known gaps.

Evidence source: Phase 1 notes/S01.md (direct code reads of all sweep files and
workflow guides). See DISCREPANCIES.md for doc/code mismatches found during audit.

---

## Part 1: Sweep Drivers

### 1. base_sweep

**File:** `sweeps/base_sweep.py`  
**CLI:** `python3 sweeps/base_sweep.py /path/to/binary [--start HEX] [--end HEX] [--top N] [--vendor STR] [--product STR] [--version STR] [--no-xref] [--report PATH] [--register THRESHOLD]`  
**Goal:** Semantic vulnerability sweep of a single x86-64 ELF binary. Starting point for any new target.

**Phases:**
1. Function discovery: prologue scan (`push rbp; mov rbp,rsp` = 0x55 0x48 0x89) + XRefGraph.eh_frame fallback when `-fomit-frame-pointer` is used
2. Function description: `describe_function()` per function (opcode summary + string xrefs + caller context from XRefGraph)
3. Semantic sweep: 8 base `VULN_PROFILES` + prior `FindingRegistry` queries via `all-MiniLM-L6-v2` (SentenceTransformer, not SemanticSearcher class)
4. Taint analysis: `TaintTracker` intraprocedural + `InterproceduralPath` depth-4 BFS on top-ranked candidates
5. Registration: interactive candidate registration into `FindingRegistry` when `--register THRESHOLD` is set

**Analyzers chained:**
- `XRefGraph.from_path` (string xrefs + call graph)
- `FindingRegistry` (prior query embeddings + registration)
- `describe_function` (per-function embedding input)
- `TaintTracker` (x86-64 intraprocedural)
- `InterproceduralPath` (depth-4 BFS, x86-64 only)
- `report_generator.generate_report` (optional)

**Inputs:** Stripped x86-64 ELF binary  
**Outputs:** Stdout ranked candidates per vuln class; optional markdown report at `--report` path or `reports/sweep_<slug>_<ts>.md`  
**Architectures:** x86-64 only  
**Status:** Working as written  
**Profiles (8):** unsafe_memcpy, strcpy_overflow, int_overflow, double_free, format_string, recv_overflow, heap_spray, cmd_injection  
**Key limitations:**
- Prologue scan misses -fomit-frame-pointer functions (eh_frame fallback covers most)
- `scan_start` default 0x200000 hardcoded — must override for non-standard load addresses
- SinkArgClassifier not called (fortinet_sweep adds that in Phase 3)
- No taint for non-x86-64 architectures
- `FindingRegistry` integration only when `--register` flag is passed

---

### 2. fortinet_sweep

**File:** `sweeps/fortinet_sweep.py`  
**CLI:** `python3 sweeps/fortinet_sweep.py <target|dir> [--vendor STR] [--product STR] [--version STR] [--top N] [--max-funcs N] [--report PATH] [--no-vendor-profile]`  
**Goal:** Four-phase multi-arch sweep of FortiOS ELF binaries with PLT triage, semantic search, arch-routed taint, and sink argument classification.

**Phases:**
0. (Directory mode) PLT triage: `batch_plt_intersect` to skip binaries with no exec-class sinks
1. Semantic sweep: `XRefGraph` + 8 base + 8 `FORTIOS_PROFILES` + registry priors; eh_frame fallback for FPO
2. Taint analysis: arch-routed dispatch
   - x86-64: `TaintTracker` full interprocedural depth-4
   - ARM32: `ARM32TaintTracker` intraprocedural
   - ARM64: `ARM64TaintTracker` intraprocedural
   - PPC32: `PPC32TaintTracker` with interprocedural
   - PPC64: `PPC64TaintTracker` with interprocedural
   - MIPS: **explicitly skipped** ("No taint tracker for arch ARCH.MIPS")
3. (x86-64 only) `SinkArgClassifier` + `VendorProfile("fortinet")` + `SanitizerDetector` — classify exec sink argument provenance (RODATA_CONST / SNPRINTF_RODATA / ARG_PROPAGATED / UNKNOWN)

**Analyzers chained:**
- `batch_plt_intersect` (PLT triage, phase 0)
- `XRefGraph.from_path` (phase 1)
- `FindingRegistry` (phase 1, prior queries)
- `describe_function` (phase 1, per-function)
- `TaintTracker` / `ARM32TaintTracker` / `ARM64TaintTracker` / `PPC32TaintTracker` / `PPC64TaintTracker` (phase 2, arch-dependent)
- `SinkArgClassifier.from_path` (phase 3, x86-64 only)
- `VendorProfile.from_vendor("fortinet")` (phase 3, x86-64 only)
- `SanitizerDetector` (phase 3, x86-64 only)

**Inputs:** ELF binary or directory; optional `--max-funcs` to skip semantic sweep for large binaries  
**Outputs:** `reports/sweep_fortinet_<product>_<version>_<ts>.md`  
**Architectures:** x86-64 (full), ARM32 (intra), ARM64 (intra), PPC32/PPC64 (inter); **MIPS not supported**  
**Status:** Working as written  
**FORTIOS_PROFILES (8):** fortios_path_traversal, fortios_fgfm_heap, fortios_sslvpn_heap, fortios_httpsd_injection, fortios_saml_bypass, fortios_format_string_log, fortios_fwupdate_intovf, fortios_json_type_confusion  
**Key limitations:**
- Phase 3 (SinkArgClassifier + SanitizerDetector) runs on x86-64 only — ARM/PPC get no sink classification
- ARM32/ARM64 taint is intraprocedural only (no depth-4 interprocedural BFS)
- MIPS completely skipped in taint phase (significant gap for older FortiGate hardware)
- `--max-funcs` disables semantic sweep for large binaries while taint/PLT still run

---

### 3. android_sweep

**File:** `sweeps/android_sweep.py`  
**CLI:** `python3 sweeps/android_sweep.py /path/to/app.apk [--native-dir DIR]`  
**Goal:** Three-phase Android APK analysis: manifest permissions, DEX dangerous API scan, native .so security properties.

**Phases:**
1. AndroidManifest.xml parse: permissions, exported components, SDK versions via `APKParser`
2. DEX scan: `DexAnalyzer` over all classes*.dex — dangerous API calls, hardcoded secrets, cleartext URLs, exported component misuse
3. Native inventory: inline ELF32 LE struct parser for NX/RELRO/stack-canary/FORTIFY; flags EOL OpenSSL 1.1, V8, PLT hooking frameworks (shadowhook/bytehook), on-device ML (ncnn/MediaPipe/TFLite), BLE libraries; extracts priority .so to `--native-dir`

**Analyzers chained:**
- `APKParser` (ablation.core.apk_parser)
- `DexAnalyzer` (ablation.analyzers.dex_analyzer)
- `_elf_security_props` (inline ELF32 LE parser, no external class)

**Inputs:** Android APK (.apk)  
**Outputs:** Stdout manifest summary + DEX findings + native .so report + RE targets list; extracted .so files under `--native-dir`  
**Architectures:** armeabi-v7a (ELF32 LE) for native analysis only; arm64-v8a .so not analyzed  
**Status:** Working as written  
**Key limitations:**
- `_elf_security_props` is ELF32 LE only — arm64-v8a native libraries skipped
- No semantic BERT sweep of APK (pattern-based DexAnalyzer only)
- `_SECURITY_CRITICAL_LIBS` set is hardcoded for Tuya/Thing SDK — not general-purpose
- No taint analysis at sweep level; DexAnalyzer provides pattern-based scanning only

---

### 4. pe_sweep

**File:** `sweeps/pe_sweep.py`  
**CLI:** `python3 sweeps/pe_sweep.py <target|dir> [--vendor STR] [--product STR] [--version STR] [--top N] [--report PATH]`  
**Goal:** Semantic vulnerability sweep of Windows PE32/PE32+ binaries.

**Phases:**
1. IAT build from lief (PE import table, not PLT)
2. Function start detection: MSVC/GCC prologues for x86-32 and AMD64 + FPO recovery via `E8 rel32` call-target scanning
3. Semantic sweep: 8 base + 8 `PE_WIN_PROFILES` + registry priors via `all-MiniLM-L6-v2`
4. Deterministic `_check_firmware_auth_bypass` (GAP-015 check): firmware flashers importing hidapi.dll/IAP without WinVerifyTrust/Crypt* = CWE-347 (no signature verification)
5. String context from `.rdata` section (falls back to `.data` for Borland VCL — GAP-016)

**Analyzers chained:**
- `describe_function` (ablation.analyzers)
- `FindingRegistry` (ablation.analyzers)
- `_check_firmware_auth_bypass` (inline deterministic check)

**Inputs:** Windows PE32/PE32+ (.exe, .dll, .ocx, .ax) or directory  
**Outputs:** `reports/sweep_pe_<vendor>_<product>_<version>_<ts>.md`  
**Architectures:** i386 and AMD64; ARM/ARM64 PE detected but skipped  
**Status:** Working as written; **no taint analysis** (semantic only)  
**PE_WIN_PROFILES (8):** qt_heap_atom_parse, qt_rtsp_recv_overflow, qt_registry_plugin_load, qt_path_string_overflow, win_cmd_exec, win_format_string, qt_codec_intovf, qt_com_stream_overflow  
**Key limitations:**
- **No taint tracker** — all taint trackers are ELF-only; pe_sweep is semantic similarity scoring only
- No XRefGraph (ELF-only); no SinkArgClassifier
- ARM/ARM64 PE binaries silently skipped
- Packed PE with .text file_offset=0 skipped

---

### 5. ti_sweep

**File:** `sweeps/ti_sweep.py`  
**CLI:** `python3 sweeps/ti_sweep.py <tirex_dir|zip|binary> [--no-taint] [--semantic] [--filter STR] [--product STR] [--version STR]`  
**Goal:** Four-phase sweep of Texas Instruments SDK firmware packages (TIREX archives).

**Phases:**
1. **NNC scan** (parallel ThreadPoolExecutor workers=8): `TiNNCScanner` on all COFF/AR + ELF files for neural network compiler artifacts
2. **Taint analysis** (arch-routed, parallel workers=8):
   - ARM32 Thumb: `ARM32TaintTracker.from_path(path, thumb=True)`
   - ARM64: `ARM64TaintTracker.from_path_full`
   - RISC-V 32: `RISCV32TaintTracker.from_path`
3. **C28x/ECU analysis**: `TiCoffLoader` enumerates C_UEXT weak symbols; `EcuC28xDecoder`; `EcuSecurityAccessScanner` on flat .bin for static UDS SecurityAccess seeds
4. **Crypto hash detection** (ARM32 Thumb ELFs, first 1MB): `HashAlgoDiscriminator`
5. **Optional semantic sweep** (off by default, `--semantic` flag): `BinaryContext.load_or_build` + `SemanticSearcher.from_context` (BAAI/bge-small-en-v1.5)

**Analyzers chained:**
- `TiNNCScanner` (phase 1)
- `ARM32TaintTracker`, `ARM64TaintTracker`, `RISCV32TaintTracker` (phase 2, arch-dependent)
- `TiCoffLoader`, `EcuC28xDecoder`, `EcuSecurityAccessScanner` (phase 3)
- `HashAlgoDiscriminator` (phase 4)
- `BinaryContext`, `SemanticSearcher` (phase 5, optional)

**Inputs:** TIREX directory, .zip package, or single binary  
**Outputs:** per-package `reports/sweep_ti_<pkg>_<ts>.md`; master `reports/sweep_ti_master_<ts>.md`  
**Architectures:** ARM32 Thumb, ARM64, RISC-V 32; TI C28x (symbol-table only); **MIPS, PPC not dispatched**  
**Status:** Working; semantic phase partial (disabled by default)  
**Key limitations:**
- Semantic sweep disabled by default — must pass `--semantic`
- `EcuC28xDecoder` `.text` section harvest not implemented — only C_UEXT weak symbol enumeration
- MIPS and PPC not dispatched in phase 2 taint
- Phase 3 C28x weak symbol scan limited to top 10 symbols

---

### 6. corpus_miner

**File:** `sweeps/corpus_miner.py`  
**CLI:** `python3 sweeps/corpus_miner.py [--re-dir PATH] [--min-count N] [--min-vendors N] [--json] [--out PATH]`  
**Goal:** Mine confirmed findings from all `re/*_re.py` RE modules to feed the ablation flywheel — identify coverage gaps and cross-target patterns.

**Phases:**
1. AST-parse all `*_re.py` under `~/ablation/re/`: extract `FINDINGS` dict entries with `status == 'CONFIRMED'`
2. Normalize CWE tags (explicit or inferred from title via `_TITLE_CWE_MAP`)
3. Build `CorpusEntry` list: vendor, target, CWE, title, severity
4. CWE frequency table: how many confirmed findings per CWE
5. Coverage gaps: high-frequency CWEs with no ablation scanner (`_CWE_COVERAGE[cwe] is None`)
6. Cross-target patterns: same CWE in ≥2 vendors → new module candidates

**Analyzers chained:** None (pure Python AST; no ablation.analyzers classes)  
**Inputs:** Python source files under `re/` directory  
**Outputs:** Text or JSON report: severity distribution, vendor breakdown, CWE frequency, coverage gaps (17 CWEs with no scanner), cross-target patterns  
**Status:** Working as written  
**Known gap CWEs (17):** CWE-416 (UAF), CWE-321 (hardcoded key), CWE-798 (hardcoded creds), CWE-295 (cert bypass), CWE-287 (auth bypass), CWE-319 (cleartext creds), CWE-328 (weak hash), CWE-347 (sig verify), CWE-610 (externally controlled ref), CWE-494 (download no integrity), CWE-426 (untrusted search path), CWE-611 (XXE), CWE-918 (SSRF), CWE-200 (info disclosure), CWE-362 (race), CWE-476 (NULL deref), CWE-908 (uninitialized mem)  
**Key limitations:**
- Requires confirmed findings in `re/` — empty `re/` produces no output
- Does not call FindingRegistry (parallel store — no bridge to sweep-registered findings)
- CWE inference from title is pattern-matched, may miss novel titles

---

### 7. report_generator

**File:** `sweeps/report_generator.py`  
**Entry point:** Library module — `from sweeps.report_generator import generate_report`  
**Goal:** Produce structured markdown reports from sweep results.

**Function:** `generate_report(results, binary_path, vendor, product, version, registry_hits, xref, taint_findings, taint_chains, top_k, min_score, output_path)` → markdown string

**Sections generated:**
1. Summary table (binary path, arch, function count, profile counts)
2. Top candidates across all profiles (score ≥ `min_score`)
3. Per-profile sections: VA / score / calls / strings / callers / registry correlations
4. Registry correlation summary table
5. Manual verification checklist (top 15 candidates)
6. Static taint analysis findings table
7. Interprocedural taint chains table

**Inputs:** Results dict + optional XRefGraph, registry_hits, taint_findings, taint_chains  
**Outputs:** Markdown string; writes to `output_path` if provided  
**Status:** Working as written  
**Key limitations:**
- `min_score` default 0.70 is higher than fortinet_sweep.py report threshold of 0.30 — callers must override
- Taint findings interface assumes specific attribute names on finding objects (tf.tainted_args, tf.source_calls, etc.)

---

### 8. win16_le_vxd_sweep

**File:** `sweeps/win16_le_vxd_sweep.py`  
**CLI:** `python3 sweeps/win16_le_vxd_sweep.py <target|dir> --vendor STR --product STR --version STR [--top-k N] [--threshold FLOAT] [--out-dir PATH]`  
**Goal:** Semantic vulnerability sweep of Windows 3.x LE VxD ring-0 driver binaries.

**Phases:**
1. LE header parse: pure Python `LEBinary` class; parses header, object page table, assembles flat code bytes
2. VxD DDB detection: names entry-point functions from Device Descriptor Block
3. INT 20h VMM service resolution: resolves `INT 20h + DWORD` service IDs from 100+ entry `_VMM_SERVICES` table (VMM, VPICD, VTDI)
4. Semantic sweep: 8 base + 8 `WIN16_NE_PROFILES` + 5 `VXD_LE_PROFILES` via `all-MiniLM-L6-v2`

**VXD_LE_PROFILES (5):** ring-0 heap overflow, NetBIOS name overflow, heap alloc integer overflow, TOCTOU on V86 parameter, ring-0 format string  
**Inputs:** Windows 3.x LE VxD (.386, .vxd, .drv, .sys) or directory  
**Outputs:** `reports/sweep_le_<vendor>_<product>_<version>_<ts>.md`  
**Architectures:** x86-32 (ring-0 VxD); no taint tracker  
**Status:** Working as written  
**Key limitations:**
- No taint tracker for ring-0 VxD
- `_VMM_SERVICES` covers only VMM/VPICD/VTDI (other device IDs return generic labels)
- max_bytes=512 per function (smaller than base_sweep=2048)

---

### 9. win16_mz_dos_sweep

**File:** `sweeps/win16_mz_dos_sweep.py`  
**CLI:** `python3 sweeps/win16_mz_dos_sweep.py <paths...> [--threshold FLOAT] [--vendor STR] [--product STR] [--version STR]`  
**Goal:** Security sweep for 16-bit real-mode MS-DOS MZ executables. Fills GAP-G.

**Note:** **The only sweep with no sentence-transformers dependency.** Uses rule-based heuristic scoring, not BERT embeddings.

**Phases:**
1. MZ parse: pure Python `MZBinary` class; parses header, relocation table, assembles code bytes
2. Function recovery: entry point + `E8 rel16` NEAR CALL targets + prologue scan (`push bp; mov bp,sp`)
3. Capstone CS_MODE_16 disassembly per function
4. Heuristic scoring against 3 DOS-specific profiles (not BERT):
   - `dos_unbounded_copy` — rep movs without CX bounds check (score 0.55 flat)
   - `dos_int21_recv_path` — INT 21h AH loaded from memory
   - `dos_fixed_stack_alloc` — `sub sp, N` where N > 0x100

**Analyzers chained:** capstone only (no ablation.analyzers classes)  
**Inputs:** Real-mode MZ executables (one or more positional paths)  
**Outputs:** stdout + `reports/sweep_mz_<vendor>_<product>_<version>_<ts>.md`  
**Architectures:** x86-16 real mode only  
**Status:** Working as written  
**Key limitations:**
- No BERT semantic sweep — heuristic scoring only
- No FindingRegistry integration (findings do not feed the flywheel)
- No string xref context
- `E8 rel16` target wraps at 0xFFFF (segment boundary edge case)

---

### 10. win16_ne_sweep

**File:** `sweeps/win16_ne_sweep.py`  
**CLI:** `python3 sweeps/win16_ne_sweep.py <target.exe|.dll|.qtc|.x16> --vendor STR --product STR --version STR [--top-k N] [--threshold FLOAT]`  
**Goal:** Semantic sweep of Win16 NE (New Executable) binaries with ordinal-resolved API imports.

**Phases:**
1. NE parse: pure Python `NEBinary`; segment table, module reference, relocation records
2. Win16 API ordinal resolution: 4 lookup tables (KERNEL 202 entries, USER 315 entries, GDI 122 entries, SHELL 20 entries)
3. Capstone CS_MODE_16 disassembly
4. Semantic sweep: 8 base + 8 `WIN16_NE_PROFILES` via `all-MiniLM-L6-v2`

**WIN16_NE_PROFILES (8):** lstrcpy overflow, GlobalAlloc overflow, GetDlgItemText overflow, OpenFile path overflow, WinExec injection, WriteProfileString injection, wsprintf format string, resource overflow  
**Inputs:** Win16 NE binary (.exe, .dll, .qtc, .x16)  
**Outputs:** `reports/sweep_ne_<vendor>_<product>_<version>_<ts>.md`  
**Architectures:** x86-16; no taint tracker  
**Status:** Working as written (single-binary mode only — no directory scan)  
**Key limitations:**
- Single-binary only (win16_le_vxd_sweep handles directory scan for NE)
- No taint tracker; no string ref extraction from DS in 16-bit mode
- max_bytes=512 per function
- FAR CALL (0x9A) resolution uses reloc map lookup with ambiguous offset arithmetic

---

## Part 2: Workflow Guides

### WF-1: Fortinet Firmware Analysis

**File:** `docs/workflows/fortinet-firmware.md`  
**Goal:** Decrypt FortiOS firmware through XOR + RC4 encryption layers, detect shared key material, run semantic sweep.

**Steps:**
1. Outer XOR: `FortiOSHardwareExtractor.from_path()` → `recover_xor_key()` → `extract_to()`
2. RC4 inner: `FirmwareContainerKeyExtractor.from_path()`
3. Key scanner: `FortiGateCertKeyScanner.from_path()` / `.from_disk()` / `.batch_scan()`
4. Version prediction: `FortiBuildTrackClassifier.from_filename()`
5. Sweep: `python sweeps/fortinet_sweep.py ./httpsd`
6. Sink classification: `SinkArgClassifier`
7. Virtual dispatch: `CppVtableReconstructorAnalyzer`

**Inputs:** FortiOS .out firmware, OVF ZIP, QCOW2, VHD/VHDX, VMDK, stripped ELF  
**Status:** Up-to-date  
**Known gap:** `CppVtableReconstructorAnalyzer` name does not match any single module — backing classes are vtable_resolver + vtable_dispatch_scanner (name mismatch in workflow doc)

---

### WF-2: Vulnerability Hunting

**File:** `docs/workflows/vuln-hunting.md`  
**Goal:** From stripped binary to confirmed disclosure-ready finding in 30-90 minutes.

**Steps:** BinaryContext → SemanticSearcher.query + PatternLibrary.sweep → FuncProfiler triage → TaintTracker → ctx.set_name + FindingRegistry.add_finding + PatternLibrary.record_hit

**Status:** Potentially stale — `TaintTracker.trace(func_va, source_va, source_reg, sink_patterns)` API shown in workflow does not match `tracker.run()` / `tracker.run_interprocedural()` used in base_sweep.py. `FindingRegistry.add_finding()` method differs from `FindingRegistry.register()` in base_sweep.py. API method name discrepancies need reconciliation.

---

### WF-3: Go Binary RE

**File:** `docs/workflows/go-binaries.md`  
**Goal:** Recover function names from Go pclntab, enable semantic search on stripped Go binaries.

**Steps:** GoFuncTable.from_binary → ctx.set_name → CorpusBuilder.build → SemanticSearcher → GoSubprocessScanner.scan; for garble-obfuscated: GoGarbleRe.find_entry_point + GoStringResolver.resolve

**Status:** Potentially stale — `GoGarbleRe` imported as `from modules.go_garble_re` (legacy path, not `from ablation.analyzers.go_garble_re`). Classes exist but import path may not resolve under current package layout.

---

### WF-4: Cross-Version Diffing

**File:** `docs/workflows/cross-version.md`  
**Goal:** Track a vulnerable function across firmware patch releases, verify patch, detect regressions.

**Steps:** BinaryContext → VersionDelta.track(func_va) → result.patch_diff → MatrixProfileDiff.compare_functions → VersionDelta.changed_functions(top_n=50) → StructuralSim (cross-vendor)

**Status:** Potentially stale — `StructuralSim` imported as `from modules.structural_sim` (legacy path); `VersionDelta.changed_functions()` and `VersionDelta.track()` method names not verified against module source.

---

### WF-5: Crypto Analysis

**File:** `docs/workflows/crypto.md`  
**Goal:** Encrypted firmware extraction, key material detection, JWT cracking, TLS posture.

**Steps:** EntropyMapper.classify_file → XorSolver.solve → CryptoAudit.scan_binary_keys → CryptoAudit.crack_jwt → CryptoAudit.check_tls

**Status:** Potentially stale — `CryptoAudit` imported as `from modules.crypto_audit` (legacy path); `CryptoAudit` not found in any unit_files entry from Phase 1 notes — may be an older or external module. `EntropyMapper` and `XorSolver` are confirmed in A01 and A14 unit_files.

---

### WF-6: KASAN-Oracle

**File:** `docs/workflows/kasan-oracle.md`  
**Goal:** Use KASAN debug kernel build to identify candidates, verify in stripped production build (LoongArch64).

**Steps:** LoongArchDecoderV2 suppresses KASAN ghost calls → LA64MaxNotMinScanner on debug build → verify candidates in production

**Status:** Potentially stale — workflow imports `ablation.analyzers.loongarch_decoder_v2` but unit_files has `loongarch_decoder` (no `_v2` suffix). `LA64MaxNotMinScanner` and `LoongArch64TaintTracker` confirmed. Workflow originated from TencentOS 6.6.119 analysis (14 hits → 11 confirmed post-KASAN).

---

### WF-7: Source Code Audit

**File:** `docs/workflows/source-code-audit.md`  
**Goal:** Go from git repository to disclosure-ready findings with 98%+ file read compression.

**Steps:** SourceContext.from_path → SourceEntryClassifier.classify → SourceSinkScanner.scan → SourceAuditCompressor.compress → priority-bucket reads → log to re/*_re.py FINDINGS dict

**Status:** Up-to-date — all five source analyzers confirmed in A06 unit_files. Worked example (2861-file Python/Django + TypeScript/Lit repo, 98.4% compression) is concrete.

---

## Cross-cutting notes

### BERT model consistency
All semantic sweeps (base, fortinet, pe, win16_ne, win16_le_vxd) use `sentence-transformers/all-MiniLM-L6-v2`. `win16_mz_dos_sweep.py` is the sole exception (heuristic scoring). The ti_sweep optional semantic phase uses `SemanticSearcher.from_context` which loads `BAAI/bge-small-en-v1.5` (fastembed) — **different model from the other sweeps**.

### Profile inheritance chain
- base: 8 profiles
- fortinet: 8 base + 8 FORTIOS = 16 (+ registry priors)
- pe: 8 base + 8 PE_WIN = 16
- win16_ne: 8 base + 8 WIN16_NE = 16
- win16_le_vxd: 8 base + 8 WIN16_NE + 5 VXD_LE = 21
- win16_mz_dos: 3 heuristic profiles (no BERT)
- ti_sweep: TI_VULN_PROFILES + arch-routed taint (no base VULN_PROFILES directly)

### Taint tracker coverage by sweep
| Sweep | x86-64 | ARM32 | ARM64 | PPC32 | PPC64 | MIPS | RISC-V | LoongArch |
|-------|--------|-------|-------|-------|-------|------|--------|-----------|
| base_sweep | Full inter | — | — | — | — | — | — | — |
| fortinet_sweep | Full inter | Intra | Intra | Inter | Inter | **Skipped** | — | — |
| ti_sweep | — | Thumb inter | Inter | — | — | — | RV32 inter | — |
| pe_sweep | — | — | — | — | — | — | — | — |
| win16_* | — | — | — | — | — | — | — | — |
| android_sweep | — | — | — | — | — | — | — | — |

### Legacy `modules.*` import paths in workflow docs
`go-binaries.md`, `cross-version.md`, and `crypto.md` all use `from modules.X` — a path that does not appear in the ablation package layout (`ablation.analyzers.X` is current). These may not resolve under current package installation. Classes exist but import paths need verification.

### Flywheel gap: corpus_miner vs FindingRegistry
`corpus_miner.py` reads `re/*_re.py` via AST and tracks confirmed findings per vendor/CWE. `FindingRegistry` stores sweep-registered findings with embeddings. These are parallel, non-bridged stores. No automated sync exists between human-written RE modules and the sweep-registered finding database.
