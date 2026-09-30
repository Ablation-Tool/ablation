# Changelog

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
