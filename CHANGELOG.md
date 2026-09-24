# Changelog

---

## v2.5.0

- **FormatStringScanner** (`format_string_scanner.py`) -- x86-64 format string
  vulnerability detector. TAOSSA Ch8-grounded. 28 format sinks: printf/fprintf/
  sprintf/snprintf/syslog/err/warn/wprintf family. Backward trace per call site:
  LEA [rip+offset] into .rodata = SAFE; register from function arg / stack slot /
  recv return = VULNERABLE. `verdict` property returns SAFE / VULNERABLE / SUSPICIOUS.
  CLI: `ablation fmtstr <binary> [--json FILE]`.

- **IoctlAttackSurfaceGenerator** (`ioctl_attack_surface.py`) -- per-IOCTL attack
  surface report for Windows kernel drivers. Wraps KernelDriverAnalyzer output. For
  each IoControlCode: METHOD_NEITHER without ProbeForRead = CRITICAL; allocation
  before InputBufferLength read = HIGH; TYPE3_INPUT_BUFFER direct deref = HIGH.
  Generates Markdown report via `report_markdown()`. CLI: `ablation ioctl-surface`.

- **CrossBinaryTaintTracker** (`cross_binary_taint.py`) -- LibGraph-backed cross-library
  taint BFS. Extends TaintTracker.run_interprocedural() to follow tainted arguments
  through PLT entries into exporting shared libraries. Resolves PLT symbol to exporting
  binary via LibGraph.defined_in(), spawns a seeded TaintTracker on that binary, and
  continues BFS. Returns TaintChain with full cross-binary hop provenance.

- **ByovdDetector / BYOVDDetector** (`byovd_detector.py`) -- BYOVD capability detector.
  12 capability classes: PHYS_MEM_RW (MmMapIoSpace), TOKEN_STEAL (PsInitialSystemProcess),
  DKOM (ObReferenceObjectByHandle), APC_INJECT (KeInitializeApc), DRIVER_LOAD,
  CALLBACK_REMOVE, PROCESS_KILL, MSR_WRITE (WRMSR instruction scan), and more.
  Known-driver PDB fingerprints (mhyprot, RTCore64, dbutil, PROCEXP, iqvw64e, cpuz).
  CLI: `ablation byovd <driver.sys>`.

- **MIPS32FuncProfiler** (`mips_analyzer.py`) -- quick MIPS32 function profiler.
  Complements MIPS32TaintTracker (taint_tracker_mips.py): single-call function
  profile returning call sites + sink flags for MIPS32 binaries. Uses `MIPS32TaintTracker`
  as backend; adds big-endian + little-endian O32 ABI support.

- **HeapUAFScanner** (`heap_uaf_scanner.py`) -- forward register-state UAF/double-free
  scanner. Complements HeapVulnScanner: simpler single-pass approach tracking ALLOC /
  FREE / UNKNOWN state per register. Compatible with both SysV and Windows x64 ABI
  (`windows_abi=True` flag uses RCX as free arg instead of RDI).

---

## v2.4.0

- **MIPS32TaintTracker** (`taint_tracker_mips.py`) -- MIPS32 source-to-sink taint
  analysis for embedded firmware (RouterOS, Broadcom CPE, MIPS-based routers).
  O32 ABI register model: $a0-$a3 args, $v0 return, $t0-$t9 caller-saved, $s0-$s7
  callee-saved. Sources: recv/recvfrom/read/fgets/gets/fread. Sinks:
  system/execve/execl/execvp/popen/strcpy/sprintf/memcpy/strcat/snprintf. Load-delay
  slot aware. Big-endian and little-endian support. Intraprocedural + interprocedural
  BFS up to depth 4. CLI: `ablation mips <binary> [--le]`.

- **HeapVulnScanner** (`heap_vuln_scanner.py`) -- four heap memory corruption classes
  for x86-64 ELF. Grounded in TAOSSA Ch5 (Memory Corruption) and Ch6 (C Language
  Issues): `INT_OVERFLOW_BEFORE_ALLOC` (IMUL/MUL/SHL result fed to allocator without
  overflow check, L6-2/L6-3 patterns); `USE_AFTER_FREE` (freed register dereferenced
  in same function); `DOUBLE_FREE` (same register freed twice without reassignment);
  `OFF_BY_ONE_ALLOC` (strlen result to malloc without +1). CLI: `ablation heap <binary>`.

---

## v2.3.0

- **BYOVDDetector** -- BYOVD (Bring Your Own Vulnerable Driver) risk assessment.
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

- **KernelDriverAnalyzer** -- first Windows `.sys` kernel driver RE module. Covers IRP/IOCTL
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

- **NameRegistry** -- persistent VA-to-name overlay at `~/.ablation/function_names.json`,
  keyed by binary SHA256. Names auto-load in all sessions and appear in every callee, caller,
  and display context.
- **FindingRegistry** -- cross-target confirmed finding store at `~/.ablation/findings.db`.
  BERT embeddings attached to findings seed future sweeps automatically.
- **PatternLibrary** -- self-improving pattern corpus. Every confirmed finding registers a
  semantic query that replays on future binaries via `pl.sweep(searcher)`.
- **BinaryContext: discovered-name overlay** -- `ctx.name(va)` returns the overlay name when
  set, cascading through export, PLT, and hex. `ctx.set_name()`, `ctx.names_table()`,
  `ctx.names_map()`.
- **Vectorized call graph** -- `_build_call_graph` replaced with NumPy `0xe8` opcode scan.
  One broadcast operation extracts all CALL rel32 displacements and resolves all targets.
  Sequential capstone retained as fallback.
- **fortinet_sweep.py rewrite** -- modernized to use current ablation.analyzers API; removed
  manual ELF parsing and hardcoded session paths.
- **modules/ migration** -- 611 vendor-specific RE modules moved from flat `modules/` to
  `targets/<vendor>/` directories. `modules/` now contains only general-purpose utilities.
- **MCP server removed** -- dead code; all functionality available directly via the Python API.
- **Document library** -- full external-facing docs: getting started, workflow guides, module
  reference, target notes, pitch document.

---

## v1.7.0

- **LlmAnalyst** -- ReAct agent loop (Claude Sonnet 5) for automated function naming and
  vulnerability hypothesis generation. `AgentLoop`, `ToolRegistry`, `ContextBuilder`,
  `RAGRetriever`.
- **TaintTracker (x86-64)** -- static intraprocedural taint analysis. libdft taint policy
  adapted for static analysis. Full stack model (rbp-relative and rsp-relative slots).
- **PathSolver** -- constraint-based path feasibility. Eliminates TaintTracker false positives
  where the tainted path is unreachable due to contradictory branch constraints.
- **FuncProfiler** -- lightweight triage: BB count, edge count, PLT calls, branch density
  classification without full disassembly.

---

## v1.6.0

- **VtableResolver** -- ARM64 C++ vtable reconstruction and BLR indirect call resolution.
  Four-phase: vtable extraction, constructor vptr detection, BLR site detection, resolution.
  Primary target: WeChat `libwechatnetwork.so` gILinkKey dispatch.
- **VersionDelta** -- cross-version function tracking. Three-stage pipeline: structural
  pre-filter, mnemonic 4-gram Jaccard, BERT tiebreaker. Patch localization via
  `difflib.SequenceMatcher`. Anchor scan for implementation variant classification (validated
  against multiple binary versions).
- **StructuralSim** -- five-signal composite similarity (opcode histogram, immediate Jaccard,
  PLT overlap, branch density, size proximity). Works on all functions, not just the ~12%
  with two or more external PLT calls.
- **MatrixProfileDiff** -- STOMP-based sequence anomaly detection for binary diffing.

---

## v1.5.0

- **SemanticSearcher** -- BERT behavioral fingerprint search over all functions in a binary.
  ~35s for 19,000 functions on CPU. Queries in plain English. Results cached.
- **CorpusBuilder** -- builds `func_id.db` behavioral description database for BERT encoding.
  Per-function: PLT calls, strings, exported name, call-graph neighbors, size.
- **EntropyMapper** -- sliding-window Shannon entropy scan. Classifies binary regions as
  ENCRYPTED, CODE, SPARSE, or PADDING. Finds encrypted and plaintext transitions.
- **XorSolver** -- three-mode automated XOR decryption: KPA (known plaintext), Hamming
  distance key length guesser, frequency analysis and transposition.
- **CryptoAudit** -- JWT weak-secret cracking (ordered by production frequency), hardcoded
  key material scan, TLS posture assessment.

---

## v1.4.0

- **XRefGraph** -- full cross-reference graph with indirect call resolution.
- **CFGBuilder** -- per-function control flow graph via iterative recursive disassembly
  (Andriesse PBA ch. 8.2.4). BasicBlock: start, end, succs, insns.
- **BinaryContext: RIP-relative xref index** -- NumPy vectorized displacement scan in
  `_build_string_xref_index`. One O(N) pass over `.text` builds `_str_xref_idx`
  (string_va -> [code_vas]) and `_func_str_idx` (func_va -> [string_vas]).
- **`ctx.strings_in_func(va)`**, **`ctx.string_xrefs(va)`**, **`ctx.funcs_referencing_string(va)`**.

---

## v1.3.0

- **Installable package** -- `ablation.analyzers.*` package structure. `pip install -e .`.
  Shims in `modules/` preserve backward compatibility.
- **BinaryContext** -- SHA256-keyed JSON cache at `~/.ablation/cache/`. Build once (0.5s),
  reload in 110ms. Captures PLT, exports, strings, func_starts, call_edges.
- **GoFuncTable (GoPclntab)** -- pclntab parser. Go 1.12 - 1.20+. All architectures.
  Lifts semantic search accuracy from ~0.20 to ~0.70+ on stripped Go binaries.
- **GoGarbleRe** -- garble-obfuscated Go binary RE. Runtime bootstrap tracing, HTTP handler
  pattern detection, VA and file-offset mapping recovery.
- **GoStringResolver** -- reconstructs Go string constants from `concatstrings` call sites.
- **GoSubprocessScanner** -- finds all `os/exec.Command`, `syscall.Exec`, SYS_EXECVE sites.
- **GoDangerousCallers** -- Go-specific dangerous caller sweep.
