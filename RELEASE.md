# Ablation Release Notes

## v2.5.0 (2026-09-25)

### FormatStringScanner: fortify variant coverage (`ablation fmtstr`)

Added glibc fortify variants: `__printf_chk`, `__fprintf_chk`, `__snprintf_chk`, `__sprintf_chk`, `__vprintf_chk`, `__vfprintf_chk`, `__vsprintf_chk`, `__vsnprintf_chk`. Full sink list is now 28 entries.

### New: IoctlAttackSurfaceGenerator (`ablation ioctl-surface`)

Per-IOCTL attack surface report for Windows kernel drivers. For each IoControlCode: METHOD_NEITHER without ProbeForRead = CRITICAL; allocation before InputBufferLength validation = HIGH; TYPE3_INPUT_BUFFER direct dereference = HIGH. Markdown report via `report_markdown()`.

```bash
ablation ioctl-surface driver.sys
ablation ioctl-surface driver.sys --json report.json
```

### New: CrossBinaryTaintTracker

LibGraph-backed cross-library taint BFS. Follows tainted arguments through PLT entries into exporting shared libraries. Resolves PLT symbol to exporting binary via `LibGraph.defined_in()`, spawns a seeded TaintTracker on that binary, and continues BFS. Returns `TaintChain` with full cross-binary hop provenance.

```python
from ablation.analyzers.cross_binary_taint import CrossBinaryTaintTracker

tracker = CrossBinaryTaintTracker.from_lib_graph(lg)
paths = tracker.run()
```

### BYOVDDetector: expanded to 12 capability classes + PDB fingerprints

Added: DKOM (ObReferenceObjectByHandle), APC_INJECT (KeInitializeApc), DRIVER_LOAD, CALLBACK_REMOVE, PROCESS_KILL, MSR_WRITE (WRMSR instruction scan). Known-driver PDB fingerprint table: mhyprot, RTCore64, dbutil, PROCEXP, iqvw64e, cpuz.

---

## v2.4.0 (2026-09-24)

### New: Heap Vulnerability Scanner (`ablation heap`)

`HeapVulnScanner` (`heap_vuln_scanner.py`) detects four heap memory corruption classes for x86-64 ELF binaries. Grounded in TAOSSA Ch5 (Memory Corruption) and Ch6 (C Language Issues).

**INT_OVERFLOW_BEFORE_ALLOC** (TAOSSA Ch6 L6-2, L6-3): IMUL/MUL/SHL result fed directly to malloc/calloc/ExAllocatePool without an intermediate overflow check or bounds test. Matches the `width * height` pattern from L6-2 and the `nresp * sizeof(char*)` pattern from the OpenSSH 3.1 challenge-response vulnerability (L6-3).

**USE_AFTER_FREE**: `free(ptr)` followed by memory dereference of the same source register in the same function, without an intervening write. Detects both `[reg+off]` loads and re-use as a callee argument.

**DOUBLE_FREE**: the same source register freed twice without reassignment between the two `free()` calls. Matches the strcpy-overflow-then-free pointer corruption pattern from TAOSSA Ch5.

**OFF_BY_ONE_ALLOC**: `strlen(s)` result fed to `malloc` without adding 1 for the NUL terminator. Classic NUL-off-by-one heap overflow.

```bash
ablation heap  firmware.so
ablation heap  firmware.so --json heap_findings.json
```

```python
from ablation.analyzers.heap_vuln_scanner import HeapVulnScanner
scanner = HeapVulnScanner.from_context(ctx)
findings = scanner.scan()
print(scanner.report(findings))
```

### New: MIPS32 Taint Tracker (`ablation mips`)

`MIPS32TaintTracker` (`taint_tracker_mips.py`) tracks network-to-sink taint in MIPS32 ELF firmware. Targets RouterOS, Broadcom CPE, and embedded routers.

- **ABI**: O32 register model. `$a0-$a3` args, `$v0` return, `$t0-$t9` caller-saved, `$s0-$s7` callee-saved.
- **Load-delay slot**: branch delay slot handled correctly; the instruction after a branch executes before the branch takes effect.
- **Endian**: big-endian (default, RouterOS/Broadcom) and little-endian (`--le`) support.
- **Sources**: recv, recvfrom, read, fgets, gets, fread.
- **Sinks**: system, execve, execl, execvp, popen, strcpy, sprintf, memcpy, strcat, snprintf.
- **Modes**: intraprocedural + interprocedural BFS up to depth 4.

```bash
ablation mips  router.elf
ablation mips  router.elf --le --json mips_findings.json
```

### New: BYOVD Detector (`ablation byovd`)

`BYOVDDetector` (`byovd_detector.py`) scores Windows kernel drivers for Bring Your Own Vulnerable Driver primitives. Wraps `KernelDriverAnalyzer` with BYOVD-specific scoring (0-100). Grounded in PRE Ch3 IOCTL walk-throughs and Rootkits: Subverting the Windows Kernel.

Eight scored attack paths:
- **PHYS_MEM_ARBITRARY_RW**: `MmMapIoSpace` with user-controlled physical address (MmMapIoSpace primitive from PRE ch3 Sample A)
- **MDL_KERNEL_WRITE**: `IoAllocateMdl` + `MmProbeAndLockPages` + `MmMapLockedPagesSpecifyCache` kernel write chain
- **MSR_LSTAR_MANIPULATION**: RDMSR/WRMSR targeting `0xC0000082` (syscall handler replacement)
- **SSDT_HOOK**: CR0 WP-disable sequence + `KeServiceDescriptorTable` (UTF-16LE scan)
- **TOKEN_STEALING_LPE**: `PsInitialSystemProcess` + DKOM token field manipulation
- **SMEP_BYPASS**: CR4 combined sequence disabling SMEP
- **APC_KERNEL_INJECTION**: `KeInitializeApc` + `KeInsertQueueApc`
- **VIRTUAL_MEM_WRITE**: `ZwWriteVirtualMemory` called from IOCTL handler

Verdict: BYOVD_CONFIRMED when a signed driver has a METHOD_NEITHER IOCTL and any attack path.

```bash
ablation byovd driver.sys
ablation byovd driver.sys --json byovd_report.json
```

### New: Format String Scanner (`ablation fmtstr`)

`FormatStringScanner` (`format_string_scanner.py`) finds printf-family calls where the format argument is not a string literal. Grounded in TAOSSA Ch8.

- 28 sinks: printf/vprintf, fprintf/vfprintf, sprintf/vsprintf, snprintf/vsnprintf, asprintf, dprintf, syslog/vsyslog, err/errx/warn/warnx + glibc fortify variants (`__printf_chk`, `__fprintf_chk`, `__snprintf_chk`, etc.)
- Backward trace from each call site classifies the format register: `LEA [rip+offset]` into `.rodata` = SAFE; `MOV` from stack slot = SUSPICIOUS; `MOV` from entry argument register = VULNERABLE
- Verdicts: VULNERABLE / SUSPICIOUS / SAFE

```bash
ablation fmtstr firmware.so
ablation fmtstr firmware.so --json fmt_findings.json
```

---

## v2.0.0 (2026-09-24)

### New: Windows Kernel Driver RE (`ablation driver`)

First Windows `.sys` kernel driver support. New CLI command: `ablation driver <file.sys>`.

**KernelDriverAnalyzer** (`ablation/analyzers/kernel_driver_analyzer.py`)

Standalone `decode_ioctl_code(value)`: decodes any CTL_CODE into DeviceType, Access, Function, Method; flags METHOD_NEITHER (raw user pointer, highest attack surface) explicitly.

`KernelDriverAnalyzer.from_path(path).analyze()` returns a `KernelDriverReport` covering:

- **Driver type detection**: WDM, KMDF, or minifilter by import profile. PDB path (RSDS + NB10 debug formats). Authenticode signature presence.
- **MajorFunction extraction**: capstone disassembly of DriverEntry recovers all 28 IRP dispatch slot assignments from `DRIVER_OBJECT+0x70`.
- **IOCTL extraction**: scans executable sections for CTL_CODE immediates in CMP/MOV instructions. Reports device type, transfer method, user-defined vs system-reserved function range.
- **Kernel API audit**: 40+ APIs across 12 risk classes: `phys_mem`, `pool_alloc`, `dkom`, `apc_inject`, `privilege` (token stealing via PsInitialSystemProcess), `ssdt_hook`, `mem_copy`, `driver_load`, and more.
- **Callback detection**: 20+ callbacks tagged edr_like, rootkit_risk, or info. ObRegisterCallbacks + PsSetCreateProcessNotifyRoutineEx (blocking) + KeRegisterBugCheckReasonCallback = rootkit signal.
- **Pool tag extraction**: byte scan for `41 B8` (MOV R8D) extracts 4-byte printable pool tags for ExAllocatePoolWithTag calls.
- **Dangerous patterns**: SSDT hook CR0 WP-disable combined sequence, SMEP-disable CR4 combined sequence, MSR_LSTAR targeted read (KASLR defeat) and write (syscall hijack), UTF-16LE `L"KeServiceDescriptorTable"` scan (x64 SSDT lookup via MmGetSystemRoutineAddress), RDMSR/WRMSR, CLI/STI/HLT, SWAPGS, IRETQ, I/O ports, VMware backdoor, deprecated pool allocators.

```bash
ablation driver malware.sys
ablation driver malware.sys --json report.json
ablation news
```

```python
from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer, decode_ioctl_code

report = KernelDriverAnalyzer.from_path('driver.sys').analyze()
print(report.fmt())

ic = decode_ioctl_code(0x222003)
print(ic.fmt())
# 0x00222003  DevType=0x0022 [user-defined]  Func=0x800  METHOD_NEITHER *** NEITHER
```

---

## v1.8.0 (2026-09-21)

### New: Time Series Analysis Modules (5 modules)

Adds a complete time series analysis layer on top of the existing RE toolkit. Encodes function disassembly as integer sequences over 12 opcode categories (BinFuse taxonomy), then applies classical time series algorithms for patch diffing, homolog matching, corpus indexing, and behavioral pattern search.

**OpSeqEncoder** (`ablation/analyzers/opseq.py`): shared encoding base. Maps any function VA to `List[int]` of category codes. `seq_to_str()` for compact visual, `seq_histogram()` for distribution analysis.

**MatrixProfileDiff** (`ablation/analyzers/matrix_profile_diff.py`): instruction-level patch diff via Matrix Profile AB-join. Pinpoints changed instruction regions between two function versions. STUMPY-accelerated when available; numpy fallback for function-length sequences.

**DTWMatcher** (`ablation/analyzers/dtw_matcher.py`): cross-version homolog matching via DTW with Sakoe-Chiba band (20% of max length). Semantic affinity cost matrix (ARITHMETIC/LOGIC cost 0.3 vs default 1.0). Verdict thresholds: same_era >=0.85, patched 0.45-0.85, rewritten 0.20-0.45.

**SAXIndex** (`ablation/analyzers/sax_index.py`): fast approximate corpus index via SAX encoding. Gaussian breakpoints, categorical PAA, MINDIST lower bound for index pruning. Save/load via pickle for persistent indexes.

**SubsequenceSearcher** (`ablation/analyzers/subsequence_searcher.py`): behavioral pattern search. Exact match with wildcards, DTW sliding window approximate match, and `search_like()` for behavioral clone detection. `common_patterns()` reveals structurally common n-grams (tells you what NOT to use as discriminators).

```python
# Cross-version: find stress handler homolog in v2 binary
matcher = DTWMatcher.from_paths(v1_lib, v2_lib)
matches = matcher.find_homologs(0x1000, ctx_v2=ctx_v2)

# Behavioral clone detection
ss = SubsequenceSearcher.from_path(lib, ctx=ctx)
clones = ss.search_like(ref_va=0x1000, end_va=0x1200, top_k=10)

# SAX corpus index across all firmware libraries
idx = SAXIndex()
for lib in fw_libs:
    idx.add_binary(lib)
idx.save('firmware_sax.pkl')
```

Note: use `discord_threshold=0.5` for MatrixProfileDiff on categorical sequences (default 1.5 is calibrated for continuous time series).

---

## v1.7.0 (2026-09-21)

### New: FuncProfiler

`ablation/analyzers/func_profiler.py`: complete function analysis block in one call.

Replaces the 4-call manual sequence (callees_of, dump_text, annotate_calls, string lookup)
with a single `fp.profile(va, end_va)` call returning a `FuncProfile` with all data combined.

```python
fp = FuncProfiler.from_path('/path/to/binary')
fp = FuncProfiler.from_path(binary, custom_sinks={'exec_handler': 'cmd-exec'})
print(fp.profile(va=0x1000, end_va=0x1200).fmt())
```

Output:
```
[libplugin.so] [FUNC 0x1000..0x1200]  357B  11 calls  5 strings  3 SINKS

  STRINGS:
    0x1d5099  '/var/private/test-path'
    0x1d512c  'help'
    0x1d5131  '--output-path'
    0x1d513d  '--output-path must be %s'
    0x1d5155  '/bin/target-binary'

  CALLS:
  0x1050  strcmp(rdi='help', rsi=[arg1_entry+0x0])
  0x1090  strcmp(rsi='--output-path')
  0x1100  exec_handler(rdi='/bin/target-binary', rsi=arg0_entry, rdx=arg1_entry)  *** SINK (cmd-exec) ***
  0x1180  exec_handler(rdi='/bin/target-binary', rsi=arg0_entry, rdx=arg1_entry)  *** SINK (cmd-exec) ***
```

Sink detection: default `_DEFAULT_SINKS` covers strcpy/strcat/sprintf/vsprintf/system/popen/execv*/Tcl_Eval
variants + exec_handler. `custom_sinks` adds target-specific entries. `FuncProfile.sink_calls` returns
only the sink-hitting calls.

### New: PatternLibrary

`ablation/analyzers/pattern_library.py`: persistent registry of successful semantic search patterns.

Stores query strings at `~/.ablation/patterns.json` with confirmed hit tracking per binary.
Pre-seeded with 12 default patterns covering buffer-overflow, cmd-exec, tcl-inject, path-traversal,
heap-overflow, timing-side-channel, and cmd-inject classes.

```python
pl = PatternLibrary()
print(pl.list())          # table: tag, confirmed hits, total hits, query

# Run all patterns against a SemanticSearcher (corpus already built):
results = pl.sweep(searcher, top_k=5, min_score=0.3)
print(pl.fmt_sweep(results, binary_name='libdata.so'))

# Record a confirmed finding:
pl.record_hit('strcpy with user-controlled src', binary='libdata.so', va=0x5000, confirmed=True)
pl.save()

# Add target-specific pattern:
pl.add('CLI handler passes argv directly to exec_handler without sanitization', tag='cmd-exec')
```

Pattern registry accumulates over time; hit rates guide which patterns to run first on new binaries.

### New: IPRegAnnotator

`ablation/analyzers/ipreg_annotator.py`: interprocedural register annotator (N-hop forward symbolic pass).

Follows call chains across function AND library boundaries, carrying RegVal arg states at
each callee entry. At each callee, seeds entry registers from the caller's register state at
the call site rather than generic argN placeholders.

```python
from ablation.analyzers.ipreg_annotator import IPRegAnnotator

# Single-binary, 2 hops:
ira = IPRegAnnotator.from_context(ctx)
chain = ira.annotate_chain(entry_va=0x1234, max_hops=2)
print(chain.fmt())

# Cross-binary with LibGraph:
ira = IPRegAnnotator.from_context(ctx, lib_graph=lg)
chain = ira.annotate_chain(entry_va=0x1234, max_hops=2)

# Sink report across entire chain:
SINKS = {'dangerous_sink', 'strcpy', 'system'}
print(chain.sink_report(SINKS))
```

Validated: 2-hop cross-binary chain automatically traces call sites across shared
library boundaries and identifies dangerous sink reachability without symbols.

---

## v1.6.0 (2026-09-21)

### New: LibGraph

`ablation/analyzers/lib_graph.py`: cross-binary import/export matrix.

Load all .so files in a firmware directory once, build a unified index over every
library, then query callers/exporters/imports across the entire set in a single call.
Backed by BinaryContext per binary (cache benefits fully apply).

```python
lg = LibGraph.from_dir('/path/to/firmware/rootfs/usr/lib/')
# or
lg = LibGraph.from_paths([lib1, lib2, lib3])

lg.callers_of('target_function')
# -> [LibCaller(binary='libA.so', caller_va=0x1234, fn='caller_name'),
#     LibCaller(binary='libB.so', caller_va=0x5678, fn='other_caller')]

lg.defined_in('target_function')        # -> [('libA.so', 0x9abc)]
lg.imports_of('libA.so')               # -> ['target_function', 'other_import', ...]
lg.exports_of('libB.so')               # -> ['target_function', 'another_export', ...]
lg.call_chain('libA.so', 'danger_sink') # BFS cross-library chain
print(lg.summary())                     # table: binary x exports/imports/edges
```

Resolves the multi-session pattern of building separate BinaryContext objects and manually
correlating callers across libraries. One `LibGraph.from_dir()` replaces N per-binary queries.

### New: RegAnnotator

`ablation/analyzers/reg_annotator.py`: lightweight forward symbolic register pass.

Single forward pass through a function window tracking register assignments
(mov/lea/xor/call) and annotating call sites with inferred argument register values.
No Z3, no lattice. Recovers ~85% of arg values in typical firmware dispatch functions.

```python
ra = RegAnnotator.from_path('/path/to/binary')
result = ra.annotate_calls(func_va=0x1000, func_end_va=0x1200)

for call in result.calls:
    print(f"0x{call.site_va:x}: call {call.target_name}")
    for reg, val in call.args.items():
        if val.kind != 'unknown':
            print(f"  {reg} = {val.display()}")

print(result.fmt())  # full formatted block
```

Example output for stress handler (libplugin.so 0x1000):
```
0x1100: call exec_handler
  rdi = '/bin/target-binary'  (0x1a5e40 via r13)
  rsi = arg0_entry  (rdi@entry via ebp)
  rdx = arg1_entry  (rsi@entry via r12)
```

Handles:
- mov/lea register-to-register transfers (follows chains: r12 = rsi@entry -> rdx = r12 shows rdx = arg1_entry)
- RIP-relative .rodata string loads
- xor reg, reg zeroing
- Callee-saved register preservation across calls (r12-r15, rbx, rbp survive)
- Caller-saved clobber (rax, rcx, rdx, rsi, rdi, r8-r11 cleared at call sites)
- Entry arg seeding: rdi=arg0, rsi=arg1, rdx=arg2, rcx=arg3, r8=arg4, r9=arg5

Does NOT handle branches (single path), loops, or complex stack frame indexing.

---

## v1.5.0 (2026-09-21)

### New: BinaryContext

`ablation/analyzers/binary_context.py`: pre-computed binary context cache.

Build once (~0.5s for a 24MB ELF), cache to `~/.ablation/cache/`, reload in <110ms.
Captures: PLT symbol map, exported functions, .rodata strings, function start VAs,
full call graph as (from_va, to_va, label) edges.

```python
ctx = BinaryContext.load_or_build('/path/to/binary')

ctx.plt[0x3000]                     # -> 'target_func'
ctx.callers_of('target_func')   # -> [(0x4000, '0x4000')]
ctx.callees_of(0x4000)              # -> full call sequence for the function
ctx.strings_near(0x6000, radius=64) # -> [(..., 'init_handler')]
ctx.func_containing(0x4060)         # -> 0x4000 (binary search over sorted starts)
print(ctx.summary())                  # session-start context block
```

Validated on libservice.so (24MB): 0.51s build, 0.109s cache reload, 1115 PLT entries,
498 exports, 2851 strings, 12357 call edges. `callees_of(0x4000)` returns the full
`init_handler` call sequence in one query; what previously required a full
session of manual tracing.

Cache invalidation: SHA256 mismatch triggers rebuild. Safe across firmware versions.

---

## v1.5.1 (2026-09-21)

### TaintTracker: custom sinks + seeded entry analysis

`custom_sinks` and `custom_sink_vas` constructor parameters add target-specific
functions to the sink table without modifying the default list.

`run_on_function_seeded(func_va, seed_arg_indices)` seeds entry argument registers
as tainted before analysis begins; handles CLI handler functions where taint
originates from the caller (entry args) rather than from recv/read calls.

```python
tt = TaintTracker(binary, xref=xg,
    custom_sinks={'exec_handler': [2]})
findings = tt.run_on_function_seeded(
    func_va=0x1000, func_end_va=0x1200,
    seed_arg_indices=[1])
# -> 2 findings: exec_handler(arg2) at 0x1100, 0x1180
```

Changes are backward-compatible: all new parameters default to None.

---

## v1.4.0 (2026-09-21)

### New: WindowAnalyzer

`ablation/analyzers/window_analyzer.py`: LLM-native bulk disassembly window.

One capstone call over a configurable region (default 1536 bytes) with inline annotation of:
- PLT call targets via `.rela.plt` (handles `.plt.sec` CET stubs, `.plt`, `.plt.got`)
- `.rodata` string references via RIP-relative addressing
- Function start candidates via endbr64 detection

Primary interface:

```python
wa = WindowAnalyzer.from_path('/path/to/binary')
print(wa.dump_text(va=0x4060, window=1536, align_back=256))
calls = wa.calls_in_window(va=0x4060, window=1536, align_back=256)
starts = wa.find_func_starts(va=0x41000, window=2048)
```

Motivation: per-instruction tracing requires N round trips through the disassembly pipeline.
A 1.5KB annotated dump returns a complete function-boundary-visible region for one-pass
pattern recognition; the natural unit for LLM-assisted RE.

---

## v1.3.0 (2026-09-21)

### Infrastructure

- Ablation restructure to installable package (ablation/core + ablation/analyzers).
- Shims preserve compatibility with 665 existing modules in modules/.
