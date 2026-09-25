# Ablation: Claude Operational Reference

## What this tool is

Binary RE toolkit for stripped firmware. No symbols. No source.

**Core capabilities:**
- **Semantic sweep**: describe dangerous code in plain English; BERT matches behavioral fingerprints across 19k functions in ~35s
- **Static taint tracking**: x86-64 source-to-sink data flow; MFP worklist CFG; interprocedural BFS; custom sinks + seeded entry analysis
- **ARM32 taint tracker**: recv/read -> malloc/strcpy/system source-to-sink for ARM32/Thumb ELF; AAPCS-aware caller-saved clobber model
- **ARM32 integer overflow scanner**: MUL/UMULL/SMULL operand wire-control detection; ReachingDefs ud-chain trace; allocation downstream check
- **BinaryContext cache**: PLT + exports + strings + call graph; arch-aware (x86_64/arm64/arm32); 0.5s build, 110ms reload, SHA256-keyed
- **Discovered-name overlay**: persistent VA->name map at `~/.ablation/function_names.json`; survives cache rebuilds and firmware version bumps
- **Cross-binary matrix**: LibGraph unified import/export index over all .so files; cross-library caller/callee queries in one call
- **Function profiler**: single-call complete function analysis: strings + call args + sink detection
- **Interprocedural chain tracer**: N-hop cross-binary call chains with full register value provenance
- **Pattern library**: persistent registry of successful semantic queries; auto-replays on new binaries
- **Finding registry**: cross-target confirmed finding store; each new finding seeds future sweeps
- **Patch epoch tracking**: DTWMatcher + MatrixProfileDiff; firmware version diffing without source
- **Behavioral corpus search**: SAXIndex approximate NN + SubsequenceSearcher wildcard pattern matching
- **Scanner primitives**: LengthUnderflowScanner (C12 class), ChunkWalkerValidator (C13 class)
- **Pre-auth route auditor**: flatui route scanner + PoC generator for Fortinet web framework
- **Windows kernel driver analysis**: KernelDriverAnalyzer: WDM/KMDF/minifilter classification, IRP dispatch table, IOCTL decoding, kernel API audit, callback registrations, pool tags, PDB path, SMEP/MSR/CR4 pattern scan
- **Format string scanner**: FormatStringScanner: 28 printf/syslog/err family sinks; backward trace to classify format arg as SAFE (LEA .rodata), VULNERABLE (stack slot/arg), or SUSPICIOUS; two-hop vsnprintf-to-syslog detection
- **Heap vulnerability scanner**: HeapVulnScanner: INT_OVERFLOW_BEFORE_ALLOC (TAOSSA Ch6 L6-2/L6-3), USE_AFTER_FREE, DOUBLE_FREE, OFF_BY_ONE_ALLOC; x86-64 ELF; TAOSSA Ch5+Ch6 grounded
- **MIPS32 taint tracker**: MIPS32TaintTracker: O32 ABI; recv/read -> system/execve/strcpy/sprintf source-to-sink; load-delay slot aware; intraprocedural + interprocedural BFS; big-endian and little-endian (RouterOS, Broadcom, CPE)
- **MIPS64 taint tracker**: MIPS64TaintTracker: N64 ABI (8 arg regs: a0-a3 + capstone t0-t3 for $8-$11); 64-bit ops (LD/SD/DADDU/DADDIU/DMULT); delay-slot aware; big-endian (Cisco IOS/OCTEON) and little-endian (RouterOS 64)
- **nanoMIPS decoder**: NanoMIPSDecoder + NanoMIPSDisasm: variable-length frame walker (16/32/48-bit); full decode with capstone 6.x; frame-boundary + branch-hint fallback on capstone 5.x; function-start heuristic; targets Ingenic SoC, MediaTek embedded
- **PPC32 taint tracker**: PPC32TaintTracker: System V / EABI ABI; r3-r10 args (8 regs), r3 return, r13-r31 callee-saved; no delay slots; recv/read to system/strcpy/execve sinks; prologue scan via stwu r1,-N(r1); interprocedural BFS depth 4; big-endian (Cisco IOS 7200/3700, MikroTik RB600, VxWorks) and POWER LE Linux
- **PPC64 taint tracker**: PPC64TaintTracker: ELFv2 (OpenPOWER Linux) and ELFv1 (AIX/old Linux PPC64) ABI; r3-r10 args, r14-r31 callee-saved; 64-bit ops LD/STD/MULLD/DIVD/DIVDU/SLD/RLDICL/EXTSW; prologue scan via stdu r1,-N(r1); interprocedural BFS depth 4; big-endian (IBM POWER/AIX, Juniper MX/PTX, Apple G5) and little-endian (POWER8+ Linux)
- **ARC taint tracker**: ARCTaintTracker: Synopsys DesignWare ARC 700 / ARC HS; r0-r7 args (8 regs), r0 return, r13-r25 callee-saved, r31=BLINK; variable-length 16/32-bit frame decoder (ARCDecoder); auto-upgrades to full decode when capstone next (CS_ARCH_ARC) is installed; push_s blink prologue detection; recv/read to system/strcpy/execve sinks; interprocedural BFS depth 4; little-endian (Linux ARC HS, IoT MCUs, smart TV SoCs, Marvell/Seagate storage controllers) and big-endian (ARC 700)
- **RISC-V 32 taint tracker**: RISCV32TaintTracker: ilp32 ABI; a0-a7 args (8 regs), a0 return, s0-s11 callee-saved; capstone CS_ARCH_RISCV + CS_MODE_RISCV32 + CS_MODE_RISCVC; jal (direct, PC-rel 21-bit), jalr (indirect), c.jal/c.jalr (RVC); ret/c.jr ra/jr ra return detection; prologue scan addi sp,sp,-N; recv/read to system/strcpy/execve sinks; interprocedural BFS depth 4; SiFive/StarFive Linux, Allwinner D1, ESP32-C3, GD32VF103, VisionFive 2, Milk-V Duo, OpenWrt RISC-V
- **RISC-V 64 taint tracker**: RISCV64TaintTracker: lp64 ABI (same register model as RV32); capstone CS_ARCH_RISCV + CS_MODE_RISCV64 + CS_MODE_RISCVC; adds ld/sd, addiw, addw/subw/mulw/divw/remw, sllw/srlw/sraw, c.ld/c.ldsp/c.addiw/c.addw/c.subw; identical call/ret detection; interprocedural BFS depth 4; VisionFive 2 (JH7110), SiFive Unmatched (FU740), Milk-V Pioneer (SG2042), SpacemiT K1, SOPHON BM1684, OpenWrt RISC-V 64
- **DisasmEngine MIPS/PPC/ARC/RISC-V expansion**: arch='mips32'/'mips64'/'mips32r6'/'nanomips'/'ppc'/'ppc32'/'ppc64'/'arc'/'arc32'/'riscv'/'riscv32'/'riscv64' + endian kwarg; prologue detection per arch (stwu PPC32, stdu PPC64, push_s blink ARC, addi sp,sp,-N RISC-V 32+64); per-arch branch/call/ret classification in stream()
- **Crypto analysis**: XorSolver key recovery, CryptoAudit JWT/TLS/key-material scanner
- **LLM-assisted analysis**: ReAct agent loop for automated function naming and vuln hypothesis

**Package:** `pip install -e ~/ablation/` (editable install, already done)

---

## Session start: run this every time

```python
from ablation.analyzers.binary_context import BinaryContext

# 1. Load SESSION.md index at ablation root, then the target's session file
#    ~/ablation/SESSION.md -> active target + path to targets/<vendor>/SESSION_<target>.md

# 2. Load context (0.5s first run, 110ms from cache)
ctx = BinaryContext.load_or_build('/path/to/target.so')
print(ctx.summary())          # PLT/export/func/string/edge counts + overlay count

# 3. Surface all previously confirmed function names before doing anything else
if ctx.names_count():
    print(ctx.names_table())  # VA | Source | Name, sorted

# RULE: use ctx.name(va) everywhere. Never use f"0x{va:x}" in display contexts.
# Register any newly confirmed function immediately:
#   ctx.set_name(0x17b660, "ips_diameter_parse_message", source="confirmed")
```

**SESSION.md convention:**
- Root index: `~/ablation/SESSION.md` (active target, pointers to per-target files)
- Per-target state: `targets/<vendor>/SESSION_<target>.md` (binary path, overlay table, confirmed findings, exact next steps)
- Read session file BEFORE touching any binary. It has the context.
- Update session file AFTER each session with what changed and what's next.

---

## Which tool for which task?

| Task | First reach |
|---|---|
| "What does this function call?" | `ctx.callees_of(va)` |
| "What calls this symbol?" | `ctx.callers_of('symbol')` or `ctx.callers_of(va)` |
| "What strings does this function reference?" | `ctx.strings_in_func(va)` |
| "Which functions reference this string?" | `ctx.funcs_referencing_string(string_va)` |
| "What is this function?" | `ctx.name(va)` (overlay > export > PLT > hex) |
| "Show me the disassembly around this address" | `WindowAnalyzer.dump_text(va, window=1536)` |
| "Find functions matching this vulnerability pattern" | `SemanticSearcher.query(description)` (ALWAYS first on a new binary) |
| "What values are passed to this sink?" | `FuncProfiler.profile(va).fmt()` |
| "Trace taint from network recv to sink" | `TaintTracker.run_interprocedural()` |
| "ARM32: trace recv to malloc/strcpy/system" | `ARM32TaintTracker.from_context(ctx).run_interprocedural()` |
| "ARM32: find MUL before malloc without bounds check" | `ARM32IntOverflowScanner.from_context(ctx).scan()` |
| "MIPS32: trace recv to system/strcpy/sprintf" | `MIPS32TaintTracker.from_path(elf).run_interprocedural()` |
| "MIPS32: big-endian RouterOS or little-endian CPE" | `MIPS32TaintTracker.from_path(elf, endian='big')` |
| "MIPS64: trace recv to system/strcpy/sprintf (Cisco IOS/OCTEON)" | `MIPS64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "MIPS64: little-endian RouterOS 64" | `MIPS64TaintTracker.from_path(elf, endian='little').run_interprocedural()` |
| "nanoMIPS: walk frame boundaries in Ingenic/MediaTek binary" | `NanoMIPSDecoder(endian='little').decode_frames(data, base_addr)` |
| "nanoMIPS: find function starts by prologue pattern" | `NanoMIPSDisasm(endian='little').find_function_starts(data, base_addr)` |
| "nanoMIPS: DisasmEngine-compatible instruction stream" | `NanoMIPSDisasm(endian='little').stream(data, base_addr)` |
| "MIPS disasm (any variant) via DisasmEngine" | `DisasmEngine(arch='mips64', endian='big')` |
| "PPC32: trace recv to system/strcpy (Cisco IOS 7200, VxWorks)" | `PPC32TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "PPC32: POWER LE Linux userspace" | `PPC32TaintTracker.from_path(elf, endian='little').run_interprocedural()` |
| "PPC32: custom sinks (VxWorks vxExecCmd)" | `PPC32TaintTracker.from_path(elf, custom_sinks={'vxExecCmd': [0]}).run()` |
| "PPC32 disasm via DisasmEngine" | `DisasmEngine(arch='ppc32', endian='big')` |
| "PPC64: trace recv to system/strcpy (IBM POWER, AIX)" | `PPC64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "PPC64: POWER8+ OpenPOWER Linux little-endian" | `PPC64TaintTracker.from_path(elf, endian='little').run_interprocedural()` |
| "PPC64 disasm via DisasmEngine" | `DisasmEngine(arch='ppc64', endian='big')` |
| "ARC: trace recv to system/strcpy (ARC HS IoT, Marvell, Seagate)" | `ARCTaintTracker.from_path(elf).run_interprocedural()` |
| "ARC: big-endian ARC 700 firmware" | `ARCTaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "ARC: custom sinks (arc_exec_cmd)" | `ARCTaintTracker.from_path(elf, custom_sinks={'arc_exec_cmd': [0]}).run()` |
| "ARC: walk frame boundaries, decode all instructions" | `ARCDecoder(endian='little').decode_frames(data, base_addr)` |
| "ARC: find function starts by prologue (push_s blink)" | `ARCDisasm(endian='little').find_function_starts(data, base_addr)` |
| "ARC: DisasmEngine-compatible instruction stream" | `DisasmEngine(arch='arc', endian='little')` |
| "ARC: check if capstone next ARC support is available" | `ARCDecoder().has_full_decode` |
| "RISC-V 32: trace recv to system/strcpy (SiFive, StarFive, Allwinner D1)" | `RISCV32TaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 32: custom sinks (riscv_exec_cmd)" | `RISCV32TaintTracker.from_path(elf, custom_sinks={'riscv_exec': [0]}).run()` |
| "RISC-V 32 disasm via DisasmEngine (with RVC)" | `DisasmEngine(arch='riscv32')` |
| "RISC-V 64: trace recv to system/strcpy (VisionFive 2, SiFive Unmatched)" | `RISCV64TaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 64: custom sinks" | `RISCV64TaintTracker.from_path(elf, custom_sinks={'rv64_exec': [0]}).run()` |
| "RISC-V 64 disasm via DisasmEngine (with RVC)" | `DisasmEngine(arch='riscv64')` |
| "Find printf/syslog with non-literal format string" | `FormatStringScanner.from_context(ctx).scan()` |
| "Scan for heap integer overflow / UAF / double-free" | `HeapVulnScanner.from_context(ctx).scan()` |
| "Trace an arg across 3 library hops" | `IPRegAnnotator.annotate_chain(va, max_hops=3)` |
| "Which library exports this symbol?" | `LibGraph.defined_in('symbol')` |
| "Is this the same function as in v7.4?" | `DTWMatcher.score_functions(va_a, va_b)` |
| "Where did this function change across versions?" | `MatrixProfileDiff.diff_functions(va_v1, va_v2)` |
| "Confirm this taint path is reachable" | `PathSolver.solve_path(func_va, target_va)` |
| "Find pre-auth routes in flatui firmware" | `PreAuthRouteAuditor.run(route_init_va, factory_va)` |
| "Generate PoC curl commands" | `PocGenerator.generate_all(preauth_routes)` |
| "Analyze JWT token in memory or file" | `CryptoAudit.analyze_jwt(token)` |
| "Crack XOR-encrypted firmware section" | `XorSolver.solve(ciphertext_path)` |
| "Extract FortiOS hardware firmware (.out file)" | `FortiOSHardwareExtractor.from_path(fw).extract_to(outdir)` |
| "Find encrypted/packed sections in binary" | `EntropyMapper.scan()` |
| "Resolve C++ vtable indirect calls (ARM64)" | `VtableResolver.extract_vtable_regions()` + `resolve_blr_sites()` |
| "Parse Go pclntab and enumerate functions" | `GoBinaryRE.parse_pclntab()` |
| "Find Go subprocess/exec injection sites" | `GoSubprocessScanner.scan()` |
| "Auto-name stripped functions via LLM" | `LlmAnalyst.FunctionNamer(ctx).run(va)` |
| "Find confirmed similar findings from past engagements" | `FindingRegistry.find_similar(embedding)` |
| "Write a new scanner for an undetected vuln class" | See **Custom scanner workflow** below |
| "Analyze a Windows kernel .sys driver" | `KernelDriverAnalyzer.from_path(path).analyze()` |
| "Decode a Windows IOCTL CTL_CODE value" | `decode_ioctl_code(value)` from `kernel_driver_analyzer` |
| "Find IRP dispatch handlers in DriverEntry" | `KernelDriverAnalyzer.analyze().major_functions` |
| "Find IOCTL codes in driver binary" | `KernelDriverAnalyzer.analyze().ioctl_codes` |
| "Audit kernel API surface of .sys file" | `KernelDriverAnalyzer.analyze().kernel_api_findings` |
| "Find kernel callback registrations" | `KernelDriverAnalyzer.analyze().callback_registrations` |
| "Find SMEP bypass / MSR / CR4 patterns" | `KernelDriverAnalyzer.analyze().dangerous_patterns` |
| "Extract PDB path / build tree from .sys" | `KernelDriverAnalyzer.analyze().pdb_path` |
| "Check if driver is Authenticode-signed" | `KernelDriverAnalyzer.analyze().is_signed` |

**Ordering rule:** BinaryContext (always) -> SemanticSearcher (new binary/vuln class) -> FuncProfiler (candidate) -> TaintTracker (sinks known) -> PathSolver (confirm feasibility). Manual capstone only when TaintTracker has no configured sink.

---

## Module index

### BinaryContext

**Import:** `from ablation.analyzers.binary_context import BinaryContext`

```python
ctx = BinaryContext.load_or_build('/path/to/binary')
ctx = BinaryContext.load_or_build('/path', force_rebuild=True)

# Symbol lookups
ctx.plt[0x256f0]                        # -> 'conf_ctx_set_cli'
ctx.exports['func_name']                # -> va
ctx.plt_name(va)                        # -> str or None
ctx.export_va('func_name')              # -> va or None
ctx.func_containing(va)                 # -> nearest func start <= va

# Call graph (labels use overlay names automatically)
ctx.callers_of('conf_ctx_set_cli')      # -> [(caller_va, name), ...]
ctx.callers_of(va)                      # same, by VA
ctx.callees_of(va)                      # -> [(target_va, name), ...]

# String xrefs (numpy RIP-relative displacement scan, O(|text|))
ctx.strings_in_func(va)                 # -> [(string_va, content), ...]
ctx.funcs_referencing_string(string_va) # -> [func_va, ...]
ctx.string_xrefs(string_va)             # -> [code_va, ...]  (instruction level)
ctx.strings_near(va, radius=128)        # -> [(string_va, content), ...]
ctx.build_xref_index('/path/to/binary') # populate on old cache (returns pair count)

# Discovered-name overlay
ctx.name(va)                            # overlay > export > PLT > "0x<hex>"
ctx.set_name(va, "name", source="confirmed")  # register; auto-saves to disk
ctx.delete_name(va)                     # remove
ctx.names_map()                         # -> {va: name} for all overlay entries
ctx.names_count()                       # -> int
ctx.names_table(limit=0)                # -> formatted table sorted by VA

ctx.summary()                           # compact session-start block
```

**Persistence:** cache at `~/.ablation/cache/<sha256[:16]>_<name>.json`; name overlay at `~/.ablation/function_names.json`. Cache invalidated on SHA256 mismatch.

**Key fields:** `ctx.plt` `{va: name}`, `ctx.exports` `{name: va}`, `ctx.strings` `{va: content}`, `ctx.func_starts` sorted list, `ctx.call_edges` list of `(from_va, to_va, label)`.

---

### NameRegistry

**Import:** `from ablation.analyzers.name_registry import get_registry, NameRegistry`

Standalone persistent map backing `ctx.name()` / `ctx.set_name()`. Use BinaryContext methods in normal flow; reach the registry directly only for bulk operations.

```python
reg = get_registry()                           # module-level singleton

reg.get_name(sha256, va)                       # -> str or None
reg.set_name(sha256, va, "name", source="manual")  # auto-saves
reg.delete_name(sha256, va)                    # -> bool
reg.all_names(sha256)                          # -> [(va, name, source), ...] sorted
reg.names_map(sha256)                          # -> {va: name}
reg.count(sha256)                              # -> int
reg.save()                                     # explicit flush (set_name auto-saves)
```

Sources: `confirmed` (finding verified), `string` (derived from nearby string), `manual` (analyst assigned).

---

### FindingRegistry

**Import:** `from ablation.analyzers.finding_registry import FindingRegistry`

Cross-target confirmed finding store. Every confirmed vulnerability registers here; the BERT embedding of each finding seeds future sweeps on new binaries automatically.

```python
reg = FindingRegistry()                        # storage: ~/.ablation/findings.db

# Build semantic index (call after loading a BERT model)
reg.build_embeddings(model)

# Find past findings similar to a new function
hits = reg.find_similar(func_embedding, top_k=8, min_sim=0.60)

# Register a confirmed finding after disclosure
reg.register(
    vendor="fortinet", product="fortigate", version="8.0.0",
    title="DCE/RPC zero-length record infinite loop",
    description="advance_ptr += wire_length without floor check; CPU DoS",
    cwe_class="CWE-835", severity="HIGH",
    embedding=func_vec, func_addr=0x20dd40, binary="libips.so.new",
)

reg.stats()                                    # hit counts, vendor breakdown
reg.list_findings(vendor="fortinet", limit=50) # tabular listing
reg.prior_queries(top_n=20)                    # most-used semantic query strings

# CLI:
# python3 -m ablation.analyzers.finding_registry stats
# python3 -m ablation.analyzers.finding_registry list --vendor fortinet
```

**Persistence:** `~/.ablation/findings.db` (SQLite, not committed to git). Seed corpus at `ablation/data/seed_corpus.json` ships with the package.

---

### WindowAnalyzer

**Import:** `from ablation.analyzers.window_analyzer import WindowAnalyzer`

Annotated disassembly dump. One capstone call over a configurable window with inline PLT labels and string references.

```python
wa = WindowAnalyzer.from_path('/path/to/binary')

print(wa.dump_text(va=0x412f4, window=1536))
# 0x412f4: push  r12                  ; [FUNC_START]
# 0x41339: call  0x24cc0              ; PLT -> conf_parse_devinfo
# 0x4137f: lea   rdx, [rip+0x59d9a]  ; "__conf_ctx_from_file"

calls = wa.calls_in_window(va=0x412f4, window=1536)   # [(site_va, target_va, label)]
starts = wa.find_func_starts(va=0x41000, window=2048)  # [func_va, ...]
```

---

### FuncProfiler

**Import:** `from ablation.analyzers.func_profiler import FuncProfiler`

Complete function analysis in one call: strings + call site args + sink detection.

```python
fp = FuncProfiler.from_context(ctx, custom_sinks={'fm_exec_cli': 'cmd-exec'})
fp = FuncProfiler.from_path('/path/to/binary')

profile = fp.profile(va=0x15a78a)       # end_va auto-estimated if omitted
print(profile.fmt())                     # header + strings + all calls + SINK flags
profile.sink_calls                       # list of ProfiledCall where is_sink=True
profile.has_sink('fm_exec_cli')          # bool

fp.sinks_in_region(va, end_va)           # quick triage: only sink calls
fp.profile_many([va1, va2, va3])         # batch
```

Default sinks: strcpy/strcat/sprintf/vsprintf/system/popen/execv*/Tcl_Eval/fm_exec_cli.

---

### SemanticSearcher

**Import:** `from ablation.analyzers.semantic_search import SemanticSearcher`

BERT behavioral fingerprint search. **Always run first on a new binary or new vuln class.**

```python
from ablation.analyzers.xref_graph import XRefGraph

xg = XRefGraph.from_path('/path/to/binary').build()
searcher = SemanticSearcher('/path/to/binary', xg=xg)
searcher.build_corpus()    # ~35s on CPU, 19k functions

results = searcher.query('SCTP chunk length underflow without bounds check', top_k=10)
for r in results:
    print(f"{ctx.name(r.va)}  score={r.score:.3f}  {r.desc[:80]}")
```

---

### PatternLibrary

**Import:** `from ablation.analyzers.pattern_library import PatternLibrary`

Persistent registry of successful semantic queries. Seeded with 12 default patterns; accumulates confirmed hits across sessions.

```python
pl = PatternLibrary()        # loads ~/.ablation/patterns.json
print(pl.list())             # tag | confirmed | total | query

results = pl.sweep(searcher, top_k=5, min_score=0.3)
print(pl.fmt_sweep(results, binary_name='libips.so.new'))

pl.record_hit('SCTP chunk underflow', binary='libips.so.new', va=0x21b3c0, confirmed=True)
pl.add('DCE/RPC zero-length record infinite loop', tag='zero-len-loop')
pl.save()
```

---

### TaintTracker

**Import:** `from ablation.analyzers.taint_tracker_x86 import TaintTracker`

x86-64 source-to-sink data flow. Three modes: linear, MFP worklist, interprocedural BFS.

```python
tt = TaintTracker('/path/to/binary', xref=xg,
    custom_sinks={'fm_exec_cli': [2]})           # arg index list
tt = TaintTracker('/path/to/binary', xref=xg,
    custom_sink_vas={0x595c0: ('fm_exec_cli', [2])})

findings = tt.run_on_function(func_va=0x15a78a)
findings = tt.run_interprocedural()

# For CLI handlers where taint enters via argv, not recv:
findings = tt.run_on_function_seeded(func_va=0x15a78a, seed_arg_indices=[1])
```

---

### IPRegAnnotator

**Import:** `from ablation.analyzers.ipreg_annotator import IPRegAnnotator`

Interprocedural register annotator. Follows call chains N hops, carrying RegVal arg states across library boundaries.

```python
ira = IPRegAnnotator.from_context(ctx, lib_graph=lg)  # cross-binary
ira = IPRegAnnotator.from_context(ctx)                 # single-binary

chain = ira.annotate_chain(entry_va=0x412f4, max_hops=2)
print(chain.fmt())

SINKS = {'Tcl_Eval', 'strcpy', 'fm_exec_cli', 'system'}
print(chain.sink_report(SINKS))
chain.all_sinks(SINKS)     # [(func_va, binary, ChainCallSite)]
```

---

### LibGraph

**Import:** `from ablation.analyzers.lib_graph import LibGraph`

Cross-binary import/export matrix. One load, then query across ALL libraries.

```python
lg = LibGraph.from_dir('/tmp/fmg800/rootfs/usr/lib/')
lg = LibGraph.from_paths([lib1, lib2, lib3])

lg.callers_of('conf_ctx_set_cli')        # -> [LibCaller(binary, caller_va, fn), ...]
lg.defined_in('conf_ctx_set_cli')        # -> [('libdmapi.so', 0x5aee0)]
lg.imports_of('libfmgsvrd.so')           # -> ['conf_ctx_set_cli', ...]
lg.call_chain('libfmgsvrd.so', 'Tcl_Eval')  # BFS cross-library shortest path
lg.context('libfmgsvrd.so')             # -> BinaryContext for that binary
print(lg.summary())
```

---

### RegAnnotator

**Import:** `from ablation.analyzers.reg_annotator import RegAnnotator`

Lightweight forward symbolic register pass. No Z3. Annotates call sites with inferred arg values.

```python
ra = RegAnnotator.from_path('/path/to/binary')
result = ra.annotate_calls(func_va=0x15a78a, func_end_va=0x15a8ef)
print(result.fmt())

for call in result.calls:
    for reg, val in call.args.items():
        if val.kind != 'unknown':
            print(f"  {reg} = {val.display()}")

cs = result.call_at(0x15a892)    # -> CallSite with .args dict
```

RegVal kinds: `arg`, `string`, `const`, `copy`, `ret`, `zero`, `unknown`. Handles callee-saved preservation (r12-r15), caller-saved clobber (rax/rcx/rdx/rsi/rdi/r8-r11). Does NOT handle branches or loops.

---

### XRefGraph

**Import:** `from ablation.analyzers.xref_graph import XRefGraph`

Full cross-reference graph. Required input for SemanticSearcher and TaintTracker.

```python
xg = XRefGraph.from_path('/path/to/binary').build()

xg.strings_at(0x12e8fc)     # -> ['GlobalObj', '__cdb_obj_ctx_init', ...]
xg.callers(0x12e8fc)        # -> {caller_va, ...}
xg.callees(0x12e8fc)        # -> {callee_va, ...}
xg.plt_name(0x334c0)        # -> '__cdb_obj_ctx_init'
xg.callee_names(0x5aee0)    # -> ['Tcl_CreateInterp', ...]
```

Prefer `ctx.strings_in_func()` for string lookups. Use XRefGraph directly only when passing to SemanticSearcher or TaintTracker.

---

### PathSolver

**Import:** `from ablation.analyzers.path_solver import PathSolver, MemoryConstraint`

Z3 path feasibility. Use after TaintTracker to confirm reachability.

```python
ps = PathSolver('/path/to/binary')
result = ps.solve_path(
    func_va=0x12e8fc,
    target_va=0x12ebc6,
    constraints=[MemoryConstraint(reg='rsi', min_len=256)]
)
result.sat       # True/False
result.clauses   # number of Z3 clauses (0 = always reachable)
```

---

### CFGBuilder

**Import:** `from ablation.analyzers.cfg_builder import CFGBuilder`

Per-function CFG via recursive disassembly (BFS).

```python
cfg = CFGBuilder('/path/to/binary')
graph = cfg.build(func_va=0x12e8fc)
graph.blocks     # list of BasicBlock objects
graph.to_dot()   # DOT format
```

---

### ARM32TaintTracker

**Import:** `from ablation.analyzers.taint_tracker_arm32 import ARM32TaintTracker, TaintFinding32`

ARM32/Thumb intraprocedural taint tracker. Sources: recv/read family (r0 tainted on return). Sinks: memcpy length, malloc/calloc size, strcpy dst, system/execve path. AAPCS-aware: r0-r3 and r12 clobbered on calls; callee-saved r4-r11 preserved.

```python
tracker = ARM32TaintTracker('/path/to/libhijoyptt.so')
findings = tracker.run_on_function(func_va=0x2511c)
print(tracker.report(findings))

findings = tracker.run_interprocedural()

# Custom sinks (symbol -> [arg indices]):
tracker = ARM32TaintTracker(path, custom_sinks={'custom_alloc': [0]})

# From BinaryContext (reuses PLT/exports/func_starts):
tracker = ARM32TaintTracker.from_context(ctx)
```

Thumb binaries: pass `thumb=True`. For mixed ARM/Thumb binaries analyze each function separately with the appropriate mode.

---

### ARM32IntOverflowScanner

**Import:** `from ablation.analyzers.intoverflow_scanner_arm32 import ARM32IntOverflowScanner, IntOverflowFinding32`

Detects MUL/UMULL/SMULL operands traced to wire-controlled sources (recv/read callers) that flow into allocation calls without bounds checks. ARM32 equivalent of the x86-64 imul-from-memory pattern that found the Pta/JPEG2000 vulnerabilities.

```python
scanner = ARM32IntOverflowScanner.from_context(ctx)
findings = scanner.scan()
print(scanner.report(findings))

unguarded = [f for f in findings if not f.bounds_checked]

# From path (no BinaryContext needed):
scanner = ARM32IntOverflowScanner.from_path('/path/to/libhijoy.so')
```

`IntOverflowFinding32` fields: `func_va`, `mul_va`, `mnemonic`, `operand_regs`, `alloc_va`, `alloc_sym`, `wire_evidence`, `bounds_checked`.

---

### LengthUnderflowScanner

**Import:** `from ablation.analyzers.length_underflow import LengthUnderflowScanner`

C12-class detector: `lea -N(%reg)` or `sub $N, %reg` + movzwl truncation + call, without prior bounds check.

```python
scanner = LengthUnderflowScanner.from_context(ctx)
findings = scanner.scan_unguarded()
print(scanner.report(findings))
```

---

### ChunkWalkerValidator

**Import:** `from ablation.analyzers.chunk_walker_validator import ChunkWalkerValidator`

C13-class detector: TLV pointer advancement without 4-byte alignment (`ptr += raw_len` without `(len+3)&~3`).

```python
scanner = ChunkWalkerValidator.from_context(ctx)
unaligned = scanner.scan_unaligned()
print(scanner.report(unaligned))
```

---

### PreAuthRouteAuditor + PocGenerator + FlatuiMethodDecoder

**Fortinet flatui pre-auth route audit suite.**

```python
from ablation.analyzers.preauth_route_auditor import PreAuthRouteAuditor

auditor = PreAuthRouteAuditor.from_path('/tmp/fmg800_libs/libfmgd.so')
results = auditor.run(
    route_init_va=0x27b324,
    route_init_end_va=0x288d50,
    factory_va=0x2a5000,
    factory_end_va=0x2b0000,
)
print(results.fmt())
preauth = results.preauth_with_sinks()   # [(RouteEntry, HandlerEntry)] where handler has sinks

# Decode HTTP method IDs from route entries
from ablation.analyzers.flatui_method_decoder import FlatuiMethodDecoder
dec = FlatuiMethodDecoder.from_path('/tmp/fmg800_libs/libfmgd.so')
print(dec.fmt_table())                   # full ID -> verb mapping
print(dec.decode(11))                    # -> {'GET', 'POST', 'DELETE'}
print(dec.is_preauth_exploitable([11]))  # 'exploitable' | 'read-only' | 'safe'

# Generate PoC curl commands
from ablation.analyzers.poc_generator import PocGenerator
gen = PocGenerator(host='192.168.1.1', port=443)
for route in [r for r in results.routes if r.is_preauth]:
    print(gen.curl(route))
script = gen.fmt_script(preauth_routes)  # shell script with all curls
```

**Scope:** Designed for FortiManager 8.0.0 libfmgd.so flatui framework. Update VA constants in `preauth_route_auditor.py` for other versions.

---

### CryptoAudit

**Import:** `from ablation.analyzers.crypto_audit import CryptoAudit, KeyCryptoAnalyzer, forge_jwt`

JWT analysis, TLS audit, key material scanner.

```python
ca = CryptoAudit()
result = ca.analyze_jwt(token_string)       # decode + alg-none check + weak-secret scan
result = ca.analyze_saml_assertion(xml)     # SAML assertion analysis
hits = ca.scan_key_material(['/etc/'])      # find embedded keys/certs
hits = ca.scan_for_jwts(['/var/log/'])      # find JWT tokens in log files
result = ca.analyze_tls('192.168.1.1')      # TLS version + cipher audit

# Forge JWT for PoC
token = forge_jwt({'sub': 'admin', 'role': 'superuser'}, secret='', alg='none')

# RSA/DH key strength
kca = KeyCryptoAnalyzer()
findings = kca.analyze_rsa_key(pem_bytes)   # -> [{severity, description}, ...]
```

---

### XorSolver

**Import:** `from ablation.analyzers.xor_solver import XorSolver, AffineMapAnalyzer`

XOR cipher key recovery. IC-based key length estimation + frequency analysis.

```python
solver = XorSolver('/path/to/encrypted.bin')

result = solver.kpa_attack(crib=b'\x7fELF', offset=0)  # known-plaintext
key_len = solver.guess_key_length(max_key=32)            # IC method
result = solver.freq_attack(key_len)
result = solver.solve()                                   # full auto
print(result.fmt())                                       # key (hex) + entropy improvement
decrypted = result.decrypt(ciphertext)
solver.decrypt_file('/out/decrypted.bin', result)

# Affine/substitution cipher variant
ama = AffineMapAnalyzer(encrypt_fn, block_size=16)
ama.reconstruct()
print(ama.analyze())
```

---

### FortiOSHardwareExtractor

**Import:** `from ablation.analyzers.fortios_firmware_extractor import FortiOSHardwareExtractor, extract_fortios_hardware`

Full extraction pipeline for FortiOS .out hardware firmware files (FortiWiFi, FortiGate appliances).
Handles multi-stream gzip decompression, 64-byte XOR key recovery via IC + frequency analysis
(NAND 0xFF assumption), partition boundary detection, and extraction to disk.

```python
from ablation.analyzers.fortios_firmware_extractor import FortiOSHardwareExtractor

ex = FortiOSHardwareExtractor.from_path('/path/to/FWF_60E-v7.2.4.F-build1396-FORTINET.out')

# Recover key (NAND 0xFF assumption; default for all FortiWiFi and FortiGate hardware)
result = ex.recover_xor_key(plaintext_assumption=0xFF)
print(result.key.hex())         # 64-byte XOR key
print(result.confidence)        # entropy drop fraction (0.81+ = reliable)

# Scan partitions (key auto-recovered if not done)
scan = ex.scan_partitions()
print(scan.fmt())               # offset table with kind labels

# Full pipeline: decompress -> key -> scan -> write to disk
result = ex.extract_to('/tmp/fw_extracted/')
print(result.fmt())

# One-call shortcut
from ablation.analyzers.fortios_firmware_extractor import extract_fortios_hardware
result = extract_fortios_hardware('/path/to/fw.out', '/tmp/out/')
```

Key cipher characteristics (confirmed FortiWiFi 60E v5.0.9-v7.2.4.F, FortiGate 7000F v8.0.0):
- 64-byte repeating pure XOR; IC spike at shift=64 is 192-244x above random baseline
- NAND plaintext 0xFF-dominant (80-86% erased cells); key is version-independent
- x86-64 FortiGate images (0x00-sparse): pass `plaintext_assumption=0x00`

---

### EntropyMapper

**Import:** `from ablation.analyzers.entropy_mapper import EntropyMapper`

Maps entropy regions in binary to identify encrypted/compressed/packed sections.

```python
em = EntropyMapper('/path/to/binary')
result = em.scan(window=256, step=64)

for region in result.regions:
    print(f"0x{region.start_va:x}--0x{region.end_va:x}  {region.label}  H={region.entropy:.2f}")
    # labels: 'code', 'data', 'compressed', 'encrypted', 'zero'

result.high_entropy    # regions with H > 7.0 (likely encrypted)
result.transitions     # [(va, from_label, to_label)] entropy boundary crossings
```

---

### VtableResolver

**Import:** `from ablation.analyzers.vtable_resolver import extract_vtable_regions, detect_ctor_vptr_inits, detect_blr_sites, resolve_blr_sites`

ARM64 C++ vtable reconstruction and indirect call resolution.

```python
import lief
binary = lief.parse('/path/to/libwechatnetwork.so')
text_data = bytes(binary.get_section('.text').content)

vtables = extract_vtable_regions(binary, text_va, text_size, min_slots=3)
ctor_inits = detect_ctor_vptr_inits(text_data, text_va, text_size, vtables)
blr_sites = detect_blr_sites(text_data, text_va, text_size)
resolved = resolve_blr_sites(blr_sites, vtables)

for site, targets in resolved.items():
    print(f"BLR@0x{site.va:x} slot {site.slot_idx} -> {[hex(t) for t in targets]}")
```

---

### Go RE Suite

```python
from ablation.analyzers.go_binary_re import (
    parse_pclntab, detect_go_version, parse_elf_sections, disasm_function
)
from ablation.analyzers.go_subprocess_scanner import GoSubprocessScanner
from ablation.analyzers.go_dangerous_callers import GoDangerousCallerScanner

binary_data = open('/path/to/go_binary', 'rb').read()
go_ver = detect_go_version(binary_data)                  # 'go1.18', etc.
sections = parse_elf_sections(binary_data)
funcs, _ = parse_pclntab(binary_data, pclntab_off, pclntab_size, sections)

# Subprocess injection surfaces
scanner = GoSubprocessScanner(binary_data, sections, func_table=funcs)
results = scanner.scan()
for r in results:
    print(r['severity'], r['func_name'], r['cmd_string'], r['cmd_type'])
    # cmd_type: 'relative', 'path', 'absolute', 'dynamic'

# Dangerous callers (os/exec, syscall.Exec, etc.)
dcs = GoDangerousCallerScanner(binary_data, sections, funcs)
hits = dcs.scan()
```

---

### LlmAnalyst

**Import:** `from ablation.analyzers.llm_analyst.tasks.function_namer import FunctionNamer`

ReAct agent loop for automated function naming and vulnerability hypothesis. Uses claude-sonnet-5 by default. Hard stop at 20 tool calls.

```python
from ablation.analyzers.llm_analyst.tasks.function_namer import FunctionNamer
from ablation.analyzers.llm_analyst.tasks.vuln_hypothesis import VulnHypothesis

# Auto-name a stripped function
namer = FunctionNamer(ctx)
result = namer.run(va=0x17b660)
print(f"{result.name}  confidence={result.confidence:.2f}  role={result.role}")
if result.confidence > 0.75:
    ctx.set_name(0x17b660, result.name, source='string')

# Vulnerability hypothesis for a scanner candidate
hyp = VulnHypothesis(ctx)
result = hyp.analyze(va=0x29fa90)
print(result.hypothesis)
```

---

### VersionTracker

**Import:** `from ablation.analyzers.version_delta import VersionTracker`

Cross-version homolog tracking.

```python
tracker = VersionTracker({'v7.4': '/path/v74/lib.so', 'v8.0': '/path/v80/lib.so'})
tracker.build_all()
match = tracker.find_homolog('v7.4', func_va=0x12e8fc, search_in='v8.0')
print(f"homolog 0x{match.va:x}  sim={match.score:.2f}")
```

---

### DTWMatcher

**Import:** `from ablation.analyzers.dtw_matcher import DTWMatcher`

```python
matcher = DTWMatcher.from_paths(v1_path, v2_path)
report = matcher.score_functions(va_a, va_b)
print(report.fmt())   # dtw_sim + dtw_dist + jaccard + verdict
# Verdicts: same_era (>=0.85), patched (0.45-0.85), rewritten (0.20-0.45), different (<0.20)
matches = matcher.find_homologs(va_v1, ctx_v2=ctx_v2, top_k=5)
```

---

### MatrixProfileDiff

**Import:** `from ablation.analyzers.matrix_profile_diff import MatrixProfileDiff`

```python
mpd = MatrixProfileDiff.from_paths(v1_path, v2_path, discord_threshold=0.5)
result = mpd.diff_functions(va_v1, va_v2)
print(result.change_summary())   # 'change=18.4%  modified:14  unchanged:82'
result.is_likely_patched()       # change_pct >= 15.0
result.patch_offset_v1()         # instruction index of first change
```

Use `discord_threshold=0.5` for categorical sequences (default 1.5 is too high).

---

### SAXIndex

**Import:** `from ablation.analyzers.sax_index import SAXIndex`

```python
idx = SAXIndex(word_size=8, alphabet_size=8)
idx.add_binary('/firmware/lib/libcdb.so', ctx=ctx)
results = idx.query_va(binary_path, func_va, top_k=10)
idx.save('/path/index.pkl')
idx2 = SAXIndex.load('/path/index.pkl')
```

---

### SubsequenceSearcher

**Import:** `from ablation.analyzers.subsequence_searcher import SubsequenceSearcher`

```python
ss = SubsequenceSearcher.from_path('/path/to/binary', ctx=ctx)
ss.precompute()
pattern = ss.pattern('COMPARISON_OP CONDITIONAL_OP * UNCONDITIONAL_OP')
results = ss.search(pattern)
clones = ss.search_like(ref_va=0x15a78a, top_k=10)
```

---

### OpSeqEncoder

**Import:** `from ablation.analyzers.opseq import OpSeqEncoder, seq_to_str`

```python
enc = OpSeqEncoder('/path/to/binary')
seq = enc.encode_va(va)            # -> List[int]
seq_to_str(seq)                    # 'ADCJDDUCJ...' compact visual
```

Categories: ARITHMETIC(0) DATA_TRANSFER(1) COMPARISON(2) LOGIC(3) BIT_SHIFT(4) UNCONDITIONAL(5) CONDITIONAL(6) MEMORY_MGMT(7) PROCESSOR_STATE(8) SYNCHRONIZATION(9) VECTOR_MGMT(10) OTHER(11).

---

### CorpusBuilder

**Import:** `from ablation.analyzers.corpus_builder import CorpusBuilder, build_fortios_corpus`

```python
cb = CorpusBuilder('~/.ablation/func_id.db')
count = cb.build('/path/to/libips.so.new', product='libips', version='8.0.0')

# FortiOS shortcut:
from ablation.analyzers.corpus_builder import build_fortios_corpus
build_fortios_corpus('/path/libips.so.new', '/path/libav.so.new')
```

---

### KernelDriverAnalyzer

**Import:** `from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer, decode_ioctl_code`

Windows kernel driver (.sys) static analysis. Built on PEParser; does not require BinaryContext (ELF-centric). Uses capstone for disassembly when available; import-only analysis runs without it.

Sources: Windows Internals (Yosifovich/Russinovich), Rootkits: Subverting the Windows Kernel (Hoglund/Butler), Practical Reverse Engineering (Dang et al.).

```python
kda = KernelDriverAnalyzer.from_path('/path/to/driver.sys')
report = kda.analyze()
print(report.fmt())

# Summary dict for ledger / visorlog
report.summary()
# {driver_type, is_signed, pdb_path, subsystem, major_functions, ioctl_codes,
#  ioctl_neither, kernel_api_crit, kernel_api_high, callbacks, pool_ops, dangerous}

# Per-category access
report.major_functions          # [MajorFunction(index, handler_rva)]
report.ioctl_codes              # [IoctlCode(raw, device_type, function, method, access)]
report.kernel_api_findings      # [KernelApiFinding(api, dll, severity, category)]
report.callback_registrations   # [CallbackRegistration(api, severity, description, risk_class)]
report.pool_operations          # [PoolOperation(api, tag, file_offset, notes)]
report.dangerous_patterns       # [DangerousPattern(pattern, offset, description, severity)]
report.pdb_path                 # str or None; internal build path leaks vendor/project
report.is_signed                # bool; Authenticode cert table present

# IOCTL code standalone decoder:
ic = decode_ioctl_code(0x222003)
print(ic.fmt())
# 0x00222003  DevType=0x0022  Func=0x800  METHOD_NEITHER *** NEITHER (raw user ptr)
ic.is_neither()         # True -> no buffer copy, raw user ptr in dispatch handler
ic.is_user_defined()    # True -> function >= 0x800
```

**Integration with TaintTracker for IOCTL handler analysis:**
```python
# After finding METHOD_NEITHER IOCTL codes, configure TaintTracker
# with kernel pool sinks to trace InputBuffer size -> allocation path:
from ablation.analyzers.taint_tracker_x86 import TaintTracker
from ablation.analyzers.xref_graph import XRefGraph

xg = XRefGraph.from_path('/path/driver.sys').build()
tt = TaintTracker('/path/driver.sys', xref=xg, custom_sinks={
    'ExAllocatePoolWithTag': [1],  # NumberOfBytes = RDX (arg2)
    'ExAllocatePool2':       [1],
    'RtlCopyMemory':         [2],  # Length = R8 (arg3)
    'memcpy':                [2],
})
# Seed taint from IRP stack location reads (InputBufferLength at IO_STACK_LOCATION+0x10)
findings = tt.run_interprocedural()
```

**Key kernel structures (x64 Windows 10+):**
- `DRIVER_OBJECT.MajorFunction[n]` at `+0x70 + n*8`; `IRP_MJ_DEVICE_CONTROL` (0x0E) = `+0xE0`
- `IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode` at `+0x08` within Parameters
- `IO_STACK_LOCATION.Parameters.DeviceIoControl.InputBufferLength` at `+0x10`
- Pool tag is 4-byte ASCII in R8 for `ExAllocatePoolWithTag(PoolType, Size, Tag)`

**METHOD_NEITHER warning:** `IoctlCode.is_neither()` true means the driver's dispatch handler receives `Type3InputBuffer`, a raw unvalidated user-mode pointer, with no kernel buffer copy. Any dereference without `ProbeForRead` first = arbitrary kernel read/write.

---

## RE workflow

**New binary, initial triage:**

1. Read `SESSION.md` (root) + target's `SESSION_<target>.md` file
2. `BinaryContext.load_or_build()` + `ctx.summary()` + `ctx.names_table()`
3. `CorpusBuilder.build()` if this binary has no prior ANGR_INFERRED coverage
4. `SemanticSearcher.query()`: sweep ALL vuln classes before touching disasm
5. `PatternLibrary.sweep()`: replay confirmed patterns from prior engagements
6. `FuncProfiler.profile()` on top candidates: one call per function
7. `TaintTracker` if sinks are standard (strcpy/system/execv/Tcl_Eval)
8. `IPRegAnnotator` for call chains across library boundaries
9. `WindowAnalyzer.dump_text()` for manual disasm only when automated tools don't have the sink

**Confirming a finding:**

1. `PathSolver.solve_path()` for feasibility
2. `ctx.set_name(va, name, source="confirmed")`: register the function name
3. `PatternLibrary.record_hit(confirmed=True)`: improve pattern hit rate
4. `FindingRegistry.register()`: cross-target finding store
5. Write finding to `targets/<vendor>/<target>_re.py` (NOT into ablation itself)
6. Update `targets/<vendor>/SESSION_<target>.md` with what changed

**Custom scanner workflow for vuln classes not covered by existing scanners:**

1. Confirm SemanticSearcher has no existing pattern for this class (run a query first)
2. Create `ablation/analyzers/<scanner_name>.py`; follow `length_underflow.py` as the template
3. Wire: `from_context(ctx)` classmethod, `scan()` -> list of findings, `report(findings)` -> str
4. Run on a known-positive binary first to verify the scanner fires correctly
5. Analyze false positives explicitly:
   - **Cross-basic-block register clobber?** Track WRITE ops between source and target; invalidate if register written before hit
   - **Data network-facing or from trusted DB?** Trace initialization back to recv/read vs internal DB lookup
   - **Callee actually uses the register?** Disasm the callee and check whether the suspect register is read
6. Document hit counts: raw hits -> filtered hits -> confirmed after FP analysis
7. Add the scanner to the "Which tool for which task?" table in this file
8. Add a usage example to README.md

**Cross-version patch analysis:**

1. `DTWMatcher.score_functions()`: is this the same era?
2. `MatrixProfileDiff.diff_functions()`: exactly what changed?
3. `VersionTracker.find_homolog()`: where did the function move?

---

## Hard rules

- **GitHub:** active account is `francis-rancid`. ALL repo ops via `gh` CLI. `mcp__github` is BANNED.
- **Push:** after every commit: `env HOME=/home/cowboy GIT_LFS_SKIP_SMUDGE=1 git push origin main`
- **Edits:** main session only. Never fork or delegate ablation work.
- **Repo integrity:** `~/ablation/` is never deleted, moved, or destructively modified.
- **No findings in repo:** reports, disclosures, and write-ups never go into the ablation repo.
- **No Ghidra:** ever. For any RE work.
- **Semantic sweep first:** before ANY manual disasm on a new binary or new vuln class. No exceptions.
- **Gaps become modules:** every missing sink, scanner pattern, or analysis gap -> fix as a new ablation module. Never a workaround script.
- **Findings go in RE modules:** `targets/<vendor>/<target>_re.py`. Nowhere else. NOT `modules/`.
- **Name everything:** use `ctx.set_name()` the moment a function is confirmed. Use `ctx.name(va)` everywhere display code appears.
- **Session files:** update `targets/<vendor>/SESSION_<target>.md` at end of each session. Update root `SESSION.md` if active target changes.
