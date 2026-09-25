# Ablation: Claude Operational Reference

## What this tool is

Binary RE toolkit for stripped firmware. No symbols. No source.

`pip install -e ~/ablation/` (editable install, already done)

---

## Session start: run this every time

```python
from ablation.analyzers.binary_context import BinaryContext

# 1. Read SESSION.md (root) + targets/<vendor>/SESSION_<target>.md
# 2. Load context (0.5s first run, 110ms from cache)
ctx = BinaryContext.load_or_build('/path/to/target.so')
print(ctx.summary())

# 3. Surface all confirmed function names before anything else
if ctx.names_count():
    print(ctx.names_table())

# RULE: ctx.name(va) everywhere. Never raw hex in display contexts.
# ctx.set_name(0x17b660, "ips_diameter_parse_message", source="confirmed")
```

SESSION.md convention: root index at `~/ablation/SESSION.md`; per-target state at `targets/<vendor>/SESSION_<target>.md`. Read before touching any binary. Update at end of each session.

---

## Which tool for which task?

| Task | First reach |
|---|---|
| "What does this function call?" | `ctx.callees_of(va)` |
| "What calls this symbol?" | `ctx.callers_of('symbol')` or `ctx.callers_of(va)` |
| "What strings does this function reference?" | `ctx.strings_in_func(va)` |
| "Which functions reference this string?" | `ctx.funcs_referencing_string(string_va)` |
| "What is this function?" | `ctx.name(va)` |
| "Show disassembly around address" | `WindowAnalyzer.dump_text(va, window=1536)` |
| "Find functions matching vulnerability pattern" | `SemanticSearcher.query(description)` (ALWAYS first on new binary) |
| "What values are passed to this sink?" | `FuncProfiler.profile(va).fmt()` |
| "Trace taint from network recv to sink" | `TaintTracker.run_interprocedural()` |
| "ARM32: trace recv to malloc/strcpy/system" | `ARM32TaintTracker.from_context(ctx).run_interprocedural()` |
| "ARM32: find MUL before malloc without bounds check" | `ARM32IntOverflowScanner.from_context(ctx).scan()` |
| "MIPS32: trace recv to system/strcpy/sprintf" | `MIPS32TaintTracker.from_path(elf).run_interprocedural()` |
| "MIPS32: big-endian RouterOS or little-endian CPE" | `MIPS32TaintTracker.from_path(elf, endian='big')` |
| "MIPS64: trace recv (Cisco IOS/OCTEON big-endian)" | `MIPS64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "MIPS64: little-endian RouterOS 64" | `MIPS64TaintTracker.from_path(elf, endian='little').run_interprocedural()` |
| "nanoMIPS: walk frame boundaries" | `NanoMIPSDecoder(endian='little').decode_frames(data, base_addr)` |
| "PPC32: trace recv (Cisco IOS 7200, VxWorks)" | `PPC32TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "PPC64: trace recv (IBM POWER, AIX)" | `PPC64TaintTracker.from_path(elf, endian='big').run_interprocedural()` |
| "ARC: trace recv (ARC HS IoT, Marvell, Seagate)" | `ARCTaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 32: trace recv (SiFive, Allwinner D1)" | `RISCV32TaintTracker.from_path(elf).run_interprocedural()` |
| "RISC-V 64: trace recv (VisionFive 2, SiFive Unmatched)" | `RISCV64TaintTracker.from_path(elf).run_interprocedural()` |
| "V850: trace recv (RH850/G3M ECU)" | `V850TaintTracker.from_path(elf).run_interprocedural()` |
| "Find printf/syslog with non-literal format string" | `FormatStringScanner.from_context(ctx).scan()` |
| "Scan for heap integer overflow / UAF / double-free" | `HeapVulnScanner.from_context(ctx).scan()` |
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
| "Find encrypted/packed sections in binary" | `EntropyMapper.scan()` |
| "Resolve C++ vtable indirect calls (ARM64)" | `VtableResolver.extract_vtable_regions()` + `resolve_blr_sites()` |
| "Parse Go pclntab and enumerate functions" | `GoBinaryRE.parse_pclntab()` |
| "Find Go subprocess/exec injection sites" | `GoSubprocessScanner.scan()` |
| "Auto-name stripped functions via LLM" | `LlmAnalyst.FunctionNamer(ctx).run(va)` |
| "Find confirmed similar findings from past engagements" | `FindingRegistry.find_similar(embedding)` |
| "Write a new scanner for an undetected vuln class" | See **Custom scanner workflow** below |
| "Analyze a Windows kernel .sys driver" | `KernelDriverAnalyzer.from_path(path).analyze()` |
| "Decode a Windows IOCTL CTL_CODE value" | `decode_ioctl_code(value)` from `kernel_driver_analyzer` |

**Ordering rule:** BinaryContext (always) -> SemanticSearcher (new binary/vuln class) -> FuncProfiler (candidate) -> TaintTracker (sinks known) -> PathSolver (confirm feasibility). Manual capstone only when TaintTracker has no configured sink.

---

## Module quick-reference

All modules under `ablation.analyzers.*`. Construction pattern: `ClassName.from_context(ctx)` or `ClassName.from_path('/path/to/binary')`.

**BinaryContext** — `from ablation.analyzers.binary_context import BinaryContext`
Core: `load_or_build(path)`, `summary()`, `names_table()`, `name(va)`, `set_name(va, name, source)`, `callers_of()`, `callees_of()`, `strings_in_func(va)`, `funcs_referencing_string(va)`. Cache at `~/.ablation/cache/`; name overlay at `~/.ablation/function_names.json`.

**SemanticSearcher** — `from ablation.analyzers.semantic_search import SemanticSearcher`
Requires `XRefGraph.from_path(path).build()` passed as `xg=`. Call `build_corpus()` (~35s, 19k functions), then `query(description, top_k=10)`.

**TaintTracker (x86-64)** — `from ablation.analyzers.taint_tracker_x86 import TaintTracker`
`TaintTracker(path, xref=xg, custom_sinks={'sink': [arg_idx]})`. Modes: `run_on_function(va)`, `run_interprocedural()`, `run_on_function_seeded(va, seed_arg_indices=[1])`.

**Arch taint trackers** — all follow `ClassName.from_path(elf[, endian='big'|'little'][, custom_sinks={}]).run_interprocedural()`:
- `ARM32TaintTracker` — `taint_tracker_arm32`; Thumb binaries: `ARM32TaintTracker(path, thumb=True)`
- `MIPS32TaintTracker` — `taint_tracker_mips32`
- `MIPS64TaintTracker` — `taint_tracker_mips64`
- `PPC32TaintTracker` — `taint_tracker_ppc32`
- `PPC64TaintTracker` — `taint_tracker_ppc64`
- `ARCTaintTracker` — `taint_tracker_arc`; check `ARCDecoder().has_full_decode` for capstone next
- `RISCV32TaintTracker` — `taint_tracker_riscv32`
- `RISCV64TaintTracker` — `taint_tracker_riscv64`
- `V850TaintTracker` — `taint_tracker_v850`; endian auto-detected via lief

**DisasmEngine** — `from ablation.analyzers.disasm_engine import DisasmEngine`
`DisasmEngine(arch='mips32'|'mips64'|'ppc32'|'ppc64'|'arc'|'riscv32'|'riscv64'|'v850'[, endian='big'])`. Arch decoders: `NanoMIPSDecoder`, `ARCDecoder`, `V850Decoder` all follow `decode_frames(data, base_addr)`.

**FuncProfiler** — `from ablation.analyzers.func_profiler import FuncProfiler`
`from_context(ctx)`. `profile(va).fmt()`. `profile.sink_calls`. Default sinks: strcpy/strcat/sprintf/vsprintf/system/popen/execv*/Tcl_Eval/fm_exec_cli.

**PatternLibrary** — `from ablation.analyzers.pattern_library import PatternLibrary`
`pl.sweep(searcher)`, `pl.record_hit(tag, binary, va, confirmed=True)`, `pl.add(query, tag=)`.

**FindingRegistry** — `from ablation.analyzers.finding_registry import FindingRegistry`
`reg.register(vendor, product, version, title, description, cwe_class, severity, embedding, func_addr, binary)`. `find_similar(embedding, top_k=8, min_sim=0.60)`. Storage: `~/.ablation/findings.db`.

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

**KernelDriverAnalyzer** — `from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer, decode_ioctl_code`
`KernelDriverAnalyzer.from_path(path).analyze()`. Key: `report.ioctl_codes`, `report.dangerous_patterns`, `report.is_signed`. `decode_ioctl_code(val).is_neither()` true = raw user pointer, no kernel buffer copy; trace `InputBufferLength` via TaintTracker with `ExAllocatePoolWithTag`/`RtlCopyMemory` sinks.

**DTWMatcher** — `from ablation.analyzers.dtw_matcher import DTWMatcher`
`score_functions(va_a, va_b)`. Verdicts: same_era (>=0.85), patched (0.45-0.85), rewritten (0.20-0.45).

**MatrixProfileDiff** — `from ablation.analyzers.matrix_profile_diff import MatrixProfileDiff`
`diff_functions(va_v1, va_v2)`. Use `discord_threshold=0.5` for categorical sequences (default 1.5 too high).

**FormatStringScanner** — `from ablation.analyzers.format_string_scanner import FormatStringScanner`
**HeapVulnScanner** — `from ablation.analyzers.heap_vuln_scanner import HeapVulnScanner`
**LengthUnderflowScanner** — `from ablation.analyzers.length_underflow import LengthUnderflowScanner` — C12-class
**ChunkWalkerValidator** — `from ablation.analyzers.chunk_walker_validator import ChunkWalkerValidator` — C13-class
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

---

## RE workflow

**New binary, initial triage:**

1. Read `SESSION.md` (root) + `targets/<vendor>/SESSION_<target>.md`
2. `BinaryContext.load_or_build()` + `ctx.summary()` + `ctx.names_table()`
3. `CorpusBuilder.build()` if no prior coverage
4. `SemanticSearcher.query()`: sweep ALL vuln classes before touching disasm
5. `PatternLibrary.sweep()`: replay confirmed patterns from prior engagements
6. `FuncProfiler.profile()` on top candidates
7. `TaintTracker` if sinks are standard
8. `IPRegAnnotator` for cross-library call chains
9. `WindowAnalyzer.dump_text()` for manual disasm only when automated tools don't have the sink

**Confirming a finding:**

1. `PathSolver.solve_path()` for feasibility
2. `ctx.set_name(va, name, source="confirmed")`
3. `PatternLibrary.record_hit(confirmed=True)`
4. `FindingRegistry.register()`
5. Write finding to `targets/<vendor>/<target>_re.py` (NOT into ablation itself)
6. Update `targets/<vendor>/SESSION_<target>.md`

**Custom scanner workflow:**

1. Confirm SemanticSearcher has no existing pattern (run a query first)
2. Create `ablation/analyzers/<scanner_name>.py`; follow `length_underflow.py` as template
3. Wire: `from_context(ctx)` classmethod, `scan()` -> findings list, `report(findings)` -> str
4. Run on a known-positive binary first
5. Analyze FPs: cross-basic-block register clobber? Data network-facing or from trusted DB? Callee actually reads the register?
6. Document: raw hits -> filtered -> confirmed after FP analysis
7. Add to "Which tool for which task?" table above
8. Add usage example to README.md

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
- **Findings go in RE modules:** `targets/<vendor>/<target>_re.py`. Nowhere else. NOT `modules/`.
- **Name everything:** `ctx.set_name()` the moment a function is confirmed. `ctx.name(va)` everywhere.
- **Session files:** update `targets/<vendor>/SESSION_<target>.md` at end of each session. Update root `SESSION.md` if active target changes.
