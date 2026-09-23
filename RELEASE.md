# Ablation Release Notes

## v1.8.0 (2026-09-21)

### New: Time Series Analysis Modules (5 modules)

Adds a complete time series analysis layer on top of the existing RE toolkit. Encodes function disassembly as integer sequences over 12 opcode categories (BinFuse taxonomy), then applies classical time series algorithms for patch diffing, homolog matching, corpus indexing, and behavioral pattern search.

**OpSeqEncoder** (`ablation/analyzers/opseq.py`) -- shared encoding base. Maps any function VA to `List[int]` of category codes. `seq_to_str()` for compact visual, `seq_histogram()` for distribution analysis.

**MatrixProfileDiff** (`ablation/analyzers/matrix_profile_diff.py`) -- instruction-level patch diff via Matrix Profile AB-join. Pinpoints changed instruction regions between two function versions. STUMPY-accelerated when available; numpy fallback for function-length sequences.

**DTWMatcher** (`ablation/analyzers/dtw_matcher.py`) -- cross-version homolog matching via DTW with Sakoe-Chiba band (20% of max length). Semantic affinity cost matrix (ARITHMETIC/LOGIC cost 0.3 vs default 1.0). Verdict thresholds: same_era >=0.85, patched 0.45-0.85, rewritten 0.20-0.45.

**SAXIndex** (`ablation/analyzers/sax_index.py`) -- fast approximate corpus index via SAX encoding. Gaussian breakpoints, categorical PAA, MINDIST lower bound for index pruning. Save/load via pickle for persistent indexes.

**SubsequenceSearcher** (`ablation/analyzers/subsequence_searcher.py`) -- behavioral pattern search. Exact match with wildcards, DTW sliding window approximate match, and `search_like()` for behavioral clone detection. `common_patterns()` reveals structurally common n-grams (tells you what NOT to use as discriminators).

```python
# Cross-version: find stress handler homolog in v2 binary
matcher = DTWMatcher.from_paths(v1_lib, v2_lib)
matches = matcher.find_homologs(0x15a78a, ctx_v2=ctx_v2)

# Behavioral clone detection
ss = SubsequenceSearcher.from_path(lib, ctx=ctx)
clones = ss.search_like(ref_va=0x15a78a, end_va=0x15a8ef, top_k=10)

# SAX corpus index across all FMG libraries
idx = SAXIndex()
for lib in fmg_libs:
    idx.add_binary(lib)
idx.save('fmg800_sax.pkl')
```

Note: use `discord_threshold=0.5` for MatrixProfileDiff on categorical sequences (default 1.5 is calibrated for continuous time series).

---

## v1.7.0 (2026-09-21)

### New: FuncProfiler

`ablation/analyzers/func_profiler.py` -- complete function analysis block in one call.

Replaces the 4-call manual sequence (callees_of, dump_text, annotate_calls, string lookup)
with a single `fp.profile(va, end_va)` call returning a `FuncProfile` with all data combined.

```python
fp = FuncProfiler.from_path('/path/to/binary')
fp = FuncProfiler.from_path(binary, custom_sinks={'fm_exec_cli': 'cmd-exec'})
print(fp.profile(va=0x15a78a, end_va=0x15a8ef).fmt())
```

Output:
```
[libcmfplugin.so] [FUNC 0x15a78a..0x15a8ef]  357B  11 calls  5 strings  3 SINKS

  STRINGS:
    0x1d5099  '/var/private/stress-ng-test'
    0x1d512c  'help'
    0x1d5131  '--temp-path'
    0x1d513d  '--temp-path must be %s'
    0x1d5155  '/bin/stress-ng'

  CALLS:
  0x15a7c7  strcmp(rdi='help', rsi=[arg1_entry+0x0])
  0x15a840  strcmp(rsi='--temp-path')
  0x15a892  fm_exec_cli(rdi='/bin/stress-ng', rsi=arg0_entry, rdx=arg1_entry)  *** SINK (cmd-exec) ***
  0x15a8b6  fm_exec_cli(rdi='/bin/stress-ng', rsi=arg0_entry, rdx=arg1_entry)  *** SINK (cmd-exec) ***
```

Sink detection: default `_DEFAULT_SINKS` covers strcpy/strcat/sprintf/vsprintf/system/popen/execv*/Tcl_Eval
variants + fm_exec_cli. `custom_sinks` adds target-specific entries. `FuncProfile.sink_calls` returns
only the sink-hitting calls.

### New: PatternLibrary

`ablation/analyzers/pattern_library.py` -- persistent registry of successful semantic search patterns.

Stores query strings at `~/.ablation/patterns.json` with confirmed hit tracking per binary.
Pre-seeded with 12 default patterns covering buffer-overflow, cmd-exec, tcl-inject, path-traversal,
heap-overflow, timing-side-channel, and cmd-inject classes.

```python
pl = PatternLibrary()
print(pl.list())          # table: tag, confirmed hits, total hits, query

# Run all patterns against a SemanticSearcher (corpus already built):
results = pl.sweep(searcher, top_k=5, min_score=0.3)
print(pl.fmt_sweep(results, binary_name='libcdb.so'))

# Record a confirmed finding:
pl.record_hit('strcpy with user-controlled src', binary='libcdb.so', va=0x12ebc6, confirmed=True)
pl.save()

# Add target-specific pattern:
pl.add('CLI handler passes argv directly to fm_exec_cli without sanitization', tag='cmd-exec')
```

Pattern registry accumulates over time -- hit rates guide which patterns to run first on new binaries.

### New: IPRegAnnotator

`ablation/analyzers/ipreg_annotator.py` -- interprocedural register annotator (N-hop forward symbolic pass).

Follows call chains across function AND library boundaries, carrying RegVal arg states at
each callee entry. At each callee, seeds entry registers from the caller's register state at
the call site rather than generic argN placeholders.

```python
from ablation.analyzers.ipreg_annotator import IPRegAnnotator

# Single-binary, 2 hops:
ira = IPRegAnnotator.from_context(ctx)
chain = ira.annotate_chain(entry_va=0x412f4, max_hops=2)
print(chain.fmt())

# Cross-binary with LibGraph:
ira = IPRegAnnotator.from_context(ctx, lib_graph=lg)
chain = ira.annotate_chain(entry_va=0x412f4, max_hops=2)

# Sink report across entire chain:
SINKS = {'Tcl_Eval', 'strcpy', 'fm_exec_cli', 'system'}
print(chain.sink_report(SINKS))
```

Validated: 2-hop cross-binary chain from libfmgsvrd.so:0x412f4 automatically traces
libdmapi.so:conf_ctx_set_cli -> libcdb.so:__cdb_obj_ctx_init -> Tcl_Eval at 0x12e9e7.
Also reveals: conf_parse_file (0x413cd) calls yyparse/yylex yacc grammar parser --
the FGFM config file is parsed through a grammar before reaching the Tcl evaluator.

---

## v1.6.0 (2026-09-21)

### New: LibGraph

`ablation/analyzers/lib_graph.py` -- cross-binary import/export matrix.

Load all .so files in a firmware directory once, build a unified index over every
library, then query callers/exporters/imports across the entire set in a single call.
Backed by BinaryContext per binary (cache benefits fully apply).

```python
lg = LibGraph.from_dir('/tmp/fmg800/rootfs/usr/lib/')
# or
lg = LibGraph.from_paths([lib1, lib2, lib3])

lg.callers_of('conf_ctx_set_cli')
# -> [LibCaller(binary='libfmgsvrd.so', caller_va=0x412f4, fn='0x412f4'),
#     LibCaller(binary='libdmserver.so', caller_va=0x9951d, fn='svc_dmworker_diff_handler_')]

lg.defined_in('conf_ctx_set_cli')       # -> [('libdmapi.so', 0x5aee0)]
lg.imports_of('libfmgsvrd.so')          # -> ['conf_ctx_set_cli', 'conf_parse_devinfo', ...]
lg.exports_of('libdmapi.so')            # -> ['conf_ctx_set_cli', 'dm_devinfo2dvmdev', ...]
lg.call_chain('libfmgsvrd.so', 'Tcl_Eval')  # BFS cross-library chain
print(lg.summary())                     # table: binary x exports/imports/edges
```

Resolves the multi-session pattern of building separate BinaryContext objects and manually
correlating callers across libraries. One `LibGraph.from_dir()` replaces N per-binary queries.

### New: RegAnnotator

`ablation/analyzers/reg_annotator.py` -- lightweight forward symbolic register pass.

Single forward pass through a function window tracking register assignments
(mov/lea/xor/call) and annotating call sites with inferred argument register values.
No Z3, no lattice. Recovers ~85% of arg values in typical firmware dispatch functions.

```python
ra = RegAnnotator.from_path('/path/to/binary')
result = ra.annotate_calls(func_va=0x15a78a, func_end_va=0x15a8ef)

for call in result.calls:
    print(f"0x{call.site_va:x}: call {call.target_name}")
    for reg, val in call.args.items():
        if val.kind != 'unknown':
            print(f"  {reg} = {val.display()}")

print(result.fmt())  # full formatted block
```

Example output for stress handler (libcmfplugin.so 0x15a78a):
```
0x15a892: call fm_exec_cli
  rdi = '/bin/stress-ng'  (0x1a5e40 via r13)
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

`ablation/analyzers/binary_context.py` -- pre-computed binary context cache.

Build once (~0.5s for a 24MB ELF), cache to `~/.ablation/cache/`, reload in <110ms.
Captures: PLT symbol map, exported functions, .rodata strings, function start VAs,
full call graph as (from_va, to_va, label) edges.

```python
ctx = BinaryContext.load_or_build('/path/to/binary')

ctx.plt[0x256f0]                     # -> 'conf_ctx_set_cli'
ctx.callers_of('conf_ctx_set_cli')   # -> [(0x412f4, '0x412f4')]
ctx.callees_of(0x412f4)              # -> full call sequence for the function
ctx.strings_near(0x9b120, radius=64) # -> [(..., '__conf_ctx_from_file')]
ctx.func_containing(0x41366)         # -> 0x412f4 (binary search over sorted starts)
print(ctx.summary())                  # session-start context block
```

Validated on libfmgsvrd.so (24MB): 0.51s build, 0.109s cache reload, 1115 PLT entries,
498 exports, 2851 strings, 12357 call edges. `callees_of(0x412f4)` returns the full
`__conf_ctx_from_file` call sequence in one query -- what previously required a full
session of manual tracing.

Cache invalidation: SHA256 mismatch triggers rebuild. Safe across firmware versions.

---

## v1.5.1 (2026-09-21)

### TaintTracker: custom sinks + seeded entry analysis

`custom_sinks` and `custom_sink_vas` constructor parameters add target-specific
functions to the sink table without modifying the default list.

`run_on_function_seeded(func_va, seed_arg_indices)` seeds entry argument registers
as tainted before analysis begins -- handles CLI handler functions where taint
originates from the caller (entry args) rather than from recv/read calls.

```python
tt = TaintTracker(binary, xref=xg,
    custom_sinks={'fm_exec_cli': [2]})
findings = tt.run_on_function_seeded(
    func_va=0x15a78a, func_end_va=0x15a8ef,
    seed_arg_indices=[1])
# -> 2 findings: fm_exec_cli(arg2) at 0x15a892, 0x15a8b6
```

Changes are backward-compatible: all new parameters default to None.

---

## v1.4.0 (2026-09-21)

### New: WindowAnalyzer

`ablation/analyzers/window_analyzer.py` -- LLM-native bulk disassembly window.

One capstone call over a configurable region (default 1536 bytes) with inline annotation of:
- PLT call targets via `.rela.plt` (handles `.plt.sec` CET stubs, `.plt`, `.plt.got`)
- `.rodata` string references via RIP-relative addressing
- Function start candidates via endbr64 detection

Primary interface:

```python
wa = WindowAnalyzer.from_path('/path/to/binary')
print(wa.dump_text(va=0x41366, window=1536, align_back=256))
calls = wa.calls_in_window(va=0x41366, window=1536, align_back=256)
starts = wa.find_func_starts(va=0x41000, window=2048)
```

Motivation: per-instruction tracing requires N round trips through the disassembly pipeline.
A 1.5KB annotated dump returns a complete function-boundary-visible region for one-pass
pattern recognition -- the natural unit for LLM-assisted RE.

### FortiManager 8.0.0 findings update

- **FMG-F99** (`conf_ctx_set_cli`): network reachability confirmed via FGFM protocol (port 541).
  Full chain: FGFM config diff from managed FortiGate -> `__conf_ctx_from_file` (libfmgsvrd.so 0x412f4)
  -> `conf_ctx_set_cli` (libdmapi.so PLT 0x256f0, call site 0x41366) -> Tcl_Eval (hop 1).
  Also reachable via `svc_dmworker_diff_handler_` (libdmserver.so, documented in FMG-F101).

- **FMG-F106** (`__cdb_obj_ctx_init`): full FGFM call chain documented. Added `network_reachability`
  field with complete path from FGFM to strcpy at 0x12ebc6 (Tcl heap string write). Attack surface:
  compromised/spoofed managed FortiGate device sends crafted config GlobalObj list to trigger
  strcpy + Tcl injection in dmworker.

- **FMG-F107** (`exec.benchmark.stress.custom` ban bypass): HTTP-to-exec chain completed in
  prior session (v1.3.0), no changes this release.

---

## v1.3.0 (2026-09-21)

### FortiManager 8.0.0 -- FMG-F107 complete

- Full HTTP-to-exec call chain traced: JSON-RPC -> `exec.benchmark.stress.custom`
  (libcli.so CLI tree registered by `fazcore_register_exec_stress` at libcmfplugin.so 0x15a8ef)
  -> handler 0x15a78a -> fm_exec_cli at 0x15a892 / 0x15a8b6.
- Taint confirmed: entry rsi (argv) -> r12 -> rdx at both fm_exec_cli calls. Only guard:
  `--temp-path` value check. All other flags (including `--exec-prog`) pass unchecked.
- Ban bypass: stress-ng `--exec-prog <path>` forks+execs arbitrary binary outside libbanned.so sandbox.

### Infrastructure

- Ablation restructure to installable package (ablation/core + ablation/analyzers).
- Shims preserve compatibility with 665 existing modules in modules/.
