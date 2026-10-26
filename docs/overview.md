# Understanding Ablation

Ablation is a local reverse-engineering and binary-triage toolkit. Its purpose is to help an analyst make sense of stripped binaries and firmware by building useful structural context, finding functions worth inspecting, and applying targeted static analyses. The analyst or an assistant such as Codex uses those outputs to investigate and validate hypotheses. Ablation does not, by itself, prove that a candidate is exploitable.

This page describes the implementation and docs in this checkout. It is intended as a practical map of what the system does, where its components live, and how to interpret its results. The package metadata currently reports version 2.5.0; the CLI and update notes contain newer commands and architecture work than the version label and some reference pages, so check `ablation --help` and the implementation before relying on an older example.

## The analysis model

Most workflows follow this sequence:

1. Load a binary and collect structural facts: format, architecture, segments, imports/PLT entries, exports, strings, probable function starts, calls, and cross-references.
2. Use that context to locate code relevant to a question. This can be semantic search over function descriptions, known signatures, pattern sweeps, string/call relationships, or a specialized scanner.
3. Inspect a candidate with function profiles, instruction windows, control-flow graphs, cross-references, and architecture-specific taint/dataflow analysis.
4. Verify the path and assumptions manually against the binary, its callers, input source, guards, and runtime behavior where possible.
5. Preserve useful analyst knowledge in the local name, function-identity, pattern, or finding stores, and in the target's session notes.

Ablation is a static analysis toolkit: it reads binaries without executing them. Static analysis can examine all code paths in principle, including error paths and rarely-triggered branches, but it cannot observe actual runtime values, heap layout, or dynamically loaded libraries. The complement is dynamic analysis fuzzing, debugger tracing, instrumentation: it observes only paths that a given input triggers, but produces exact values and no false positives on executed paths. Ablation's pipeline ends at PathSolver, which is still static. Dynamic confirmation requires running the binary under instrumentation with a crafted input. That is the step that turns a PathSolver result into an observed crash.

```mermaid
flowchart LR
    A(["binary.elf"]):::input --> B["Static analysis\nAblation\nall code paths visible\nbinary never executes"]:::primary
    B:::primary --> C["TaintTracker\ncandidates"]:::secondary
    C:::secondary --> D["PathSolver\nfeasibility check"]:::tertiary
    D:::tertiary --> E(["Dynamic confirmation\nfuzzing · instrumentation\nconcrete input triggers crash"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

The tools use bounded static approximations and heuristics. A hit is a lead, a score is a ranking signal, and an apparent taint path is a model result. None should be presented as a confirmed vulnerability without validating reachability, input control, checks, sink behavior, and impact.

## Repository map

| Path | Responsibility |
|---|---|
| `ablation/cli.py` | Main `ablation` command line entry point and command dispatch. |
| `ablation/core/` | Binary/file-format helpers, disassembly engine, platform detection, firmware and protocol utilities, shellcode helpers, and exports such as YARA generation. |
| `ablation/analyzers/` | The main analysis library: binary context, xrefs, CFGs, dataflow/taint, semantic search, registries, diffing, crypto, Go analysis, kernel/heap/format-string scanners, and architecture-specific decoders. |
| `ablation/analyzers/llm_analyst/` | Optional Anthropic-backed analysis loop, context construction, retrieval, tools, and analyst tasks. It is an optional component, not required for Codex to use the CLI. |
| `ablation/export/` | JSON and SARIF serialization. |
| `ablation/integrations/` | Disassembler integrations; the current tree includes a Binary Ninja plugin. |
| `ablation/data/` | Seed finding and signature data shipped with the package. |
| `sweeps/` | A separate, older sweep implementation and report generation path. Its behavior/model should not be conflated with the main CLI's corpus and pattern path. |
| `modules/` | Standalone and target-oriented research scripts. This is not one uniform public API. |
| `targets/` | Product/vendor-specific reverse-engineering scripts and evolving session notes. These are research artifacts built using Ablation, rather than generic framework components. |
| `tests/`, `test/` | Unit tests and workflow notes. |
| `docs/` | User guides, module references, integration notes, release notes, and update notes. |

The checkout may also contain firmware, extracted filesystems, generated reports, vendor reference material, and other research artifacts. Such inputs are not all framework source, and their presence does not mean Ablation automatically analyzes them as one unified target.

## Binary context and disassembly

`BinaryContext` (`ablation/analyzers/binary_context.py`) is the common high-level context object. It uses LIEF, Capstone, NumPy, and related helpers to identify useful binary properties and construct indexes for later analysis. The context can expose summaries, function starts, names, call relationships, strings, and string references. Its cache is keyed by the binary SHA-256 under `~/.ablation/cache`, so a different build does not silently reuse the same cached context merely because its filename matches.

Function boundaries and references are inferred. The implementation combines format metadata, exported symbols, unwind information where available, instruction decoding, and prologue/call heuristics. Call-graph and string-reference coverage depends on architecture and instruction forms; direct-call scans do not magically resolve arbitrary indirect calls. Treat the indexes as navigation aids and inspect the actual instructions for consequential claims.

The core package contains ELF, PE, and Mach-O-related support, while analysis coverage is not identical across formats and architectures. The main context and much of the workflow are ELF-oriented. The architecture-specific analyzer and decoder modules implement different subsets of decoding, CFG construction, function discovery, and taint analysis. “Supports architecture X” should therefore be read as support by particular commands/components, not a guarantee that every feature has equivalent coverage on every ISA.

```mermaid
flowchart TD
    A(["binary (ELF · PE · flat ROM)"]):::input --> B["LIEF\nformat detection\narch · segments · imports · exports · strings"]:::primary
    B:::primary --> C["Capstone\ninstruction decode\nfunc_starts via DWARF .eh_frame + prologue scan\ncall_edges via vectorized numpy scan"]:::secondary
    C:::secondary --> D["BinaryContext\nplt: {va → symbol}\nstrings: {va → content}\nfunc_starts: sorted VA list\ncall_edges: [(from, to, label)]\n_callers_idx / _callees_idx built once"]:::tertiary
    D:::tertiary --> E["~/.ablation/cache/<sha256[:16]>_name.json\nkeyed by SHA-256 of binary bytes\nreloads in under 100ms"]:::tertiary
    E:::tertiary --> F(["Shared by every tool\nSemanticSearcher · FuncProfiler · TaintTracker\nWindowAnalyzer · VersionDelta · MatrixProfileDiff"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

This is a binary analysis toolkit, not a general source-level decompiler equivalent to a full interactive commercial or open-source reverse-engineering suite. It offers disassembly, structural analysis, matching, and targeted analysis features; users should inspect each command's actual output and scope.

## Finding candidate functions

### Corpus construction and semantic search

`CorpusBuilder` gathers a textual description for functions and persists function identity/context in a SQLite database, normally `~/.ablation/func_id.db`. Descriptions can include names, inferred role, callees, strings, and analyst notes. `SemanticSearcher` embeds those descriptions and ranks them against natural-language queries. The default model in the implementation is `sentence-transformers/all-mpnet-base-v2`.

This is semantic similarity over the description corpus, not a direct semantic understanding of arbitrary machine code. In particular, the normal corpus description path does not automatically include a full instruction sequence or invoke angr for every function. A high score says the indexed description resembles the query; it does not establish that the function has the queried behavior. Signature data and analyst-provided names improve context but are also evidence to verify.

`SemanticSearcher` works by vector similarity over function descriptions, not by understanding machine code. `CorpusBuilder` generates a textual description for each function names, callees, strings, inferred role and embeds it with `sentence-transformers/all-mpnet-base-v2`. A search query is embedded with the same model and the closest functions by cosine distance are returned. A high score means the function's description resembles the query. It does not mean the function has the queried behavior.

Two consequences follow from this. First, a function with no symbols, no recognizable strings, and no known callees produces a thin description and matches poorly regardless of what the function actually does. Second, a function named `copy_data` that calls `memcpy` ranks high for "buffer copy" even if it is safe. Semantic search narrows the candidate list. `FuncProfiler` and `TaintTracker` determine what the candidates actually do.

```mermaid
flowchart TD
    A(["stripped binary"]):::input --> B["CorpusBuilder\nnames · callees · strings · inferred role\none description per function"]:::primary
    B:::primary --> C["sentence-transformers\nall-mpnet-base-v2\ndescription → 768-dim vector"]:::tertiary
    C:::tertiary --> D["~/.ablation/func_id.db\nvector index"]:::tertiary
    E(["query: 'network-controlled length\nreaches allocation or copy'"]):::input --> F["embed query\nsame model"]:::secondary
    F:::secondary --> G["cosine similarity\nagainst index"]:::tertiary
    D:::tertiary --> G:::tertiary
    G:::tertiary --> H(["ranked candidates\nfn_0x1234 · copy_field · parse_pkt"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#6a1b9a,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#00695c,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
```

`PatternLibrary` stores confirmed textual search patterns in a local JSON file under `~/.ablation`. A pattern is a natural-language description string confirmed to match a vulnerable function class. The `sweep` command applies every registered pattern against the current corpus and returns ranked candidates. The difference from `SemanticSearcher.query()` is persistence: a query runs once for the current session; a pattern persists to disk, records every confirmed hit, and replays automatically on every future target that runs `ablation sweep`. When a buffer overflow is confirmed in a Cisco router, the pattern that found it applies to every subsequent target without re-typing the query. `PatternLibrary.record_hit(confirmed=True)` updates the hit record so sweep scores calibrate over time.

A separate legacy `sweeps/base_sweep.py` path has its own extraction and embedding behavior including a different model. Do not assume it is interchangeable with `ablation sweep` without checking which entry point is running.

### Function profiling

`FuncProfiler` bridges the gap between a semantic search result and a TaintTracker run. SemanticSearcher returns a ranked list of candidate VAs. FuncProfiler collects all the context needed to decide whether a candidate is worth tracing: every call site with argument register values annotated, every string reference in the function, and a `*** SINK ***` flag on any call to a dangerous function. Without FuncProfiler, the same information requires four separate calls: `callees_of()`, `dump_text()`, `RegAnnotator`, and a string lookup. FuncProfiler runs all four in one call and formats the output so sink calls stand out immediately.

The argument annotation uses `RegAnnotator`, which traces each argument register backward from the call site for up to 20 instructions to determine its value. A string literal loads from `.rodata` and RegAnnotator labels it with the actual string content. An entry argument passes through unmodified and RegAnnotator labels it `arg0_entry` or `arg1_entry`. A return value from a prior call gets labeled `retfuncname`.

```mermaid
flowchart TD
    A(["SemanticSearcher\ncandidate VAs"]):::input --> B["FuncProfiler.profile(va)"]:::primary
    B:::primary --> C["RegAnnotator\ntrace each arg register\n≤20 instructions backward per call site"]:::secondary
    C:::secondary --> D(["string literals\n.rodata loads → actual content\narg0_entry · arg1_entry · ret(name)"]):::output
    B:::primary --> E(["call site list\nwith annotated arguments"]):::output
    B:::primary --> F["*** SINK *** flags\ndangerous arg is arg1_entry\nor comes from recv return value"]:::tertiary
    F:::tertiary --> G{"proceed to\nTaintTracker?"}:::neutral
    G:::neutral -->|"sink arg is entry arg\nor tainted return"| H(["run_interprocedural(depth=4)"]):::output
    G:::neutral -->|"sink arg is RODATA_CONST"| I(["SinkArgClassifier confirms safe\nskip this call site"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#546e7a,stroke-width:2px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
```

A profile output showing `*** SINK cmd-exec ***` where the dangerous argument is labeled `arg1_entry` means a function parameter flows directly into a dangerous call. That is the input that makes `TaintTracker.run_interprocedural()` worth running.

### Names, identities, and findings

- `NameRegistry` stores analyst or inferred names keyed by binary identity in `~/.ablation/function_names.json`.
- `FuncIdDB` stores function records and cross-build identity/context in SQLite. Confidence labels distinguish confirmed identities from inferred/candidate records.
- `SigLibrary` applies shipped signatures to help identify functions.
- `FindingRegistry` stores finding records in a local SQLite database and can retrieve related prior records using embeddings.

These are local analyst knowledge stores, not necessarily shared/team databases. Keep private target data and sensitive finding details in mind when exporting or sharing them. A name or registry record is a useful annotation, not independent proof.

## Triage and program analysis

The CLI provides several levels of inspection:

- `analyze`: summarize the binary and optionally inspect entropy.
- `window`: print an annotated instruction window near an address, with optional calls/function starts.
- `profile`: collect function-level context such as strings, call-site arguments, and sink-like calls.
- `cfg`: build and print a function's basic blocks and edges, optionally including instructions.
- `search`, `corpus`, and `sweep`: build/query the semantic corpus and run registered patterns.
- `taint` and the architecture-specific taint commands: trace modeled input values through supported instruction and call behavior toward selected sinks.
- `overflow`, `fmtstr`, `heap`, `driver`, `byovd`, and `crypto`: run more specialized scans.
- `findings`, `sigs`, and `news`: inspect registry, signatures, or update information.

**Source/sink model.** Taint analysis requires two definitions: a source and a sink. A source is a function whose return value or output buffer carries attacker-controlled data. A sink is a function that is dangerous when called with that data. The analysis finds paths from sources to sinks. If no configured sink is matched in the binary, the analysis returns no findings. This is not a clean result: it means no matched sink was found, not that the binary is safe.

Default sources include `recv`, `recvfrom`, `read`, `fgets`, and `gets`. Default sinks include `system`, `popen`, `execve`, `strcpy`, `strcat`, `sprintf`, `memcpy`, and `malloc`.

Firmware wraps standard library functions in vendor-specific wrappers. A binary that calls `vendor_exec_cmd(input)` instead of `system(input)` produces zero findings because `vendor_exec_cmd` is not in the sink table. `SinkPropagator` discovers these wrapper chains automatically. `custom_sinks=` adds specific wrappers directly.

`SinkArgClassifier` classifies each sink argument before the interprocedural pass. `RODATA_CONST` means the argument is a hardcoded string and the sink is not dangerous at that call site. `ARG_PROPAGATED` means the argument comes from a function parameter and is worth tracing. Running `SinkArgClassifier` before `TaintTracker` eliminates call sites where the dangerous argument is provably constant, so the interprocedural pass only runs on sites where the value is actually attacker-influenced.

```mermaid
flowchart TD
    A(["recv · recvfrom · read\nfgets · gets"]):::input -->|"return value tainted"| B["TaintTracker\nforward slice"]:::primary
    B:::primary --> C["SinkPropagator\ndiscover vendor wrappers\nadd to sink table"]:::secondary
    C:::secondary --> D["SinkArgClassifier\nclassify each sink call site"]:::tertiary
    D:::tertiary -->|"RODATA_CONST\nhardcoded string"| E(["skip\nnot attacker-controlled"]):::output
    D:::tertiary -->|"ARG_PROPAGATED"| F["run_interprocedural()\nfollow taint across call graph"]:::tertiary
    D:::tertiary -->|"UNKNOWN"| F:::tertiary
    F:::tertiary -->|"taint reaches sink"| G(["Finding\nsource · chain · sink · arg"]):::output
    F:::tertiary -->|"no path found"| H(["no finding\ncheck SinkPropagator coverage"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
```

**Control flow and data flow.** The `cfg` command builds a Control Flow Graph (CFG): nodes are basic blocks, edges are possible branches. This is control flow analysis. It answers whether one instruction can execute after another. It says nothing about what values the registers hold. Taint analysis is data flow analysis built on top of a CFG: it propagates facts tainted or clean along CFG edges through each instruction's transfer function. `dataflow_engine.py` provides the shared CFG worklist and fixed-point machinery; architecture modules define the transfer functions. Correctness depends on the modeled instruction subset, the calling convention model, and CFG recovery quality.

The data flow analysis runs to a fixed point: it propagates facts around the CFG until the taint sets stop changing. For straight-line code this converges in one pass. For loops, the analysis revisits the loop body each time new taint facts appear. When a loop's taint state changes at each iteration, the analysis widens the taint state after a fixed number of passes and forces convergence by treating everything as tainted. The known-anomalies docs refer to this as the "loop fixpoint" limitation. It is conservative: the analysis terminates but may report taint in a register that is only tainted on some loop iterations.

```mermaid
flowchart TD
    A(["Block A\nr3 = recv()\nr3 = TAINTED"]):::input -->|"r3 = TAINTED"| B{"Block B\nbranch on r3 > 0"}:::neutral
    B:::neutral -->|"yes · TAINTED"| C["Block C\nprocess(r3)"]:::primary
    B:::neutral -->|"no · TAINTED"| D(["Block D\nreturn -1"]):::output
    C:::primary -->|"r3 = TAINTED"| E(["Block E\nstrcpy(dst, r3)\nFINDING"]):::output

    note(["Control flow: are B→C and B→D reachable?\nData flow: is r3 tainted at Block E?\nBoth answers come from the same CFG.\nThe CFG provides the paths; the taint facts travel the edges."]):::input
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#546e7a,stroke-width:2px
    linkStyle 1 stroke:#bf360c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

**Flow sensitivity vs path sensitivity.** Flow-sensitive analysis tracks the order of operations: `r3 = recv(); r3 = 0; system(r3)` produces no finding because the clean assignment came after the taint. Flow-insensitive analysis ignores order and flags a finding regardless of sequence.

Path-insensitive analysis merges facts from all branches when they join:

```mermaid
flowchart TD
    A(["entry"]):::input --> B{"x > 0?"}:::neutral
    B:::neutral -->|"yes"| C["r3 = recv()\nr3 = TAINTED"]:::primary
    B:::neutral -->|"no"| D["r3 = 0\nr3 = CLEAN"]:::secondary
    C:::primary --> E["merge point\npath-insensitive: r3 = TAINTED\npath-sensitive: TAINTED on yes-path only"]:::tertiary
    D:::secondary --> E:::tertiary
    E:::tertiary --> F(["system(r3)\npath-insensitive: FINDING\npath-sensitive: PathSolver filters this"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#546e7a,stroke-width:2px
    linkStyle 1 stroke:#bf360c,stroke-width:2px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

A path-sensitive analysis would track each branch separately and know `r3` is only tainted on the `x > 0` path. Tracking separate facts per path costs exponential time in the number of branches, so it does not scale to firmware binaries.

Ablation's trackers are flow-sensitive and path-insensitive. Findings at branch merge points may be false positives: taint from one branch appears to reach a sink that is only reachable on the other branch. PathSolver is the follow-up step that filters these by checking whether the tainted branch conditions are actually satisfiable.

**Intraprocedural vs interprocedural.** Intraprocedural analysis stays within one function and treats every callee as a black box. It misses paths where taint passes through a callee before reaching a sink in the caller. `run_interprocedural(depth=N)` follows taint across call boundaries with a BFS over the call graph. At the default `depth=4` it traces chains like `recv → parse_header → copy_field → strcpy`. Ablation's interprocedural analysis is context-insensitive: it computes one taint summary per function and reuses it at every call site. This is the correct tradeoff for stripped firmware where the call graph is uncertain. Intraprocedural mode (`run()` or `scan_function()`) is appropriate when a bounded scan of a confirmed candidate function is enough.

```mermaid
flowchart TD
    subgraph "Intraprocedural (run)"
    I1(["process_input(data)\nr3 = data\nr3 = TAINTED"]):::input --> I2["sanitize(r3)\ncallee treated as black box\nreturn value: CLEAN (assumed)"]:::primary
    I2:::primary --> I3(["strcpy(dst, r0)\nr0 = CLEAN\nno finding"]):::output
    end
    subgraph "Interprocedural (run_interprocedural depth=4)"
    P1(["process_input(data)\nr3 = data\nr3 = TAINTED"]):::input --> P2["sanitize(r3)\ndescend into callee"]:::secondary
    P2:::secondary --> P3["sanitize body:\nreturn r3\nreturn value: TAINTED"]:::tertiary
    P3:::tertiary --> P4(["strcpy(dst, r0)\nr0 = TAINTED\nFINDING"]):::output
    end
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

**Calling conventions and ABI.** A calling convention defines which registers hold function arguments, which holds the return value, which the callee must preserve callee-saved, and which the callee may freely clobber caller-saved. Every taint tracker embeds a calling convention model. When `run_interprocedural()` reaches a call site, it uses the convention to determine which registers carry tainted arguments into the callee, which register holds the return value, and which caller-saved registers the callee may have clobbered.

Getting this wrong produces silent incorrect results. A big-endian MIPS32 binary analyzed with `endian='little'` decodes every instruction's register fields incorrectly. An RH850 binary compiled with GHS `double=32-bit` default analyzed with the GCC `double=64-bit` model shifts argument registers for any function with a `double` parameter. The `arch=`, `endian=`, and `double_is_32bit=` parameters control which registers the ABI model assigns to argument positions. For stripped binaries with no symbol information, calling-convention mismatches produce findings at wrong VAs with wrong argument registers cited, which fail byte-verification.

```mermaid
flowchart LR
    A(["call site:\nstrcpy(r0, r1)"]):::input --> B["ABI model:\nwhich register is arg0 (dest)?\nwhich is arg1 (src)?"]:::primary
    B:::primary -->|"ARM32 AAPCS\nr0=dest · r1=src"| C(["check r1 for taint\ncorrect finding"]):::output
    B:::primary -->|"MIPS32 O32\na0=dest · a1=src\n(r4 · r5)"| D(["check r5 for taint\ncorrect finding"]):::output
    B:::primary -->|"wrong endian\nor wrong ISA set"| E(["wrong register decoded\nsilent incorrect result\nfails byte-verification"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

**Slicing and copy propagation.** A taint tracker computes a forward slice from a source: it tracks which registers and memory locations are reachable from `recv` and checks whether any path reaches a sink. Copy propagation makes register renaming transparent. Every `mov rd, rs` propagates taint from `rs` to `rd`. Without it, a tracker watching only the original source register misses the sink the moment the value is renamed. Some instructions clear taint because they bound the value to a fixed range. `uxtb`/`uxth` on HiSilicon RV32 bound a register to ≤255 or ≤65535. `andi rd, rj, mask` on LoongArch64 records the bound so PathSolver can check whether overflow is still possible past the mask. Address constants are not tainted because they load instruction addresses, not attacker-controlled data.

```mermaid
flowchart LR
    A(["r3 = recv()\nr3 = TAINTED"]):::input --> B["r5 = r3\nr5 = TAINTED\ncopy propagation"]:::primary
    B:::primary --> C["r6 = r5 + 1\nr6 = TAINTED\narithmetic"]:::secondary
    C:::secondary --> D["r7 = r6 & 0xFF\nr7 = TAINTED\nbound ≤ 255 recorded"]:::tertiary
    D:::tertiary --> E(["strcpy(dst, r7)\nFINDING\nbounds check needed"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

**Alias analysis.** Register taint is precise: each register is a distinct name and the tracker follows renames exactly. Memory taint is harder because two pointers can reference the same address. A store through one pointer taints a memory location; a load through a different pointer that holds the same address should recover that taint. Determining whether two pointer expressions alias requires alias analysis.

Ablation's trackers track memory taint at the level of base-register and offset pairs: a store to `r3 + 8` taints the slot `(r3, 8)` and a load from `r3 + 8` later in the same function recovers it. This handles struct field accesses. It does not handle aliased pointers: if `r5` holds the same address as `r3 + 8`, a load from `r5` does not recover the taint stored through `r3 + 8`.

This is why `readfd, buf, n` taints `r3` the byte count returned but not the buffer. The buffer is written through a pointer in `r4`. Tracking taint into the buffer requires following all loads from any pointer that might alias `r4`. The return-value taint model instead finds paths where the byte count reaches a size argument of `malloc` or `memcpy`, which is a distinct and common vulnerability class.

```mermaid
flowchart TD
    A(["st.d r5, r3+8\ntaints slot (r3, 8)"]):::input --> B{"load from where?"}:::neutral
    B:::neutral -->|"ld.d r6, r3+8\nsame base+offset"| C(["r6 = TAINTED\ntaint recovered"]):::output
    B:::neutral -->|"ld.d r6, r5+0\nr5 may alias r3+8\nbut tracker does not know"| D(["r6 = CLEAN\nalias not tracked\nmissed taint"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#546e7a,stroke-width:2px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
```

**Taint analysis vs symbolic execution.** Taint analysis answers whether attacker data can reach a sink. It does not answer whether the attacker can trigger that path or what value would be needed. `PathSolver` is symbolic execution: it assigns symbolic variables to source values, accumulates path constraints at each branch, and asks a constraint solver whether any concrete input satisfies all constraints. Taint produces candidates with false positives. PathSolver confirms one candidate with no false positives. PathSolver does not scale to a whole binary because branches multiply the paths that must be explored exponentially. The correct order is `TaintTracker.run_interprocedural()` on the whole binary to build the candidate list, then `PathSolver.solve_path()` on one candidate.

```mermaid
flowchart TD
    A(["binary.elf"]):::input --> B["TaintTracker.run_interprocedural()\nforward slice from all sources\npath-insensitive · scales to whole binary"]:::primary
    B:::primary --> C["candidate list\ne.g. 30 functions · 12 source-sink paths\nmay include false positives"]:::secondary
    C:::secondary --> D{"for each candidate"}:::neutral
    D:::neutral --> E["PathSolver.solve_path()\nsymbolic execution on one function\nZ3 constraint solver"]:::tertiary
    E:::tertiary -->|"satisfiable"| F(["confirmed path\nconcrete input exists"]):::output
    E:::tertiary -->|"unsatisfiable"| G(["false positive\nbranch guards block path"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#546e7a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

The x86 taint family includes intraprocedural and interprocedural modes, with a flow-sensitive CFG/MFP mode exposed by the CLI. Other ISA implementations have their own ABI assumptions, sink/source sets, and analysis limits. The CLI currently routes generic `taint` to ARM32 when detected and otherwise to its x86 tracker; other architectures have explicit commands. Always consult `ablation --help` and the command's implementation for routing and coverage.

## Cross-version diffing

Firmware vendors patch vulnerabilities without publishing diffs. The patched function moves to a new VA, loses its symbol, and may gain or lose basic blocks. Porting a name overlay or confirmed finding from build N to build N+1 requires matching functions by structure, not address.

Three tools answer three distinct questions. DTWMatcher answers whether two functions are from the same implementation era. MatrixProfileDiff identifies the most changed region when the answer is "patched." VersionDelta produces the unified diff and locates where the function moved.

```mermaid
flowchart TD
    A(["confirmed function\nva=0x4000 in v1"]):::input --> B["DTWMatcher.find_homologs(va_v1)\npre-filter by opcode histogram\nrun DTW on top 200 candidates"]:::primary
    B:::primary -->|"same_era ≥ 0.85\nrecompiled, no logic change"| C(["port name overlay directly\nctx.set_name(va_v2, name)"]):::output
    B:::primary -->|"patched 0.45-0.85\nlogic changed"| D["MatrixProfileDiff.compare_functions()\nSTOMP: find most changed subsequence\nanomaly region = new bounds check / removed block"]:::secondary
    D:::secondary --> E(["VersionDelta.track(va_v1)\nstage 1: structural pre-filter\nstage 2: 4-gram Jaccard\nstage 3: BERT tiebreaker if tie\noutput: unified diff"]):::output
    B:::primary -->|"rewritten < 0.45\nstructural rewrite"| F(["VersionDelta.changed_functions()\nrank all changed functions\nchange_score ≥ 0.20 = meaningful change"]):::output
    B:::primary -->|"different < 0.20\nunrelated"| G(["function may be split · merged · removed\ncheck VersionDelta.changed_functions()"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

**DTWMatcher.** DTWMatcher uses Dynamic Time Warping over opcode category sequences. Opcode categories are a 12-bucket classification DATA, ARITH, BIT, CMP, BRANCH, CALL, RET, FRAME, MEMOP, FLOAT, SIMD, OTHER that normalizes away ISA-specific encoding differences. DTW is warp-invariant so it handles insertions and deletions of basic blocks that Jaccard penalizes unfairly. A function that gained one bounds-check block between firmware versions scores ~0.91 DTW versus ~0.65 4-gram Jaccard because DTW stretches the alignment to absorb the inserted block and scores the structural remainder as a match. The Sakoe-Chiba band default 20% of sequence length prevents pathological alignments where a 5-instruction stub matches a 200-instruction function.

`find_homologs()` pre-filters all functions in the target binary by opcode histogram L1 distance, then runs full DTW only on the top 200 candidates. Verdict thresholds are `same_era` (≥0.85), `patched` 0.45–0.85, `rewritten` 0.20–0.45, `different` (<0.20).

**VersionDelta.** VersionDelta localizes the change after a homolog is found. Stage 1 eliminates candidates whose basic block count or edge count differ by more than ±2 or ±30%. Stage 2 ranks survivors by mnemonic 4-gram Jaccard with addresses and immediates normalized to zero. Stage 3 applies SemanticSearcher BERT embeddings to break ties when the top two candidates are within 0.05 Jaccard. The output is a `difflib`-style unified diff with addresses and RIP-relative immediates stripped, so the diff shows only logic changes.

`changed_functions()` scores all functions between two builds and ranks by `change_score`. Functions with `change_score ≥ 0.20` had meaningful code changes, not just recompilation address shifts. This is the entry point for finding what a vendor actually fixed in a firmware update.

**MatrixProfileDiff.** When the change is a multi-instruction insertion or deletion, the inserted region appears as a subsequence in v2 with no close neighbor in v1. MatrixProfileDiff runs STOMP (O(n log n)) to find the region of T1 whose nearest match in T2 is most distant. That region is what changed. STOMP is better than VersionDelta's difflib output for inserted bounds checks 3–5 new instructions in a loop body or removed authentication blocks.

**StructuralSim.** StructuralSim computes a five-signal composite score opcode histogram, immediate value Jaccard, PLT overlap, branch density, size proximity for cross-vendor comparison. Immediate value Jaccard is the key signal because struct field offsets, magic constants, and buffer sizes survive recompilation and optimization. A composite score ≥ 0.70 across two vendors' binaries predicts a shared codebase ancestor. When one vendor's version has a confirmed vulnerability, that score predicts whether the other vendor carries the same flaw.

## Crypto and entropy analysis

Firmware images arrive encrypted or compressed. Before analyzing binary code you need to know which regions are encrypted, recover any encryption keys, and identify cryptographic algorithm implementations inside the code.

```mermaid
flowchart TD
    A(["firmware.bin"]):::input --> B["EntropyMapper\nsliding-window Shannon entropy\nH 8.0 = encrypted · compressed\nH 4.0-6.0 = code · data\nH 0.0-4.0 = ASCII · padding"]:::primary
    B:::primary --> C{"high entropy\nH above 7.5?"}:::neutral
    C:::neutral -->|"yes"| D["XorKeyRecoverer\nKPA against known plaintext\nELF magic 0x7f454c46\ngzip magic 0x1f8b08\nkey repeats at 64-byte NAND period"]:::secondary
    C:::neutral -->|"no, code region"| E["CryptoAuditor\nhardcoded keys · weak algorithms\nmode misuse: ECB, zero IV\nRC4 in 2024+ firmware"]:::tertiary
    D:::secondary --> F(["decrypted payload\nrerun EntropyMapper\nfeed to firmware extraction"]):::output
    E:::tertiary --> G(["HashAlgoDiscriminator\nK-table constants in .rodata\nSHA-1/256/512 round constants\nidentify algorithm from constant set"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#546e7a,stroke-width:2px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

**EntropyMapper.** EntropyMapper runs a sliding-window Shannon entropy scan across the binary. Shannon entropy measures information density: H = 8.0 means all 256 byte values appear with equal probability, which is the expected distribution of AES ciphertext. H between 4.0 and 6.0 is typical of compiled code. H below 4.0 indicates ASCII text or sparse data. EntropyMapper produces a region list so you can immediately identify where encrypted blobs, compressed payloads, and key material live before extracting anything.

**XorKeyRecoverer.** XorKeyRecoverer uses a known-plaintext attack. Firmware images compressed with gzip start with the magic bytes `0x1f 0x8b 0x08`. ELF binaries start with `0x7f 0x45 0x4c 0x46`. XOR-ing the encrypted bytes against the known plaintext recovers the keystream. Firmware stored on NAND flash uses a repeating XOR key aligned to the 64-byte NAND page boundary.

**CryptoAuditor.** CryptoAuditor scans code regions for cryptographic misuse patterns: hardcoded AES keys, ECB mode identical 16-byte output blocks from identical input, IV set to zero for CBC mode, and RC4 usage in products shipping after 2015.

**HashAlgoDiscriminator.** HashAlgoDiscriminator finds hash algorithm K-table constants in `.rodata`. SHA-1, SHA-256, and SHA-512 each use unique round constant arrays that are stable across compiler versions and optimization levels. A match identifies the algorithm without disassembling the implementation.

## Firmware extraction

Vendor firmware uses proprietary container formats and layered encryption. `binwalk` and `unsquashfs` fail silently on non-standard XZ filters and encrypted containers. The firmware extraction modules handle these cases.

```mermaid
flowchart TD
    A(["encrypted.bin or .out"]):::input --> B["Stage 1: outer XOR\nKPA against ELF 0x7f454c46\nkeystream[0:4] = encrypted[0:4] XOR known_plain\nkey repeats at 64-byte period"]:::primary
    B:::primary --> C["partially decrypted binary"]:::secondary
    C:::secondary --> D["Stage 2: PKCS#1 v1.5 block scan\n0x00 0x02 nonzero bytes 0x00 message\n256-byte RSA-2048 encrypted RC4 session key\n128 bytes from cert partition start"]:::tertiary
    D:::tertiary --> E["Stage 3: RC4 KPA\ngzip magic 0x1f8b0800\nkeystream[0:4] = encrypted XOR magic\nfull session key recovered via PRGA inversion"]:::tertiary
    E:::tertiary --> F(["decrypted payload\nfilesystem image · ELF binaries\n/etc/shadow · SSH host keys"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

**FirmwareContainerKeyExtractor.** FirmwareContainerKeyExtractor runs the three-stage key recovery chain as one call: outer XOR layer, PKCS#1 v1.5 block scan, RC4 known-plaintext attack. The chain targets formats where each stage produces partial plaintext that unlocks the next stage.

**HuaweiSquashfsExtractor.** Huawei VRP v600R024 and later use the ARM64 BCJ XZ filter (filter ID 0x0A) rather than the x86 BCJ filter (0x04). Standard `unsquashfs` cannot handle the ARM64 filter so extraction silently fails and produces an empty filesystem. HuaweiSquashfsExtractor handles the ARM64 BCJ filter without external tool dependencies.

Container format extractors for AMI, CRAMFS, BFF, AppleDouble, and Guardian PAK each handle a specific vendor format that generic tools do not recognize.

## Specialized vulnerability scanners

TaintTracker finds paths from network sources to dangerous sinks. The specialized scanners find specific vulnerability classes using targeted detection methods that are faster than a full taint pass.

```mermaid
flowchart TD
    A(["binary function"]):::input --> B["FormatStringScanner\nfind printf-family call sites\nfmt register: RDI for printf\nRSI for fprintf · syslog\nRDX for snprintf"]:::primary
    B:::primary --> C["backward slice from fmt register\nup to 20 instructions"]:::tertiary
    C:::tertiary -->|"LEA from .rodata\nstring literal"| D(["safe\nnot a finding"]):::output
    C:::tertiary -->|"function arg register\nstack load · recv return"| E(["FINDING\nHIGH: arg from entry register\nMEDIUM: provenance unclear"]):::output

    A:::input --> F["DeprecatedFuncScanner\nPLT scan for unsafe symbols\ngets · strcpy · sprintf · mktemp · rand"]:::secondary
    F:::secondary --> G(["FINDING per call site\nwith replacement recommendation"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#6a1b9a,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#00695c,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

**FormatStringScanner.** FormatStringScanner identifies format string vulnerabilities by tracing the fmt argument register backward from each printf-family call site. The fmt register varies by function: RDI for `printf`, RSI for `fprintf` and `syslog`, RDX for `snprintf`. A load from `.rodata` means the argument is a string literal and the call is safe. Any other provenance, function argument, stack variable, or register populated by a prior `recv` or `read`: it is a finding. Severity is HIGH when the fmt register holds a function entry argument, because the caller controls the format string directly.

**DeprecatedFuncScanner.** DeprecatedFuncScanner scans the PLT for functions deprecated because of memory safety problems: `gets` no length limit, `strcpy`/`strcat`/`sprintf` no size argument, `mktemp` predictable temp file, `rand` weak random in security context. Each hit produces a finding with the call site VA and a recommended replacement.

**HeapOverflowScanner** and **IntegerOverflowScanner** find user-controlled values that reach the size argument of `malloc` or `realloc`, and arithmetic before allocation where values could wrap at uint32 or uint16 boundaries.

## Windows and PE analysis

Windows PE binaries use mechanisms, Control Flow Guard, SafeSEH, RPC server registration, COM dispatch, kernel pool allocation, all requiring Windows-aware analysis separate from ELF taint tracking. Seven analyzers cover the full Windows PE attack surface in one session.

```mermaid
flowchart TD
    A(["Windows PE binary\n.exe · .dll · .sys"]):::input --> B(["KernelDriverAnalyzer (.sys)\nframework: WDM · KMDF · minifilter\nDriverEntry + MajorFunction dispatch table\nIOCTL codes from IRP_MJ_DEVICE_CONTROL\n40+ kernel API patterns across 8 risk classes\nWRMSR · CR0 · CR4 write patterns"]):::output

    A:::input --> C(["CFGBypassDetector\nGuardFlags bits 8/9/28-31\nCFG function table\nexport not in CFG table = bypass"]):::output

    A:::input --> D(["ByovdDetector\n8 capability classes\nphys mem · token steal · callback removal\nSMEP bypass · DSE bypass\nMSR write · CR0 write · debug register write"]):::output

    A:::input --> E(["WindowsPoolTaintTracker\nExAllocatePool size argument\nuser-controlled value reaches\nRtlCopyMemory size\nCWE-122"]):::output

    A:::input --> F(["SEHChainAnalyzer (x86-32)\npush-handler · push FS:[0] patterns\nSafeseh registration check"]):::output

    A:::input --> G(["ETWProviderExtractor\nEventRegister → provider GUID\nEventWrite call count\nzero EventWrite = detection gap"]):::output

    A:::input --> H(["RPCServerAnalyzer\nRpcServerRegisterIf* calls\nRPC_C_AUTHN_LEVEL_NONE = HIGH"]):::output

    A:::input --> I(["COMAttackSurfaceMapper\nDllGetClassObject presence\nCLSID enumeration\nIStream marshal check"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#2e7d32,stroke-width:3px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
```

**KernelDriverAnalyzer.** KernelDriverAnalyzer detects PE machine type (0x014c for x86-32, 0x8664 for x64) and classifies the driver framework WDM, KMDF, or minifilter. It recovers the MajorFunction dispatch table from DRIVER_OBJECT, decodes every CTL_CODE in the IRP_MJ_DEVICE_CONTROL handler, audits 40+ kernel API patterns across 8 risk classes, and flags dangerous byte patterns including WRMSR, CR0 modification, and HLT. MSVC-compiled IOCTL switch handlers emit a register subtraction cascade rather than a jump table. The IoctlCascadeDecoder reconstructs every CTL_CODE from the cascade, including codes derived via the push-imm/pop-reg MSVC optimizer idiom.

**ByovdDetector.** ByovdDetector classifies eight BYOVD capability classes from the kernel API surface of any `.sys` file. It reads the import table and disassembles DriverEntry to determine whether the driver has physical memory read/write, token stealing, callback removal, SMEP bypass, DSE bypass, MSR write, CR0 write, or debug register write capability. A signed driver with any of these capabilities is a BYOVD candidate.

**ETWProviderExtractor.** ETWProviderExtractor finds every `EventRegister` call, extracts the provider GUID from the second argument, and counts `EventWrite` call sites for each provider. A provider with zero `EventWrite` calls generates no telemetry and produces a detection gap.

## Kernel and driver analysis

Kernel modules require analysis at the boundary between user space and the kernel. `KernelModuleSubsystemClassifier` maps a kernel module to its subsystem network, block, filesystem, USB, audio from exported symbol patterns. `PreAuthExposureScanner` traces code paths reachable before authentication and reports which kernel APIs are callable from unauthenticated input.

## Go binary analysis

Go binaries embed the pclntab PC line table in the binary for runtime stack traces. The table survives `strip(1)` because Go requires it at runtime. Extracting function names before BERT encoding lifts SemanticSearcher accuracy from approximately 0.20 to 0.70 on stripped Go binaries because the corpus descriptions contain actual function names instead of generic `func_0xABCD` labels.

```mermaid
flowchart TD
    A(["stripped Go binary"]):::input --> B["GoFuncTable.from_binary(data)\nscan for pclntab magic\n0xFFFFFFF1 (Go 1.20+)\n0xFFFFFFFA (Go 1.16-1.19)\n0xFFFFFFFB (Go 1.12-1.15)"]:::primary
    B:::primary -->|"magic found"| C["parse function name table\nVA → function name\nfor every function in binary"]:::secondary
    B:::primary -->|"garble obfuscated"| D(["go_garble_re\nfind decrypt stubs\nrecover obfuscated names"]):::output
    C:::secondary --> E(["CorpusBuilder\nfunction names improve descriptions\nSemanticSearcher accuracy: 0.20 → 0.70+"]):::output
    C:::secondary --> F(["GoStringResolver\ntrace runtime.concatstring* calls\nrecover string values from call sites"]):::output
    C:::secondary --> G(["GoSubprocessScanner\nfind exec.Command calls\nresolve static command-path via GoStringResolver"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

**GoFuncTable.** GoFuncTable supports pclntab format across Go 1.12 through 1.20+. It produces a `{VA: function_name}` map for every function in the binary. `CorpusBuilder.build()` uses these names to produce descriptions that BERT can match against natural-language queries.

**GoStringResolver.** Go's runtime concatenates strings at runtime using `runtime.concatstring*`. String values do not appear as static `.rodata` references. GoStringResolver traces these calls and recovers the source strings at each call site.

**GoSubprocessScanner.** GoSubprocessScanner finds `exec.Command` and `os.StartProcess` call sites and resolves the static command-path argument using GoStringResolver. It produces a finding for every command execution with a user-controlled path argument.

## ECU and automotive analysis

Automotive ECU firmware is a flat binary image with no ELF headers. ISAs are non-standard: TriCore Bosch, Continental, RH850 Denso, Bosch, C28x TI traction inverters, SH-2A (Denso), CPU32/M68K (GM), and VLE (NXP). Calling conventions differ from Linux ABI. Function boundaries require ISA-specific prologue scan heuristics because there is no DWARF metadata.

```mermaid
flowchart TD
    A(["flat ECU ROM .bin"]):::input --> B["EcuArchDetector\nidentify ISA from binary patterns\nTriCore · RH850 · C28x · SH-2A · CPU32 · VLE"]:::primary
    B:::primary --> C["FlatBinaryFuncStartScanner\nISA-specific prologue patterns\nfunction boundaries without ELF metadata"]:::secondary
    C:::secondary --> D["ISA-specific decoder\nTriCoreDecoder · RH850Decoder\nC28xDecoder · SH2aDecoder\nM68kCPU32Decoder · VLEDecoder"]:::tertiary
    D:::tertiary --> E["CFG construction\nbasic blocks + branch edges\nISA-specific jump/call resolution"]:::tertiary
    E:::tertiary --> F(["Structurizer\ndominator tree analysis\ngoto CFG → if/while/for pseudo-C"]):::output
    E:::tertiary --> G["ISA-specific TaintTracker\nABI model for each ISA\nTaintTrackerTricore · TaintTrackerRH850\nforward slice to dangerous sinks"]:::tertiary
    G:::tertiary --> H(["ECUSecurityAccessScanner\nSeed-Key algorithm identification\nweak entropy detection"]):::output
    G:::tertiary --> I(["ECURomLayoutAnalyzer\ncalibration regions · code regions\nOBD-II diagnostic surfaces"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
```

Each ISA decoder handles the quirks of its architecture. TriCore uses a hardware-enforced Call Save Area (CSA) instead of a software stack frame. RH850 under GHS ABI defaults to 32-bit double and uses leading-underscore symbol prefixes. C28x is word-addressed: a byte offset and a word address refer to different locations unless the decoder applies the correct scale. VLE uses mixed 16/32-bit instruction widths that require per-instruction length detection.

**ECUSecurityAccessScanner.** ECUSecurityAccessScanner identifies Seed-Key algorithm implementations used for ECU diagnostic access. It flags weak entropy sources fixed seed, counter-based seed, timestamp-only seed and documents the algorithm structure for security assessment.

**ECURomLayoutAnalyzer.** ECURomLayoutAnalyzer classifies ROM regions into code, calibration, and data sections. Calibration regions hold tunable engine maps. Code regions hold the firmware. The classifier feeds downstream analysis with correct base addresses and section types so TaintTracker uses the right segment for string references and function starts.

## Decompilation and control flow structuring

TaintTracker and CFG analysis identify which code paths are dangerous. Reading those paths as goto-based IR requires tracing branch targets manually. Structurizer converts a reducible CFG to if/while/for pseudo-C in one pass so the logic is directly readable.

```mermaid
flowchart TD
    A(["CFG from ISA decoder\nbasic blocks + goto edges"]):::input --> B["DomTree\nCooper-Harvey-Kennedy\nblock A dominates block B\nif every path to B passes through A"]:::primary
    B:::primary --> C["LoopInfo\nback edges identify natural loop headers\nblock is loop header if it dominates a predecessor"]:::secondary
    B:::primary --> D["PostDomTree\nreversed CFG DomTree\nblock X post-dominates Y\nif every path from Y to exit passes through X\nfinds if/else join points"]:::tertiary
    C:::secondary --> E["Structurizer\nwalk in RPO order\ndominators visited before dominated nodes"]:::tertiary
    D:::tertiary --> E:::tertiary
    E:::tertiary --> F["loop header → WhileNode\ntwo-successor block → IfNode\nback-edge tail → ContinueNode\nno-successor block → ReturnNode"]:::tertiary
    F:::tertiary --> G(["pseudo-C\nif (x > 0) {\n  while (len > 0) {\n    copy(dst, src, len);\n  }\n}"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
```

Structurizer works on any CFG that exposes `.blocks`, `.entry`, `.flow`, and `.flow_r()`. The same module runs on CFGs from `cfg_sh2a`, `cfg_v850`, and every future ECU-family decoder without ISA-specific changes. The algorithm is O(n) in block count because RPO guarantees dominators are visited before the blocks they dominate, so the tree walk converges in one pass.

## LLM analyst

TaintTracker produces candidates. PathSolver confirms feasibility. The remaining work, understanding what the function does, what caller controls which argument, and what a concrete exploit input looks like. That work is currently done by reading disassembly manually. AgentLoop automates that for one candidate function by running Claude in a tool-calling loop against the binary.

```mermaid
flowchart TD
    A(["AgentLoop.run(va, task='vuln_hypothesis')"]):::input --> B["ContextBuilder\nbinary summary\nnamed functions from NameRegistry\nRAGRetriever: prior confirmed findings\nby embedding similarity from func_id.db"]:::primary
    B:::primary --> C["Claude claude-sonnet-5\nReAct loop\nreason about function at va"]:::secondary
    C:::secondary -->|"get_callees(va)"| D["ToolRegistry\nexecutes against BinaryContext"]:::tertiary
    C:::secondary -->|"disassemble(va, n)"| D:::tertiary
    C:::secondary -->|"get_strings(va)"| D:::tertiary
    C:::secondary -->|"get_callers(va)"| D:::tertiary
    D:::tertiary --> E["tool result injected into context"]:::tertiary
    E:::tertiary --> C:::secondary
    C:::secondary -->|"task complete"| F(["name + confidence + hypothesis\n'arg1 is wire-supplied length\npassed to memcpy without upper bound check'"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#6a1b9a,stroke-width:2px
    linkStyle 7 stroke:#00695c,stroke-width:2px
    linkStyle 8 stroke:#2e7d32,stroke-width:3px
```

**AgentLoop.** AgentLoop runs the ReAct Reasoning + Acting loop. Claude issues tool calls, receives results, reasons about them, and issues further tool calls until the task is complete. The two supported tasks are `name_function` and `vuln_hypothesis`.

**RAGRetriever.** RAGRetriever retrieves confirmed findings from `func_id.db` by embedding similarity. It injects those findings into the context window before the loop starts. This grounds Claude's analysis in concrete patterns from prior engagements rather than pure inference from disassembly.

**ToolRegistry.** ToolRegistry maps Claude tool-use schema names to Ablation BinaryContext methods. It validates arguments, executes the call, and returns the result in a format the model can reason about. Available tools: `get_callees`, `get_callers`, `get_strings`, `disassemble`.

LLM analyst requires `pip install ablation[llm]`.

## Exports and integrations

**SARIF.** SARIF 2.1.0 is the OASIS standard for static analysis results. GitHub Code Scanning, VS Code, and most SAST platforms consume it natively. `ablation sweep firmware.so --sarif results.sarif` exports sweep results so they appear as PR annotations without custom integration. `ablation findings --sarif findings.sarif` exports confirmed findings from the local database.

```mermaid
flowchart LR
    A(["ablation sweep firmware.so\n--sarif results.sarif\n--json results.json"]):::input --> B["sweep_to_sarif()\none rule per pattern\none result per candidate\nlocation: binary path + function VA"]:::primary
    B:::primary --> C(["GitHub Code Scanning\ngh api repos/owner/repo/code-scanning/sarifs\nsweep results appear as PR annotations"]):::output
    B:::primary --> D(["VS Code SARIF Viewer\nresults inline in editor"]):::output
    B:::primary --> E(["ablation findings\nconfirmed findings from FindingRegistry\nseparate SARIF export"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

**JSON export.** `ablation sweep --json results.json` produces a flat JSON array with one entry per candidate: pattern text, score, function VA, binary path, and hit metadata. Use this for downstream scripts and custom reporting tools.

**Binary Ninja plugin.** The Binary Ninja plugin loads Ablation data inside the Binary Ninja session. Name overlays from NameRegistry apply to the Binary Ninja address view. Taint findings and pattern matches appear as annotations on the relevant functions and call sites.

## Additional analysis families

The sections above cover every major capability. The following entries point to the relevant sections for quick reference.

- **Cross-version diffing:** `VersionDelta`, `DTWMatcher`, `MatrixProfileDiff`, `StructuralSim`: see the Cross-version diffing section.
- **Crypto and entropy:** `EntropyMapper`, `XorKeyRecoverer`, `CryptoAuditor`, `HashAlgoDiscriminator`: see Crypto and entropy analysis.
- **Firmware extraction:** `FirmwareContainerKeyExtractor`, `HuaweiSquashfsExtractor`, container extractors: see Firmware extraction.
- **Vulnerability scanners:** `FormatStringScanner`, `DeprecatedFuncScanner`, heap and integer overflow scanners: see Specialized vulnerability scanners.
- **Windows and PE:** `KernelDriverAnalyzer`, `ByovdDetector`, `CFGBypassDetector`, `ETWProviderExtractor`, `RPCServerAnalyzer`, `COMAttackSurfaceMapper`, `WindowsPoolTaintTracker`: see Windows and PE analysis.
- **Go binaries:** `GoFuncTable`, `GoStringResolver`, `GoSubprocessScanner`, `go_garble_re`: see Go binary analysis.
- **ECU and automotive:** `EcuArchDetector`, ISA decoders, `ECUSecurityAccessScanner`, `ECURomLayoutAnalyzer`, `Structurizer`: see ECU and automotive analysis.
- **LLM analyst:** `AgentLoop`, `RAGRetriever`, `ToolRegistry`: see LLM analyst.
- **Exports:** SARIF, JSON, Binary Ninja plugin: see Exports and integrations.

## Using Ablation with Codex

Codex can work with Ablation when it can access the checkout or an environment where the Ablation CLI is installed. The interaction is through ordinary shell commands and files: Codex runs a command, reads its output, and decides what evidence to inspect next. This checkout does not require a Codex-specific plugin or MCP server for that workflow.

From the repository environment, install the project into the Python environment used by the shell or invoke its Python module in that environment:

```bash
python -m pip install -e .
ablation --help
```

Then give Codex the target binary path, the research question, and the relevant analysis boundary. A practical sequence is:

```bash
ablation analyze ./target.bin
ablation search ./target.bin "network-controlled length reaches an allocation or copy"
ablation profile ./target.bin 0xADDRESS
ablation cfg ./target.bin 0xADDRESS --insns
ablation taint ./target.bin
```

Use the architecture-specific commands when the generic `taint` route does not select the target ISA. For repeatable work, have Codex preserve exact commands, binary hashes, candidate addresses, and raw output in the user's research notes. Ask it to distinguish tool output from its own inference, then verify a candidate by tracing the relevant instructions, callers, guards, and input source. JSON/SARIF output can be useful where the corresponding command exposes those options; inspect the CLI help because export support differs by command.

Codex must run in an environment that can see both the executable and the binary. If the project is not installed, use the repository's virtual environment/Python interpreter or install from the checkout. A remote Codex session cannot use a binary that exists only on the user's workstation unless that binary is made available to the session. Do not assume that an LLM feature is active just because Codex is reasoning over CLI output; Codex's shell-driven analysis is distinct from Ablation's optional Anthropic `llm_analyst` package.

## Result quality and safe interpretation

Use Ablation to reduce search space and make evidence easier to inspect. For each candidate, establish:

1. The actual instruction and function boundaries around the reported address.
2. Whether attacker-controlled input can reach the relevant operation.
3. Whether bounds checks, sanitization, or error paths block the dangerous case.
4. Whether the called function uses the value as assumed.
5. Whether the path is reachable in the product configuration and has meaningful impact.

Static analysis can miss code, infer incorrect boundaries, and produce false positives or negatives. Confirm important claims with manual disassembly, dynamic experiments, or independent tooling as appropriate. Preserve uncertainty explicitly in reports.

## Documentation and implementation drift

Some existing docs contain aging examples or claims that no longer line up with the current code. Examples include stale command inventories, optimistic claims about semantic-search inputs, version summaries that stop at 2.5.0, and old contributor layout/API descriptions. The implementation and CLI parser are the source of truth for current command behavior. This page records the architecture and limitations visible in this checkout; it does not certify every old code comment, target-specific note, or third-party file in the working tree.

For installation and command examples see [Getting Started](getting-started.md). For the existing workflow and module guides see the [documentation index](INDEX.md). For changes by release see [CHANGELOG](CHANGELOG.md) and [updates](updates/).


## Next Steps

- New to Ablation? Start with the [Getting Started guide](./getting-started.md).
- To understand the underlying analysis concepts, read [Decompiler Concepts](./concepts-decompiler.md).
- To see an reverse engineering engagement, read the [RE Workflow guide](./guide-re-workflow.md).
- For a full task → tool lookup table, see the [Tool and Mode Selection guide](./guide-tool-selection.md).
