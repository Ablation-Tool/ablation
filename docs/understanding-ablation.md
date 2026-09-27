# Understanding Ablation

Ablation is a local reverse-engineering and binary-triage toolkit. Its purpose is to help an analyst make sense of stripped binaries and firmware by building useful structural context, finding functions worth inspecting, and applying targeted static analyses. The analyst (or an assistant such as Codex) uses those outputs to investigate and validate hypotheses. Ablation does not, by itself, prove that a candidate is exploitable.

This page describes the implementation and docs in this checkout. It is intended as a practical map of what the system does, where its components live, and how to interpret its results. The package metadata currently reports version 2.5.0; the CLI and update notes contain newer commands and architecture work than the version label and some reference pages, so check `ablation --help` and the implementation before relying on an older example.

## The analysis model

Most workflows follow this sequence:

1. Load a binary and collect structural facts: format, architecture, segments, imports/PLT entries, exports, strings, probable function starts, calls, and cross-references.
2. Use that context to locate code relevant to a question. This can be semantic search over function descriptions, known signatures, pattern sweeps, string/call relationships, or a specialized scanner.
3. Inspect a candidate with function profiles, instruction windows, control-flow graphs, cross-references, and architecture-specific taint/dataflow analysis.
4. Verify the path and assumptions manually against the binary, its callers, input source, guards, and runtime behavior where possible.
5. Preserve useful analyst knowledge in the local name, function-identity, pattern, or finding stores, and in the target's session notes.

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
| `docs/`, `updates/` | User guides, module references, integration notes, and release/update notes. |

The checkout may also contain firmware, extracted filesystems, generated reports, vendor reference material, and other research artifacts. Such inputs are not all framework source, and their presence does not mean Ablation automatically analyzes them as one unified target.

## Binary context and disassembly

`BinaryContext` (`ablation/analyzers/binary_context.py`) is the common high-level context object. It uses LIEF, Capstone, NumPy, and related helpers to identify useful binary properties and construct indexes for later analysis. The context can expose summaries, function starts, names, call relationships, strings, and string references. Its cache is keyed by the binary SHA-256 under `~/.ablation/cache`, so a different build does not silently reuse the same cached context merely because its filename matches.

Function boundaries and references are inferred. The implementation combines format metadata, exported symbols, unwind information where available, instruction decoding, and prologue/call heuristics. Call-graph and string-reference coverage depends on architecture and instruction forms; direct-call scans do not magically resolve arbitrary indirect calls. Treat the indexes as navigation aids and inspect the actual instructions for consequential claims.

The core package contains ELF, PE, and Mach-O-related support, while analysis coverage is not identical across formats and architectures. The main context and much of the workflow are ELF-oriented. The architecture-specific analyzer and decoder modules implement different subsets of decoding, CFG construction, function discovery, and taint analysis. “Supports architecture X” should therefore be read as support by particular commands/components, not a guarantee that every feature has equivalent coverage on every ISA.

This is a binary analysis toolkit, not a general source-level decompiler equivalent to a full interactive commercial or open-source reverse-engineering suite. It offers disassembly, structural analysis, matching, and targeted analysis features; users should inspect each command's actual output and scope.

## Finding candidate functions

### Corpus construction and semantic search

`CorpusBuilder` gathers a textual description for functions and persists function identity/context in a SQLite database, normally `~/.ablation/func_id.db`. Descriptions can include names, inferred role, callees, strings, and analyst notes. `SemanticSearcher` embeds those descriptions and ranks them against natural-language queries. The default model in the implementation is `sentence-transformers/all-mpnet-base-v2`.

This is semantic similarity over the description corpus, not a direct semantic understanding of arbitrary machine code. In particular, the normal corpus description path does not automatically include a full instruction sequence or invoke angr for every function. A high score says the indexed description resembles the query; it does not establish that the function has the queried behavior. Signature data and analyst-provided names improve context but are also evidence to verify.

`PatternLibrary` stores reusable textual search patterns and hit metadata in a local JSON file under `~/.ablation`. A sweep applies patterns and reports candidates. A separate legacy `sweeps/base_sweep.py` path has its own extraction and embedding behavior, including a different model; do not assume it is interchangeable with `ablation sweep` without checking which entry point is being run.

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

The x86 taint family includes intraprocedural and interprocedural modes, with a flow-sensitive CFG/MFP mode exposed by the CLI. Other ISA implementations have their own ABI assumptions, sink/source sets, and analysis limits. The CLI currently routes generic `taint` to ARM32 when detected and otherwise to its x86 tracker; other architectures have explicit commands. Always consult `ablation --help` and the command's implementation for routing and coverage.

The shared `dataflow_engine.py` contains reusable CFG/worklist and fixed-point analysis machinery. Architecture modules define instruction semantics and transfer behavior. This makes the analysis extensible but also means correctness depends on the modeled instruction subset, calling convention, memory abstraction, and CFG recovery. Some specialized solvers bound path length, block count, or runtime; symbolic results are conditional on those bounds and constraints.

## Additional analysis families

- **Version and structural comparison:** `VersionDelta`, `StructuralSim`, opcode/subsequence helpers, and related modules compare functions or binaries using structural features and normalized instruction representations. Similarity and diff outputs prioritize review; they do not independently prove shared vulnerable logic or a complete patch.
- **Crypto and firmware:** entropy mapping, XOR solving, crypto auditing, and firmware extraction helpers help identify regions and candidate key/format behavior. Entropy is a heuristic and cannot by itself distinguish encryption from compression or other high-entropy data.
- **Go binaries:** pclntab recovery, Go-specific string resolution, garble-oriented analysis, and subprocess scanning address Go runtime conventions. These are specialized heuristics and should be checked against binary/version details.
- **Kernel and memory-safety scanners:** driver/IOCTL, BYOVD, heap, format-string, integer-overflow, source/sink, and related modules look for selected patterns. Each scanner has a defined target/API surface; a clean result is not a general proof of safety.
- **Exports and integrations:** JSON and SARIF exporters support downstream review and code-scanning tools. The Binary Ninja plugin uses Ablation data and commands from inside that environment. Optional LLM analyst code is a separate integration path.

## Using Ablation with Codex

Codex can work with Ablation when it can access the checkout or an environment where the Ablation CLI is installed. The interaction is through ordinary shell commands and files: Codex runs a command, reads its output, and decides what evidence to inspect next. This checkout does not require a Codex-specific plugin or MCP server for that workflow.

From the repository environment, install the project into the Python environment used by the shell (or invoke its Python module in that environment):

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

For installation and command examples see [Getting Started](getting-started.md). For the existing workflow and module guides see the [documentation index](INDEX.md). For changes by release see [CHANGELOG](../CHANGELOG.md) and [updates](../updates/).
