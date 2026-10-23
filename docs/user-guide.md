# User Guide

Practical reference for day-to-day use of Ablation.

---

## Session setup

Every session starts with a `BinaryContext`. It caches the binary's section map, PLT/IAT symbol table, confirmed function names, exported symbols, string table, function start list, and call graph. Build it once; reuse it across all tools in the session.

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/target.elf')
print(ctx.summary())
```

`load_or_build()` auto-detects format ELF, PE, XCOFF, flat ROM and architecture. On subsequent runs it reloads from cache in under 200 ms via SHA-256-keyed JSON.

---

## Tool ordering

For most targets, follow this ordering:

```
BinaryContext
  → SemanticSearcher          # find candidate functions by vuln class
  → FuncProfiler              # profile top candidates
  → SinkArgClassifier         # eliminate RODATA_CONST before taint runs
  → TaintTracker              # ARG_PROPAGATED / UNKNOWN sinks only
  → PathSolver                # confirm feasibility with Z3
```

See [Tool Selection Guide](guide-tool-selection.md) for the full task → tool lookup table.

---

## CLI usage

### Sweep scripts

Standalone sweep scripts live in `sweeps/`. Each accepts a binary path and prints findings to stdout.

```bash
python sweeps/fortinet_sweep.py /path/to/httpsd
python sweeps/pe_sweep.py /path/to/target.exe
python sweeps/ti_sweep.py /path/to/sdk/
```

### Direct Python

All tools are importable as `ablation.analyzers.*`:

```python
from ablation.analyzers.taint_tracker_arm64 import ARM64TaintTracker

findings = ARM64TaintTracker.from_path_full('/path/to/binary').run_interprocedural()
for f in findings:
    print(f)
```

### BinaryLifter one-liner

```bash
python -c "
from ablation.analyzers.binary_lifter import BinaryLifter
BinaryLifter.report('/path/to/binary', 0x12340, arch='arm64')
"
```

---

## Configuration

Ablation has no config file. Behaviour is controlled by:

- **`arch=` strings** passed to `BinaryLifter`, `TaintTracker`, and related tools: see [Decompiler and IR Lifter Concepts](concepts-decompiler.md#complete-tool-and-isa-reference) for the full reference.
- **`BinaryContext.set_name(va, name, source=)`**: name confirmed functions; names propagate to all tools in the session.
- **`PatternLibrary` / `FindingRegistry`**: persist confirmed patterns and findings across sessions for flywheel replay.
- **FORGE cache**: stored at `~/.ablation/forge_cache.json`; keyed by module source hash; cleared automatically on source change.

---

## Worked examples

### Taint-to-finding on an ARM64 binary

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.semantic_search import SemanticSearcher, CorpusBuilder
from ablation.analyzers.taint_tracker_arm64 import ARM64TaintTracker
from ablation.analyzers.binary_lifter import BinaryLifter

elf = '/path/to/httpsd'
ctx = BinaryContext.load_or_build(elf)

# 1. Build corpus and sweep for format-string candidates
corpus = CorpusBuilder.build(ctx)
searcher = SemanticSearcher.from_context(ctx, corpus)
candidates = searcher.query('format string user input printf')

# 2. Taint-track the top candidates
findings = ARM64TaintTracker.from_path_full(elf).run_interprocedural()

# 3. Lift a flagged function for manual review
lifter = BinaryLifter.from_context(ctx).with_taint(findings)
print(lifter.lift_function(findings[0].sink_va))
```

### Cross-version patch diff

```python
from ablation.analyzers.structural import VersionDelta

delta = VersionDelta.from_paths('/path/to/v1.elf', '/path/to/v2.elf')
delta.report()
```

### ECU firmware (PPC32)

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.ppc32_taint_tracker import PPC32TaintTracker

ctx = BinaryContext.load_or_build('/path/to/ecu.elf')
findings = PPC32TaintTracker.from_context(ctx).run_interprocedural()
```

---

## Naming and session persistence

Name every confirmed function immediately:

```python
ctx.set_name(0x12340, 'parse_user_header', source='confirmed')
```

Names from `source='confirmed'` appear in BinaryLifter output, TaintTracker call graphs, and SARIF exports. They persist across sessions via the BinaryContext cache.

Export findings as SARIF for GitHub Code Scanning:

```python
from ablation.analyzers.export import SarifExporter
SarifExporter.from_findings(findings, ctx).write('/path/to/results.sarif')
```
