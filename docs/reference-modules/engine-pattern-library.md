# EnginePatternLibrary

Engine code labeling for PC game reverse engineering.

Labels functions in a stripped game binary as known engine code: UE4/UE5, id Tech 6/7, Unity il2cpp, Source 2, and CryEngine. The labeling uses three passes of increasing cost and decreasing precision.

**Goal:** Label 60–80% of a AAA game binary automatically, leaving
only game-specific code for human reverse engineering.

---

## Why this module exists

Three things were not possible before in Ablation:

**1. Separating engine code from game code automatically.**
A stripped AAA game binary contains 30,000 to 80,000 functions. 60 to
80% of them are Unreal Engine, id Tech, Unity, or CryEngine code that
is identical across studios and titles. Without this module, every new
game binary started at zero. The analyst manually triaged each function
to decide whether it was already-known boilerplate or game-specific
logic worth analyzing. There was no batch classification.

**2. Signal-quality-ordered labeling.**
Even when patterns were known informally, there was no structured way
to apply them. A weak semantic hit could shadow a strong string-marker
match because nothing enforced priority. The three-pass pipeline fixes
that: exact string markers run first, regex patterns second, semantic
similarity last. The highest-confidence evidence always wins.

**3. A flywheel that grows coverage from confirmed findings.**
Each RE engagement produced confirmed function names that sat in a
session file and were never reused. `ingest_from_findings()` closes
that loop. Confirmed findings become new signatures, so every future
binary benefits from the accumulated corpus without any manual curation.

`EnginePatternLibrary` addresses all three with a single
`label_binary(ctx, xg)` call, returning an `{va: EngineLabel}` map
and an `unlabeled()` residual that is the actual human RE target.

---

## Quick start

```python
from ablation.analyzers.engine_pattern_library import EnginePatternLibrary
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.xref_graph import XRefGraph

ctx = BinaryContext.load_or_build('/path/to/game.exe')
xg  = XRefGraph.from_path('/path/to/game.exe')
xg.build()

lib = EnginePatternLibrary.default()
labels = lib.label_binary(ctx, xg)

# Coverage report
print(lib.strip_report(labels, len(ctx.func_starts)))

# Functions to analyze manually
targets = lib.unlabeled(ctx.func_starts, labels)
print(f"{len(targets)} functions remaining for manual RE")
```

---

## Three-pass labeling pipeline

| Pass | Method | Confidence boost | Cost |
|---|---|---|---|
| String marker | Exact match against `string_markers` list | +0.15 | Cheap: dict lookup |
| String pattern | Regex match against string xrefs of each function | Base confidence | Medium: per-function string walk |
| Semantic | SemanticSearcher description match | Base × score | Expensive: embedding inference |

Passes run in order. The first match wins, so a weak semantic match cannot shadow a confirmed string marker match.

### String marker pass

Engine functions frequently embed unique string constants. For example,
`FDebug::EnsureFailed` always references the literal `"EnsureFailed"`.
This is the most reliable signal.

### String pattern pass

Regex patterns match against all strings referenced by each function.
Useful when the exact string varies but the pattern is stable
(e.g. `r"GUObjectArray"` appears in `StaticFindObject` regardless of
version string content).

### Semantic pass

Calls `SemanticSearcher.query(sig.description)` and maps hits back to
function VAs. Useful when no string constants are present but the
function's behavior description is distinctive (e.g. "UE4 TArray
growth; doubles capacity; moves elements").

Requires a `SemanticSearcher` instance. Omit it to run string-only
matching with `label_binary_fast()`.

---

## API reference

### EnginePatternLibrary

```python
# Constructors
lib = EnginePatternLibrary.default()               # load from ~/.ablation/engine_patterns.json, or seed corpus
lib = EnginePatternLibrary.load('/path/to/lib.json')
lib = EnginePatternLibrary(signatures=[...])       # build from explicit signature list

# Labeling
labels = lib.label_binary(ctx, xg,
    semantic_searcher=None,     # omit for string-only passes
    arch='arm64',
    min_confidence=0.70,
    semantic_top_k=8,
)
labels = lib.label_binary_fast(ctx, xg)            # string passes only

# Query
lib.signature_count()                              # → int
lib.signatures_for_engine('unreal')                # → List[EngineSignature]

# Reporting
lib.strip_report(labels, total_funcs, show_all=False)   # → str
lib.unlabeled(func_starts, labels)                      # → List[int] (human RE targets)

# Corpus management
lib.add_signature(sig)                             # replace or add
lib.save('/path/to/lib.json')                      # persist (default: ~/.ablation/engine_patterns.json)

# Flywheel integration
lib.ingest_from_findings(findings, engine='unreal', category='gameplay')  # → count added
```

### EngineSignature

```python
from ablation.analyzers.engine_pattern_library import EngineSignature

sig = EngineSignature(
    sig_id      = 'ue4.fmemory.malloc',     # stable identifier
    engine      = 'unreal',                  # key from ENGINES dict
    category    = 'memory',                  # key from CATEGORIES dict
    name        = 'FMemory::Malloc',         # canonical function name
    description = 'allocate memory via UE4 FMemory interface; calls GMalloc->Malloc',
    string_markers  = ['FMemory::Malloc called with size'],  # exact string constants
    string_patterns = [r'GMalloc'],          # regex patterns against string xrefs
    arch            = 'any',                 # 'arm64', 'x86_64', or 'any'
    min_size_insns  = 2,
    max_size_insns  = 50000,
    confidence_base = 0.72,
    notes           = '',
)
```

### EngineLabel

```python
label = labels[va]       # → EngineLabel

label.va                 # function virtual address
label.engine             # 'unreal', 'id_tech', 'unity', 'source2', ...
label.category           # 'memory', 'render', 'scripting', ...
label.name               # canonical function name
label.confidence         # 0.0–1.0
label.match_kind         # 'string_marker', 'string_pattern', 'semantic', 'sax'
label.sig_id             # which EngineSignature produced this label
label.strip()            # True if confidence >= 0.75
```

---

## Built-in seed corpus

The seed corpus covers the most commonly encountered engine functions.

| Engine | Functions | High-value categories |
|---|---|---|
| Unreal Engine 4/5 | 22 | memory, string, reflection, scripting, render, debug |
| id Tech 6/7 | 7 | memory, render, scripting, debug |
| Unity il2cpp | 8 | memory, reflection, string, debug |
| Source 2 | 4 | memory, io, gameplay, scripting |
| CryEngine | 3 | debug, gameplay, render |
| Cross-engine runtime | 12 | memory, runtime, debug |

**Confidence base values:**
- Unity il2cpp: 0.80 (machine-generated, highly consistent)
- id Tech: 0.75 (strong RTTI and debug string coverage)
- Unreal: 0.72 (version drift reduces exact match rate)
- Source 2 / CryEngine: 0.70
- Runtime / stdlib: 0.65 (pattern varies by compiler and version)

---

## Extending the corpus

### Adding a new engine

```python
lib = EnginePatternLibrary.default()

lib.add_signature(EngineSignature(
    sig_id      = 'frostbite.ea.memalloc',
    engine      = 'frostbite',
    category    = 'memory',
    name        = 'EA::Allocator::Malloc',
    description = 'Frostbite allocator; size+alignment; falls back to system malloc',
    string_markers  = ['EA::Allocator::Malloc', 'FrostbiteAllocator'],
    string_patterns = [r'FrostbiteAllocator'],
    confidence_base = 0.72,
))

lib.save()
```

### Ingesting confirmed findings (flywheel)

```python
from ablation.analyzers.finding_registry import FindingRegistry

reg = FindingRegistry()
reg.load('/path/to/findings.json')
confirmed = [f for f in reg.all() if f.status == 'CONFIRMED']

added = lib.ingest_from_findings(confirmed, engine='unreal', category='gameplay')
print(f"Added {added} new signatures from confirmed findings")
lib.save()
```

---

## Integration with Active Architecture Tomography

The EnginePatternLibrary is Phase 1 of Active Architecture Tomography
for PC game RE. The full pipeline:

```
EnginePatternLibrary.label_binary()     ← Pass 1: strip engine code
        ↓ unlabeled residual
BinaryLifter.lift_function(va)          ← Lift candidates to pseudo-C
        ↓ lift output
HypothesisEngine.add_evidence()         ← Score competing hypotheses
        ↓ ranked probes
ProbeRanker → next probe type           ← Phase 3: QEMU dynamic execution
```

After stripping engine code, the analyst runs the hypothesis engine on
unlabeled functions. The lifter provides structural evidence. The
engine proposes targeted probes (disassembly → xref → taint → semantic)
and converges to CONFIRMED/REJECTED states without manual triage.

---

## Design notes

The three-pass pipeline is ordered by signal quality, not by cost.
String markers are the ground truth. When a function contains `"EnsureFailed"`, it is `FDebug::EnsureFailed`. Semantic
similarity is the weakest signal; it is useful for prioritization but
insufficient for confirmation. The architecture mirrors the evidence
family hierarchy in `evidence_scorer.py`: exact match → structural →
semantic.

The `il2cpp` confidence advantage (0.80 vs. 0.72) reflects a real
property of the target code, not an arbitrary choice. Unity's il2cpp
is a C# IL → native code transpiler. The output is deterministic and the patterns are stable across Unity versions. UE4 hand-written C++
varies by editor version, studio customization, and build configuration,
so the same function can look different across games even when the
behavior is identical.

---

## Why this exists

Prior to this module, enginepatternlibrary required manual work outside the Ablation pipeline. This module integrates the capability directly so findings feed the shared `PatternLibrary` and `FindingRegistry` without a separate toolchain.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Usage

```python
from ablation.analyzers.engine_pattern_library import EnginePatternLibrary

results = EnginePatternLibrary.from_context(ctx).run()
for r in results:
    print(r)
```

---

## Example output

```
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading output

`PatternLibrary.match(ctx)` returns `List[EngineLabel]` — one per confirmed function match:

| Attribute | Content |
|:---|:---|
| `va` | VA of the matched function in the target binary |
| `engine` | Engine identifier string (e.g., `'ue4'`, `'unity'`, `'godot'`) |
| `category` | Functional category (e.g., `'memory'`, `'render'`, `'network'`) |
| `name` | Canonical engine function name (e.g., `'FMemory::Malloc'`) |
| `confidence` | Float 0.0–1.0 — match confidence from the signature |
| `match_kind` | `'string_marker'` / `'string_pattern'` / `'semantic'` / `'sax'` |
| `sig_id` | Stable signature identifier (e.g., `'ue4.fmemory.malloc'`) |

Use `label.strip()` to test if the match is high-confidence enough to exclude from manual analysis.

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
