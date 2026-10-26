# PathSolver / FindingRegistry

  - [What is symbolic path solving?](#what-is-symbolic-path-solving)
  - [Why this exists](#why-this-exists)
  - [PathSolver](#pathsolver)
    - [Usage](#usage)
    - [Result fields (PathResult)](#result-fields-pathresult)
    - [Limitations](#limitations)
  - [FindingRegistry](#findingregistry)
    - [Usage](#usage-1)
    - [Schema](#schema)
  - [Workflow](#workflow)
  - [How it works](#how-it-works)
  - [Example output](#example-output)
  - [False positives](#false-positives)
  - [Pipeline position](#pipeline-position)
  - [Reading output](#reading-output)
  - [See also](#see-also)

**Files:** `modules/path_solver.py` · `ablation/analyzers/finding_registry.py`

---

## What is symbolic path solving? <sup>[↑](#pathsolver--findingregistry)</sup>

Symbolic path solving answers the question taint analysis cannot: not "does attacker-controlled data reach this sink?" but "is there a concrete input that causes execution to actually reach this sink?" The distinction matters because taint analysis is sound-over-approximate. It reports any path where tainted data could theoretically flow, including paths guarded by bounds checks, authentication gates, or state conditions that never hold in practice. Every such false positive must be manually discarded.

`PathSolver` uses Z3, a satisfiability modulo theories (SMT) solver from Microsoft Research, to decide reachability precisely. It enumerates the basic-block paths in the CFG from function entry to the target block, encodes each branch condition as a Z3 `BitVec` constraint, and asks: does there exist an assignment to the entry-register variables that satisfies all constraints along this path? A SAT answer proves a concrete exploit input exists and reveals its value. An UNSAT answer proves the path is infeasible under the encoded model.

`FindingRegistry` closes the loop between analysis and submission. It records each SAT-confirmed finding in a persistent SQLite store (`~/.ablation/findings.db`, never committed), indexes a sentence embedding for the Flywheel to replay on future binaries, and formats the record for PSIRT submission. The rule from `CLAUDE.md` is explicit: call `FindingRegistry.register()` only after Z3 returns SAT. Pattern-only matches that skip path solving have carried false-positive findings through multiple sessions in prior engagements.

## Why this exists <sup>[↑](#pathsolver--findingregistry)</sup>

Three things were not possible before these modules:

1. **Taint hits required manual feasibility verification.** A taint path from network input to `memcpy` does not confirm exploitability, branches along the path may guard the sink. `PathSolver` enumerates all paths to the sink, encodes their constraints in Z3, and returns the concrete input values that satisfy a reachable path.

2. **Confirmed findings had no persistent home.** Without a registry, each session re-derived the same finding from scratch. `FindingRegistry` stores every confirmed finding with its CWE, severity, binary, function address, and a sentence embedding, so the next sweep against a related binary replays it automatically.

3. **PSIRT submissions required manual compilation.** The registry exports findings in a format the Flywheel can replay and a researcher can hand directly to a PSIRT analyst: title, description, CWE class, severity, and the binary-specific address.

---

## PathSolver <sup>[↑](#pathsolver--findingregistry)</sup>

`PathSolver` runs bounded symbolic execution on x86-64 binaries. It enumerates all simple paths in the CFG from a function entry to a target block, encodes register state at each branch as Z3 BitVec constraints, and calls Z3 to solve. A SAT result means the path is feasible and the model gives concrete entry-register values.

### Usage <sup>[↑](#pathsolver--findingregistry)</sup>

```python
from modules.path_solver import PathSolver, solve_for_sink
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary')

# All feasible paths to a target VA
solver = PathSolver(ctx.path, ctx.cfg, ctx.text_data, ctx.text_va, ctx.plt)
results = solver.solve(target_va=0x1234abcd)

for r in results:
    if r.sat:
        print(f"SAT at path depth {len(r.path)}")
        for reg, val in r.model.items():
            print(f"  {reg} = 0x{val:x}")

# Convenience: first SAT result only
result = solver.solve_first_sat(target_va=0x1234abcd)
if result and result.sat:
    print(f"exploit inputs: {result.model}")

# Direct call from sink VA
result = solve_for_sink(ctx, sink_va=0x1234abcd)
```

### Result fields (`PathResult`) <sup>[↑](#pathsolver--findingregistry)</sup>

| Field | Description |
|---|---|
| `sat` | `True` if Z3 found a satisfying assignment |
| `path` | Block VA sequence from entry to sink |
| `model` | `dict[str, int]`: concrete register values at function entry that reach the sink |
| `clauses` | `int`: Z3 clauses added during path exploration |
| `note` | `str`: `'timeout'` or `'unsat'` when `sat=False`; empty on success |
| `seeded_fields` | `list[str]`: struct field names from `MemoryConstraint` that constrained this path |

### Limitations <sup>[↑](#pathsolver--findingregistry)</sup>

- Memory reads modeled as unconstrained symbolic values sound over-approximation.
- Calls clobber caller-saved registers to fresh unconstrained symbols.
- Indirect jumps stop path enumeration at the branch site.
- Bounded by `MAX_PATH_BLOCKS` to avoid path explosion on large CFGs.

---

## FindingRegistry <sup>[↑](#pathsolver--findingregistry)</sup>

`FindingRegistry` persists confirmed findings to `~/.ablation/findings.db` SQLite, never committed to git. It seeds embeddings from `ablation/data/seed_corpus.json` on first run, then extends with every registered finding. The Flywheel replays registered findings as search patterns on every new binary sweep.

### Usage <sup>[↑](#pathsolver--findingregistry)</sup>

```python
from ablation.analyzers.finding_registry import FindingRegistry

reg = FindingRegistry()
print(reg.stats())

# Register a confirmed finding after PathSolver confirms it
reg.register(
    vendor="fortinet",
    product="fortigate",
    version="7.2.x",
    title="stack overflow in parse_option via network DHCP Option 82",
    description="ARG_PROPAGATED | calls: strncpy | vuln: user-controlled length, no bounds check",
    cwe_class="CWE-121",
    severity="CRITICAL",
    embedding=func_vec,
    func_addr=0x1234abcd,
    binary="httpsd",
)

# Query for similar patterns in a new binary
hits = reg.find_similar(func_embedding, top_k=8)
for h in hits:
    print(f"[{h['severity']}] {h['title']}  sim={h['similarity']:.3f}")

# Export for Flywheel replay
patterns = reg.export_patterns(confirmed_only=True)

# Findings not yet synced to seed corpus
unsynced = reg.unsynced_findings()
```

### Schema <sup>[↑](#pathsolver--findingregistry)</sup>

| Field | Description |
|---|---|
| `vendor` | Target vendor name |
| `product` | Target product name |
| `version` | Affected firmware/software version |
| `title` | One-line finding description |
| `description` | Free-text technical detail: taint path, call chain, vuln class |
| `cwe_class` | CWE identifier (e.g. `CWE-121`) |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `embedding` | Sentence vector for similarity search |
| `func_addr` | VA of the vulnerable function |
| `binary` | Filename of the analyzed binary |

---

## Workflow <sup>[↑](#pathsolver--findingregistry)</sup>

```
TaintTracker confirms ARG_PROPAGATED sink
    ↓
PathSolver.solve(sink_va) → SAT model (concrete exploit inputs)
    ↓
Byte-verify the VA: open(binary,'rb').read()[va - base : va - base + n]
    ↓
FindingRegistry.register(...)   ← stores for Flywheel replay
    ↓
PSIRT submission: title + CWE + severity + func_addr + binary + PoC inputs
```

---

## How it works <sup>[↑](#pathsolver--findingregistry)</sup>

`PathSolver` builds a basic-block adjacency list from Capstone disassembly and DFS-enumerates all simple paths from the function entry block to the block containing `target_va`, bounded by `max_path_blocks`. Each path is symbolically executed: registers are `z3.BitVec(64)` expressions; arithmetic and comparison instructions add constraints; `MemoryConstraint` seeds inject bounds for struct-field reads. Z3 is queried with a per-path timeout; a SAT result yields a concrete model of register values at function entry. `FindingRegistry.register()` inserts a row into `~/.ablation/findings.db` (SQLite), L2-normalizes the supplied embedding, and stores it for cosine-similarity retrieval. On registration the embedding is added to the in-memory matrix so `find_similar()` queries against it immediately without a reload.

---

## Usage <sup>[↑](#pathsolver--findingregistry)</sup>

```python
from modules.path_solver import PathSolver
from ablation.analyzers.finding_registry import FindingRegistry
from ablation.analyzers.binary_context import BinaryContext
import capstone

ctx = BinaryContext.load_or_build('/path/to/binary')
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# Confirm exploitability: enumerate all feasible paths to a taint sink
solver = PathSolver(
    data=ctx.text_data,
    func_va=0x12000,
    func_end_va=0x12800,
    plt=ctx.plt,
    cfg=ctx.cfg,
    md=md,
)
results = solver.solve(target_va=0x1234abcd)
for r in results:
    if r.sat:
        print(f"SAT — input constraints:")
        for reg, val in r.model.items():
            print(f"  {reg} = 0x{val:x}")

# Register the confirmed finding
reg = FindingRegistry()
reg.register(
    vendor='acme',
    product='firmware',
    version='1.0',
    binary='libservice.so',
    func_addr=0x1234abcd,
    cwe_class='CWE-121',
    severity='HIGH',
    title='Stack overflow in input parser',
    description='Attacker-controlled length field flows to memcpy without bounds check.',
)
```

---

## Example output <sup>[↑](#pathsolver--findingregistry)</sup>

```
[SAT] path=0x12000 -> 0x12200 -> 0x1234ab clauses=42 model=(rdi=0x41414141, rsi=0x0)
  seeded_fields: ['attr_len', 'attr_type']
[UNSAT] path=0x12000 -> 0x12100 -> 0x1234ab clauses=19

FindingRegistry.register() → finding_id='fgt-0042'
  stored: vendor=fortinet  product=fortigate  cwe=CWE-121  severity=CRITICAL
  embedding indexed (matrix size: 87 findings)

FindingRegistry.stats()
  findings: 87  seeds: 62  user-registered: 25
  CRITICAL: 4  HIGH: 18  MEDIUM: 35  LOW: 30
```

---

## False positives <sup>[↑](#pathsolver--findingregistry)</sup>

**`PathSolver` SAT on an infeasible path**: unconstrained memory reads let Z3 assign arbitrary values to struct fields, producing models that satisfy the formula but are not reachable in practice. Use `MemoryConstraint` seeding to constrain known struct fields, and always validate the model against the vulnerability semantics for example the `len` register should exceed the allocation size for a buffer overflow.

**`PathSolver` UNSAT on a real path**: loops and indirect calls create unconstrained symbolic values that over-constrain the Z3 formula. Increase `max_path_blocks` or add `MemoryConstraint` seeds for register-held struct pointers. If a path still produces UNSAT, manual disassembly trace is the fallback.

---

## Pipeline position <sup>[↑](#pathsolver--findingregistry)</sup>

**Before this module:** `TaintTracker` to identify the `sink_va`; `cfg_builder` or disassembly-derived CFG for `PathSolver`. The binary must be accessible at a stable path since `PathSolver` reads `text_data` directly.

**After this module:** A SAT result confirms the finding is reachable. Register with `FindingRegistry.register()`, write to `re/<vendor>/<target>_re.py`, and byte-verify the `func_addr` against the binary before submitting to PSIRT.

---

## Reading output <sup>[↑](#pathsolver--findingregistry)</sup>

`PathSolverdata, func_va, func_end_va, plt, cfg, md.solvetarget_va` returns `List[PathResult]`:

| Attribute | Content |
|:---|:---|
| `sat` | `True` if Z3 found a satisfiable path to the target VA |
| `path` | `List[int]`: basic block VAs on the satisfying path |
| `model` | `Dict[str, int]`: concrete register values at function entry that satisfy the constraints |
| `clauses` | Integer: number of Z3 clauses added during path exploration |
| `note` | Status string: `'timeout'` / `'unsat'` / empty on success |
| `seeded_fields` | `List[str]`: struct field names used to seed the Z3 model |

---

## See also <sup>[↑](#pathsolver--findingregistry)</sup>

- [BinaryContext](binary-context.md): session foundation for all analysis
- [SemanticSearch](semantic-search.md): function candidate identification
- [FindingRegistry](registry.md): persistent finding storage
