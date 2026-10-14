# Finding Validation

**Files:** `ablation/analyzers/path_solver.py` · `ablation/analyzers/finding_registry.py`

Finding validation confirms that a taint-traced candidate is exploitable and structures the finding for PSIRT submission. `PathSolver` derives concrete register values that reach a target sink — the PoC inputs. `FindingRegistry` stores the confirmed finding with CWE classification, severity, and description so the submission arrives with working proof and no manual formatting.

---

## Why this exists

Three things were not possible before these modules:

1. **Taint hits required manual feasibility verification.** A taint path from network input to `memcpy` does not confirm exploitability — branches along the path may guard the sink. `PathSolver` enumerates all paths to the sink, encodes their constraints in Z3, and returns the concrete input values that satisfy a reachable path.

2. **Confirmed findings had no persistent home.** Without a registry, each session re-derived the same finding from scratch. `FindingRegistry` stores every confirmed finding with its CWE, severity, binary, function address, and a sentence embedding — so the next sweep against a related binary replays it automatically.

3. **PSIRT submissions required manual compilation.** The registry exports findings in a format the Flywheel can replay and a researcher can hand directly to a PSIRT analyst: title, description, CWE class, severity, and the binary-specific address.

---

## PathSolver

`PathSolver` runs bounded symbolic execution on x86-64 binaries. It enumerates all simple paths in the CFG from a function entry to a target block, encodes register state at each branch as Z3 BitVec constraints, and calls Z3 to solve. A SAT result means the path is feasible and the model gives concrete entry-register values.

### Usage

```python
from ablation.analyzers.path_solver import PathSolver, solve_for_sink
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

### Result fields (`PathResult`)

| Field | Description |
|---|---|
| `target_va` | VA of the sink instruction |
| `sat` | `True` if Z3 found a satisfying assignment |
| `path` | Block VA sequence from entry to sink |
| `model` | `dict[str, int]` — concrete register values at function entry that reach the sink |
| `constraints` | Z3 formula encoding all path and state constraints |

### Limitations

- Memory reads modeled as unconstrained symbolic values (sound over-approximation).
- Calls clobber caller-saved registers to fresh unconstrained symbols.
- Indirect jumps stop path enumeration at the branch site.
- Bounded by `MAX_PATH_BLOCKS` to avoid path explosion on large CFGs.

---

## FindingRegistry

`FindingRegistry` persists confirmed findings to `~/.ablation/findings.db` (SQLite, never committed to git). It seeds embeddings from `ablation/data/seed_corpus.json` on first run, then extends with every registered finding. The Flywheel replays registered findings as search patterns on every new binary sweep.

### Usage

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

### Schema

| Field | Description |
|---|---|
| `vendor` | Target vendor name |
| `product` | Target product name |
| `version` | Affected firmware/software version |
| `title` | One-line finding description |
| `description` | Free-text technical detail — taint path, call chain, vuln class |
| `cwe_class` | CWE identifier (e.g. `CWE-121`) |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `embedding` | Sentence vector for similarity search |
| `func_addr` | VA of the vulnerable function |
| `binary` | Filename of the analyzed binary |

---

## Workflow

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
