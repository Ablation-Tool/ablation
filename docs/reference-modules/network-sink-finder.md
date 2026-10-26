# NetworkSinkFinder

Finds every network-reachable dangerous exec sink in a binary by cross-referencing BFS callgraph reachability with SinkArgClassifier results.

---

## Why this exists <sup>[↑](#networksinkfinder)</sup>

1. High-SAC binaries 100+ sinks require cross-referencing network entry points with dangerous sinks. Doing this manually takes 30-50 lines per session because `callers_of`, `reachable_from`, and `SinkArgClassifier` are separate tools with incompatible outputs.
2. `SinkArgClassifier.classify_all()` returns results by call site, not by network reachability. A binary with 363 ARG_PROPAGATED results requires further filtering before any finding is meaningful.
3. The HACMP-003 analysis HACMP PPC32 clstrmgr, CONFIRMED HIGH NETWORK_ARG_PROPAGATED_STRCPY required writing this pattern by hand. `NetworkSinkFinder` encodes that exact pattern so it runs in 3 lines instead of 30.

---

## How it works <sup>[↑](#networksinkfinder)</sup>

```
PLT network sources (recv, read, fgets, …)
        ↓  callers_of
seed function set
        ↓  BFS via callees_of (depth N)
reachable VA set
        ↓  intersect with SAC ARG_PROPAGATED + UNKNOWN results
{func_va: NetworkSinkResult}
```

The BFS uses `BinaryContext.reachable_from`, which guarantees minimum call depth from the source. Results are keyed by function VA so multiple sinks in the same function collapse to the highest-priority verdict.

Verdict priority: `ARG_PROPAGATED` > `UNKNOWN` > `SNPRINTF_RODATA`. `RODATA_CONST` sinks are dropped: they are not injectable.

---

## NetworkSinkFinder <sup>[↑](#networksinkfinder)</sup>

```python
from ablation.analyzers.network_sink_finder import NetworkSinkFinder

nsf = NetworkSinkFinder.from_context(ctx)
results = nsf.find(depth=3)
for r in results.values():
    print(r.fmt())
```

### Constructor <sup>[↑](#networksinkfinder)</sup>

```python
NetworkSinkFinder(ctx, depth=3, net_source_names=None, extra_sinks=None)
```

| Parameter | Type | Description |
|:---|:---|:---|
| `ctx` | `BinaryContext` | Target binary context |
| `depth` | `int` | Maximum BFS call depth from network source to sink function |
| `net_source_names` | `Set[str]` | Additional PLT source names beyond `recv/read/fgets/accept/…` |
| `extra_sinks` | `Dict[str, int]` | Additional sink names + arg positions beyond SAC defaults |

### Methods <sup>[↑](#networksinkfinder)</sup>

| Method | Returns | Description |
|:---|:---|:---|
| `find(depth=None)` | `Dict[int, NetworkSinkResult]` | Run full analysis; keyed by function VA |
| `report(findings=None)` | `str` | Format findings as a readable string block |

---

## Usage <sup>[↑](#networksinkfinder)</sup>

```python
# Minimal — depth-3 BFS, all default sources and sinks
nsf = NetworkSinkFinder.from_context(ctx)
results = nsf.find()
print(nsf.report(results))

# Add a vendor-specific sink
nsf = NetworkSinkFinder.from_context(ctx, extra_sinks={'fadcsystem': 1})
results = nsf.find(depth=4)

# Check only accept()-seeded paths
nsf = NetworkSinkFinder.from_context(ctx, net_source_names={'accept'})
results = nsf.find()

# One-liner for the HACMP-003 pattern
dangerous = NetworkSinkFinder.from_context(ctx).find(depth=3)
```

---

## Example output <sup>[↑](#networksinkfinder)</sup>

```
NetworkSinkFinder: 7 network-reachable dangerous sinks
  depth=1  CL_cluster::retr_net (0x10144a58): strcpy [ARG_PROPAGATED] depth=1 via recv@@GLIBC_2.0
  depth=2  HaDebugLong::Msg1 (0x1008ef64): sprintf [ARG_PROPAGATED] depth=2 via recv@@GLIBC_2.0
  depth=3  ha_init (0x100a1234): system [UNKNOWN] depth=3 via recv@@GLIBC_2.0
```

---

## False positives <sup>[↑](#networksinkfinder)</sup>

**Reachability without data flow.** A function that calls recv and also calls strcpy on unrelated data will appear in results. Verify with `WindowAnalyzer.dump_text()` that the strcpy argument actually comes from the recv buffer.

**Depth inflation.** BFS from all network callers includes functions reachable through long chains that may not carry attacker data. Start with depth=2 to see direct hits first, then increase.

**UNKNOWN sinks that are safe.** SAC UNKNOWN means the argument source was not resolved statically. Some UNKNOWN sinks use hardcoded config paths. Check with `FuncProfiler` before classifying as exploitable.

---

## Pipeline position <sup>[↑](#networksinkfinder)</sup>

**Before this module:** `BinaryContext.load_or_build` + `SinkArgClassifier.from_context`. NetworkSinkFinder runs both internally, but running SAC first lets you see the total sink count before filtering by reachability.

**After this module:** `TaintTracker` on each `ARG_PROPAGATED`/`UNKNOWN` result to confirm the data-flow path from network source to sink. Then `WindowAnalyzer.dump_text` on each confirmed func_va to trace the argument chain manually. `PathSolver` for feasibility.

---

## Reading findings <sup>[↑](#networksinkfinder)</sup>

| Field | Content |
|:---|:---|
| `func_va` | VA of the function containing the sink |
| `func_name` | Name from `ctx.name(func_va)` |
| `sink_name` | PLT symbol of the dangerous sink |
| `verdict` | `ARG_PROPAGATED` / `UNKNOWN` / `SNPRINTF_RODATA` |
| `depth` | BFS call depth from nearest network source |
| `source_syms` | Which PLT network source names reach this function |

---

## See also <sup>[↑](#networksinkfinder)</sup>

- [Sink Arg Classifier](sink-arg-classifier.md): provides the ARG_PROPAGATED results NetworkSinkFinder filters
- [Window Analyzer](window-analyzer.md): use after NetworkSinkFinder to confirm the argument chain
- [TaintTracker PPC32](taint-tracker-ppc32.md): interprocedural taint for confirmed candidates
