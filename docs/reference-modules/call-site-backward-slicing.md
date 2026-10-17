# Interprocedural Register Annotation

Extend `RegAnnotator`'s single-function forward symbolic pass to follow call chains across function boundaries — seeding each callee's entry registers with the actual `RegVal` objects from the caller's register state at the call site, enabling argument provenance to trace back to the root function's entry arguments across N hops.

---

## Why this exists

1. **`RegAnnotator` stops at function boundaries.** When a tainted register is passed as an argument to a callee, `RegAnnotator` tracks it inside that callee separately from the caller — losing the chain of provenance back to the original source. `IPRegAnnotator` re-seeds the callee's entry registers with the caller's live values, maintaining the full provenance chain across the call.

2. **`ChainCallSite` records the call VA, callee name, and live argument registers at each hop** — enabling `ChainResult.all_sinks()` to find every sink call site reachable from the root function's tainted arguments, regardless of how many intermediate functions the tainted value passes through. This is the mechanism that confirms a multi-hop injection chain: `user_input → handler → validator → exec_wrapper → system()`.

3. **`IPRegAnnotator` is the required tool for cross-library call chains** — when a tainted value crosses a PLT boundary into another library, `RegAnnotator` alone cannot continue the trace. `IPRegAnnotator` uses `LibGraph` to resolve the callee's binary and continues the forward symbolic pass into the external library's function, producing a complete cross-binary argument provenance chain.

---

## How it works

```mermaid
flowchart TD
    A["IPRegAnnotator(ctx, lib_graph=None)"] --> B["annotate(func_va, max_hops=3) → ChainResult\n  Run RegAnnotator.annotate(func_va)\n  For each BL/CALL in the result:\n    If callee is resolvable (PLT name in ctx or lib_graph):\n      Load callee function\n      Seed callee entry registers with caller's live RegVals at call_va\n      Run RegAnnotator.annotate(callee_va, seeded_state)\n      → ChainCallSite(call_va, callee_name, args, chain_result)\n  Recurse up to max_hops"]
    B --> C["ChainResult:\n  root_func_va: int\n  call_sites: List[ChainCallSite]\n  all_sinks(sink_names) → List[Tuple[int, str, ChainCallSite]]\n    Find (va, sink_name, call_site) where callee in sink_names\n  fmt() → str"]
    C --> D["ChainCallSite:\n  call_va: int\n  callee_name: str\n  args: Dict[str, RegVal]  ($a0–$a7 or r0–r7 etc)\n  depth: int\n  chain_result: Optional[ChainResult]\n  fmt() → str"]
```

---

## Usage

```python
from ablation.analyzers.ipreg_annotator import IPRegAnnotator
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.lib_graph import LibGraph

ctx = BinaryContext.load_or_build('/path/to/httpd')
lib_graph = LibGraph.from_dir('/path/to/firmware/lib/')

annotator = IPRegAnnotator(ctx, lib_graph=lib_graph)

result = annotator.annotate(handler_va, max_hops=3)
print(result.fmt())

# Find all sink calls reachable from this handler
for va, sink_name, call_site in result.all_sinks({'system', 'execv', 'popen'}):
    print(f"  Sink: {sink_name} at {va:#x}  depth={call_site.depth}")
    print(f"  args: {call_site.args}")
```

---

## Example output

The following illustrates interprocedural register annotation output format. Actual VAs are binary-specific.

```
IPRegAnnotator: httpd  root=<va>

ChainResult:
  Depth 0 → handler at <va>
    BL validate_input(<va>)  args: {r0: ARG0_from_recv, r1: 0x20}
  Depth 1 → validate_input at <va>
    BL exec_wrapper(<va>)    args: {r0: ARG0_from_recv (passed through)}
  Depth 2 → exec_wrapper at <va>
    BL system(<va>)          args: {r0: ARG0_from_recv}

all_sinks('system'): [(system_va, 'system', call_site)]
  ARG0 = ARG0_from_recv  (provenance: recv() at <va>)
```

---

## False positives

**`max_hops` limits the chain depth** — a taint path deeper than `max_hops` is not traced. If no sink is found at `max_hops=3`, increase to 5 before concluding no path exists.

**Register state at cross-library calls is based on the caller's symbolic values at the call site** — if the caller modifies a register between the last symbolic write and the call, the modification may not be captured. Always verify the annotated argument provenance against the disassembly.

---

## Pipeline position

Run `IPRegAnnotator.annotate()` on confirmed pre-auth handler VAs or CMDB sink-co-location callers. It produces the multi-hop argument provenance chain needed for `byte_proof` in confirmed findings that span multiple function boundaries.

---

## Reading output

`IPRegAnnotator.annotate_chain(root_va)` returns an `IPChain` object:

| Attribute | Content |
|:---|:---|
| `root_va` | VA of the root entry function |
| `root_binary` | Path of the binary containing the root function |
| `max_hops` | Maximum call depth configured for this trace |
| `root` | `ChainResult` — root function result, with nested callee chains via `.calls` |

Each `ChainResult` in the chain:

| Attribute | Content |
|:---|:---|
| `func_va` | VA of this function |
| `func_end_va` | End VA of this function |
| `binary` | Path of the binary containing this function |
| `hop` | Hop depth (0 = root, 1 = callee, 2 = callee's callee, …) |
| `calls` | `List[ChainCallSite]` — each call site with its argument register annotations |

Call `chain.all_sinks(sink_names)` to get all `(func_va, binary, ChainCallSite)` tuples for any named sink within the full chain.

---

## See also

- [Register Annotation (Single Function)](register-annotation.md) — `RegAnnotator` base for single-function symbolic forward pass
- [Cross-Binary Taint Analysis](configurable-taint-reporting.md) — `CrossBinaryTaintTracker` for labeled taint across library boundaries
- [CMDB Attack Surface Mapping](finding-corpus-mining.md) — `CMDBSurfaceMapper` that identifies callers for IPRegAnnotator analysis
