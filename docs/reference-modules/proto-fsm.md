<a id="protocol-fsm-extractor"></a>
# Protocol & Steganography Analysis

**File:** `modules/proto_fsm.py`

Extracts the handshake state machine from network protocols in stripped ARM64 binaries using static loop and BSS state-variable analysis. Authentication state transitions become explicit without a running server or traffic capture.

Developed from the MMTLS handshake implementation in WeChat's `libwechatnetwork.so`, applying techniques from two research papers: NEMETYL segment-based similarity and DBSCAN clustering for message-type inference and static loop analysis for FSM recovery from 5G protocol implementations.

---

## Why this exists

Three gaps existed before this module:

1. **Handshake FSM recovery required live traffic.** Tools like NEMETYL operate on PCAPs. Stripped ARM64 libraries with no symbols produce no traffic until they run. This module recovers the FSM entirely from static analysis, no emulation, no network capture.

2. **BSS state variables were invisible to generic analysis.** The handshake state machine writes integer state values to fixed BSS addresses and branches on them. No existing static tool identified those addresses as state variables or built a graph from the read → branch → write pattern.

3. **WeChat MMTLS was unanalyzed.** The custom TLS-like handshake in `libwechatnetwork.so` (WeChat 8.0.56 ARM64) had no public FSM reconstruction. This module produced the first static extraction of its authentication state graph.

---

## Pipeline

The extractor runs four phases against the target shared object:

**Phase 1, State variable identification** 
Scans the handshake function cluster for BSS addresses written with small integer immediates and read before conditional branches. These are the state variables.

**Phase 2, Handshake function cluster** 
Builds a BL-reachable subgraph from user-supplied seed VAs, bounded by `hop_depth` default 2 hops. The cluster contains the complete handshake implementation without manual identification.

**Phase 3, Transition extraction** 
Finds `state_read → branch → BL call → state_write` quads within the cluster. Each quad is an FSM transition.

**Phase 4, Graph output** 
Builds `FSMState` and `FSMTransition` objects and exports a Graphviz DOT graph.

---

## Usage

```python
from modules.proto_fsm import (
    _load, _text_bounds, _bss_bounds, build_cluster,
    identify_state_vars, analyze_fn, extract_transitions, build_fsm, emit_dot,
    DEFAULT_SEEDS, FnProps, FSMState, FSMTransition,
)

binary, raw, _ = _load('/path/to/libwechatnetwork.so')
text_va, text_size, _ = _text_bounds(binary)
bss_va, bss_size = _bss_bounds(binary)

state_vars = identify_state_vars(raw, binary, text_va, text_size, bss_va, bss_size)
cluster = build_cluster(raw, binary, DEFAULT_SEEDS, hop_depth=2)
fn_props = {va: analyze_fn(raw, binary, va, state_vars) for va in cluster}
transitions = extract_transitions(raw, binary, cluster, state_vars, fn_props)
states, transitions = build_fsm(state_vars, transitions, cluster, fn_props)
dot = emit_dot(states, transitions, state_vars)

# Print transitions
for t in transitions:
    print(f"state {t.from_state} --[0x{t.trigger_pc:x}]--> state {t.to_state}")

# Export DOT for Graphviz
with open('fsm.dot', 'w') as f:
    f.write(dot)
# Render: dot -Tpng fsm.dot -o fsm.png
```

**CLI:**
```bash
python3 proto_fsm.py --so /path/to/libwechatnetwork.so --dot fsm.dot
python3 proto_fsm.py --so /path/to/target.so --seed 0x111f98 --seed 0x305020 --hop-depth 2
```

---

## Data classes

### `StateVar`

| Field | Description |
|---|---|
| `addr` | BSS virtual address of the state variable |
| `read_sites` | VAs of LDR instructions that read this variable before a branch |
| `write_sites` | VAs of STR instructions that write this variable after a branch or call |
| `observed_values` | Set of integer values written to this variable |

### `FSMState`

| Field | Description |
|---|---|
| `id` | State node ID in the graph |
| `value` | Integer value of the state variable in this state |
| `functions` | VAs of functions associated with this state |

### `FSMTransition`

| Field | Description |
|---|---|
| `from_state` | ID of the originating state |
| `to_state` | ID of the destination state |
| `trigger_pc` | VA of the BL instruction that triggers the transition |
| `trigger_fn` | VA of the called function |
| `state_var` | BSS address of the state variable this transition reads/writes |

---

## Bitmap LSB key extraction

`BmpKeyExtractor` reads least-significant-bit data from a BMP using a target-specific seed, extracts coordinate pairs, and reconstructs key components with exact rational arithmetic.

```python
from ablation.analyzers.lsb_stego_extractor import BmpKeyExtractor

extractor = BmpKeyExtractor('/path/to/embedded.bmp')
result = extractor.extract(seed='target-specific-seed', n_primes=8)
print(result.fmt())
for component in result.components:
    print(component)
```

For lower-level access, `LSBStegoReader(pixel_data).extract_coords(seed)` returns coordinates and `LagrangeKeyExtractor.extract(coords, n_pts)` performs reconstruction. This is a target-specific encoding, not general steganography detection. Ordinary BMP data can produce meaningless coordinates; validate recovered material against the consuming implementation without exposing secrets in logs or reports.

---

## Default seed VAs (WeChat 8.0.56 ARM64)

| VA | Function |
|---|---|
| `0x111f98` | `ILinkKey` constructor / init |
| `0x305020` | list clear-all |
| `0x305094` | list sort-reorder |
| `0x304d64` | list search + delete |
| `0x2ec280` | list insertion |
| `0x246364` | `saveAuthLongList` |

For other ARM64 targets, supply seed VAs from semantic search results for handshake-related functions (`SemanticSearcher.query("handshake state machine authentication")`).

---

## Error conditions

`_load()` raises `ValueError` if:
- The `.so` file exceeds `_MAX_BINARY_BYTES` (256 MB).
- `lief.parse()` raises an exception corrupt/unsupported ELF.
- `lief.parse()` returns `None`: checked explicitly to prevent `AttributeError` on the
 subsequent `.segments` access.

## Known limitations

- Requires at least one known seed VA; the cluster-expansion phase cannot start from zero.
- Indirect BL calls function pointers stop cluster expansion at the indirect site.
- The BSS state variable heuristic filters out addresses written with large immediates (>255); genuine state variables that use enum values outside that range require a manual seed override.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `_load()` reads the ELF directly: `_MAX_BINARY_BYTES=256MB`; `Path.stat().st_size` guard before `lief.parse()`; `lief.parse()` in `try/except Exception` + explicit `binary is None` check.

---

## How it works

Four-phase pipeline using `_load()` lief + raw bytes directly: no `BinaryContext` required.

**Phase 1**: `identify_state_vars()` scans the entire `.text` section for STR/STP instructions writing small integer immediates (≤255) to BSS addresses, and LDR instructions reading BSS addresses within 4 instructions of a conditional branch. These patterns identify state variables.

**Phase 2**: `build_cluster()` performs BFS from user-supplied seed VAs over direct `BL` edges, bounded by `hop_depth` default 2. Returns `{fn_va: set_of_callees}`.

**Phase 3**: `analyze_fn()` runs once per cluster function. Returns a `FnPropsva, reads_state_vars, writes_state_vars, calls_insert, calls_delete` where `reads_state_vars` and `writes_state_vars` are lists of BSS VAs. Then `extract_transitions()` finds `LDR state_var → branch → BL → STR state_var` quads and emits `FSMTransition` objects.

**Phase 4**: `build_fsm()` assigns integer state IDs and `emit_dot()` exports Graphviz DOT.

---

## Example output

```python
# FnProps for one cluster function (fn_va=0x246364, saveAuthLongList)
fn_props[0x246364]
# FnProps(va=0x246364,
#   reads_state_vars=[0x3d1a08, 0x3d1a10],   # BSS VAs of state vars read
#   writes_state_vars=[0x3d1a08],              # BSS VAs of state vars written
#   calls_insert=True,
#   calls_delete=False)

# Transitions (printed via the Usage section loop):
# state 0 --[0x246380]--> state 1
# state 1 --[0x111fa4]--> state 2
# state 2 --[0x305020]--> state 0

# DOT graph:
# digraph FSM {
#   0 [label="s0\n(val=0)\n[0x246364]"];
#   1 [label="s1\n(val=1)\n[0x111f98]"];
#   0 -> 1 [label="@0x246380\n->0x111fa4"];
# }
```

---

## False positives

State variable identification heuristic BSS writes with small immediates ≤255 may pick up non-state counters or flags. Check `observed_values` in each `StateVar`: a genuine state enum has a small number of distinct values (2–8). Counters produce many distinct values and should be excluded.

---

## Pipeline position

**Before this module:** Use `_load(path)` directly returns `binary, raw, load_addr`. Identify seed VAs via `SemanticSearcher.query("handshake state machine authentication")` or known entry points. No `BinaryContext` required.

**After this module:** Call `emit_dotstates, transitions, state_vars` and render with Graphviz to visualize the FSM. Identify missing authentication state checks for example a transition from an unauthenticated state to a sensitive resource that skips the authenticated state.

---

## Reading output

`analyze_fnraw, binary, fn_va, state_vars` returns a `FnProps` for one function. Build the protocol FSM by calling it across all functions. The state model objects:

`FSMState`:

| Attribute | Content |
|:---|:---|
| `id` | Integer state identifier |
| `value` | State variable value in this state |
| `functions` | `List[int]`: function VAs active in this state |

`FSMTransition`:

| Attribute | Content |
|:---|:---|
| `from_state` | Source state ID |
| `to_state` | Destination state ID |
| `trigger_pc` | PC of the instruction that caused the transition |
| `trigger_fn` | VA of the function containing `trigger_pc` |
| `state_var` | BSS VA of the state variable being written |

`StateVar` input to the analysis:

| Attribute | Content |
|:---|:---|
| `addr` | BSS VA of the state variable |
| `read_sites` | `List[int]`: PCs of LDR instructions that read it before a branch |
| `write_sites` | `List[int]`: PCs of STR instructions that write it after a branch |
| `observed_values` | `Set[int]`: concrete values observed at write sites |

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
