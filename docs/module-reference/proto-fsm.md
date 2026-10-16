# Protocol FSM Extractor

**File:** `ablation/analyzers/proto_fsm.py`

Extracts the handshake state machine from network protocols in stripped ARM64 binaries using static loop and BSS state-variable analysis. Authentication state transitions become explicit without a running server or traffic capture.

Developed from the MMTLS handshake implementation in WeChat's `libwechatnetwork.so`, applying techniques from two research papers: NEMETYL (segment-based similarity and DBSCAN clustering for message-type inference) and static loop analysis for FSM recovery from 5G protocol implementations.

---

## Why this exists

Three gaps existed before this module:

1. **Handshake FSM recovery required live traffic.** Tools like NEMETYL operate on PCAPs. Stripped ARM64 libraries with no symbols produce no traffic until they run. This module recovers the FSM entirely from static analysis — no emulation, no network capture.

2. **BSS state variables were invisible to generic analysis.** The handshake state machine writes integer state values to fixed BSS addresses and branches on them. No existing static tool identified those addresses as state variables or built a graph from the (read → branch → write) pattern.

3. **WeChat MMTLS was unanalyzed.** The custom TLS-like handshake in `libwechatnetwork.so` (WeChat 8.0.56 ARM64) had no public FSM reconstruction. This module produced the first static extraction of its authentication state graph.

---

## Pipeline

The extractor runs four phases against the target shared object:

**Phase 1 — State variable identification**  
Scans the handshake function cluster for BSS addresses written with small integer immediates and read before conditional branches. These are the state variables.

**Phase 2 — Handshake function cluster**  
Builds a BL-reachable subgraph from user-supplied seed VAs, bounded by `hop_depth` (default 2 hops). The cluster contains the complete handshake implementation without manual identification.

**Phase 3 — Transition extraction**  
Finds `(state_read → branch → BL call → state_write)` quads within the cluster. Each quad is an FSM transition.

**Phase 4 — Graph output**  
Builds `FSMState` and `FSMTransition` objects and exports a Graphviz DOT graph.

---

## Usage

```python
from modules.proto_fsm import extract_fsm, FSMState, FSMTransition

# Extract with default WeChat seeds
states, transitions, dot = extract_fsm('/path/to/libwechatnetwork.so')

# Print state graph
for t in transitions:
    print(f"state {t.from_state} --[0x{t.trigger_pc:x}]--> state {t.to_state}")

# Export DOT for Graphviz
with open('fsm.dot', 'w') as f:
    f.write(dot)
# Render: dot -Tpng fsm.dot -o fsm.png

# Custom seeds (for a different target)
from modules.proto_fsm import extract_fsm
states, transitions, dot = extract_fsm(
    '/path/to/target.so',
    seed_vas=[0x111f98, 0x305020],
    hop_depth=3,
)
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

`extract_fsm()` and `_load()` raise `ValueError` if:
- The `.so` file exceeds `_MAX_BINARY_BYTES` (256 MB).
- `lief.parse()` raises an exception (corrupt/unsupported ELF).
- `lief.parse()` returns `None` — checked explicitly to prevent `AttributeError` on the
  subsequent `.segments` access.

## Known limitations

- Requires at least one known seed VA; the cluster-expansion phase cannot start from zero.
- Indirect BL calls (function pointers) stop cluster expansion at the indirect site.
- The BSS state variable heuristic filters out addresses written with large immediates (>255); genuine state variables that use enum values outside that range require a manual seed override.
