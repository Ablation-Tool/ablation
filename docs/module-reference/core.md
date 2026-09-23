# Core Analyzers

Every workflow starts here.

---

## BinaryContext

**File:** `ablation/analyzers/binary_context.py`

Build once, reload in 110ms. BinaryContext is the single object that represents everything
Ablation knows about a stripped ELF binary: PLT symbols, exports, strings, function starts,
call graph, and a NumPy-built RIP-relative xref index.

### Build and load

```python
from ablation.analyzers.binary_context import BinaryContext

# Load from cache if valid (SHA256-keyed), otherwise build from scratch
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Force rebuild (ignore cache)
ctx = BinaryContext.load_or_build('/path/to/binary.so', force_rebuild=True)

# Load from cache file when the binary itself is unavailable
ctx = BinaryContext.load_from_cache_file('~/.ablation/cache/<slug>.json', orig_path='')
```

**Build time:** 0.5 to 5 seconds depending on binary size.
**Reload time:** 110ms from `~/.ablation/cache/<sha256[:16]>_<name>.json`.
**Invalidation:** SHA256 mismatch triggers automatic rebuild.

### What gets built

| Field | Type | Description |
|---|---|---|
| `plt` | `{va: symbol_name}` | All PLT stubs resolved to symbol names |
| `exports` | `{symbol_name: va}` | All globally exported functions |
| `strings` | `{va: content}` | Printable strings in `.rodata` (>= 4 chars) |
| `func_starts` | `[va, ...]` | Sorted function entry VAs (eh_frame + callee augmentation) |
| `call_edges` | `[(from_va, to_va, label)]` | Flat call graph |
| `_str_xref_idx` | `{string_va: [code_va, ...]}` | NumPy-built RIP-relative xref index |
| `_func_str_idx` | `{func_va: [string_va, ...]}` | Per-function string reference index |

### Query API

```python
# Function name (overlay > export > PLT > hex)
ctx.name(0x17b660)                         # "ips_diameter_parse_message"

# Call graph navigation
ctx.callers_of('memcpy')                   # [(caller_va, name), ...]
ctx.callers_of(0x17b660)                   # [(caller_va, name), ...]
ctx.callees_of(0x17b660)                   # [(target_va, label), ...]

# String xrefs
ctx.strings_in_func(0x17b660)             # [(string_va, content), ...]
ctx.string_xrefs(string_va)               # [code_va, ...]
ctx.funcs_referencing_string(string_va)   # [func_va, ...]
ctx.strings_near(va, radius=128)           # [(string_va, content), ...]

# Function boundary
ctx.func_containing(0x17b851)             # 0x17b660  (nearest start <= va)

# Summary
print(ctx.summary())                       # PLT/export/func/string/edge counts
```

### Discovered-name overlay

```python
# Register a name (persists across sessions via NameRegistry)
ctx.set_name(0x17b660, 'ips_diameter_parse_message', source='confirmed')
ctx.delete_name(0x17b660)

# Read the overlay
ctx.name(0x17b660)           # returns overlay name if set, then export/PLT/hex
ctx.names_table()            # formatted table of all discovered names
ctx.names_map()              # {va: name} dict
ctx.names_count()            # int
```

### RIP-relative xref index

`_build_string_xref_index` treats `.text` as a `uint8` NumPy array, extracts 4-byte
little-endian displacement fields at every byte offset using `as_strided`, and computes
`target_va = text_va + pos + 4 + disp32[pos]` in a single broadcast operation. It then
binary-searches the result against the known string VA array.

This builds `_str_xref_idx` (string_va -> [code_vas]) and `_func_str_idx`
(func_va -> [string_vas]) in one O(N) pass over the binary.

### Vectorized call graph

`_build_call_graph` scans `.text` for the CALL rel32 opcode byte (`0xe8`) with
`np.where(buf[:-4] == 0xe8)`, extracts all 4-byte LE displacements in one stride-indexed
operation, and computes `target_va = sec_va + pos + 5 + disp32` across all candidates in a
single broadcast. A `searchsorted` filter against `plt | func_starts` eliminates false
positives from `0xe8` bytes that appear inside other instruction operands. Owner assignment
uses one batched `searchsorted` call rather than per-site binary search.

---

## XRefGraph

**File:** `ablation/analyzers/xref_graph.py`

Full cross-reference graph with indirect call resolution. SemanticSearcher and TaintTracker
require XRefGraph as their structural neighborhood source.

```python
from ablation.analyzers.xref_graph import XRefGraph

xg = XRefGraph.from_path('/path/to/binary.so')
xg.build()

xg.callers(0x17b660)        # direct callers
xg.callees(0x17b660)        # direct callees
xg.reachable(0x17b660)      # all functions reachable via BFS
xg.call_depth(0x17b660)     # max call depth from va
```

---

## CFGBuilder

**File:** `ablation/analyzers/cfg_builder.py`

Per-function control flow graph via iterative recursive disassembly. Implements the approach
from Andriesse's *Practical Binary Analysis*, ch. 8.2.4.

```python
from ablation.analyzers.cfg_builder import CFGBuilder
from ablation.analyzers.xref_graph import XRefGraph

xg = XRefGraph.from_path('/path/to/binary.so').build()
builder = CFGBuilder('/path/to/binary.so', xref=xg)

cfg = builder.build_function(0x17b660)

for bb_va, bb in cfg.blocks.items():
    print(f"  BB 0x{bb_va:x}: {len(bb.insns)} insns -> succs={[hex(s) for s in bb.succs]}")
```

**BasicBlock fields:**

| Field | Type | Description |
|---|---|---|
| `start` | `int` | First instruction VA |
| `end` | `int` | Last instruction VA (inclusive) |
| `succs` | `List[int]` | Successor VAs (branch targets and fall-through) |
| `insns` | `List[(va, mnemonic, op_str)]` | Instruction list |

**Algorithm:** Starts from the function entry VA. At each instruction: branch instructions
push both fall-through and target onto the queue; unconditional jmp/ret/hlt end the block;
call instructions push fall-through only (CFGBuilder does not follow cross-function calls).
The queue runs to empty.

---

## TaintTracker (x86-64)

**File:** `ablation/analyzers/taint_tracker_x86.py`

Static intraprocedural x86-64 taint analysis. Adapts the libdft taint policy from Andriesse's
*Practical Binary Analysis*, ch. 11, for static analysis.

### Taint propagation rules

| Instruction class | Behavior |
|---|---|
| `mov/movsx/movzx` (XFER) | `dst_taint = src_taint` |
| `add/sub/and/or/xor/shl` (ALU) | `dst_taint |= operand taints` |
| `xor rX, rX` / `sub rX, rX` (CLR) | `dst_taint = {}` |
| `lea` (SPEC) | `dst_taint = union(base_reg, index_reg taints)` |
| Call to source function | `rax` tainted; buffer arg tracked if on stack |
| Call to sink function | Alert if relevant arg register is tainted |
| Call to unknown function | Caller-saved regs cleared (rax/rcx/rdx/rsi/rdi/r8-r11) |

### Stack model

Tracks both `rbp-relative` and `rsp-relative` (with delta tracking) stack slots. Taint
follows values through stack loads and stores within the function.

### Usage

```python
from ablation.analyzers.taint_tracker_x86 import TaintTracker
from ablation.analyzers.xref_graph import XRefGraph

xg = XRefGraph.from_path('/path/to/binary.so').build()
tracker = TaintTracker('/path/to/binary.so', xref=xg)

findings = tracker.run()
for f in findings:
    print(f)

# CLI
# python -m ablation.analyzers.taint_tracker_x86 /path/to/binary.so
```

**Sources (default):** `recv`, `read`, `recvfrom`, `recvmsg`
**Sinks (default):** `memcpy`, `malloc`, `memmove`, `sprintf`, `strcpy`, `system`, `popen`

---

## PathSolver

**File:** `ablation/analyzers/path_solver.py`

Constraint-based path feasibility checker. Given a CFG and a target basic block (e.g., a
memcpy call site), PathSolver determines whether a path exists from the function entry that
satisfies the branch conditions leading to that block.

```python
from ablation.analyzers.path_solver import PathSolver
from ablation.analyzers.cfg_builder import CFGBuilder

builder = CFGBuilder('/path/to/binary.so', xref=xg)
cfg = builder.build_function(0x17b660)

solver = PathSolver(cfg)
result = solver.is_reachable(target_bb_va=0x17b84c)
print(result.feasible, result.path)
```

TaintTracker uses PathSolver to eliminate false positives where the tainted path is unreachable
due to contradictory branch constraints.

---

## FuncProfiler

**File:** `ablation/analyzers/func_profiler.py`

Rapid triage in one call. FuncProfiler combines CFGBuilder, TaintTracker, and BinaryContext
queries into a structured summary without full disassembly.

```python
from ablation.analyzers.func_profiler import FuncProfiler

profiler = FuncProfiler('/path/to/binary.so', ctx=ctx, xg=xg)
profile = profiler.profile(0x17b660)
print(profile.summary())
```

**Profile output includes:** basic block count, edge count, PLT calls, string references,
estimated size, and branch density classification (linear / switch / loop-heavy).
