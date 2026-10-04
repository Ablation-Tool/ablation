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
ctx.name(0x1000)                         # "proto_parse_message"

# Call graph navigation
ctx.callers_of('memcpy')                   # [(caller_va, name), ...]
ctx.callers_of(0x1000)                   # [(caller_va, name), ...]
ctx.callees_of(0x1000)                   # [(target_va, label), ...]

# String xrefs
ctx.strings_in_func(0x1000)             # [(string_va, content), ...]
ctx.string_xrefs(string_va)               # [code_va, ...]
ctx.funcs_referencing_string(string_va)   # [func_va, ...]
ctx.strings_near(va, radius=128)           # [(string_va, content), ...]

# Function boundary
ctx.func_containing(0x1200)             # 0x1000  (nearest start <= va)

# Summary
print(ctx.summary())                       # PLT/export/func/string/edge counts
```

### Discovered-name overlay

```python
# Register a name (persists across sessions via NameRegistry)
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')
ctx.delete_name(0x1000)

# Read the overlay
ctx.name(0x1000)           # returns overlay name if set, then export/PLT/hex
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

### PPC64 string xref — 5-pass system (Cell PPU / CryEngine PS3)

PowerPC64 big-endian binaries use an ABI-defined Table of Contents (r2) for all global
data access.  Direct RIP-relative displacement scanning finds nothing because PPC64 never
encodes absolute addresses as inline 4-byte fields in the instruction stream.  The PPC64
path runs five passes against the binary to build equivalent `_str_xref_idx` /
`_func_str_idx` coverage:

| Pass | Method | Mechanism | Coverage |
|---|---|---|---|
| 1 | `_build_string_xref_index_ppc64` (main) | TOC far-load: `ADDIS rX, r2, ha16 + LWZ rX, lo16(rX)` | Direct far-TOC string loads |
| 2 | same | TOC near-load: `LWZ rX, off(r2)` within ±32KB of r2 | Near-TOC string loads |
| 3 | `_augment_xrefs_ppc64_precall` | Backward scan from BL: `LIS rX, hi + ADDI rX, lo` pre-call pattern | Inline arg-reg loads before calls |
| 4 | `_augment_xrefs_ppc64_arrays` | Dense string-pointer array in data seg → batch-indexed by (ha16,lo16) key; single O(M×16) scan replaces O(arrays×M) | String pointer arrays via TOC |
| 5 | `_augment_xrefs_ppc64_twohop` | Near-TOC entry → far string-pointer array (2-hop: load array base from TOC, then index into array) — target segment: writable data | **Dominant CryEngine PS3 pattern** |
| 6 | `_augment_xrefs_ppc64_twohop` (Pass 6) | Same 2-hop mechanism; target segment: X\|R LOAD (code/rodata) — covers arrays that LIEF places in the executable segment | NanoSuit display strings and other rodata arrays |

**Pass 5/6 detail — the 2-hop pattern:**

CryEngine PS3 packs string VAs into dense arrays far from r2.  The access pattern is:
```
LWZ r11, near_off(r2)    # load array BASE pointer from near-TOC slot
LWZ r3,  N*4(r11)        # load individual string VA from the array
```

Pass 5 scans the near-TOC window (r2±32KB) for slots whose target begins a run of ≥3
consecutive string VAs.  It then does a single linear pass over `.text` matching any
`LWZ rX, off(r2)` whose displacement bytes collide with a discovered slot offset, and
attributes all strings in the pointed-to array to the enclosing function.

Pass 6 is identical but the "target" segment is the X|R LOAD segment (code/rodata) rather
than the writable data segment.  The two segments are passed separately because LIEF may
split them differently depending on whether `.rodata` is in the same PT_LOAD as `.text`.
`_augment_xrefs_ppc64_twohop` accepts optional `target_data`/`target_va` parameters;
Pass 5 omits them (defaults to ds_data/ds_va); Pass 6 passes `target_data=code_data`.

For the Crysis 2 PS3 binary (CryEngine 3, Cell PPU, ELFCLASS64), Pass 5 alone produces
~12,600 function → string xrefs from 51 array-base TOC slots.

**ELFCLASS64 note:** The Crysis 2 PS3 ELF is ELFCLASS64 despite running in 32-bit
effective-address mode.  The entry-point OPD descriptor (8 bytes: code-VA + TOC-VA) is
parsed at `e_entry` using 64-bit struct layout; r2 is extracted from offset 4.

### Vectorized call graph

`_build_call_graph` scans `.text` for the CALL rel32 opcode byte (`0xe8`) with
`np.where(buf[:-4] == 0xe8)`, extracts all 4-byte LE displacements in one stride-indexed
operation, and computes `target_va = sec_va + pos + 5 + disp32` across all candidates in a
single broadcast. A `searchsorted` filter against `plt | func_starts` eliminates false
positives from `0xe8` bytes that appear inside other instruction operands. Owner assignment
uses one batched `searchsorted` call rather than per-site binary search.

### func_starts for stripped static ELF32 binaries

ELF32 binaries that are both statically linked and stripped have no `.symtab` or `.dynsym`
entries, so `_extract_func_starts` normally produces an empty list.  lief finds no function
starts because it relies on symbol tables.  Without `func_starts`, SemanticSearcher and
TaintTracker have no function boundaries and cannot run.

`BinaryContext` automatically calls `StaticELF32FuncStartScanner` for `x86_32` binaries when
`func_starts` would otherwise be empty.  The scanner scans every PT_LOAD+PF_X segment for the
3-byte i386 function prologue pattern `55 89 e5` (`push ebp; mov ebp, esp`) — the canonical
CDECL frame setup emitted by GCC for every non-leaf function.  Secondary patterns (`55 57 56`,
`55 53`) are tried only when the primary count is under ten, indicating a non-CDECL binary.

The scanner is also available standalone when you want to augment a context from outside:

```python
from ablation.analyzers.static_elf32_func_start_scanner import StaticELF32FuncStartScanner

scanner = StaticELF32FuncStartScanner.from_path('/path/to/stripped.elf')
result = scanner.scan_full()
print(result.report())
# StaticELF32FuncStartScanner: /path/to/stripped.elf
#   executable segments scanned: 1
#   patterns used: primary (55 89 e5)
#   function starts found: 2684

# Inject into an existing context (no-op if ctx.func_starts is already populated)
scanner.inject(ctx)
```

False-positive rate on GCC i386 code is low.  The ModRM byte 0xe5 in `89 e5` encodes
(mod=11, reg=ESP, rm=EBP) — a combination that occurs inside other instruction operands
rarely enough to be negligible in practice.

---

## I386AbsoluteXrefScanner

**File:** `ablation/analyzers/i386_absolute_xref_scanner.py`

### Why the default xref index finds almost nothing in i386 code

The default `BinaryContext` xref scanner is built for x86-64, where the compiler encodes
data references as RIP-relative 32-bit signed displacements: `target_va = insn_end_va + disp32`.
On i386, the same role is played by 4-byte LE absolute immediates embedded in `push imm32`,
`mov reg, imm32`, and `lea reg, [addr]` instructions.  The formula is simply `target_va = u32`.

Without this scanner, a 675KB statically linked i386 binary yields 21 xref pairs from the
x86-64 scanner (coincidental false hits) instead of the correct 548.

### How it works

1. Read every 4-byte LE window at every byte offset in `.text` — identical stride-trick
   approach to the x86-64 scanner, but no displacement arithmetic.
2. Binary-search each window value against the sorted list of known string VAs.
3. Attribute each hit to the enclosing function via `func_containing()`.
4. Populate `ctx._str_xref_idx` and `ctx._func_str_idx` in the same format as the x86-64 index.

`BinaryContext` calls this scanner automatically for `x86_32` binaries.  StaticELF32FuncStartScanner
must already have run (so `func_starts` is populated) before this scanner fires.

```python
from ablation.analyzers.i386_absolute_xref_scanner import I386AbsoluteXrefScanner

scanner = I386AbsoluteXrefScanner.from_context(ctx)
result  = scanner.scan_full()
print(result.report())
# I386AbsoluteXrefScanner: /path/to/wsconv
#   .text size    : 452568 bytes
#   string VAs    : 934
#   xref pairs    : 548
#   unique strings: 388  unique functions: 153

# Inject into an existing context (no-op if ctx._str_xref_idx already populated)
scanner.inject(ctx)
```

**ELF32 only.** PE32 (i386 DLL/EXE) is not supported — too many false positives from vtable
and jump-table entries that accidentally fall in `.rdata` ranges.

---

## XRefGraph

**File:** `ablation/analyzers/xref_graph.py`

Full cross-reference graph with indirect call resolution. SemanticSearcher and TaintTracker
require XRefGraph as their structural neighborhood source.

```python
from ablation.analyzers.xref_graph import XRefGraph

xg = XRefGraph.from_path('/path/to/binary.so')
xg.build()

xg.callers(0x1000)        # direct callers
xg.callees(0x1000)        # direct callees
xg.reachable(0x1000)      # all functions reachable via BFS
xg.call_depth(0x1000)     # max call depth from va
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

cfg = builder.build_function(0x1000)

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
cfg = builder.build_function(0x1000)

solver = PathSolver(cfg)
result = solver.is_reachable(target_bb_va=0x1050)
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
profile = profiler.profile(0x1000)
print(profile.summary())
```

**Profile output includes:** basic block count, edge count, PLT calls, string references,
estimated size, and branch density classification (linear / switch / loop-heavy).

---

## CrossBinaryTaintTracker

**File:** `ablation/analyzers/cross_binary_taint.py`

Extends `TaintTracker` to follow tainted arguments across shared library boundaries.
`TaintTracker.run_interprocedural()` stops when a tainted argument passes into a PLT
entry. It knows the symbol name but not its address in the exporting library.
`CrossBinaryTaintTracker` resolves that name via `LibGraph`, loads the exporting
binary, and continues the BFS from the exported function's entry point.

Requires a `LibGraph` built from the firmware's library directory.

### Usage

```python
from ablation.analyzers.cross_binary_taint import CrossBinaryTaintTracker
from ablation.analyzers.lib_graph import LibGraph

lg = LibGraph.from_dir('/path/to/firmware/lib/')
tracker = CrossBinaryTaintTracker(
    entry_binary='/path/to/firmware/lib/libservice.so',
    lib_graph=lg,
    max_hops=6,
)
chains = tracker.run()
print(tracker.report(chains))
```

### TaintChain output

Each `TaintChain` records the full cross-binary path from source to sink:

```
libservice.so:recv_wrapper [tainted: arg0]
  -> libdata.so:parse_packet [tainted: arg0, arg1]
  -> libcmd.so:exec_command [tainted: arg0]
  -> system()  SINK
```

### TaintChain fields

| Field | Description |
|---|---|
| `hops` | Ordered list of `TaintHop` objects, one per function in the chain |
| `sink_binary` | Path to the binary where the dangerous sink was reached |
| `sink_va` | VA of the sink call |
| `sink_name` | Name of the sink function (`system`, `execve`, `memcpy`, etc.) |
| `tainted_args` | Which arguments arrived tainted at the sink |
| `source_name` | Entry-point function name where the taint was introduced |
| `depth` | Number of hops in the chain |
