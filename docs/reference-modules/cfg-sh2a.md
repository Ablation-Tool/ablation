# cfg_sh2a: SH-2A Control-Flow Graph Builder

**File:** `ablation/analyzers/cfg_sh2a.py` 
**Added:** v2.64.0

---

## Why this exists

Three things were not possible before in Ablation:

**1. No CFG for SH-2A firmware.** Every other ISA with a lifter backend also had a CFG
module. Without a CFG, the `Structurizer` and `DomTree` cannot run on SH-2A (Bosch EDC,
Denso, Siemens) ECU firmware. The SH-2A lifter could only produce a linear goto-chain.

**2. No delay-slot semantics in any CFG module.** SH-2A executes one instruction after a
branch fires: the delay slot. Every prior CFG module (ARM, V850, ARC, x86) works on
architectures without delay slots. `cfg_sh2a` attaches the delay-slot instruction to the
terminating block so that successor VAs are computed from after the delay slot, not from
after the branch opcode.

**3. No `.flow` / `.flow_r()` interface on any ECU-family CFG.** `dataflow_engine.DomTree`
and all backward-dataflow passes iterate `cfg.flow` as a list of `(src, dst)` edge tuples.
`cfg_sh2a.CFG` adds `.flow` (property) and `.flow_r()` (method) so DomTree and LoopInfo
from `dataflow_engine` work without any adaptation.

---

## Usage

```python
from ablation.analyzers.ecu_sh2a_decoder import EcuSH2aDecoder
from ablation.analyzers.cfg_sh2a import build_cfg

with open("sh7058_ecu.bin", "rb") as f:
    rom = f.read()

dec = EcuSH2aDecoder(rom, base_va=0)
insns = dec.disassemble(0, len(rom))
cfg = build_cfg(insns, entry=0x1000)

for block in cfg:
    print(block)

# Plug straight into dataflow_engine
from ablation.analyzers.dataflow_engine import DomTree, LoopInfo
dom   = DomTree(cfg)
loops = LoopInfo(cfg, dom)
print("back edges:", dom.back_edges())
print("is reducible:", loops.is_reducible())
```

---

## Delay-slot semantics

| Instruction | Delay slot? | Successor(s) |
|---|---|---|
| `rts` | YES | none |
| `rte` | YES | none |
| `rts/n` | **NO** | none |
| `bra` | YES | [target] |
| `bsr` | YES | [fall-through after DS] |
| `jsr @Rn` | YES | [fall-through after DS] |
| `bt/s` | YES | [target, fall-through after DS] |
| `bf/s` | YES | [target, fall-through after DS] |
| `bt` | **NO** | [target, fall-through] |
| `bf` | **NO** | [target, fall-through] |
| `braf Rn` | indirect: decoded MISC | open block (limitation) |
| `jmp @Rn` | indirect: decoded MISC | open block (limitation) |

When the terminator has a delay slot, the delay-slot instruction is the last entry in
`block.insns`.  Successors are set based on the VA after the delay slot.

---

## API

### `build_cfg(insns, entry=None) -> CFG`

Three-pass construction:

1. **Leader scan**: discovers all block-start VAs: entry, all branch targets, all
 fall-through-after-terminator addresses. Delay-slot instructions are not leaders;
 the instruction two steps after the branch is the next-block leader.
2. **Partition**: assigns each instruction to a block. Delay-slot instructions are
 appended to the terminating block, consuming two steps in a single pass iteration.
3. **Edge fill**: for each block, computes `succs` from the block's terminator type.
 Sets `preds` from the inverse.

### `Block`

| Field | Type | Description |
|---|---|---|
| `start` | `int` | First instruction VA (block label) |
| `insns` | `List[SH2aInsn]` | Instructions, including delay slot when present |
| `succs` | `List[int]` | Successor block-start VAs |
| `preds` | `List[int]` | Predecessor block-start VAs |
| `end` | `int` (property) | VA after last instruction |
| `terminator()` | method | Returns the branch/call/return instruction, or None |
| `delay_slot()` | method | Returns the delay-slot instruction, or None |

### `CFG`

| Field/Method | Type | Description |
|---|---|---|
| `blocks` | `Dict[int, Block]` | All blocks keyed by start VA |
| `entry` | `int` | Entry block start VA |
| `flow` | property → `List[(int,int)]` | Forward edges for DomTree |
| `flow_r()` | method → `List[(int,int)]` | Reversed edges for backward passes |
| `block_at(addr)` | method | Returns block at VA, or None |
| `__iter__` |: | Iterates blocks sorted by start VA |

---

## Limitations

- **`braf`, `bsrf`, `jmp @Rn`**: the `EcuSH2aDecoder` classifies these as `MISC` (no
 explicit decode branch). They are treated as fall-through in the CFG, creating open
 blocks with no successors. Functions that use only `bra`, `bt`, `bf`, `bsr`, `jsr`,
  `rts`, and `rts/n` are fully correct.  Indirect indirect-jump functions (dispatch
 tables) will have open blocks where the jump is; the structurizer will emit the
 instructions before the jump as a plain sequence.
- The module does not resolve cross-function CFG edges (calls are treated as
 fall-through after the delay slot: the callee is abstracted away).

---

## How it works

Reads the binary image and resolves the target-specific data structures (PLT, GOT, `.eh_frame`, symbol tables) to build a function and import index. Architecture-specific calling conventions and instruction encodings are applied to recover call edges, argument registers, and return value locations. Results are stored in the session `BinaryContext` so downstream tools can use resolved names and edges.

---

## Example output

```
Resolved 847 PLT entries
Recovered 312 function starts from .eh_frame
Named 28 functions from DWARF remnants

va=0x401200  name=verify_admin_token  confidence=HIGH
va=0x4015C0  name=process_http_request  confidence=HIGH
va=0x403A00  name=''  confidence=MEDIUM  (stripped)
```

---

## False positives

Symbol resolution errors produce phantom function boundaries. Verify any candidate VA against `ctx.func_starts` before analysis. Compiler-synthesized stubs (PLT entries, thunks) appear as functions in some loaders — `BinaryContext` filters known stub patterns but custom thunks may slip through.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for symbol and import resolution. For stripped binaries, run `SemanticSearcher` first to identify candidate function VAs.

**After this module:** Pass resolved call edges and function VAs to `TaintTracker` or `SinkArgClassifier`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `va` | Virtual address of the resolved symbol, function, or instruction |
| `name` | Recovered name if available, empty string if stripped |
| `detail` | What was resolved or decoded |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` — how certain the resolution is |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
