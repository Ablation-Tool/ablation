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
branch fires: the delay slot. Every prior CFG module ARM, V850, ARC, x86 works on
architectures without delay slots. `cfg_sh2a` attaches the delay-slot instruction to the
terminating block so that successor VAs are computed from after the delay slot, not from
after the branch opcode.

**3. No `.flow` / `.flow_r()` interface on any ECU-family CFG.** `dataflow_engine.DomTree`
and all backward-dataflow passes iterate `cfg.flow` as a list of `src, dst` edge tuples.
`cfg_sh2a.CFG` adds `.flow` property and `.flow_r()` (method) so DomTree and LoopInfo
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
| `braf Rn` | indirect: decoded MISC | open block limitation |
| `jmp @Rn` | indirect: decoded MISC | open block limitation |

When the terminator has a delay slot, the delay-slot instruction is the last entry in
`block.insns`. Successors are set based on the VA after the delay slot.

---

## API

### `build_cfg(insns, entry=None) -> CFG`

Three-pass construction:

1. Leader scan: discovers all block-start VAs: entry, all branch targets, all
 fall-through-after-terminator addresses. Delay-slot instructions are not leaders;
 the instruction two steps after the branch is the next-block leader.
2. Partition: assigns each instruction to a block. Delay-slot instructions are
 appended to the terminating block, consuming two steps in a single pass iteration.
3. Edge fill: for each block, computes `succs` from the block's terminator type.
 Sets `preds` from the inverse.

### `Block`

| Field | Type | Description |
|---|---|---|
| `start` | `int` | First instruction VA block label |
| `insns` | `List[SH2aInsn]` | Instructions, including delay slot when present |
| `succs` | `List[int]` | Successor block-start VAs |
| `preds` | `List[int]` | Predecessor block-start VAs |
| `end` | `int` property | VA after last instruction |
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
 `rts`, and `rts/n` are correct. Indirect indirect-jump functions (dispatch
 tables) will have open blocks where the jump is; the structurizer will emit the
 instructions before the jump as a plain sequence.
- The module does not resolve cross-function CFG edges (calls are treated as
 fall-through after the delay slot: the callee is abstracted away).

---

## How it works

`build_cfg` is a three-pass algorithm over a flat `Sequence[SH2aInsn]` (already decoded by `EcuSH2aDecoder`):

1. Leader scan: discovers all block-start VAs: the entry point, all branch targets extracted from `insn.target_va`, and the fall-through address immediately after each terminator or two instructions after when the terminator has a delay slot. Delay-slot instructions are explicitly excluded from the leader set.
2. Partition: assigns each instruction to the current block. When a terminator with a delay slot is encountered, the next instruction is consumed into the same block as the delay slot; the block is then closed. Without a delay slot, the block closes at the terminator itself.
3. Edge fill: iterates over all blocks; for each block's terminator type `rts`, `bra`, `bt`/`bf`, and `jsr`, and so on the `succs` list is populated from the delay-slot-adjusted successor VA. `preds` is built as the inverse.

Indirect branches `braf` and `jmp @Rn` cannot be resolved statically, these produce open blocks with no successors.

---

## Example output

The following illustrates CFG construction output format. Actual addresses and block counts are ROM-specific.

```python
>>> cfg = build_cfg(insns, entry=0x1000)
>>> for block in cfg:
...     print(f"block 0x{block.start:x}: {len(block.insns)} insns  succs={[hex(s) for s in block.succs]}")
block 0x1000: 6 insns  succs=['0x1014', '0x1034']  # bt conditional
block 0x1014: 4 insns  succs=['0x1034']             # fall-through
block 0x1034: 3 insns  succs=[]                     # rts + delay slot

>>> dom = DomTree(cfg)
>>> dom.back_edges()
[]
>>> loops.is_reducible()
True
```

---

## False positives

**Open blocks from indirect branches:** `braf Rn`, `bsrf Rn`, and `jmp @Rn` produce blocks with no successors because the target VA cannot be resolved from a static instruction sequence. Functions with dispatch tables (switch statements compiled to `jmp @Rn`) will have unreachable blocks in the CFG. `DomTree` and `LoopInfo` handle open blocks gracefully they are not reachable from the entry block.

**Delay-slot instruction boundary errors:** If `EcuSH2aDecoder` returns a disassembly list with a gap for example truncated ROM or bad start offset, the delay-slot consumer may assign the wrong instruction as the delay slot, shifting all subsequent block boundaries. Verify the input `insns` covers the entire function before building the CFG.

---

## Pipeline position

**Before this module:** Decode the function with `EcuSH2aDecoder.disassemblestart_va, end_va` to produce the instruction list. Identify function entry points using `EcuSH2aDecoder.function_starts()` or from IVT entries.

**After this module:** Pass `cfg` to `DomTree(cfg)` and `LoopInfocfg, dom` from `dataflow_engine` for dominance and loop structure analysis. Use `cfg.flow` as the edge list for backward dataflow passes.

---

## Reading output

`build_cfg(insns, entry=None)` returns a `CFG`. `entry` defaults to the VA of the first instruction in `insns`.

| Field | Type | Content |
|:---|:---|:---|
| `blocks` | `Dict[int, Block]` | All basic blocks keyed by start VA |
| `entry` | `int` | Entry point VA |
| `flow` | property → `List[Tuple[int,int]]` | All `src_va, dst_va` forward edges |
| `flow_r()` | method → `List[Tuple[int,int]]` | Reversed edges for backward dataflow |

Each `Block`:

| Field | Type | Content |
|:---|:---|:---|
| `start` | `int` | VA of the first instruction |
| `insns` | `List[SH2aInsn]` | Instructions in the block delay slot last if present |
| `succs` | `List[int]` | Start VAs of successor blocks |
| `preds` | `List[int]` | Start VAs of predecessor blocks |
| `end` | property → `int` | VA one past the last instruction |
| `terminator()` | method | The control-transfer instruction, or `None` |
| `delay_slot()` | method | The delay-slot instruction if terminator has one |

---

## See also

- [SH-2A Decoding](sh2a-decoding.md): `EcuSH2aDecoder` that produces the `SH2aInsn` list consumed by `build_cfg`
- [Dataflow Engine](dataflow-engine.md): `DomTree` and `LoopInfo` that consume `CFG.flow` and `CFG.flow_r()`
- [Flat ROM Function Discovery](flat-rom-function-discovery.md): function start discovery for SH-2A ROMs before CFG construction
