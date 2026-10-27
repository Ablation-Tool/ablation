# MicroBlaze recursive CFG recovery

**File:** `ablation/analyzers/microblaze_cfg.py`

## Why this exists

Linear disassembly cannot distinguish reachable MicroBlaze code from embedded constants, jump tables, or unused bytes. `recover_cfg()` follows control flow from explicit entries, carries `IMM` state along each path, keeps delay slots with their control transfers, and discovers direct callees without sweeping through unreachable regions.

The analyzer separates **reachable code** from **unclassified bytes**. Unclassified bytes are not automatically data: they may include functions reached only through unresolved indirect calls, exception entries, or external reset-vector mappings.

## Basic usage

```python
from ablation.analyzers.microblaze_cfg import recover_cfg
from ablation.analyzers.microblaze_decoder import MicroBlazeDecoder

decoder = MicroBlazeDecoder(image, 0xF6130000, byte_order="little")
recovery = recover_cfg(decoder, entries=[0xF6130050])

for entry, function in sorted(recovery.functions.items()):
    print(hex(entry), len(function.blocks), len(function.calls))
    for block in function:
        print(f"  {block.start:#x} -> {[hex(s) for s in block.succs]}")

print(recovery.code_ranges)
print(recovery.unclassified_ranges)
for issue in recovery.issues:
    print(issue)
```

Entries are global addresses in the decoder's address space. `entries=None` uses `base_va`. A reset vector targeting another address space is not mapped automatically; establish the mapping and supply the corresponding loaded entry explicitly.

## Recovery model

- Direct calls create new function-recovery entries and retain a post-call edge in the caller.
- Conditional branches produce target and fall-through edges after any delay slot.
- Direct jumps follow only their targets; returns and traps have no fall-through.
- Indirect calls retain their fall-through and report an unresolved issue.
- Unresolved indirect jumps stop that path and report an issue.
- Invalid, truncated, out-of-image, conflicting-`IMM`, and cross-function ownership cases stop the affected path and produce diagnostics.
- `code` maps each reachable instruction address to its decoded instruction and owning function.
- `code_ranges` merges adjacent reachable words. `unclassified_ranges` is their complement within the image.

The defaults are 4,096 functions and 1,000,000 recovered instructions. `max_functions` and `max_instructions` provide smaller limits. Exceeding either raises `ValueError` instead of returning silently truncated results.

## Bounded jump tables

`resolve_jump_tables()` resolves the common compiler sequence:

```text
bslli  rTarget, rIndex, 2
imm    upper
addik  rTarget, rTarget, table
lwi    rTarget, rTarget, 0
bra    rTarget
```

The shift may write a different register from its index input. The caller must establish the table address, entry count from surrounding bounds checks, and any local-to-global target delta. The resolver rejects unknown site patterns, invalid table bounds, and out-of-image targets. Tables are capped at 4,096 entries.

```python
from ablation.analyzers.microblaze_cfg import JumpTableSpec, recover_cfg, resolve_jump_tables

initial = recover_cfg(decoder, [0xF6130050])
targets = resolve_jump_tables(decoder, initial, {
    0xF61311E8: JumpTableSpec(0xF6146DA4, 19, 0xF6110000),
    0xF613C664: JumpTableSpec(0xF6146DF4, 5, 0xF6110000),
})
recovery = recover_cfg(decoder, [0xF6130050], jump_table_targets=targets)
```

Run recovery once to identify unresolved indirect jumps, validate each table manually, then recover again with the resolved targets. Table entries become edges in the containing function, not separate function entries. Direct calls discovered from newly reached case blocks are recovered normally.

## Result types

| Type | Important fields |
|---|---|
| `MicroBlazeRecovery` | `functions`, `code`, `issues`, `code_ranges`, `unclassified_ranges` |
| `MicroBlazeFunction` | `entry`, `blocks`, `calls`, `issues`, `instructions` |
| `MicroBlazeBlock` | `start`, `end`, `insns`, `succs`, `preds`, `terminator` |
| `ControlFlowIssue` | `function`, `address`, `reason`, optional `target` |
| `JumpTableSpec` | `table_address`, `entry_count`, optional `target_delta` |

## CERN GEP PLM validation

For `GCI_GCM415_boot-v0.159.38-35A2CC3.pdi`, the reset vector targets local `0x20050`; the corresponding loaded entry is `0xF6130050`. A local-to-global delta of `0xF6110000` also maps the two validated jump tables and their targets.

Initial direct-control-flow recovery found 103 functions and 14,008 instructions. Adding the bounded 19-entry and 5-entry tables recovered 123 functions, 21,733 instructions (86,932 bytes), and 3,723 basic blocks. The 19-entry table has nine unique targets; the 5-entry table has three. The image has 7,148 unclassified bytes, six unresolved indirect calls, four external call sites to `0xF6110000`, and two direct-call entries overlapping already recovered functions. These figures describe this image and entry model, not complete firmware coverage.

## Limitations

- No general reset-vector, MMU, or address-alias inference is performed.
- Indirect calls require register/data-flow analysis or analyst-supplied targets.
- Table sizes and address mappings are not guessed from table contents.
- Reachability does not prove function semantics, memory safety, or the absence of malicious behavior.
- Unclassified ranges may contain data, unreachable code, exception handlers, or indirectly reached functions.
- The CFG API is not currently an SSA lifter or pseudo-C decompiler.

## Validation and FORGE

Synthetic and real-PDI tests cover branches, calls, returns, delay slots, `IMM`, invalid/truncated paths, embedded unreachable bytes, overlapping entries, work limits, bounded table recovery, and real GEP invariants. `FORGE.audit_module()` and the SAFE CODE 10-section review pass with zero findings. Pre-audit hardening bounds caller-supplied entries and tables and computes unclassified ranges without allocating an entry for every image word.

## See also

- [MicroBlazeDecoder](microblaze-decoder.md)
- [MicroBlaze structural lifter](microblaze-lifter.md)
- [VersalPdi](versal-pdi.md)
- [Control-flow graph construction](control-flow-graph-construction.md)
