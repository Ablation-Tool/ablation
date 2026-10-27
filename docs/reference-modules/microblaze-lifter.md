# MicroBlaze structural lifter

**File:** `ablation/analyzers/microblaze_lifter.py`

## Why this exists

`MicroBlazeDecoder` provides instructions and `microblaze_cfg` establishes reachable functions and blocks. `MicroBlazeLifter` turns that recovered CFG into address-tagged, C-like statements for manual firmware review without requiring Capstone MicroBlaze support.

This is **structural pseudo-C**, not a full decompiler. It does not perform SSA construction, high-level control structuring, type recovery, or symbol recovery.

## Usage

```python
from ablation.analyzers.microblaze_lifter import MicroBlazeLifter

lifter = MicroBlazeLifter(recovery)
print(lifter.lift_function(0xF61306EC))

# Lift every recovered function, subject to the configured total limits.
all_pseudo_c = lifter.lift_recovery()
```

Optional analyst-supplied names replace generated `sub_XXXXXXXX` labels:

```python
lifter = MicroBlazeLifter(recovery, function_names={0xF6130050: "plm_entry"})
```

Defaults permit 4,096 blocks and 100,000 instructions per requested function or whole-recovery report. `max_blocks` and `max_instructions` can lower those limits. Unknown entries and exceeded limits raise `ValueError`.

## Output model

- Each block has a `loc_XXXXXXXX` label; statements retain their instruction addresses.
- Delay-slot instructions are emitted before the control transfer takes effect.
- Direct calls use recovered or analyst-supplied names with the MicroBlaze `r5`–`r10` argument registers.
- Indirect calls and unresolved jumps remain explicit helper operations.
- Resolved jump tables list their CFG successor labels with `jump_table(...)`.
- Conditional branches test the branch register against zero, with signed comparisons where required.
- Returns use `r3`; traps remain explicit.
- Loads and stores preserve byte, halfword, and word widths.
- Unsupported valid operations become `/* unlifted: ... */`, never silent omissions.

The header records the ABI register roles: `r1` stack pointer, `r3` return value, `r5`–`r10` arguments, `r15` link register, and `r0` zero. These annotations do not assert a recovered function prototype.

Example shape:

```c
loc_f6130710:
  /* f6130710 */ r3 = *(uint32_t *)(r5 + 40);
  /* f6130714 */ if (r3 == 0) goto loc_f6130720; else goto loc_f6130718;
loc_f6130718:
  /* f6130718 */ r3 = indirect_call_r3(r5, r6, r7, r8, r9, r10);
```

## Instruction coverage

The lifter handles core add/reverse-subtract and carry forms, logical operations, multiply/divide, comparisons, immediate and register memory operations, shifts, bit insertion, unary operations, FSL transfers, special registers, barriers, direct and indirect control flow, returns, and traps. Carry and uncommon operations use named helper expressions where C operators alone would hide machine semantics.

The output is for analysis, not recompilation. Register expressions are not simplified into claimed source-level variables, and arithmetic is not a formal model of every MicroBlaze flag or overflow corner case.

## CERN GEP PLM results

Lifting all 123 recovered GEP PLM functions produces 21,479 lines. Every recovered instruction has an emitted statement or an intentional no-op/`IMM` omission; there are no `unlifted` operations in this image. Output includes six indirect-call operations and two resolved jump-table operations.

The six indirect calls remain unresolved:

| Site | Structural role |
|---|---|
| `0xF61300E8` | Init-array dispatch through a table pointer |
| `0xF6130718` | Callback at offset `+0x28` from the runtime structure rooted at local `0x36DA0` |
| `0xF6130A98`, `0xF6130AC0`, `0xF6130AD8` | Three dynamic callback paths through `r7` in the runtime-list routine |
| `0xF6130B18` | Sentinel-terminated fini-array dispatch |

The root at local `0x36DA0` initially points to local `0x1C050`, outside the recovered RAM, and no recovered instruction directly writes that root. Consequently these targets require runtime initialization evidence or broader interprocedural analysis. Sentinel/empty array contents do not establish callable targets.

The routine at `0xF61306EC` contains length-driven 16-byte, 4-byte, and single-byte copy loops after its callback. This supports a memory-copy structural role, but does not by itself prove a symbol name, caller-supplied length safety, or a vulnerability.

## Limitations

- No SSA, phi nodes, expression propagation, high-level structuring, or automatic type/symbol recovery.
- No resolution of runtime callback structures or external memory contents.
- No claim that all unclassified image bytes are data or that direct-call entries are confirmed source functions.
- Calls use a uniform six-argument notation; this is not a recovered prototype.
- C-like expressions are review aids, not formally verified executable semantics.

## Validation and FORGE

Tests cover arithmetic, reverse subtraction, zero stores, memory widths, shifts, direct/indirect control flow, delay-slot order, unsupported operations, limits, invalid entries, and real GEP lifting. `FORGE.audit_module()` and the SAFE CODE 10-section review pass with zero findings.

## See also

- [MicroBlazeDecoder](microblaze-decoder.md)
- [MicroBlaze recursive CFG recovery](microblaze-cfg.md)
- [VersalPdi](versal-pdi.md)
