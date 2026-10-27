# MicroBlaze Decoder, CFG Recovery & Structural Lifter

**Files:** `ablation/analyzers/microblaze_decoder.py`, `ablation/analyzers/microblaze_cfg.py`, `ablation/analyzers/microblaze_lifter.py`

## Why this exists

1. **Capstone does not support Xilinx MicroBlaze.** Versal PLM firmware recovered from CDO `DmaWrite` commands cannot be decoded by Ablation's normal Capstone path. `MicroBlazeDecoder` provides a dependency-free instruction decoder for these raw load segments.
2. **MicroBlaze `IMM` prefixes change the following instruction.** Treating each word independently produces incorrect 32-bit constants and branch destinations. The decoder carries the upper 16 bits to exactly one successor and records whether the operand was extended.
3. **CDO word order differs from ordinary instruction-byte order.** Normal MicroBlaze instruction bytes are big-endian, while recovered CDO DMA words use little-endian byte storage. The explicit `byte_order` option supports both without mutating source bytes.
4. **Linear sweep cannot establish code coverage.** Recursive CFG recovery separates reachable code from unclassified bytes, handles delay slots and direct callees, and supports analyst-validated jump tables.
5. **Recovered CFGs need a readable review form.** `MicroBlazeLifter` emits address-tagged structural pseudo-C while preserving unresolved indirect control flow. It is not a full SSA/type-recovered decompiler.

## Disassembly

```python
from ablation.analyzers.microblaze_decoder import MicroBlazeDecoder

decoder = MicroBlazeDecoder.from_path("plm.bin", base_va=0xF6130000, byte_order="little")
for insn in decoder.disassemble(start=0, end=0x400):
    print(insn)

print(decoder.call_targets())
print(decoder.function_starts())
```

For an in-memory image:

```python
decoder = MicroBlazeDecoder.from_bytes(data, base_va=0xF6130000, byte_order="little")
insn = decoder.decode_one(0x50)
```

CLI:

```bash
python -m ablation.analyzers.microblaze_decoder plm.bin \
  --base 0xF6130000 --byte-order little --end 0x400
```

`start` and `end` are byte offsets within the input buffer. `base_va` is the virtual address associated with byte offset zero. `image_size` exposes the bounded input length. File and buffer inputs are capped at 256 MiB.

### Versal PDI integration

`VersalPdi.dma_write_segments()` recovers linked load bytes, not necessarily an ELF container. Merge only segments known to be contiguous and use the first segment's address as `base_va`:

```python
from ablation.analyzers.versal_pdi import VersalPdi
from ablation.analyzers.microblaze_decoder import MicroBlazeDecoder

vp = VersalPdi.from_path("GCI_GCM415_boot.pdi")
segments = sorted(vp.dma_write_segments(), key=lambda segment: segment.address)
plm = [s for s in segments if 0xF6130000 <= s.address < 0xF6140000]
assert all(a.end_address == b.address for a, b in zip(plm, plm[1:]))

image = b"".join(s.data for s in plm)
decoder = MicroBlazeDecoder(image, plm[0].address, byte_order="little")
```

### Instruction model

`MicroBlazeInsn` provides:

| Field | Meaning |
|---|---|
| `offset` | Byte offset in the source buffer |
| `address` | `base_va + offset` |
| `word` | Decoded 32-bit instruction word |
| `mnemonic`, `operands` | Printable instruction and formatted operands |
| `rd`, `ra`, `rb` | Decoded register indices when applicable |
| `imm` | Signed immediate, including an `IMM` prefix when present |
| `target` | Static direct branch/call destination, otherwise `None` |
| `flow` | `linear`, `jump`, `call`, `conditional`, `return`, or `trap` |
| `delay_slot` | Whether the instruction has a delay slot |
| `extended_imm` | Whether an `IMM` prefix formed the operand |
| `valid` | `False` for an unrecognized word emitted as `.word` |

The decoder covers core integer arithmetic, logical operations, multiply/divide, immediate and register branches, returns, loads/stores, shifts and bit insertion, compare operations, `IMM`, `mbar`, FSL `get`/`put`, and special-register operations. Optional floating-point and less common instructions are not claimed as complete.

### Decoder control-flow behavior

- `bri`, `brid`, `brlid`, and immediate conditional branches use PC-relative destinations.
- `brai`, `braid`, `bralid`, and `brki` use absolute destinations.
- `brlid` and `bralid` are marked as calls; `rtsd`, `rtbd`, `rtid`, and `rted` are marked as returns.
- Register-indirect branches have `target=None` because their destination requires runtime state.
- `call_targets()` returns direct call destinations found by a linear sweep.
- `function_starts()` combines those destinations with the common `addik r1,r1,-N; swi r15,r1,0` prologue pattern.

Candidate addresses are analysis seeds, not confirmed function boundaries. Calls into other memory regions may be valid, while instruction-like data can create false candidates.

## Recursive CFG recovery

`recover_cfg()` follows control flow from explicit entries, carries `IMM` state along each path, keeps delay slots with their control transfers, and discovers direct callees without sweeping through unreachable regions.

The analyzer separates **reachable code** from **unclassified bytes**. Unclassified bytes are not automatically data: they may include functions reached only through unresolved indirect calls, exception entries, or external reset-vector mappings.

```python
from ablation.analyzers.microblaze_cfg import recover_cfg

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

### Recovery model

- Direct calls create new function-recovery entries and retain a post-call edge unless their target is a validated no-return address.
- Conditional branches produce target and fall-through edges after any delay slot.
- Direct jumps follow only their targets; returns and traps have no fall-through.
- Indirect calls retain their fall-through and report an unresolved issue.
- Unresolved indirect jumps stop that path and report an issue.
- Invalid, truncated, out-of-image, conflicting-`IMM`, and cross-function ownership cases stop the affected path and produce diagnostics.
- `code` maps each reachable instruction address to its decoded instruction and owning function.
- `code_ranges` merges adjacent reachable words. `unclassified_ranges` is their complement within the image.

The defaults are 4,096 functions and 1,000,000 recovered instructions. `max_functions` and `max_instructions` provide smaller limits. Exceeding either raises `ValueError` instead of returning silently truncated results. Caller-supplied entry, table, and no-return collections are also bounded, and unclassified ranges are computed without allocating an entry for every image word.

### No-return calls

`no_return_addresses(recovery)` identifies direct unconditional self-loops only when every block in the containing function can reach the loop and no return instruction exists. Pass validated addresses back to recovery to suppress false post-call paths:

```python
from ablation.analyzers.microblaze_cfg import no_return_addresses, recover_cfg

initial = recover_cfg(decoder, [0xF6130050], jump_table_targets=targets)
recovery = recover_cfg(
    decoder,
    [0xF6130050],
    jump_table_targets=targets,
    no_return=no_return_addresses(initial),
)
```

Missing returns, traps, and indirect calls are not no-return evidence. A validated loop already owned by another function is not reported again as an overlapping entry. `no_return_functions()` is available for standalone self-loop function entries; address-level detection is required when a loop is embedded in a larger function.

### Call argument recovery

`call_arguments(function, call_site)` performs bounded forward constant propagation within the caller's basic block. It handles `IMM`-extended `addi/addik`, `add/addk` register moves and arithmetic, and `ori`/`or`, including instructions in the call delay slot. Unknown writes produce an unknown value rather than a guessed constant.

```python
from ablation.analyzers.microblaze_args import call_arguments

arguments = call_arguments(function, 0xF61326D8, registers=(5, 6, 7))
for register, argument in arguments.items():
    print(register, argument.value, argument.definition)
```

The API validates direct call sites, defaults to `r5`–`r7`, accepts at most 256 preceding instructions by default, and reports each value's nearest definition address. It intentionally does not propagate across blocks, runtime memory, or intervening calls.

### Direct memory references

`direct_memory_references(recovery, start, end)` collects absolute immediate address candidates only from recovered instructions with `r0` as the base. It excludes branch flow and linear-sweep false positives. `reference_neighbors(references, address)` returns the nearest lower and upper candidate addresses.

```python
from ablation.analyzers.microblaze_xrefs import direct_memory_references, reference_neighbors

references = direct_memory_references(recovery, 0x1C000, 0x20000)
print(reference_neighbors(references, 0x1C658))  # lower=..., upper=0x1C683
```

These are address candidates, not proof of memory accesses, C object types, or allocation boundaries. A referenced interval can constrain layout review, but source-level object sizes require independent confirmation.

### Bounded jump tables

`resolve_jump_tables()` resolves the common compiler sequence:

```text
bslli  rTarget, rIndex, 2
imm    upper
addik  rTarget, rTarget, table
lwi    rTarget, rTarget, 0
bra    rTarget
```

The shift may write a different register from its index input. The caller must establish the table address, entry count from surrounding bounds checks, and any local-to-global target delta. The resolver rejects unknown site patterns, invalid table bounds, and out-of-image targets. Tables and specification collections are capped at 4,096 entries.

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

### CFG result types

| Type | Important fields |
|---|---|
| `MicroBlazeRecovery` | `functions`, `code`, `issues`, `code_ranges`, `unclassified_ranges` |
| `MicroBlazeFunction` | `entry`, `blocks`, `calls`, `issues`, `instructions` |
| `MicroBlazeBlock` | `start`, `end`, `insns`, `succs`, `preds`, `terminator` |
| `ControlFlowIssue` | `function`, `address`, `reason`, optional `target` |
| `JumpTableSpec` | `table_address`, `entry_count`, optional `target_delta` |

## Structural pseudo-C lifting

`MicroBlazeLifter` turns a recovered CFG into address-tagged, C-like statements for manual review. This is **structural pseudo-C**, not a full decompiler: it does not perform SSA construction, high-level control structuring, type recovery, or symbol recovery.

```python
from ablation.analyzers.microblaze_lifter import MicroBlazeLifter

lifter = MicroBlazeLifter(recovery)
print(lifter.lift_function(0xF61306EC))

# Lift every recovered function, subject to configured total limits.
all_pseudo_c = lifter.lift_recovery()
```

Optional analyst-supplied names replace generated `sub_XXXXXXXX` labels:

```python
lifter = MicroBlazeLifter(recovery, function_names={0xF6130050: "plm_entry"})
```

Defaults permit 4,096 blocks and 100,000 instructions per requested function or whole-recovery report. `max_blocks` and `max_instructions` can lower those limits. Unknown entries and exceeded limits raise `ValueError`.

### Output model and coverage

- Each block has a `loc_XXXXXXXX` label; statements retain instruction addresses.
- Delay-slot instructions are emitted before the control transfer takes effect.
- Direct calls use recovered or analyst-supplied names with `r5`–`r10` arguments.
- Indirect calls and unresolved jumps remain explicit helper operations.
- Resolved jump tables list CFG successor labels with `jump_table(...)`.
- Conditional branches test the branch register against zero, with signed comparisons where required.
- Returns use `r3`; traps remain explicit.
- Loads and stores preserve byte, halfword, and word widths.
- Unsupported valid operations become `/* unlifted: ... */`, never silent omissions.

The header records ABI register roles: `r1` stack pointer, `r3` return value, `r5`–`r10` arguments, `r15` link register, and `r0` zero. These annotations do not assert a recovered function prototype. Calls use uniform six-argument notation.

```c
loc_f6130710:
  /* f6130710 */ r3 = *(uint32_t *)(r5 + 40);
  /* f6130714 */ if (r3 == 0) goto loc_f6130720; else goto loc_f6130718;
loc_f6130718:
  /* f6130718 */ r3 = indirect_call_r3(r5, r6, r7, r8, r9, r10);
```

The lifter handles core add/reverse-subtract and carry forms, logical operations, multiply/divide, comparisons, immediate and register memory operations, shifts, bit insertion, unary operations, FSL transfers, special registers, barriers, direct and indirect control flow, returns, and traps. Carry and uncommon operations use named helper expressions where C operators alone would hide machine semantics.

Output is for analysis, not recompilation. Register expressions are not simplified into claimed source-level variables, and arithmetic is not a formal model of every MicroBlaze flag or overflow corner case.

## Versal PLM validation

For a production Versal `boot.pdi`, two contiguous DMA segments reconstruct 94,080 bytes at `0xF6130000–0xF6146F80`. Linear decoding recognizes 23,393 of 23,520 words; the remaining 127 occur mostly in trailing data tables. This is not a claim of 99.5% code coverage.

An additional 16,384-byte DMA segment covers `0xF612C000–0xF6130000`. Only 37 bytes are nonzero. The callback storage and copy-relevant objects examined below are zero-initialized, but the complete segment is not asserted to be zero-filled. No DMA payload covers external call target `0xF6110000`.

The reset vector targets local `0x20050`; the corresponding loaded entry is `0xF6130050`. A local-to-global delta of `0xF6110000` also maps the two validated jump tables and their targets.

Initial direct-control-flow recovery found 103 functions and 14,008 instructions. Adding the bounded 19-entry and 5-entry tables and validating the no-return loop at `0xF6130080` recovered 124 functions, 21,733 instructions (86,932 bytes), and 3,723 basic blocks. The tables have nine and three unique targets respectively. No-return suppression removed false fall-through and both former overlap diagnostics. The image has 7,148 unclassified bytes, six unresolved indirect calls, and four external call sites to `0xF6110000`. These figures describe this image and entry model, not complete firmware coverage.

Lifting all 124 recovered functions produces 21,484 lines. Every recovered instruction has an emitted statement or an intentional no-op/`IMM` omission; there are no `unlifted` operations in this image. Output includes six indirect-call operations and two resolved jump-table operations.

| Indirect-call site | Structural role |
|---|---|
| `0xF61300E8` | Init-array dispatch through a table pointer |
| `0xF6130718` | Callback at offset `+0x28` from the runtime structure rooted at local `0x36DA0` |
| `0xF6130A98`, `0xF6130AC0`, `0xF6130AD8` | Three dynamic callback paths through `r7` in the runtime-list routine |
| `0xF6130B18` | Sentinel-terminated fini-array dispatch |

The callback root initially points to local `0x1C050` in the adjacent data segment. Its callback-relevant storage is zero-initialized and no recovered instruction directly writes that root. These targets require runtime initialization evidence or broader interprocedural analysis. Sentinel/empty array contents do not establish callable targets.

The separate function at `0xF613072C` contains 62 instructions in 16 blocks with length-driven 16-byte, 4-byte, and single-byte copy loops. Earlier ownership at `0xF61306EC` was a false post-call path to the no-return loop and was retracted. Three direct callers have constant arguments:

| Call site | Destination | Source | Length |
|---|---|---|---|
| `0xF61326D8` | `0x1C4F8` | `0x1C8C4` | 72 |
| `0xF61347A4` | `0x1C4F8` | `0x1C8C4` | 72 |
| `0xF613D894` | `0x1C658` | `0x36D60` | 43 |

The next reference after `0x1C4F8` is `0x1C5D0`, a 216-byte referenced interval; both 72-byte copies fit. The next reference after `0x1C658` is `0x1C683`, exactly 43 bytes, matching its copy length. The 72-byte source is zero-initialized, and the 43-byte source is a binary table rather than a string. These sites do not show attacker-controlled lengths, and all three lengths fit the observed layouts. Referenced intervals are not source-level type proof, so this is not a blanket buffer-safety or symbol verdict.

## Limitations

- Linear sweep does not separate code from embedded data and follows `IMM` state only in linear input order. Starting in the middle of an `IMM` pair cannot recover the missing upper half.
- Incorrect `base_va` or `byte_order` values invalidate addresses and decoded operands.
- Function-start and call-target lists require code-region validation before downstream security analysis.
- No general reset-vector, MMU, address-alias, runtime callback, or external-memory inference is performed.
- Table sizes and address mappings are not guessed from table contents.
- Unclassified ranges may contain data, unreachable code, exception handlers, or indirectly reached functions.
- Reachability does not prove function semantics, memory safety, or the absence of malicious behavior.
- The lifter has no SSA, phi nodes, expression propagation, high-level structuring, or automatic type/symbol recovery.
- The toolchain is not an emulator or formally verified decompiler. Unrecognized decoder words remain explicit `.word` entries.

## Validation and FORGE

Synthetic and real-PDI tests cover signed/extended immediates, branches, calls, returns, no-return suppression, delay slots, argument constants and unknown writes, load/store widths, shifts, special registers, invalid/truncated paths, unreachable embedded bytes, overlapping entries, resource limits, bounded jump tables, structural output, unsupported operations, and real PLM invariants.

`FORGE.audit_module()` and the SAFE CODE 10-section review pass with zero findings for the decoder, CFG analyzer, argument analyzer, reference analyzer, and lifter. Input, recovery, table, argument, and emission limits are covered by regression tests. Residual analysis limitations are explicit rather than silently ignored failures.

## See also

- [VersalPdi](versal-pdi.md) for CDO validation and `DmaWrite` load-segment extraction
- [Control-flow graph construction](control-flow-graph-construction.md) for downstream CFG concepts
