# MicroBlazeDecoder

**File:** `ablation/analyzers/microblaze_decoder.py`

## Why this exists

1. **Capstone does not support Xilinx MicroBlaze.** Versal PLM firmware recovered from CDO `DmaWrite` commands cannot be decoded by Ablation's normal Capstone path. `MicroBlazeDecoder` provides a dependency-free instruction decoder for these raw load segments.

2. **MicroBlaze `IMM` prefixes change the following instruction.** Treating each word independently produces incorrect 32-bit constants and branch destinations. The decoder carries the upper 16 bits to exactly one successor and records whether the operand was extended.

3. **CDO word order differs from ordinary instruction-byte order.** Normal MicroBlaze instruction bytes are big-endian, while the recovered CDO DMA words use little-endian byte storage. The explicit `byte_order` option supports both without mutating the source bytes.

4. **Control-flow metadata is needed for firmware analysis.** Direct branches, calls, conditional branches, returns, and delay slots are exposed as structured fields. Candidate call targets and compiler-prologue function starts can seed further analysis without presenting linear sweep as a complete CFG.

## Usage

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

`start` and `end` are byte offsets within the input buffer. `base_va` is the virtual address associated with byte offset zero. File and buffer inputs are capped at 256 MiB to avoid uncontrolled allocation.

## Versal PDI integration

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

## Instruction model

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

## Control-flow behavior

- `bri`, `brid`, `brlid`, and immediate conditional branches use PC-relative destinations.
- `brai`, `braid`, `bralid`, and `brki` use absolute destinations.
- `brlid` and `bralid` are marked as calls; `rtsd`, `rtbd`, `rtid`, and `rted` are marked as returns.
- Register-indirect branches have `target=None` because their destination requires runtime state.
- `call_targets()` returns direct call destinations found by a linear sweep.
- `function_starts()` combines those destinations with the common `addik r1,r1,-N; swi r15,r1,0` prologue pattern.

Candidate addresses are analysis seeds, not confirmed function boundaries. Calls into other memory regions may be valid, while instruction-like data can create false candidates.

## Validation

Synthetic tests cover signed and extended immediates, relative and absolute calls, conditional branches, returns, loads/stores, shifts, special registers, invalid words, and candidate function starts.

On the CERN `GCI_GCM415_boot-v0.159.38-35A2CC3.pdi` image, two contiguous DMA segments reconstruct 94,080 bytes at `0xF6130000–0xF6146F80`. Linear decoding recognizes 23,393 of 23,520 words. The remaining 127 words occur mostly in trailing data tables; this is not a claim of 99.5% code coverage.

## Limitations

- This is a disassembler, not a decompiler, SSA lifter, or emulator. Use `microblaze_cfg.recover_cfg()` for recursive-descent CFG recovery.
- Linear sweep does not separate code from embedded data and does not account for branch delay-slot reachability when choosing regions.
- `IMM` state follows linear input order. Starting in the middle of an `IMM` pair cannot recover the missing upper half.
- Incorrect `base_va` or `byte_order` values invalidate addresses and decoded operands.
- Function-start and call-target lists require code-region validation before downstream security analysis.
- Unrecognized words remain explicit `.word` entries; they are never silently treated as valid instructions.

## FORGE audit

`FORGE.audit_module()` and the SAFE CODE 10-section review pass with zero open findings. Pre-audit hardening added the 256 MiB input limit and removed a duplicate path read. Regression tests cover the limit and real GEP PLM decoding. The residual risks above are explicit analysis limitations, not silently ignored parser failures.

## See also

- [VersalPdi](versal-pdi.md) for CDO validation and `DmaWrite` load-segment extraction
- [Control-flow graph construction](control-flow-graph-construction.md) for downstream CFG concepts
