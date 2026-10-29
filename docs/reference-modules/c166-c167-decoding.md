<a id="ecuc166decoder"></a>
# Infineon C166 / C167 ROM Decoding

`EcuC166Decoder` decodes C166-family firmware in pure Python. It recovers variable-width instructions, interrupt vectors, direct call targets, and selected data references without Capstone.

---

## Why this exists

1. Capstone has no C166 decoder. Ablation previously depended on a small opcode subset that could lose alignment or assign the wrong mnemonic to valid instructions.
2. Boot-loaded C166 applications do not always place their vector table at file offset zero. The decoder now accepts arbitrary nonzero image sizes and a caller-selected IVT base.
3. Code segments and DPP data pages have different sizes and address rules. Explicit helpers keep those address domains separate.

---

## How it works

The opcode byte selects a two- or four-byte instruction length. The decoder then handles common moves, arithmetic, comparisons, multiplication, shifts, stack operations, returns, relative branches, absolute calls, and direct or indirect memory forms. Unknown operations remain explicit placeholders.

```mermaid
flowchart LR
    A[Raw image] --> B[Instruction-length table]
    B --> C[Typed instructions]
    C --> D[IVT and CALLS candidates]
    C --> E[Data-reference scans]
    F[DPP register and page] --> E
```

`function_starts()` scans direct `CALLS` targets. It does not add IVT targets automatically and does not recover indirect calls. Use `parse_ivt()` separately when vector targets are needed.

Immediate `SUBB` is decoded when `0x29` has bit 3 of the second byte clear. The high nibble selects the destination byte register and the low three bits select the immediate value. For example, `29 81` becomes `SUBB RL8, #1` and `29 82` becomes `SUBB RL8, #2`. Other `SUBB` addressing modes remain explicit unknowns rather than being assigned invented semantics. This support makes immediate-count dispatch chains readable without treating every `0x29` form as an immediate instruction.

The decoder also covers the word and byte comparisons, short subtraction, byte moves, and indirect jumps used by table-driven command dispatch. These are small mechanical pieces with a useful result: an analyst can follow a selector from a comparison through a computed table entry instead of disassembling operands as unrelated byte strings.

Three encoding details matter:

- In the short `CMP`, `CMPB`, and `SUB` forms, the high nibble selects the destination. Bit 3 distinguishes register-indirect memory from a three-bit immediate; the low two bits select the indirect register.
- In `ADDB`, `CMPB`, and `MOVB` four-byte immediate forms, only the first immediate byte is significant. The ISA notation is `RR ## xx`; the `xx` byte is not part of the 8-bit value. For example, `07 F8 0F FF` is `ADDB RL4, #0x0f`, not addition of `0xff0f`.
- `JMPI` records an indirect branch but leaves `target` as `None`. A table address must be established from surrounding register arithmetic and validated table bytes before assigning a destination.

Condition names now follow the vendor condition-code table: codes 0 through 15 are `UC`, `NET`, `Z`, `NZ`, `V`, `NV`, `N`, `NN`, `C`, `NC`, `SGT`, `SLE`, `SLT`, `SGE`, `UGT`, and `ULE`. Immediate shifts use the high nibble for the count and the low nibble for the destination. These correct earlier renderings; they are decoding fixes, not claims that a firmware security property changed.

Direct stores found by `scan_xram_stores()` include word, byte, zero-extension, and sign-extension forms. As with load scans, a matching immediate is a candidate reference, not proof of an access on every execution path.

Power-of-two images retain the original ROM-mirror folding behavior. Other image sizes are accepted without applying a mirror mask. An image may occupy at most the 24-bit C166 physical address space.

---

## EcuC166Decoder

```python
from ablation.analyzers.ecu_c166_decoder import EcuC166Decoder

decoder = EcuC166Decoder.from_path('/path/to/application.bin', base_pa=0)
vectors = decoder.parse_ivt(num_vectors=64, start_pa=0x20000)
insns = decoder.disassemble(0x25EBC, 0x25F00)
```

Important methods:

- `decode_one(byte_off)` and `insn_length(byte_off)` use buffer offsets.
- `disassemble(start_pa, end_pa)` uses physical addresses and returns `C166Insn` objects.
- `parse_ivt()` returns `IVTEntry` objects and defaults to the image base.
- `function_starts()` returns direct `CALLS` target candidates.
- `scan_xram_loads()` and `scan_xram_stores()` find references to a 16-bit data offset.
- `code_pa(seg, addr)` resolves 64 KiB code segments.
- `dpp_pa(offset, dpp)` resolves a 16-bit data offset through a 16 KiB DPP page.
- `dpp_offset(physical_addr, dpp, dpp_index)` recovers a data offset when the DPP register and page value are known.
- `scan_dpp_loads()` applies the same explicit DPP model to a reference scan.

The DPP register index is required because the page value alone cannot recover the top two bits of a 16-bit data pointer.

---

## Usage

Decode a boot-loaded vector table and inspect control flow:

```python
for insn in decoder.disassemble(0x20000, 0x20100):
    if insn.is_call or insn.is_branch:
        print(insn)
```

Find references to physical address `0x1C5E9` through DPP1 with page value 7:

```python
hits = decoder.scan_dpp_loads(0x1C5E9, dpp=7, dpp_index=1)
for hit in hits:
    print(hit)
```

Example output:

```
0x02302A  e6 f9 e9 45  MOV R9, #0x45e9
```

---

## What this adds for the user

The decoder turns otherwise opaque C166 bytes into typed instructions, vector entries, and explicit code/data address candidates. It provides the mechanical foundation needed to inspect update handlers and service paths without depending on a Capstone backend or a target execution environment.

It remains a focused decoding component rather than a complete C166 analysis framework. A future CFG or state-machine analyzer could consume its typed instructions, but DPP values, indirect targets, and code-region choices still need target evidence. Keeping those inputs explicit makes the decoder reusable across ROM layouts while preventing an address guess from becoming an unsupported security conclusion.

## False positives

Linear scanning can interpret data as instructions. Confirm candidate functions against code regions and call evidence. A direct-reference scan can also find an immediate constant that is not a pointer. Validate the surrounding operation before treating it as an address reference.

A power-of-two image size does not prove that ROM mirroring is active. Review the target memory map before relying on folded targets.

---

## Pipeline position

**Before this module:** Use `EcuArchDetector` for an initial ISA hypothesis and identify likely code and data regions.

**After this module:** Review typed instructions, IVT entries, and reference hits during focused C166 analysis. Build a separate CFG or service-path analyzer only after checking decode correctness.

---

## Reading findings

| Field | Content |
|:---|:---|
| `pa` | Physical instruction address |
| `raw` | Original two- or four-byte encoding |
| `mnemonic` | Decoded operation or explicit unknown placeholder |
| `insn_type` | Machine-readable operation class |
| `reg` | Selected register number, when applicable |
| `imm` | Immediate value or direct address, when applicable |
| `target` | Resolved branch or call target, when applicable; `None` for an unresolved `JMPI` |
| `is_call` | True for `CALLS` and `CALLA` |
| `is_branch` | True for `JMPS`, `JMPA`, `JMPR`, and `JMPI` |

---

## Limitations

- Semantic decoding remains a useful subset, not a complete C166 lifter or decompiler.
- Unknown instructions do not prove invalid code. Not every operand, SFR alias, or ISA form is named.
- Direct scans do not recover every indirect call or computed data reference.
- `JMPI` does not automatically resolve a table; proving a table target requires surrounding code and bytes.
- Physical addresses, buffer offsets, code segments, and DPP offsets must not be mixed.
- Security-relevant results require byte verification and target-specific memory-map review.

## See also

- [C166 Family Instruction Set Manual](https://www.keil.com/dd/docs/datashts/infineon/c166ism.pdf)
- [ECU Architecture Detector](ecu-arch-detector.md)
- [Strict Intel HEX Parser](intel-hex.md)
- [TI TMS320C28x Decoding](ecu-c28x-decoder.md)
