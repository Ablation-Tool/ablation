# C166 Recursive Control Flow and Direct Data Xrefs

`c166_cfg.py` recovers reachable C166 functions and basic blocks from raw firmware, then indexes direct RAM, SFR, and peripheral references. It is designed for command dispatchers, flag producers, update handlers, and other paths that are easy to misread in a long linear disassembly.

## Why this module exists

Linear C166 decoding answers what the bytes look like, not which instructions execute together. The A1396 analysis needed proof that CAN command `0x06` reaches the arming handler and command `0x07` reaches the trigger handler. Manually following that subtract-and-branch chain was correct but slow and difficult to repeat across the other CAEN images.

This module provides three practical benefits:

1. **Reachability before interpretation.** Unreached bytes remain unclassified instead of becoming false functions or false data writers.
2. **Repeatable data-producer searches.** A query for `0x84FE`, `0x83B9`, or `0x90A6` returns instruction addresses and access classes, not arbitrary occurrences of those two bytes.
3. **Structured evidence for review and execution.** Functions, blocks, calls, issues, and direct references feed the C166 interpreter and stable JSON reports.

## Inputs and trust boundary

The input is an `EcuC166Decoder` containing an untrusted flat image. Callers select one or more physical entry addresses. There is no automatic claim that the whole image is code and no automatic vector-table guessing.

Recovery is bounded by independent limits:

- 4,096 functions by default;
- 250,000 decoded instructions by default;
- 16,384 explicit issues by default;
- one C166 24-bit image address space by the underlying decoder.

Limits raise `ValueError`; partial output is not presented as a successful complete recovery.

## Recovery algorithm

1. Queue the supplied entry addresses.
2. Decode only reachable two- or four-byte instructions.
3. Follow direct `CALLS`, `CALLA`, `JMPS`, `JMPA`, and conditional `JMPR` successors.
4. Discover callees as new function candidates.
5. Preserve fallthrough for calls and conditional branches.
6. Stop at returns and unconditional direct jumps.
7. Record unresolved indirect calls/jumps without inventing destinations.
8. Detect entries or instructions owned by another function.
9. Build leaders, basic blocks, predecessors, and successors.
10. Classify direct data accesses in the recovered instructions.

Unknown instruction encodings remain explicit issues. Their known instruction widths are retained for linear reachability, but they are not assigned invented semantics or control flow.

## Direct data-reference model

Only proven absolute encodings are indexed. Three access classes are emitted:

| Class | Meaning |
|---|---|
| `read` | The instruction reads the absolute memory location |
| `write` | The instruction writes the absolute memory location |
| `read_write` | The instruction reads and modifies the absolute memory location |

Immediate constants such as `MOV R5, #0x84FE` and register-indirect accesses such as `MOVB [R4], RL5` are not direct xrefs. Indirect accesses are not silently assigned to the pointed-to address.

Each `C166DataXref` includes the instruction PA, 16-bit direct address, opcode, mnemonic, access class, DPP register index, and 14-bit page offset. `physical_address(dpp_pages)` resolves only when the caller supplies an explicit page value for the relevant DPP register. The DPP index alone never becomes a physical-address claim.

## Python API

```python
from ablation.analyzers.c166_cfg import recover_c166_cfg
from ablation.analyzers.ecu_c166_decoder import EcuC166Decoder

image = '/media/cowboy/research/CERN/analysis/edms-firmware/a1396.bin'
decoder = EcuC166Decoder(image)
recovery = recover_c166_cfg(decoder, [0x237B2])

for xref in recovery.xrefs_to(0x84FE):
    print(hex(xref.instruction), xref.access, xref.mnemonic)

print('functions:', len(recovery.functions))
print('instructions:', len(recovery.code))
print('issues:', len(recovery.issues))
```

Expected update-path evidence includes:

- `0x247E6` — `write` to `0x84FE`;
- `0x24868` — `read` from `0x84FE`;
- recovered handlers at `0x24792` and `0x24802`;
- the copy and `SRST` instructions at `0x2487A` and `0x248A4`.

## CLI

```bash
python3 -m ablation.analyzers.c166_cfg \
  /media/cowboy/research/CERN/analysis/edms-firmware/a1396.bin \
  0x237B2 \
  --xref 0x84FE \
  --output /media/cowboy/research/CERN/analysis/edms-firmware/c166-update-cfg.json
```

The output schema is `ablation.c166-recovery.v1` and includes image bounds, code and unclassified ranges, functions, blocks, calls, issues, and direct xrefs. Physical addresses are formatted as fixed-width hexadecimal strings to avoid JSON integer ambiguity.

## Dataclasses

| Type | Purpose |
|---|---|
| `C166Recovery` | Complete bounded recovery, ranges, direct xrefs, and JSON export |
| `C166Function` | One function entry, blocks, direct calls, and issues |
| `C166Block` | Ordered instructions plus predecessor/successor addresses |
| `C166ControlFlowIssue` | Explicit unresolved, overlapping, outside-image, or unknown-code condition |
| `C166DataXref` | One direct data access and its optional DPP interpretation |

Use `C166CFGBuilder` directly when recovery configuration must be retained across calls. Use `recover_c166_cfg()` for the standard bounded pipeline.

## Verification

`tests/test_c166_cfg.py` uses byte-exact synthetic images for:

- direct-call discovery and unreachable-byte exclusion;
- conditional and unconditional successors;
- direct read, write, and read-modify-write classification;
- immediate and register-indirect exclusion;
- unresolved indirect branches;
- unknown instructions;
- overlapping entries;
- function, instruction, issue, and entry limits;
- stable JSON and unclassified ranges.

The real A1396 integration test recovers the CAN dispatcher and both update handlers. The combined C166 suite also runs all pre-existing decoder regressions.

## Limitations

- Seeded recovery does not prove whole-image coverage.
- Indirect jump tables require target-specific evidence and are not guessed.
- Tail sharing and alternate function entries may produce ownership issues requiring analyst review.
- Unknown instructions are not proof of invalid code.
- Direct-reference tables are intentionally conservative and may omit an absolute operation not yet characterized.
- A direct access in recovered code is not proof that a particular runtime input reaches it.

See [known anomalies](../reference-anomalies/c166-cfg.md), [C166 decoding](c166-c167-decoding.md), and [bounded C166 execution](c166-execution.md).
