# Bounded C166 Execution and CAN Message Objects

`c166_execution.py` is a fail-closed interpreter for focused C166 firmware paths and a model of the 16-byte CAN message objects used by the A1396 handler. It runs supported instructions against sparse 24-bit memory; it is not a cycle-accurate processor or full-chip simulation.

## Why this module exists

Static analysis can identify a handler but still leave arithmetic, pointer, and flag questions unresolved. Executing the A1396 update path exposed several behaviors that matter for correctness:

- ordinary `MOVB` operations update flags used by command dispatch;
- `MOVBZ` preserves the flags used by the peripheral poll;
- `ZEROS` and `ONES` are pseudo-registers, not `RL7` or the value one;
- subtracting `ONES` increments a byte modulo 256, producing the ten-copy indices 0 through 9;
- indirect source reads require an explicit DPP mapping while internal-RAM destinations remain direct;
- flat Intel HEX spans include gaps that must not become protected RAM or peripheral writes.

The interpreter turns those details into reusable, testable semantics instead of a one-off script.

## Main components

| Component | Role |
|---|---|
| `C166Memory` | Sparse 24-bit memory, read/write protection, direct and DPP-mapped access |
| `C166CPU` | Registers, flags, program counter, bounded trace, direct branches/calls, supported instruction execution |
| `C166CANMessage` | Eight-byte command/channel/subcommand/payload/checksum frame model |
| `C166CANController` | Bounded 16-byte message-object addressing and frame I/O |
| `C166ExecutionResult` | Final PC, stop reason, steps, registers, flags, and bounded trace |
| `C166ExecutionError` | Explicit unsupported, out-of-range, protection, or limit failure |

No global CPU or memory state is shared between runs.

## Memory model

`C166Memory` allocates 4 KiB pages on demand. Unwritten bytes read as zero; this is a model choice, not a claim about physical reset contents. Initialize security-relevant state explicitly.

Two independent address forms are provided:

- `read()` / `write()` / `read16()` / `write16()` for direct addresses;
- `read_indirect()` / `write_indirect()` and word variants for DPP-mapped accesses.

DPP pages are caller-supplied and validated. Offsets at or above `0xF000` remain direct peripheral/internal addresses in this focused model. Other offsets use the relevant page register and 14-bit page offset.

Firmware writes are rejected by default. For flat files with holes, provide exact `protected_ranges` instead of protecting the entire dense container. A1396 uses `(0x1C000, 0x1DACC)` and `(0x20000, 0x2A72C)` so RAM at `0x84FE` and CAN objects at `0xEF20` remain writable.

## CPU behavior and limits

The interpreter supports the instruction families needed by the focused paths: register/immediate moves, direct and indirect loads/stores, zero extension, byte arithmetic and comparison, selected read-modify-write operations, direct branches, direct calls and returns, and `SRST`.

Execution stops or fails on:

- `SRST` or a selected stop address;
- an unsupported instruction or condition;
- an indirect jump without a validated target model;
- a return with an empty modeled call stack;
- a protected-memory write;
- the configured step or call-depth limit.

The trace is a bounded `deque`, not an unbounded log. Large event histories therefore do not silently exhaust memory.

## CAN message objects

The controller defaults to 15 objects at `0xEF10`, each 16 bytes long, with eight data bytes at offset seven:

```text
D0 command | D1 channel | D2 subcommand | D3..D6 payload | D7 additive checksum
```

`C166CANMessage` validates field widths and payload type/length. The checksum defaults to the sum of D0 through D6 modulo 256; an explicit alternate checksum supports negative tests.

The model addresses message objects and checks frames. It does not arbitrate on a physical CAN bus.

## A1396 reference execution

The reference starts at `0x237B2`, after receive framing and checksum classification. The harness initializes:

- TX/RX object pointers at `0x83C6` and `0x83C8`;
- the command/channel/subcommand aliases at `0x838F`, `0x838D`, and `0x838C`;
- checksum status `0x8387` to 7 for valid or zero for invalid;
- update state `0x84FE` and password flag `0x8374` to zero;
- peripheral status `0xEF01` bit 3 so the transmit poll completes;
- DPP1 page 7 so indirect reads from `0x5AAE + index` resolve to `0x1DAAE + index`.

It then executes:

1. command `0x06`, stopping at `0x2492A`, and checks the arming store;
2. command `0x07` from `0x237B2` until `SRST`;
3. exact bytes `update req` at `0xF800` through `0xF809`.

A separate invalid-arm test proves that the response at `0x247AA` skips the arming store. A valid arm followed by an invalid trigger still reaches the reset gate. This corrected the earlier static interpretation: not every checksum failure arms or resets the board.

## Verification

`tests/test_c166_execution.py` covers:

- arithmetic loops and condition flags;
- direct calls and returns;
- DPP-mapped reads at the original address;
- protected spans versus writable RAM;
- unsupported opcodes and execution limits;
- CAN layout, checksums, and invalid objects;
- valid and invalid trigger behavior after valid arming;
- invalid arming with no update-state write;
- exact ten-byte handoff and a zero password flag.

The C166 test suite currently verifies 141 tests across CFG, execution, and the original decoder.

## Limitations

- The instruction subset is deliberately bounded and not a general C166 lifter.
- Timing, interrupts, pipeline behavior, and analog peripherals are not modeled.
- The call stack is modeled separately rather than as complete architectural stack memory.
- Unwritten memory defaults to zero and must not be used as reset-state evidence.
- No physical CAN transmission, hardware reset, or bootloader authenticity decision is made.
- A successful handler model does not prove a deployed board accepts an update image.

See [known anomalies](../reference-anomalies/c166-execution.md), [C166 CFG and xrefs](c166-cfg.md), and the [CERN workflow](../workflows/cern-reverse-engineering-toolchain.md).
