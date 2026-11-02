# Known Anomalies: Bounded C166 Execution and CAN

## Architectural scope

- The interpreter covers a focused instruction subset. Unsupported opcodes fail; they do not execute as NOPs.
- `JMPI` requires a validated target model and otherwise fails.
- Timing, interrupts, pipeline hazards, watchdogs, analog behavior, and bootloader execution are not represented.
- The call stack models direct call/return flow and is not a complete architectural stack/SFR implementation.

## Memory and reset state

- Unwritten bytes read as zero by design. This is not evidence that physical RAM resets to zero. The A1396 harness initializes update state explicitly because dense firmware gaps contain `0xFF`.
- Whole-file write protection can be wrong for dense Intel HEX images. Supply exact protected spans so RAM and CAN objects remain writable.
- DPP mappings are target inputs. Wrong pages produce valid-looking but incorrect source data; tests use DPP1 page 7 specifically for the A1396 source string.

## Instruction semantics

- `MOVB`/`MOV` flag updates are required for command dispatch; stale flags must not drive the next packet's zero branch.
- `MOVBZ` preserves the flags used by the peripheral poll and is not modeled as ordinary `MOVB` flag behavior.
- `ZEROS` is constant zero and `ONES` is constant `0xFF`; treating them as general registers breaks loops.
- `SUBB mem, ONES` increments the byte modulo 256. This is required for the 0-through-9 handoff copy loop.

## CAN and security evidence

- Message-object I/O is not CAN arbitration or physical transmission.
- A valid arm followed by an invalid trigger reaches `SRST`; an invalid arm skips the arming store. Do not generalize this to every checksum failure or every firmware image.
- `SRST` is a modeled stop reason, not proof of a hardware reset or of bootloader update acceptance.
- No authenticity conclusion is inferred from an additive checksum or from a successful application handler.

## Resource and verification limits

- Step, call-depth, trace, object-count, and address-space limits are intentional. Exceeding one is an explicit error requiring investigation.
- Passing tests prove the implemented model against known paths, not complete C166 ISA conformance or hardware equivalence.
