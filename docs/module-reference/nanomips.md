# nanoMIPS Taint Analysis

Interprocedural taint tracker for nanoMIPS binaries. Two-path execution: full register-level decode via Capstone 6.x, or conservative frame-walk fallback on Capstone 5.x.

Targets: Ingenic X-series SoCs (JZ4780, X1000, X2000), MediaTek Helio embedded, MIPS32r6 microcontrollers.

---

## Why this exists

Two things were not possible before `NanoMIPSTaintTracker`:

**1. Any automated taint analysis on nanoMIPS at all.**
nanoMIPS is a variable-width ISA (16, 32, and 48-bit instructions) with no branch delay slots and different call instructions than MIPS32. BALC replaces JAL/JALR; JRC $ra replaces JR $ra. No public taint tool handled this before Ablation. The tracker was built from the binutils 2.41 nanoMIPS opcode table and the Ingenic X1000 SDK firmware as the reference binary.

**2. Reliable BALC call target resolution.**
The two BALC forms (P32 and P16) encode call targets as signed PC-relative offsets in non-obvious bitfield layouts. Getting the target wrong means the interprocedural walk misses the callee entirely. The tracker extracts both forms exactly: P32 BALC target = VA + 4 + sign_extend_26(bits[25:0]) shifted left 1. P16 BALC target = VA + 2 + sign_extend_10(bits[9:0]) shifted left 1.

---

## ISA overview

nanoMIPS uses three instruction widths. The width is determined by bits[15:11] of the first halfword:

```
  nanoMIPS instruction widths
  ──────────────────────────────────────────────────────────────
  P16 (16-bit):  bits[15:11] in 0x10-0x17, 0x1A-0x1F
  P32 (32-bit):  bits[15:11] < 0x10 or other specific ranges
  P48 (48-bit):  bits[15:11] = 0x18 (LI48 load-immediate, ADDIU48)

  The 48-bit encoding is rare. Most code is P32 with P16 for
  small operations (short branches, stack pointer adjustments).

  Call instructions (nanoMIPS has no branch delay slot):
    BALC P32:  opcode[31:26] = 0x2a
               target = VA + 4 + sign_extend_26(insn[25:0]) << 1
               range: +/-64 MB from current PC

    BALC P16:  opcode[15:10] = 0b110010 (0x32)
               target = VA + 2 + sign_extend_10(insn[9:0]) << 1
               range: +/-1 KB from current PC

    JALRC P32: indirect call via register
               target address in source register

  Return instruction:
    JRC $ra    (equivalent to MIPS32 JR $ra but no delay slot)

  ABI registers (O32-compatible subset):
    $a0-$a3   first four function arguments
    $v0/$v1   return values
    $t0-$t9   caller-saved temporaries (cleared at call boundaries)
    $s0-$s7   callee-saved (preserved across calls)
    $ra ($31) return address
    $sp ($29) stack pointer
```

MIPS32 delay slots required the instruction after a branch/call to execute before the branch took effect. nanoMIPS eliminates delay slots entirely, so the instruction immediately after a BALC is the first instruction of the fall-through path, not a delayed slot. The tracker accounts for this when walking the call graph.

---

## Two execution paths

```
  NanoMIPSTaintTracker.from_path(elf)
          |
          v
  ┌────────────────────────────────────────────────────────────┐
  │  check capstone version at import time                     │
  │    capstone.__version__ >= '6.0.0a1' ?                    │
  └───────────────────────┬────────────────┬───────────────────┘
                          |                |
                    YES (6.x)         NO (5.x or absent)
                          |                |
                          v                v
  ┌─────────────────────────┐   ┌──────────────────────────────┐
  │  Full decode path       │   │  Conservative fallback path  │
  │                         │   │                              │
  │  Capstone 6.x added     │   │  BALC targets extracted via  │
  │  nanoMIPS support.      │   │  manual bitfield parsing.    │
  │                         │   │                              │
  │  register-level taint   │   │  after any source call:      │
  │  propagation identical   │   │  mark ALL $a0-$a3 tainted   │
  │  to MIPS32 tracker:     │   │  on entry to next function.  │
  │    operand-by-operand   │   │                              │
  │    taint lattice        │   │  no false negatives:         │
  │    XFER/ALU/CLR rules   │   │  every taint path is found.  │
  │    stack slot tracking  │   │  possible false positives:   │
  │                         │   │  non-tainted args appear     │
  └─────────────────────────┘   │  tainted at call sites.      │
                                └──────────────────────────────┘
          |                              |
          v                              v
  tracker.has_full_decode = True   tracker.has_full_decode = False
```

The fallback is deliberately conservative. After any call to a known source (`recv`, `read`, etc.), all four argument registers are marked tainted on entry to the next function because it is impossible to know which register the callee stored the result in without per-operand decode. This avoids false negatives at the cost of more candidates to triage manually.

---

## PLT stub unwrapping

nanoMIPS PLT stubs are 12 bytes. Each stub loads the GOT address and jumps through it. The tracker identifies .plt section boundaries and resolves PLT call targets to their import names before the interprocedural walk begins.

```
  call site disassembly:
    BALC 0x3210       (nanoMIPS P32 call to PLT stub at 0x3210)
          |
          v
  is 0x3210 within .plt section range [0x3000, 0x3400)?
          |
    YES → look up import name in relocation table
          plt[0x3210] = 'strcpy'
          'strcpy' in sink_table?
          YES → emit TaintFinding(sink='strcpy', arg=0, ...)
```

Without PLT unwrapping, every call to `strcpy` or `system` terminates the interprocedural trace at the stub VA. The trace stops before it can confirm the dangerous sink was reached.

---

## Usage

```python
from ablation.analyzers.taint_tracker_nanomips import NanoMIPSTaintTracker

tracker = NanoMIPSTaintTracker.from_path('firmware.elf')
print(f"Full decode: {tracker.has_full_decode}")

# Interprocedural scan (recommended depth=4 for most firmware)
findings = tracker.run_interprocedural(depth=4)
print(tracker.report(findings))
```

Custom sinks for vendor-specific exec wrappers:

```python
tracker = NanoMIPSTaintTracker.from_path('firmware.elf',
    custom_sinks={'vendor_exec': {0: 0}})
findings = tracker.run_interprocedural()
```

---

## Sources and sinks

| Category | Functions |
|---|---|
| Sources | `recv`, `recvfrom`, `read`, `fgets`, `gets`, `fread`, `recvmsg` |
| Exec sinks | `system`, `popen`, `execve`, `execl`, `execvp` |
| Memory sinks | `strcpy`, `strcat`, `sprintf`, `snprintf`, `memcpy`, `memmove`, `bcopy` |
| I/O sinks | `write`, `send`, `sendto` |
