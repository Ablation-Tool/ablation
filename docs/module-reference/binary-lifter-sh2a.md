# BinaryLifter — SH-2A backend

**File:** `ablation/analyzers/binary_lifter.py`  
**Arch token:** `sh2a` (aliases: `sh-2a`, `sh2`)

---

## Why this exists

2 things that were not possible before in Ablation:

**1. No pseudo-C IR for Renesas SH-2A MCU firmware.**  `BinaryLifter` covered 17 ISAs but had no
SH-2A backend.  SH-2A is the dominant MCU inside Bosch EDC, Denso, and Siemens automotive ECUs
(SH7058/SH7059 on-chip flash).  Without a lifter, security sweeps on ECU firmware produced raw
disassembly only — no call-chain analysis, no taint annotations, no caller-resolved pseudo-C.

**2. No lifter designed for headerless flat ROM files.**  All 17 prior ISA backends assumed an ELF
section map to translate VAs to file offsets.  Flat ECU ROMs have no ELF header; the MCU flash is
a raw byte image where VA == file offset.  The SH-2A backend adds an explicit flat-ROM fallback
path that works correctly when `_sections` is empty.

---

## Usage

```python
from ablation.analyzers.binary_lifter import BinaryLifter

# Flat ECU ROM (base_va=0, VA==file_offset)
lifter = BinaryLifter.from_path("sh7058_ecu.bin", arch="sh2a")
print(lifter.lift_function(0x1000))

# With confirmed function names
lifter._names[0x2400] = "can_rx_handler"
print(lifter.lift_function(0x2400))

# With taint from a prior analysis
lifter._taint_map[0x1000] = {"r4"}   # R4 carries tainted data at this function
print(lifter.lift_function(0x1000))
```

Example output:

```
// can_rx_handler @ 0x2400
{
  // sts.l
  uint32_t v0 = parse_can_frame(arg0, arg1, arg2, arg3);
  return v0;
  // nop
}
```

---

## Architecture mapping

| SH-2A | BinaryLifter |
|---|---|
| R4-R7 | arg0-arg3 |
| R0 | return value |
| R15 | sp (stack pointer) |
| PR | link register (return address) |

---

## How it works

`_lift_sh2a()` uses `EcuSH2aDecoder` (the pre-existing SH-2A decoder) to produce `SH2aInsn`
objects.  Each instruction already carries a pre-decoded `insn_type` field, so `_SH2aState.emit()`
dispatches on that string directly — no mnemonic regex parsing.

**Instruction type dispatch:**

| `insn_type` | IR output |
|---|---|
| `LR_SAVE` | `// sts.l` (prologue comment, not in IR) |
| `LR_RESTORE` | `// lds.l` (epilogue comment) |
| `RETURN` | `return rX;` |
| `CALL` (BSR, with target) | `uint32_t vN = name(arg0, ..., arg3);` |
| `CALL` (JSR, no target) | `uint32_t vN = (*rM)(arg0, ..., arg3);` |
| `BRANCH` (BRA/BRAF) | `goto loc_X;` |
| `BRANCH` (BT/BT/S) | `if (T) goto loc_X;` |
| `BRANCH` (BF/BF/S) | `if (!T) goto loc_X;` |
| `LOAD` (MOV.L/W/B @Rm,Rn) | `uint32_t vN = *(uint32_t*)rM;` |
| `STORE` (MOV.L/W/B Rm,@Rn) | `*(uint32_t*)rN = rM;` |
| `MISC` (MOV #imm, Rn) | `uint32_t vN = 0x1a;` |
| `MISC` (other) | `// mnemonic` |

**Delay slots:** SH-2A executes one instruction after BSR/BRA/RTS before the branch takes effect.
The lifter emits both the branch statement and the delay-slot instruction.  The call statement and
the return statement therefore appear in the correct logical order in the output.

**Truncation:** The lifter stops at the first `RETURN` instruction plus one delay-slot instruction.
Without this, flat ROM zero-padding would produce hundreds of spurious `// misc0` lines.

**Taint propagation:** If a function's entry registers are in `_taint_map[func_va]`, taint
propagates through loads and calls.  A call whose arguments include a tainted register emits
`/* TAINTED */` after the call statement.

---

## Flat ROM path

When `BinaryLifter._sections` is empty (lief could not parse an ELF/PE header), the lifter
treats `func_va` as a direct byte offset into `self.data`.  This is correct for all SH-2A ECU
ROM images, where the MCU flash is mapped at VA 0x00000000 and the raw binary starts at offset 0.

If `func_va >= len(self.data)`, the slice returns empty bytes and the lifter returns a comment
rather than crashing.

---

## Limitations

- Conditional branches emit `if (T)` / `if (!T)` — the T-bit value is not tracked across
  instructions.  This is a structural limitation of the linear-walk approach (no CFG).
- Indirect call targets (JSR @Rn) are not resolved — they appear as `(*rN)(...)`.  Use
  `FlatBinaryFuncStartScanner` to harvest indirect call targets separately.
- 32-bit SH-2A extension instructions (MOVI20, MOV12, BIT ops) decode as `MISC` and emit
  as comments.  The state machine does not model their register effects.
- No CFG — each function is a linear walk from entry to first RETURN.  Back-edges from loops
  appear in the output but the loop body may be partially repeated.
