# EcuM68kDecoder

**File:** `ablation/analyzers/ecu_m68k_decoder.py`

---

## What this is <sup>[↑](#ecum68kdecoder)</sup>

GM P-series PCMs use a Motorola CPU32 core, a 68000-family processor in automotive engine control modules. These ROMs have no ELF headers and no symbol tables. Capstone decodes M68K instructions but provides no way to find function boundaries in a flat image. `EcuM68kDecoder` scans the ROM for CPU32 frame-allocation prologues in one pass and produces a function-start list without calling Capstone. It also wraps Capstone output with the same typed instruction fields used throughout the Ablation pipeline, so M68K firmware is interchangeable with PPC VLE firmware downstream of the decoder.

---

## Where it's used <sup>[↑](#ecum68kdecoder)</sup>

- **GM P-series PCMs**: P01, P04, P05, P08, P10, P11, P59 engine control modules
- Any CPU32 flat ROM image from Motorola 68000-family automotive ECUs

---

## Safe usage <sup>[↑](#ecum68kdecoder)</sup>

**Call `function_starts()` before constructing a taint tracker.** Without known entry points, a taint tracker has no seeds and returns no findings. `EcuM68kDecoder` produces these seeds by scanning for `LINK.W A6` and `MOVEM.L` prologues.

**Verify `base_va` matches the ROM mapping.** CPU32 ECU ROMs map flash at MCU-specific addresses. A wrong `base_va` shifts every function address so findings report incorrect VAs.

**Do not suppress MOVEM.L at even offsets unconditionally.** The decoder suppresses `MOVEM.L` entries that appear two words after a `LINK.W` because those are the callee-save instruction inside the prologue, not a new function start. Disabling this filter produces duplicate function starts inside existing prologues.

**Use `M68kInsn.insn_type` instead of raw mnemonics in downstream stages.** The pipeline routes instructions by `insn_type`, not mnemonic string. Comparing mnemonic strings for M68K breaks when Capstone uses alternate forms for the same instruction.

---

## Why this exists <sup>[↑](#ecum68kdecoder)</sup>

Two things were not possible before in Ablation:

**1. No function_starts() for M68K/CPU32 firmware.** Capstone decodes M68K instructions
but provides no mechanism to locate function entry points in a flat ROM image. The GM P-series
PCMs P01/P04/P05/P08/P10/P11/P59 run a CPU32 core; their ROMs have no ELF headers and no
symbol tables. Before this module, seeding the taint tracker with function entry points for
P-series firmware required manual disassembly to locate LINK prologues. This module scans the
full ROM for ``LINK.W A6, #-N`` the GM CPU32 frame-allocation convention and ``MOVEM.L regs,
-(SP)`` callee-save leaf functions at any even offset without calling Capstone, producing a
complete function-start list from a single pass over the binary.

**2. No M68K instruction-type classification for the pipeline.** Capstone returns raw mnemonic
strings. Pipeline stages that route instructions by type branch, call, return, prologue had no
M68K adapter. ``M68kInsn`` wraps Capstone output with the same typed fields used by ``VLEInsn``, making M68K and PPC VLE firmware interchangeable
at all pipeline stages downstream of the decoder.

---

## CPU32 function prologue forms <sup>[↑](#ecum68kdecoder)</sup>

### Frame-allocating functions primary signal <sup>[↑](#ecum68kdecoder)</sup>

```
LINK.W A6, #-N
```

Encodes as two big-endian 16-bit words: ``0x4E56`` LINK.W A6 opcode followed by a signed
16-bit displacement with bit 15 set negative, indicating stack frame allocation downward.
This is the standard CPU32 call frame setup in the GM P-series ABI. The frame pointer is A6.

Detection:
```python
hw == 0x4E56   and   (next_word & 0x8000) != 0
```

### Callee-save leaf functions secondary signal <sup>[↑](#ecum68kdecoder)</sup>

```
MOVEM.L regs, -(SP)
```

Encodes as ``0x48E7`` followed by a 16-bit register mask. When this is the first instruction
of a function not the second instruction of a frame-allocating function, it marks a leaf
function that saves callee-saved registers without allocating a full frame.

A ``MOVEM.L`` at offset ``i`` is suppressed as a function start when the 16-bit word at
``i - 4`` equals ``0x4E56`` LINK.W opcode, indicating it is the instruction immediately
following the prologue LINK.

---

## Usage <sup>[↑](#ecum68kdecoder)</sup>

```python
from ablation.analyzers.ecu_m68k_decoder import EcuM68kDecoder

# From file path
dec = EcuM68kDecoder.from_path("P01_rom.bin", base_va=0)

# From raw bytes
dec = EcuM68kDecoder.from_bytes(rom_bytes, base_va=0)

# function_starts(): pure pattern scan, no Capstone required
starts = dec.function_starts()
print(f"{len(starts)} probable functions")

# disassemble(): requires Capstone; raises ImportError if not installed
insns = dec.disassemble(start=0xB00, end=0x2000)
for i in insns:
    if i.insn_type in ("CALL", "RETURN", "PROLOGUE"):
        print(i)

# insn_length(): uses Capstone; falls back to 2 if unavailable
length = dec.insn_length(offset=0x42C)
```

### Constructor parameters <sup>[↑](#ecum68kdecoder)</sup>

| Parameter | Default | Description |
|---|---|---|
| `data` |: | `bytes`, file path (`str`/`Path`), or raw bytes buffer |
| `base_va` | 0 | Virtual address of the first byte in `data`. All decoded instruction offsets and branch targets are expressed as VAs. |

---

## M68kInsn fields <sup>[↑](#ecum68kdecoder)</sup>

```python
@dataclass
class M68kInsn:
    offset:    int         # instruction VA (base_va + byte offset)
    mnemonic:  str         # Capstone mnemonic, e.g., "link.w", "rts", "jsr"
    op_str:    str         # Capstone operand string, e.g., "a6, #$fff0"
    insn_type: str         # "RETURN", "BRANCH", "CALL", "PROLOGUE", "MISC"
    raw:       bytes       # raw instruction bytes (2, 4, 6, or 8)
    size:      int         # len(raw): convenience alias
    target:    int | None  # branch/call target VA when statically resolvable
```

`insn_type` values:

| Type | Instructions |
|---|---|
| `RETURN` | `rts`, `rtd`, `rte`, `rtr` |
| `BRANCH` | `bra.*`, `beq.*`, `bne.*`, `blt.*`, `bgt.*`, `jmp`, all `b*` conditional |
| `CALL` | `jsr`, `bsr.*` |
| `PROLOGUE` | `link.w a6, #-N` negative displacement only |
| `MISC` | All others `move`, `movem`, `add`, `sub`, `nop`, `link` with positive disp, … |

---

## Branch target computation <sup>[↑](#ecum68kdecoder)</sup>

Capstone M68K formats absolute branch/call targets in `op_str` as `$hexaddr` or
`$hexaddr.w` / `$hexaddr.l` with a size suffix.  `EcuM68kDecoder` strips the suffix and
parses the hex value:

```
"$1102"    →  0x1102
"$5000.w"  →  0x5000
"$5000.l"  →  0x5000
```

Indirect targets for example `JSR (A0`) return `target = None`; the address is not statically
known.

---

## Capstone dependency <sup>[↑](#ecum68kdecoder)</sup>

`function_starts()` and `insn_length()` fallback do not require Capstone and work with the
pure-Python pattern scan. `disassemble()` and `decode_one()` require Capstone and raise
``ImportError`` with install instructions if it is not available.

Capstone 5.0.7 `CS_ARCH_M68K`, `CS_MODE_M68K_020` is used. CPU32 is a 68020 derivative;
no 68020-specific instructions appear in GM P-series firmware that CPU32 does not also support.

---

## Validated results <sup>[↑](#ecum68kdecoder)</sup>

### GM P01 ROM CPU32, J1850 VPW OBD-II <sup>[↑](#ecum68kdecoder)</sup>

``function_starts()`` on a synthetic P01-pattern ROM block (100 LINK.W prologues, every 32
bytes) recovers all 100 starts with zero false positives.

The ``EcuSecurityAccessScanner`` confirmed pattern at offset ``0xB60`` in the P01 image is
immediately preceded by a ``LINK.W A6, #-0x20`` at ``0xB5C``, confirming that the SA handler
is a frame-allocating function whose start ``function_starts()`` correctly identifies.

---

## Limitations <sup>[↑](#ecum68kdecoder)</sup>

- CPU32-specific instructions (``TBLS``, ``TBLSN``, ``DIVS.L``, ``DIVU.L`` with 32-bit
 operands) may not decode identically between ``CS_MODE_M68K_020`` and a hypothetical
  ``CS_MODE_M68K_CPU32`` which Capstone 5.0.7 does not implement.  In the GM P-series corpus
 these instructions are absent from SA-handler analysis paths.
- ``insn_length()`` falls back to 2 when Capstone is unavailable. A caller that iterates
 instructions using ``insn_length()`` without Capstone will advance in 2-byte steps and may
 misalign on 4-byte or 6-byte instructions. Callers that need accurate lengths must have
 Capstone installed.
- ``function_starts()`` does not detect LINK.L 32-bit displacement variant, opcode ``0x4808``.
 LINK.L is used for functions with local variable space exceeding 32 KB; this is uncommon in
 embedded firmware but possible.

---

## How it works <sup>[↑](#ecum68kdecoder)</sup>

Reads the ROM image at the specified base address and applies the ISA decoder to recover instruction objects. Function boundaries are identified from preamble/epilogue patterns specific to the target compiler and ABI. Security-relevant patterns UDS handler tables, seed/key routines, calibration write paths are identified by combining structural matching with known compiler output signatures. Decoded results are stored in a `BinaryContext`-compatible format for downstream analysis.

---

## Example output <sup>[↑](#ecum68kdecoder)</sup>

```
[CRITICAL] WEAK_SEED   UDS 0x27 0x01 at ROM:0x8004A0
  detail: seed is timestamp-derived (LSB of timer register)
  algorithm: linear congruential; key derivable in < 2^16 guesses

[HIGH] UNPROTECTED_WRITE   calibration region at ROM:0x810000
  detail: no write-protect fuse check before accepting 0x34 WriteDataByIdentifier
```

---

## False positives <sup>[↑](#ecum68kdecoder)</sup>

Calibration data regions contain byte sequences that decode as valid instructions in some ISAs. Confirm candidate function VAs against the ROM layout from `ECURomLayoutAnalyzer` before treating them as code. Security Access sequences in boot ROM are expected and not findings unless the seed/key algorithm is cryptographically weak.

---

## Pipeline position <sup>[↑](#ecum68kdecoder)</sup>

**Before this module:** `ECUArchDetector` to identify the processor family and confirm this decoder applies to the target ROM.

**After this module:** Feed decoded instructions to the appropriate taint tracker RH850, TriCore, SH-2A, or C28x for vulnerability analysis.

---

## Reading output <sup>[↑](#ecum68kdecoder)</sup>

`EcuM68kDecoder.from_bytesdata, base=0.decode_all()` returns `List[M68kInsn]`:

| Attribute | Content |
|:---|:---|
| `offset` | Byte offset or VA if base is set of this instruction |
| `mnemonic` | Instruction mnemonic for example `'MOVE.W'`, `'JSR'`, `'CLR.B'` |
| `op_str` | Decoded operands string for example `'D0, 0x1234'` |
| `insn_type` | `'BRANCH'` / `'CALL'` / `'RETURN'` / `'MISC'` |
| `raw` | Raw instruction bytes |
| `size` | Instruction size in bytes 2, 4, or 6 |
| `target` | Branch/call target address (None if not a control-flow instruction) |

---

## See also <sup>[↑](#ecum68kdecoder)</sup>

- [ECUArchDetector](ecu-arch-detector.md): identify processor family before choosing a decoder
- [ECURomLayoutAnalyzer](ecu-rom-layout-analyzer.md): map ROM sections before decoding
- [ECUSecurityAccessScanner](ecu-security-access-scanner.md): find UDS 0x27 bypass vectors in decoded code
