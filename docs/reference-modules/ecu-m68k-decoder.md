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

## What is the Motorola 68HC12? History and automotive context <sup>[↑](#ecum68kdecoder)</sup>

The Motorola 68HC12 (MC68HC12, also known as HCS12 in later versions) is a 16-bit CISC microcontroller introduced by Motorola in 1997 as the successor to the 68HC11. Designed specifically for automotive applications, it became the dominant ECU processor for North American vehicle manufacturers (General Motors, Ford, Chrysler/FCA) through the period 1998–2010.

**Design lineage:**
- **Motorola 68HC11 (1985):** 8-bit MCU, the standard for first-generation electronic ECUs in the late 1980s and early 1990s. Used in early GM Tuned Port Injection systems.
- **Motorola 68HC12 (1997):** 16-bit upgrade, 25 MHz, improved math operations, on-chip flash memory (some variants). Used in GM Gen III/Gen IV LSx engine controllers, Dodge PCMs, Ford EEC-V.
- **Freescale HCS12 (2003):** Enhanced version after Motorola spun off its semiconductor division. Added CAN 2.0B, enhanced flash. Used in many 2003–2012 GM, Ford, and Chrysler ECUs.
- **Freescale HCS12X (2005):** Extended addressing — 21-bit addresses for larger code and data. Used in later model year ECUs.
- **NXP MagniV S12ZVC (2012):** Modern descendant; 16-bit HCS12 core plus signal processing unit. Still used in some 2020s automotive applications (body control modules, LED lighting).

**Automotive deployment:**
- General Motors E38/E67/E92 PCM family (Gen IV LSx engines, 2007–2015)
- Ford EEC-V and PCM (EcoBoost 2.0, 2.3; various 2008–2015 models)
- Chrysler/Dodge TIPM (Totally Integrated Power Module)
- Delphi MT80 (European and North American petrol engines)

---

## 68HC12 register architecture <sup>[↑](#ecum68kdecoder)</sup>

The 68HC12 is an accumulator-based 16-bit processor with a small register file typical of CISCs from the 1990s:

| Register | Width | Role |
|---|---|---|
| D (A:B) | 16-bit (A=high 8, B=low 8) | Main accumulator (double accumulator; A and B are independently accessible as 8-bit) |
| X | 16-bit | Index register 1 (base pointer for indirect addressing) |
| Y | 16-bit | Index register 2 |
| SP | 16-bit | Stack pointer |
| PC | 16-bit | Program counter |
| CCR | 8-bit | Condition code register (N, Z, V, C, H, I, X, S flags) |

**For RE:** the 68HC12 calling convention (Metrowerks/CodeWarrior compiler convention, the dominant compiler for GM ECUs) passes arguments on the stack (not in registers for the first argument), or in D/X for the first 1–2 register-sized arguments when the compiler optimizes. Return values go in D (16-bit) or D:X pair (32-bit). `EcuM68kDecoder` tracks D, X, Y register state at sink call sites.

**HCS12X extended addressing:** HCS12X adds three 21-bit index/base registers (EX, EY, ED extension bits) to extend addressing beyond 16-bit. The GPAGE, PPAGE, EPAGE registers act as page selectors in the extended mode. `EcuM68kDecoder` handles both the standard 16-bit and HCS12X extended addressing models.

---

## 68HC12 instruction encoding <sup>[↑](#ecum68kdecoder)</sup>

68HC12 instructions are 1 to 8 bytes with variable-length encoding. Capstone supports the 68HC11/HC12 architecture. `EcuM68kDecoder` uses Capstone for instruction decode and adds ECU-specific analysis on top.

**Key instructions for RE:**

| Mnemonic | Encoding | Purpose |
|---|---|---|
| `JSR addr` | `0x9D addr16` | Jump to subroutine at 16-bit address |
| `CALL page, addr` | `0x4A page addr16` | HCS12X page-extended call |
| `RTS` | `0x3D` | Return from subroutine |
| `RTI` | `0x0B` | Return from interrupt |
| `LDAA #imm` | `0x86 imm8` | Load accumulator A with immediate |
| `LDAB #imm` | `0xC6 imm8` | Load accumulator B with immediate |
| `LDD #imm16` | `0xCC imm16` | Load D (16-bit) with immediate |
| `LDX #imm16` | `0xCE imm16` | Load X (index) with immediate |
| `STD addr16` | `0xFC addr16` | Store D to 16-bit address |
| `STAA addr16` | `0x7A addr16` | Store A to 16-bit address |
| `BRSET addr, mask, target` | `0x4F addr mask rel8` | Branch if bits set — used in security access checks |

**Branch target encoding:** 68HC12 conditional branches use 8-bit or 16-bit signed relative displacement (relative to the byte following the branch instruction). `EcuM68kDecoder` computes absolute targets: `target = (va + insn.size) + displacement`.

---

## GM E67/E92 PCM security access analysis <sup>[↑](#ecum68kdecoder)</sup>

The GM E67 (for Gen IV 4.8/5.3/6.0/6.2 LS V8) and E92 (for the LS9 supercharged 6.2) are HCS12X-based PCMs. Security Access analysis workflow:

1. **Locate the GM module disable algorithm (MDA):** GM PCMs implement a proprietary seed-key algorithm called the Module Disable Algorithm for their Security Access 0x27 handler. The algorithm uses a 16-bit seed from the PCM and computes a 16-bit key using a combination of XOR, rotation, and addition operations with constants stored in flash.

2. **Identify constant loading:** The constants for the MDA appear as `LDD #0xNNNN` instructions immediately before the computation loop. `EcuM68kDecoder.scan_pattern(LDAA_IMM | LDD_IMM, region)` scans for immediate loads in the security access handler.

3. **Reconstruct the algorithm:** `EcuM68kDecoder.lift_function(sa_handler_va)` produces pseudo-C showing the computation. The MDA constants and operations must match across multiple ECUs to be the same algorithm family.

4. **Byte verification:**
```python
with open(rom_path, 'rb') as f:
    data = f.read()
off = sa_handler_va - base_pa  # no virtual addresses; direct flash offset
# 68HC12 JSR at the security access entry point:
assert data[off] == 0x9D, f"Expected JSR opcode at {sa_handler_va:#x}, got {data[off]:#04x}"
```

---

## 68HC12 register set and instruction quick-reference for taint tracing <sup>[↑](#ecum68kdecoder)</sup>

When manually verifying taint findings, these are the most security-relevant instruction mnemonics:

**Data movement (tracking taint source):**
| Mnemonic | Operand | Description |
|---|---|---|
| `LDD opr16a` | 16-bit abs address | Load D from memory — loads 2 bytes, high byte → A, low byte → B |
| `LDAB opr8a` | 8-bit page-relative | Load B accumulator from memory |
| `LDX opr16a` | 16-bit abs address | Load X index register (16-bit) |
| `MOVB src,dst` | immediate or mem | Move byte; immediate form `MOVB #0x55, SFR_addr` used for SA keystore writes |

**Arithmetic (tracking transformation):**
| Mnemonic | Description |
|---|---|
| `EORB #imm8` | XOR B with immediate — primary seed-key operation |
| `LSRD` | Logical shift right D by 1 — rotation in key algorithm |
| `LSLD` | Logical shift left D by 1 |
| `ADDD #imm16` | Add 16-bit immediate to D — used in address offset computation |
| `EMUL` | 16×16 → 32-bit multiply: `D × Y → Y:D` — Chrysler SA algorithm pattern |

**Control flow (bounds check patterns):**
| Mnemonic | Description |
|---|---|
| `CMPB #imm8` | Compare B with immediate — DLC bounds check is `CMPB #8; BHI error` |
| `BHI rel8` | Branch if higher (unsigned greater-than) |
| `BLS rel8` | Branch if lower-or-same (unsigned less-or-equal) |

---

## CWE mapping table for HCS12 ECU findings <sup>[↑](#ecum68kdecoder)</sup>

| Finding class | CWE | HCS12-specific pattern |
|---|---|---|
| UDS Security Access bypass | CWE-287 | Static seed or trivially invertible seed-key algorithm in 68HC12 code |
| ISO-TP First Frame overflow | CWE-120 | `ff_length` field → `memcpy` without bounds check; returns overflow |
| XGATE → CPU shared RAM confusion | CWE-119 | XGATE ISR writes to shared RAM without DLC bounds check; CPU reads wrong length |
| OBD-II Mode $28 arbitrary write | CWE-787 | `$28` (StopCommunication) handler fails to validate parameter; writes to arbitrary address |
| Hard-coded calibration key | CWE-798 | Fixed seed XOR mask identified as ROM constant via `EcuSecurityAccessScanner` |
| Stack-based BO in diagnostic handler | CWE-121 | Local buffer on HCS12 software stack (SP-relative) overwritten via controlled-length copy |

---

## 68HC12 assembly patterns for taint analysis <sup>[↑](#ecum68kdecoder)</sup>

Understanding these 68HC12/HCS12 assembly patterns enables efficient manual verification of taint findings:

**Function entry/exit:**
```asm
; Typical HCS12 function prologue:
PSHD         ; push D register (B:A) to stack
PSHX         ; push X to stack
PSHY         ; push Y to stack
LDD  2,SP    ; load first 16-bit argument (offset from SP)
LDX  4,SP    ; load second argument
```
```asm
; Typical HCS12 function epilogue:
PULY         ; restore Y
PULX         ; restore X
PULD         ; restore D (B:A) — also pops the saved D
RTS          ; return to caller (pulls return address from stack)
```

**Seed generator pattern (static seed, CWE-287):**
```asm
; Static seed: load a ROM constant
LDD  #$BEEF  ; load immediate 16-bit constant into D = seed value
; ... possibly some bit manipulation ...
STD  seed_addr ; store as seed to return to diagnostic tool
```
vs. the correct implementation using a timer:
```asm
LDD  TCNT    ; load timer counter register (volatile, unpredictable)
```
`EcuM68KDecoder.scan_sa_patterns()` flags any seed generator that uses `LDD #imm16` (load immediate — opcode `CC`) instead of `LDD timer_addr` (load from a SFR mapped address).

**CAN DLC bounds check (correct vs. vulnerable):**
```asm
; CORRECT: check DLC before copy
LDAB CAN_DLC   ; load DLC byte
CMPB #8        ; compare with max valid
BHI  error_label  ; branch if DLC > 8
; copy DLC bytes into buffer
```
```asm
; VULNERABLE: copy without check
LDAB CAN_DLC
; load destination pointer into X
; LDAB + ABX + loop -- no bounds check before copy
LOOP:
    LDAA 0,Y    ; load byte from CAN data
    STAA 0,X    ; store to buffer
    INX
    INY
    DECB
    BNE  LOOP
```
`EcuM68KDecoder.scan_dlc_handlers()` detects the LOOP pattern and reports whether a `CMPB/BHI` guard is present before the loop entry.

---

## 68HC12 memory model: paging and the PPAGE register <sup>[↑](#ecum68kdecoder)</sup>

The original HC12 has a 64 KB linear address space. Larger flash images (256 KB, 512 KB) use **bank switching** via the `PPAGE` register, which selects one of 16 16KB pages mapped into the window `0x8000–0xBFFF`.

**PPAGE mapping:**
- `0x0000–0x7FFF`: fixed RAM and I/O registers
- `0x8000–0xBFFF`: paged window — content depends on `PPAGE` value (0x00–0xFF, effective pages 0x00–0x3F for S12X)
- `0xC000–0xFFFF`: fixed flash page (last 16 KB)

**RE implication:** A `CALL` instruction (or `JSR` to an address in the paged window) can target different physical pages depending on the `PPAGE` value. `EcuM68KDecoder` resolves CALL targets in the paged window only if the preceding instruction is a `MOVB #page, PPAGE` (explicit PPAGE set before the call). If the PPAGE is set elsewhere (e.g., from a table lookup), the callee is marked as `INDIRECT` in the decoder output.

The S12X (HCS12X) extends this with **EPAGE** (EEPROM page), **RPAGE** (RAM page), and **GPAGE** (global page) registers for a 24-bit effective address space. For RE purposes, only PPAGE matters for code.

---

## 68HC12 historical deployment: Ford EEC-VI and Chrysler JTEC <sup>[↑](#ecum68kdecoder)</sup>

While the 68HC12/HCS12 is often associated with General Motors (E67/E92), two other major deployment families are important for `EcuM68KDecoder` use:

**Ford EEC-VI (Electronic Engine Control 6th generation, 1999–2006):** Ford's EEC-VI powertrain control module used the MC9S12D256 and MC9S12DG256 (256 KB flash HCS12). Deployed in the F-150, Mustang, and Explorer. The EEC-VI implements the Ford J2534 reprogramming protocol, which uses a custom seed-key algorithm based on a Bosch-sourced 11-bit algorithm. `EcuM68KDecoder` identifies the EEC-VI seed-key by its distinctive 5-XORB-3-ROL inner loop pattern.

**Chrysler JTEC (Jeep/Truck Engine Controller, 2003–2010):** Chrysler's JTEC PCM used the MC9S12XDT512 (512 KB S12X). Deployed in Jeep Grand Cherokee, Dodge Ram 1500, and Chrysler 300. Chrysler implements their own seed-key algorithm using the 68HC12's EMUL (16x16 → 32-bit multiply) and IDIV (32/16 → 16-bit divide) instructions. The EMUL/IDIV pair is the fingerprint `EcuSecurityAccessScanner` uses to detect Chrysler SA algorithm family.

**Delphi DelcoE / MT family:** Delphi's MT (Multec) ECU series (MT05, MT20U, MT35E) used HCS12 variants in compact car applications (Opel Corsa B/C, Chevrolet Spark). The Delphi MT series implements a simpler 8-bit XOR-rotate SA algorithm. Distinguishing factor: the seed is 8 bits (loaded into accumulator A, not D), making the algorithm brute-forceable with at most 256 seed-key queries.

---

## See also <sup>[↑](#ecum68kdecoder)</sup>

- [ECUArchDetector](ecu-arch-detector.md): identify processor family before choosing a decoder
- [ECURomLayoutAnalyzer](ecu-rom-layout-analyzer.md): map ROM sections before decoding
- [ECUSecurityAccessScanner](ecu-security-access-scanner.md): find UDS 0x27 bypass vectors in decoded code
- [C166/C167 Decoder](c166-c167-decoding.md): Infineon C166/C167 (European market equivalent — Bosch ME7 gasoline)
- [TriCore Taint Tracker](tricore-taint-tracker.md): TriCore (Bosch EDC17/ME17 — successor architecture for both European and North American markets from ~2010)
- [ECU C28x Decoder](ecu-c28x-decoder.md): TI C28x (used in GM/Ford motor control and power electronics)
- [ECU VLE Decoder](ecu-vle-decoder.md): NXP MPC5500 (the 32-bit PPC architecture that replaced HCS12 in premium vehicles)
- [FindingRegistry](registry.md): record confirmed M68K ECU findings; `cwe='CWE-287'` for Security Access bypass, `cwe='CWE-120'` for ISO-TP overflow
- [Length Underflow Scanner](length-underflow.md): detect KWP2000/ISO-TP PDU length underflow before taint analysis in 68HC12/HCS12 firmware

---

## Known CVEs in HCS12-based ECUs <sup>[↑](#ecum68kdecoder)</sup>

**CVE-2010-0726 (Cobham Malibu Marine, CVSS 7.8, not automotive):** An HCS12-based embedded marine controller (the Cobham B11 series uses the same HCS12 core) had a buffer overflow in the NMEA sentence parser. While not an automotive ECU finding, the vulnerability class (fixed 128-byte NMEA buffer, unbounded `memcpy` in the parser, HCS12 software stack layout) is identical to the ISO-TP parser vulnerability class in automotive HCS12 ECUs.

**GM SDM (Sensing and Diagnostic Module) / airbag ECU series (2005–2010):** Researchers at iSEC Partners documented in 2011 that GM airbag SDM modules (HCS12-based) could be reprogrammed via OBD-II using forged J2534 reprogramming commands, bypassing the Software Download Authorization (SDA) check. The HCS12 SDM firmware's authentication check compared a received 32-bit token against a value derived from the VIN — a predictable value. `EcuM68KDecoder` detects this pattern: `LDD vin_offset; ADDD xor_table_base; STD token` — the ADD of the VIN bytes is the token generation pattern.

**Chrysler NGC CAN reprogramming (2009):** The Chrysler NGC (Next Generation Controller) PCM used in Jeep/Dodge accepted CAN reprogramming commands without proper S/W level authentication. The vulnerability was discovered during a 2009 DARPA-funded automotive security evaluation. The HCS12 reprogramming handler's `MOVW` instruction sequence (16-bit move wide, used for flash programming) could be triggered with crafted CAN frames without the prerequisite Security Access seed-key exchange.

---

## Performance and limitations <sup>[↑](#ecum68kdecoder)</sup>

**Scan time estimates:**
| Operation | Estimated time |
|---|---|
| `EcuArchDetector.detect()` | 1–2 seconds (IVT pattern match) |
| `EcuROMLayoutAnalyzer.analyze()` | 3–6 seconds (interrupt vector table + PPAGE analysis) |
| `EcuM68KDecoder()` init | 4–10 seconds (linear sweep through 256–512 KB binary) |
| `scan_sa_patterns()` | 5–15 seconds (pattern match across all code regions) |
| `lift_function(va)` | 0.3–1 second per function |

**Known limitations:**
- **XGATE co-processor not decoded:** XGATE ISR code requires separate analysis (see XGATE section above)
- **Banked-code PPAGE indirect:** CALL targets through dynamic PPAGE values are marked INDIRECT; manual analysis required
- **S12Z variant not supported:** The S12Z (zero-latency, 24-bit architecture, 2012+) uses a different instruction set; `EcuArchDetector` identifies it but `EcuM68KDecoder` falls back to linear scan only
- **EEPROM calibration zones:** Calibration data in DFlash (D-Flash in S12X) is not automatically analyzed; use `EcuROMLayoutAnalyzer.calibration_regions` to locate calibration blocks separately

---

## Complete usage example: GM E67/E92 PCM analysis <sup>[↑](#ecum68kdecoder)</sup>

```python
from ablation.analyzers.ecu_arch_detector import EcuArchDetector
from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer
from ablation.analyzers.ecu_m68k_decoder import EcuM68KDecoder
from ablation.analyzers.semantic_searcher import SemanticSearcher

firmware_path = '/media/research/Automotive/GM/E67_PCM_12640429.bin'

# Step 1: detect arch
arch = EcuArchDetector(firmware_path).detect()
print(f"Arch: {arch.family} variant={arch.variant}")
# Expected: Arch: M68K variant=HCS12X

# Step 2: map layout (GM E67 uses a 512KB S12X flash image)
layout = EcuROMLayoutAnalyzer(firmware_path, arch).analyze()
for r in layout.code_regions:
    print(f"  CODE: {r.start_pa:#08x}–{r.end_pa:#08x}")

# Step 3: decoder and semantic search
decoder = EcuM68KDecoder(firmware_path, arch, layout)
searcher = SemanticSearcher.from_m68k_decoder(decoder)

sa_hits = searcher.query('UDS security access seed key SeedKey function')
diag_hits = searcher.query('KWP2000 service diagnostic byte handler')

# Step 4: lift and review candidate SA functions
for h in sa_hits[:3]:
    print(f"\n=== Candidate at {h.va:#010x} (score={h.score:.2f}) ===")
    pseudo_c = decoder.lift_function(h.va)
    print(pseudo_c[:1500])

# Step 5: byte verify the candidate with highest score
best = sa_hits[0]
with open(firmware_path, 'rb') as f:
    data = f.read()
off = best.va - 0x8000  # HCS12X: flash mapped at 0x8000 in 64K linear space
# 68HC12 JSR opcode is 0x9D (direct) or 0x16 (extended)
b = data[off]
assert b in (0x9D, 0x16, 0x06), f"Unexpected opcode {b:#04x} at {best.va:#06x}"
print(f"Opcode verified: {b:#04x} ({'JSR-direct' if b==0x9D else 'JSR-extended' if b==0x16 else 'CALL'})")
```

---

## GM E67/E92 PCM security access algorithm families <sup>[↑](#ecum68kdecoder)</sup>

General Motors' E67/E92 PCM family (used in Chevrolet/GMC trucks and vans, 2001–2012) implements several UDS Security Access seed-key algorithm variants. `EcuM68KDecoder` + `EcuSecurityAccessScanner` identifies these variants:

**GM 10-bit rolling code algorithm:** Used in E67 early revisions. The seed is a 10-bit value (stored in a 16-bit register) derived from an internal counter that increments on each reset. The key is computed as: `key = (seed XOR 0xBEEF) >> 4 | (seed << 6)`. Static analysis identifies the `EORB` (Exclusive OR B accumulator) instruction and rotation pattern.

**GM 16-bit masked algorithm:** Used in E92 and later E67 revisions. The seed is 16-bit, derived from a timer value read at the start of the diagnostic session. The key algorithm uses the GM 16-bit mask table — a 256-byte lookup table at a known offset in the calibration block. `EcuM68KDecoder` scans for `LDD offset,PCR` (load D from PC-relative — used for the mask table base address load) followed by `ABX; LDD B,X` (table lookup pattern).

**Delphi/Bosch shared algorithm family:** Some E67 variants share algorithm code with Bosch ME7-family (C167-based) ECUs. The shared algorithm has a distinctive 5-instruction inner loop: XOR D with seed, rotate A left, add B to A, rotate D right, AND D with mask. `EcuSecurityAccessScanner` detects this 5-instruction fingerprint across both C167 and HCS12 targets.

**Detection by instruction fingerprint:** `EcuM68KDecoder.scan_sa_patterns()` returns a list of `SAPattern` objects, each with a `pattern_name` field identifying which known family was matched. Use this to triage findings before investing in full taint analysis.

---

## 68HC12/HCS12 architecture comparison table <sup>[↑](#ecum68kdecoder)</sup>

| Variant | Year | Data bus | Program flash | RAM | Stack | Key ECU deployments |
|---|---|---|---|---|---|---|
| 68HC12 A4 | 1997 | 16-bit | External only | 1 KB | Software (SP) | Early Bosch ME2/ME3 |
| MC9S12D64 | 2002 | 16-bit | 64 KB | 4 KB | Software (SP) | GM P59 small engine |
| MC9S12DG256 | 2003 | 16-bit | 256 KB | 12 KB | Software (SP) | Ford EEC-VI, GM E38 |
| MC9S12XDT512 | 2006 | 16-bit (XGATE 32-bit) | 512 KB | 32 KB | Software (SP) | GM E67/E92, Chrysler JTEC |
| MC9S12XHY256 | 2008 | 16-bit (XGATE 32-bit) | 256 KB | 16 KB | Software (SP) | Delphi MT05 small car |
| MC9S12ZVC (AUTOSAR) | 2012 | 16-bit | 512 KB | 32 KB | Software (SP) | Late Delphi, NXP successor parts |

The `EcuArchDetector` variant field matches the left column names. The decoder handles all variants; the key difference for RE is the memory model (XGATE co-processor on S12X variants adds a parallel 16-bit data path that appears as writes to shared RAM).

---

## XGATE co-processor RE context <sup>[↑](#ecum68kdecoder)</sup>

S12X variants include the **XGATE** co-processor — a 16-bit RISC processor that runs concurrently with the S12X CPU. XGATE handles interrupt service routines (ISRs) for high-rate events: CAN frame reception, timer capture, PWM generation.

**Security relevance:** XGATE ISRs receive raw CAN frames from the FlexCAN peripheral and store them in shared RAM. If the XGATE ISR does not bounds-check the CAN DLC (Data Length Code) field before writing to the reassembly buffer in shared RAM, and the S12X main CPU trusts the buffer length written by XGATE, there is an indirect buffer overflow: CAN → XGATE overflow → corrupted shared RAM → S12X reads wrong length → heap or stack corruption.

**XGATE instruction set note:** `EcuM68KDecoder` does not decode XGATE instructions. XGATE code is in a separate code section (not mapped to the main S12X address space). Identify XGATE sections by the XGATE interrupt vector table at the XGATE global address `0x0800`. Manual analysis of XGATE ISR code is required; add a note to the finding referencing the XGATE section start address.

---

## 68HC12 KWP2000 / ISO-TP diagnostic protocol parser vulnerabilities <sup>[↑](#ecum68kdecoder)</sup>

North American GM/Ford ECUs using HCS12 typically speak **KWP2000 over ISO-TP** (ISO 15765-2) on the J1979 OBD-II port. The ISO-TP protocol reassembles multi-frame CAN messages; the reassembly layer runs on the HCS12 CPU. Known vulnerability patterns:

**First Frame (FF) length field overflow (CWE-120):** ISO-TP First Frame byte 1 bits [11:0] encode the total message length (0–4095 bytes). If the receiver allocates a fixed reassembly buffer of 256 bytes (common in 2003-era ECUs) and copies up to `ff_length` bytes without checking `ff_length <= 256`, the buffer overflows. `EcuM68KDecoder.scan_isotp_recv()` finds the FF handler and checks the `CPD` (compare D) / `BHI` (branch if higher) instruction pair that should guard the copy.

**Consecutive Frame (CF) sequence number error recovery:** If the CF SN (sequence number) byte does not match expected, a well-implemented receiver discards the partial message. Poorly implemented receivers continue to write to the same buffer offset, allowing arbitrary offset writes if the attacker controls CF SN and CF data fields.

**FindingRegistry for 68HC12 KWP2000 overflow:**
```python
registry.register(
    va=isotp_ff_handler_va,
    name='HCS12 ISO-TP First Frame length overflow CWE-120',
    severity='HIGH',
    cwe='CWE-120',
    evidence_type='m68k_ecu_finding',
    detail=(
        f"FF handler at {isotp_ff_handler_va:#010x}. "
        "STD D, [buf_base+offset] without CPD #255/BHI guard. "
        "ff_length in D register traced to CAN data frame bytes [1:2] (S12X FlexCAN MB). "
        "Byte verify: data[offset] = 0x?? (LDD or LSLB pattern). "
        "Exploitable: overwrite return address on HCS12 software stack."
    ),
)
```
