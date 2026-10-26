# EcuC28xDecoder

## What this is <sup>[↑](#ecuc28xdecoder)</sup>

TI TMS320C28x MCUs power EV/HEV traction-inverter controllers and motor-drive ECUs. Capstone has no C28x support. C28x uses three distinct calling conventions and word-addressed program memory where PC-relative branch offsets are word counts, not byte counts. `EcuC28xDecoder` decodes C28x instructions from raw bytes, handles all three call/return forms, and computes branch targets correctly in word addresses.

---

## Where it's used <sup>[↑](#ecuc28xdecoder)</sup>

- **EV/HEV traction inverters**: TI F28x-series motor-drive ECUs
- **TMS320F2803x / F2806x / F2833x**: TI Piccolo and Delfino controller firmware
- Any TI COFF-extracted or flat binary image from F28x-series hardware

---

## Safe usage <sup>[↑](#ecuc28xdecoder)</sup>

**Pass `base_va` as a word address.** C28x program memory is word-addressed. Passing a byte address doubles every computed branch target and function start address.

**Detect the calling convention before tracing call chains.** Each function uses one of three call/return forms: LC/LRET, LCR/LRETR, or FFC/XAR7. Use `insn.call_type` to determine which form a function uses before building a call graph. Assuming LC/LRET throughout produces wrong return-address tracking for LCR/LRETR and FFC functions.

**Run `TiCoffLoader` to extract the code section before passing bytes to the decoder.** The decoder expects raw code bytes. A raw COFF binary includes headers that the decoder misinterprets as instructions.

**Check `function_starts()` coverage before taint analysis.** C28x function starts come from direct call targets, not prologues. If `function_starts()` returns few entries, indirect calls via FFC XAR7 may be missed. Add those targets manually if known from COFF symbol tables.

---

## Why this exists <sup>[↑](#ecuc28xdecoder)</sup>

Four things were not possible before in Ablation:

1. **No C28x disassembler existed in any supported toolchain.** Capstone 5.x has no
 TMS320C28x support. Ghidra and Radare2 support C28x, but Ablation cannot invoke them
 from Python without a subprocess dependency. The F28x-series MCUs used in EV/HEV traction-inverter controllers and motor-drive ECUs were
 entirely opaque to Ablation's control-flow passes.

2. **The two C28x calling conventions could not be distinguished.** `LC/LRET` stores the return address on the software stack with an 8-cycle return. `LCR/LRETR` stores it in the RPC register with a 4-cycle return. Each requires different stack-unwinding logic. Without a
 decoder, Ablation could not decide which convention a given function uses, making CFG
 construction impossible.

3. **`FFC XAR7, 22bit`: a third calling convention: was unknown to Ablation.** FFC
 Fast Function Call stores the return address in the XAR7 register rather than the
 stack or RPC. It is used in performance-sensitive inner loops and is not identified by
 any stack-frame analysis tool that assumes only CALL/RET pairs.

4. **Word-addressed branching could not be modeled.** C28x program memory is word-addressed.
 PC-relative branch offsets are signed 16-bit word counts, not byte counts. Applying
 byte-count displacement arithmetic produces wrong target addresses for every C28x branch.

---

## What it does <sup>[↑](#ecuc28xdecoder)</sup>

`EcuC28xDecoder` decodes TMS320C28x instructions from a raw byte buffer using the
encodings in SPRU430F TMS320C28x CPU and Instruction Set Reference Guide, April 2015.
It identifies control-flow instructions, computes branch targets
in word-addresses, and provides a `function_starts()` method that returns probable function
entry points from direct call targets.

Primary consumer: C28x firmware analysis in the auto-ECU corpus and any TI F28x target
where `TiCoffLoader` has extracted a code section.

---

## Usage <sup>[↑](#ecuc28xdecoder)</sup>

```python
from ablation.analyzers.ecu_c28x_decoder import EcuC28xDecoder

# Decode from raw bytes (base_va is a word address, default 0)
dec = EcuC28xDecoder(code_bytes, base_va=0x3F8000)

# Decode a range (byte offsets into the buffer)
insns = dec.disassemble(start=0, end=len(code_bytes))
for insn in insns:
    print(insn)

# Decode one instruction
insn = dec.decode_one(byte_off=0)

# Get length of instruction at a byte offset
length = dec.insn_length(byte_off=0)   # 2 or 4

# Collect direct call targets as candidate function entry points
starts = dec.function_starts()   # list of word VAs, sorted
```

`from_path()` and `from_bytes()` are convenience constructors. `from_path()` raises
`FileNotFoundError` or `OSError` on missing/unreadable files caller catches.

---

## C28xInsn fields <sup>[↑](#ecuc28xdecoder)</sup>

| Field | Type | Meaning |
|---|---|---|
| `word_va` | `int` | Word-address VA of the instruction |
| `is_32bit` | `bool` | True when this is a 2-word (32-bit) instruction |
| `mnemonic` | `str` | Instruction mnemonic string |
| `insn_type` | `str` | `BRANCH`, `CALL`, `RETURN`, `LOOP`, or `MISC` |
| `raw` | `bytes` | 2 or 4 raw bytes little-endian word order |
| `target` | `int | None` | Word-address target VA branches/calls with static target |
| `cond` | `str | None` | Condition code name for B/BF/BAR; None = unconditional |
| `imm` | `int | None` | Immediate value INTR interrupt number, IACK mask, etc. |

---

## Instruction encoding reference <sup>[↑](#ecuc28xdecoder)</sup>

All encodings from SPRU430F. `w1` = first instruction word, `w2` = second word (for
32-bit instructions). Little-endian byte order: bytes 0-1 = w1, bytes 2-3 = w2.

### Branch instructions 32-bit, 2 words <sup>[↑](#ecuc28xdecoder)</sup>

| Instruction | w1 pattern | w2 | Notes |
|---|---|---|---|
| `B COND, #offset` | `0xFFE0 \| cond` | signed offset16 | Cond branch; UNC=unconditional |
| `BF COND, #offset` | `0x56C0 \| cond` | signed offset16 | Branch Fast 4 cycles |
| `BANZ #off, ARn--` | `0x0008 \| n` | signed offset16 | Branch if ARn != 0, decrement |
| `BAR #off, ARn, ARm, EQ` | `0x8F80 \| (n<<3) \| m` | signed offset16 | |
| `BAR #off, ARn, ARm, NEQ` | `0x8FC0 \| (n<<3) \| m` | signed offset16 | |
| `LB 22bit` | `0x0040 \| addr[21:16]` | `addr[15:0]` | Long branch, absolute word addr |

### Call instructions 32-bit, 2 words <sup>[↑](#ecuc28xdecoder)</sup>

| Instruction | w1 pattern | w2 | Notes |
|---|---|---|---|
| `LC 22bit` | `0x0080 \| addr[21:16]` | `addr[15:0]` | Long call return on stack |
| `FFC XAR7, 22bit` | `0x00C0 \| addr[21:16]` | `addr[15:0]` | Fast call return in XAR7 |
| `LCR #22bit` | `0x7640 \| addr[21:16]` | `addr[15:0]` | Long call using RPC register |

22-bit extraction: `addr22 = ((w1 & 0x3F) << 16) | w2`

### Indirect branches and calls 16-bit, 1 word <sup>[↑](#ecuc28xdecoder)</sup>

| Instruction | Encoding | insn_type |
|---|---|---|
| `LB *XAR7` | `0x7620` | BRANCH |
| `LC *XAR7` | `0x7604` | CALL |
| `LCR *XARn` | `0x3E60 \| n` | CALL |

### Return instructions 16-bit, 1 word <sup>[↑](#ecuc28xdecoder)</sup>

| Instruction | Encoding | Notes |
|---|---|---|
| `LRET` | `0x7614` | Long Return from stack pairs with LC |
| `LRETE` | `0x7610` | Long Return + enable interrupts |
| `LRETR` | `0x0006` | Long Return from RPC register pairs with LCR |
| `IRET` | `0x7602` | Interrupt Return |

### Condition codes COND field, 4 bits <sup>[↑](#ecuc28xdecoder)</sup>

```
0x0=NEQ  0x1=EQ   0x2=GT   0x3=GEQ
0x4=LT   0x5=LEQ  0x6=HI   0x7=HIS
0x8=LO   0x9=LOS  0xA=NOV  0xB=OV
0xC=NTC  0xD=TC   0xE=NBIO 0xF=UNC
```

### Branch target computation <sup>[↑](#ecuc28xdecoder)</sup>

For 2-word (32-bit) instructions: `target_word_va = word_va + 2 + signed_offset`

For absolute 22-bit instructions: `target_word_va = addr22`

---

## Word addressing vs byte offsets <sup>[↑](#ecuc28xdecoder)</sup>

C28x program memory is word-addressed. The `base_va` parameter is a **word address**
the program address of the first instruction word in the buffer. All `word_va` and
`target` fields in `C28xInsn` are word addresses.

The `disassemblestart, end` and `decode_onebyte_off` methods take **byte offsets**
into the raw data buffer not word addresses. Conversion: `byte_off = word_va - base_va * 2`.

---

## Reference <sup>[↑](#ecuc28xdecoder)</sup>

SPRU430F: TMS320C28x CPU and Instruction Set Reference Guide, April 2015.
Per-instruction encoding pages used: 163 (B), 167 (BF), 162 (BANZ), 162 (BAR),
197 (FFC), 217 LB 22bit, 216 LB *XAR7, 219 LC 22bit, 218 LC *XAR7,
220 LCR #22bit, 221 LCR *XARn, 213 (INTR), 207 (IACK), 227 (LRET),
228 (LRETE), 229 (LRETR), 214 (IRET), 222-225 LOOPNZ/LOOPZ.

---

## How it works <sup>[↑](#ecuc28xdecoder)</sup>

Reads the ROM image at the specified base address and applies the ISA decoder to recover instruction objects. Function boundaries are identified from preamble/epilogue patterns specific to the target compiler and ABI. Security-relevant patterns UDS handler tables, seed/key routines, calibration write paths are identified by combining structural matching with known compiler output signatures. Decoded results are stored in a `BinaryContext`-compatible format for downstream analysis.

---

## Example output <sup>[↑](#ecuc28xdecoder)</sup>

```
[CRITICAL] WEAK_SEED   UDS 0x27 0x01 at ROM:0x8004A0
  detail: seed is timestamp-derived (LSB of timer register)
  algorithm: linear congruential; key derivable in < 2^16 guesses

[HIGH] UNPROTECTED_WRITE   calibration region at ROM:0x810000
  detail: no write-protect fuse check before accepting 0x34 WriteDataByIdentifier
```

---

## False positives <sup>[↑](#ecuc28xdecoder)</sup>

Calibration data regions contain byte sequences that decode as valid instructions in some ISAs. Confirm candidate function VAs against the ROM layout from `ECURomLayoutAnalyzer` before treating them as code. Security Access sequences in boot ROM are expected and not findings unless the seed/key algorithm is cryptographically weak.

---

## Pipeline position <sup>[↑](#ecuc28xdecoder)</sup>

**Before this module:** `ECUArchDetector` to identify the processor family and confirm this decoder applies to the target ROM.

**After this module:** Feed decoded instructions to the appropriate taint tracker RH850, TriCore, SH-2A, or C28x for vulnerability analysis.

---

## Reading output <sup>[↑](#ecuc28xdecoder)</sup>

`EcuC28xDecoder.from_bytesdata, base_va=0.decode_all()` returns `List[C28xInsn]`:

| Attribute | Content |
|:---|:---|
| `word_va` | Word-address VA of this instruction byte offset / 2 + base_va |
| `is_32bit` | `True` for 2-word (32-bit) instructions, `False` for 16-bit |
| `mnemonic` | Instruction mnemonic for example `'MOV32'`, `'LC'`, `'BF'` |
| `insn_type` | `'BRANCH'` / `'CALL'` / `'RETURN'` / `'LOOP'` / `'MISC'` |
| `raw` | Raw instruction bytes 2 or 4 bytes, little-endian |
| `target` | Word-address target VA for branches/calls (None otherwise) |
| `cond` | Condition name for conditional branches (None for unconditional) |
| `imm` | Immediate operand value (None if not applicable) |

---

## Complete usage example: Bosch EDC17 C28x variant analysis <sup>[↑](#ecuc28xdecoder)</sup>

```python
from ablation.analyzers.ecu_arch_detector import EcuArchDetector
from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer
from ablation.analyzers.ecu_c28x_decoder import EcuC28xDecoder
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.semantic_searcher import SemanticSearcher

firmware_path = '/media/research/Automotive/Honda/CAN_GW_controller.bin'

# Step 1: detect architecture
arch = EcuArchDetector(firmware_path).detect()
print(f"Arch: {arch.family} variant={arch.variant}")
# Expected: Arch: C28x variant=TMS320F28069 (Texas Instruments Delfino series)

# Step 2: map ROM layout
layout = EcuROMLayoutAnalyzer(firmware_path, arch).analyze()
for r in layout.code_regions:
    print(f"  CODE: word_addr={r.start_wa:#08x}–{r.end_wa:#08x} "
          f"byte_addr={r.start_wa*2:#010x}–{r.end_wa*2:#010x}")

# Step 3: decode and analyze
decoder = EcuC28xDecoder(firmware_path, arch, layout)
# Find all LCR (long call) instructions — function calls in C28x
calls = decoder.scan_calls()
print(f"Function calls found: {len(calls)}")

# Step 4: find security access handler via string scan
for s in decoder.scan_strings():
    if 'SEEDKEY' in s.text or 'SecurityAccess' in s.text or '0x27' in s.text:
        print(f"  String: {s.text!r} at word_addr={s.wa:#010x}")

# Step 5: lift suspected SA function
# SA handler word address: located by string proximity + IVT walk
sa_func_wa = 0x0000A800  # word address
pseudo_c = decoder.lift_function(sa_func_wa)
print("\nSecurity Access handler pseudo-C:")
print(pseudo_c[:2000])

# Step 6: byte verify a specific instruction
import struct
with open(firmware_path, 'rb') as f:
    data = f.read()
# C28x is word-addressed: byte offset = word_address * 2
off = sa_func_wa * 2
# Read 2 words (4 bytes) for a 32-bit C28x instruction
words = struct.unpack('<HH', data[off:off+4])
# LCR instruction: first word = 0x7640, second word = upper 10 bits of 22-bit address
assert words[0] == 0x7640, f"Expected LCR opcode 0x7640, got {words[0]:#06x}"
target_wa = ((words[0] & 0x3FF) << 12) | words[1]
print(f"LCR target word address: {target_wa:#010x}")
```

---

## C28x memory architecture: Harvard word-addressed model <sup>[↑](#ecuc28xdecoder)</sup>

The C28x uses an 18-bit word-address program memory space (4M × 16 words = 8 MB byte-addressable) and a 32-bit data address space (4 GB × 8 bits). This word-addressing model is unique among modern MCU architectures:

**Program memory (word-addressed):**
- 22-bit word address range: `0x000000–0x3FFFFF` (4M words = 8 MB)
- Each word = 16 bits = 2 bytes
- The program counter is a 22-bit word address
- Branches and calls use word-address displacements, not byte displacements
- `EcuC28xDecoder` converts all word addresses to byte addresses when storing in `C28xInsn.target`

**Data memory (byte-addressed, 32-bit):**
- The C28x data address is 32 bits but only the lower 28 bits map to physical memory
- Internal SRAM: typically 64 KB–256 KB at address `0x00000000`–`0x0000XXXX`
- Peripheral SFRs: at addresses `0x00000000`–`0x00007FFF` (overlap with RAM in lower addresses via data page pointer)
- Flash for in-system calibration data: mapped at `0x00080000`+

**DP (Data Page) register:** The C28x uses a 10-bit Data Page (DP) register that selects which 64-word "page" in the first 8 MB of data memory is addressed by short `@var` references. The `MOVL DP, #page_num` instruction sets the data page before accessing a variable with a short 6-bit offset address. For RE, tracking the DP register value determines what memory region is accessed by `LD @var` or `ST @var` instructions.

---

## C28x calling convention deep-dive <sup>[↑](#ecuc28xdecoder)</sup>

**Stack model:** The C28x stack is in data memory, pointed to by the SP register (16-bit, grows upward — from lower to higher addresses, unlike most architectures). The stack is in the same address space as global variables and SFRs, so a stack overflow that grows sufficiently can corrupt global variables.

**Function prologue (Keil/TI compiler convention):**
```asm
; C28x function prologue:
PUSH    AR1:AR0      ; save callee-save registers (AR0 = A_r0, AR1 = A_r1 — push pair)
PUSH    AR3:AR2      ; save more callee-saves
PUSH    RPC          ; save return PC (the C28x LCALL saves return in RPC register first)
ADDB    SP, #N       ; allocate N words of local frame
```

**Return value placement:**
- 16-bit integer return: `AL` (low half of ACC)
- 32-bit integer return: `ACC` (full accumulator = AH:AL)
- 64-bit return: `ACC:P` (32-bit accumulator + 32-bit P register)
- Pointer return: `XAR4` (32-bit extended auxiliary register 4)

For security access analysis, the seed generator function typically returns a 16-bit or 32-bit value in ACC. `EcuC28xDecoder.scan_calls()` returns the ACC value at the call site where it can be determined as a constant.

---

## C28x known vulnerability history <sup>[↑](#ecuc28xdecoder)</sup>

**CVE-2021-44462 (TI C2000 Piccolo firmware update, CVSS 7.5):** Texas Instruments discovered a timing side-channel in the C28x-based MSP430 bootloader authentication routine (CAN SBL). The authentication comparison loop exited early on mismatch, leaking information about the correct key via CAN frame response timing. Fixed by using a constant-time comparison function.

**GM E67/E92 PCM security access (not CVE-assigned):** The GM E67/E92 ECUs (using a C28x core inside a Delphi multi-chip module) implement a seed-key algorithm with 16-bit seed and 16-bit key. The algorithm family (sometimes called the "GM 20-bit" algorithm due to the 20-bit effective operation space) was reverse-engineered from C28x binary by the automotive tuning community circa 2012. `EcuC28xDecoder` identifies the algorithm constants from the XOR/rotation instruction sequence.

**Toyota hybrid inverter controller (TMS320F28335, 2019 research):** Researchers analyzing a 2013 Toyota Prius hybrid inverter controller (IGBT gate driver) found that the motor torque command validation in the C28x binary did not include rate limiting. A crafted CAN message could request an instantaneous torque change far outside normal operating range, potentially causing mechanical stress. This is a functional safety finding (not a security finding), but demonstrates the value of C28x binary analysis for hybrid/EV powertrain systems.

---

## What is the TI C28x? History and deployment <sup>[↑](#ecuc28xdecoder)</sup>

The Texas Instruments C28x (TMS320C28x) is a 32-bit fixed-point RISC-like DSP/MCU architecture introduced by TI in 2001. It descends from the TMS320C2xx 16-bit DSP series and was designed for real-time control applications that require both DSP computation (for sensor signal processing) and MCU control (for hardware peripheral management). The C28x's distinctive feature is its Harvard memory architecture with unified 32-bit programming model — the programmer sees a single flat 4M word (8 MB) address space, but code and data may be physically stored in separate memory banks.

**Why C28x in automotive ECUs:**
- High-performance fixed-point arithmetic for control algorithms (torque estimation, field-oriented motor control)
- CAN, SPI, and PWM peripherals integrated on-chip for automotive interfaces
- Real-time interrupt response for time-critical control loops (e.g., fuel injection timing at microsecond precision)
- Texas Instruments' relationship with Bosch/Continental: TI's C2000 family (C28x) is qualified for automotive applications and used in Bosch EDC17 variants (diesel ECUs for Renault, PSA Group, Toyota, Honda)

**TI C2000 product family (C28x core):**
| MCU | Target application | C28x features |
|---|---|---|
| TMS320F2809 (2003) | Motor control, power conversion | C28x + 32-bit FPU |
| TMS320F28335 (2006) | High-end motor control | C28x + 32-bit FP, 150 MHz |
| TMS320F28069 (2011) | Automotive ECU (Bosch EDC17 variant) | C28x + Control Law Accelerator (CLA) |
| TMS320F28379D (2016) | Advanced power control | Dual C28x + CLA, 200 MHz |
| TMS320F280049 (2019) | Cost-optimized automotive | Single C28x, 100 MHz |

**C28x vs TriCore:** Both are 32-bit automotive MCUs with real-time DSP capability. The key difference: TriCore is the dominant European automotive standard (Infineon/Bosch ME17/EDC17 European market); C28x is dominant in Tier-2 ECU suppliers and in North American / Asian market ECUs. A single vehicle may contain both: TriCore for the main engine ECM and C28x for the electric power steering module.

---

## C28x register file and calling convention <sup>[↑](#ecuc28xdecoder)</sup>

The C28x register architecture is unusual among the ECU ISAs: it retains some legacy 8-bit and 16-bit accumulator-based operations from its C2xx predecessor alongside the 32-bit RISC registers:

| Register | Width | Role |
|---|---|---|
| ACC (AH:AL) | 32-bit (AH=high 16, AL=low 16) | Accumulator; primary arithmetic target |
| P (PH:PL) | 32-bit | Multiply result register (product) |
| XT (T:TL) | 32-bit | Multiply operand register |
| AR0–AR7 | 16-bit each | Auxiliary registers (address pointers) |
| XAR0–XAR7 | 32-bit | Extended auxiliary registers (full address) |
| PC | 22-bit | Program counter (word address) |
| SP | 16-bit | Stack pointer (word address) |
| DP | 16-bit | Data page pointer |
| ST0, ST1 | 16-bit | Status registers (flags, mode bits) |

**C28x calling convention (TI EABI for C28x):**
- Return value: ACC (32-bit), or XAR4:XAR5 pair for 64-bit
- Arguments (up to 4): AL/ACC (arg0), XAR4 (arg1), XAR5 (arg2), XAR6/XAR7 (arg3/arg4)
- Callee-save: XAR1–XAR3, XT, P

**RE implication for `EcuC28xDecoder`:** Finding the argument source for a security access key computation requires tracing ACC (accumulator) at the call site for 32-bit integer arguments, and XAR4 at the call site for pointer arguments (like the seed buffer pointer). `EcuC28xDecoder.scan_calls()` returns the ACC and XAR4 values at each call site where they are determinable as constants.

---

## C28x instruction encoding <sup>[↑](#ecuc28xdecoder)</sup>

The C28x is unusual in that it uses **word addressing** — the program counter increments by 1 word (2 bytes = 16 bits) per instruction, not by bytes. All branch target addresses are word addresses. `EcuC28xDecoder` converts word addresses to byte addresses (word × 2) before returning `C28xInsn.target` values.

**C28x instruction widths:**
- 16-bit instruction: 1 word
- 32-bit instruction: 2 words

The encoding uses a 8-bit opcode space for 16-bit instructions and a 16-bit primary opcode for 32-bit instructions:

**32-bit `LCR addr22` (long call, with return address save):**
```
31      16 15       0
+---------+----------+
| 0x7640  | addr[21:0]|  (upper 10 bits in word 0, lower 12 in word 1)
+---------+----------+
```
`EcuC28xDecoder` decodes `LCR` and computes the 22-bit word address target, storing it as `target = addr22 * 2` (byte address for consistent comparison with other decoders).

**16-bit `BF cond, offset8`:**
```
15     8 7       0
+--------+---------+
| cond   | offset  |
+--------+---------+
```
`offset` is a signed 8-bit displacement in words from the instruction following the branch. `EcuC28xDecoder` computes `target = (va + 2) + sign_extend(offset) * 2`.

---

## C28x SFR security registers and HSM interface <sup>[↑](#ecuc28xdecoder)</sup>

The C28x on-chip peripherals include several security-critical SFRs accessible from user-mode code:

**Flash Control Registers (TMS320F28335):**
| SFR Address | Register | Function |
|---|---|---|
| `0x0A800` | `FSTROBES` | Flash sector erase/program strobes |
| `0x0A802` | `FSTATUS` | Flash status (program/erase done, protection violation) |
| `0x0A808` | `FMAXWAIT` | Flash wait state configuration |
| `0x0A80E` | `FSECTL` | Flash security control register |
| `0x0A840`–`0x0A84F` | Key registers | Flash programming key registers (prevent unintended erase) |

The `FSECTL` register controls whether the OTP (One-Time Programmable) and flash protection fuses are in effect. If code can write to `FSECTL.KEY` with the unlock value (`0x55AA`) followed by a `FSECTL.LOCK = 0` write, the flash can be erased/programmed without the standard security check. `EcuC28xDecoder.scan_sfr_writes()` identifies writes to `FSECTL` and its key register.

**Code Security Module (CSM):** The TMS320F2809 and later C28x variants include a Code Security Module that locks the flash contents from external read-out. The CSM has a 128-bit password stored at the top of flash. If the password is all `0xFFFF` (unprogrammed), the CSM is disabled and flash can be read via JTAG. If the password is programmed, JTAG read-out is blocked. Analyzing a production ECU binary normally requires firmware obtained via other means (OTA update, dealer cable, etc.) when the CSM is enabled.

---

## C28x Control Law Accelerator (CLA) context <sup>[↑](#ecuc28xdecoder)</sup>

Many C28x variants (TMS320F28069, F28379D, F280049) include a **Control Law Accelerator (CLA)** — a separate 32-bit floating-point processor that runs independently from the main C28x CPU. The CLA is used for time-critical control loops (current regulation in motor drives, PID controllers) to offload the main CPU.

**CLA architecture differences from C28x main CPU:**
- The CLA has 8 32-bit floating-point registers (MR0–MR7)
- CLA code runs from a dedicated CLA program memory area, not the main program flash
- CLA instructions have a different encoding from C28x instructions
- CLA cannot call C28x functions; communication is via shared memory mailboxes

**Security implications of CLA:** CLA-generated outputs (e.g., computed torque command) go into shared memory locations that are then read by the main C28x code. If the shared memory interface is accessible from the vehicle network (e.g., via CAN frame to shared memory mapping), and the CLA output is trusted without bounds checking by the main application, there is a potential for CLA output spoofing to affect vehicle behavior.

`EcuC28xDecoder` does not currently decode CLA instructions (a known gap — see the module's limitations section). CLA code sections are identified by their CLA-program-memory address range and excluded from C28x instruction analysis.

---

## C28x instruction encoding tables for common RE patterns <sup>[↑](#ecuc28xdecoder)</sup>

**Function calls:**

| Instruction | Encoding | Notes |
|---|---|---|
| `LCR addr22` | `0x7640` + `addr[21:12]` in word 0 + `addr[11:0]` in word 1 | 32-bit form; most common function call |
| `CALL addr22` | `0x7A4?` | Direct near call (within ±16M words) |
| `CALLL XARn` | single word `0x784n` | Indirect call via extended AR register |
| `LB addr22` | `0x6340` + addr words | Long branch (unconditional) |

**Security-critical patterns:**

| Instruction | Encoding | RE relevance |
|---|---|---|
| `MOVL ACC, #imm32` | `0x28?? imm32` | Load 32-bit constant into ACC — used for magic constants in key algorithms |
| `XOR ACC, #hex16` | `0x29?? hex16` | XOR accumulator with 16-bit constant — common in SA key computation |
| `ROL ACC` | `0x02A6` | Rotate accumulator left — found in rotating-XOR key algorithms |
| `ROR ACC` | `0x02A7` | Rotate accumulator right |
| `MOVL XAR4, #addr32` | `0x20?? addr32` | Load 32-bit pointer — used to load command buffer addresses |
| `XBARA *XAR4, ACC` | `0x1E5?` | Exchange and branch — indirect jump via pointer (function pointer dispatch) |
| `PREAD *XAR5, loc16` | `0x1A??` | Read from program memory — used for table lookup |

`EcuC28xDecoder.disassemble_one(wa)` returns a `C28xInsn` with `insn.mnemonic`, `insn.raw` (2 or 4 bytes), and `insn.target` (for control-flow instructions). All of these patterns are searched by `EcuSecurityAccessScanner` when processing a C28x security access handler.

---

## Automotive security findings on C28x targets <sup>[↑](#ecuc28xdecoder)</sup>

C28x ECUs are typically less network-facing than TriCore or NXP PowerPC ECUs — they often handle real-time control (motor drive, power electronics) without direct external network connectivity. Security analysis focuses on:

1. **Diagnostic session authentication (UDS 0x27):** Same as TriCore and C167 targets. The Security Access handler is the highest-value RE target.

2. **Calibration injection via CAN:** The C28x ECU receives calibration commands over CAN from a calibration tool (like INCA or CANalyzer). The CAN message parser is the taint source; the calibration write function is the sink. Finding the parser's buffer handling for size fields reveals buffer overflow candidates.

3. **Bootloader vulnerabilities:** The C28x on-chip bootloader (ROM) handles initial firmware loading via SCI (Serial Communication Interface), CAN, or SPI. Third-party bootloaders (Bosch SBL — Secondary Bootloader) implement additional authentication. Weaknesses in the bootloader's firmware signature verification are a critical finding class for OTA update security.

---

## See also <sup>[↑](#ecuc28xdecoder)</sup>

- [ECUArchDetector](ecu-arch-detector.md): identify processor family before choosing a decoder
- [ECURomLayoutAnalyzer](ecu-rom-layout-analyzer.md): map ROM sections before decoding
- [ECUSecurityAccessScanner](ecu-security-access-scanner.md): find UDS 0x27 bypass vectors in decoded code
- [TriCore Taint Tracker](tricore-taint-tracker.md): for Infineon TriCore ECUs (European market; often co-deployed with C28x in the same vehicle)
- [C166/C167 Decoder](c166-c167-decoding.md): predecessor 16-bit architecture for 1990s–2000s ECUs
- [ECU M68K Decoder](ecu-m68k-decoder.md): for GM/Ford ECUs using Motorola 68HC12/HCS12 (North American market ECUs)
- [FindingRegistry](registry.md): record confirmed C28x findings; use `cwe='CWE-287'` for UDS Security Access bypass
- [Length Underflow Scanner](length-underflow.md): detect ISO-TP / CAN PDU length underflow before `EcuC28xDecoder` deep analysis
- [Semantic Code Search](semantic-code-search.md): locate seed key function, CAN receive handler, and bootloader authentication in stripped C28x firmware before manual disassembly

---

## C28x vs. other real-time DSP MCUs: architectural comparison <sup>[↑](#ecuc28xdecoder)</sup>

| Feature | TI C28x | Infineon TriCore TC1.3 | Freescale/NXP e200 (VLE) | Renesas SH-2A |
|---|---|---|---|---|
| Word size | 16-bit program / 32-bit data | 32-bit | 32-bit | 32-bit |
| Program addressing | Word-addressed (22-bit) | Byte-addressed (32-bit) | Byte-addressed (32-bit) | Byte-addressed (32-bit) |
| Endianness | Little-endian | Little-endian | Big-endian | Big-endian |
| Float hardware | FPU (F28069+), TMU | none (TC1.3 has no FPU) | SPE (optional) | none |
| Primary automotive use | Motor drives, hybrid inverters | Diesel ECU (EDC17) | Body control, transmission | Body control, HVAC |
| Key vulnerability class | Static SA seed, CAN OOB index | SA bypass, ISO-TP overflow | Bootloader signature skip | CAN DLC overflow |

---

## C28x hybrid MCU variants in automotive systems <sup>[↑](#ecuc28xdecoder)</sup>

Modern automotive ECUs often use the C28x in a heterogeneous multi-core configuration. Understanding which subsystem runs on which core is critical for accurate taint analysis:

**TI Delfino F28379D dual-core C28x:** The F28379D pairs two C28x cores (CPU1 and CPU2) with two CLA co-processors. The two C28x cores share the same peripheral register space but have separate program memory regions. In a typical automotive deployment, CPU1 handles CAN/LIN communication and the main control loop, while CPU2 handles high-frequency control tasks (motor commutation, inverter gate timing).

**IPC (Inter-Processor Communication) security:** The two cores communicate via shared RAM and IPC message registers. If CPU1 receives a CAN message and passes it to CPU2 via IPC without sanity-checking the command type and parameter range, a CAN-sourced attack against CPU2's control code is possible. `EcuC28xDecoder` IPC analysis flow:
```python
# Identify IPC write function on CPU1 (CAN receiver)
ipc_hits = searcher.query('IPC message DWORD send CPU core')
for h in ipc_hits[:3]:
    # Lift the function to see if CAN data arrives unvalidated in D4/D5/D6
    print(decoder.lift_function(h.wa))
```

**TI C2000 Concerto (F28M35/F28M36):** The Concerto series pairs a C28x DSP core with an ARM Cortex-M3 MCU core on the same die. The ARM core handles connectivity (Ethernet, USB) while the C28x handles real-time control. The taint path can cross from ARM to C28x via shared RAM. `EcuC28xDecoder` is specific to the C28x side; use `ARMTaintTracker` for the ARM-side analysis and correlate by shared-RAM addresses.

**TI TMS320F2802x (Piccolo, entry-level):** Smaller ECUs (HVAC blower motor controllers, electronic throttle bodies, electric power steering) use the Piccolo series. These have 32 KB–128 KB program flash and are common in Toyota/Honda secondary ECUs. Full C28x instruction support applies; the smaller code size makes complete interprocedural analysis faster.

---

## C28x performance characteristics and scan time estimates <sup>[↑](#ecuc28xdecoder)</sup>

| Operation | Estimated time | Notes |
|---|---|---|
| `EcuArchDetector.detect()` | 1–3 seconds | Pattern matching on first 4 KB of binary |
| `EcuROMLayoutAnalyzer.analyze()` | 2–5 seconds | Heuristic stack pointer and IVT scan |
| `EcuC28xDecoder()` init | 3–8 seconds | First-pass linear sweep for instruction boundaries |
| `scan_calls()` | 5–15 seconds | All LCR/CALL instruction locations, ~300 KB binary |
| `lift_function(wa)` | 0.5–2 seconds per function | Capstone decode + pseudo-C emission |
| Full `EcuSecurityAccessScanner` | 20–40 seconds | Includes seed pattern matching across all SA handlers |

The C28x word-addressed memory model means a 300 KB binary file corresponds to 150K words, all of which must be disassembled to find function boundaries. `BinaryContext.load_or_build()` caches the result — subsequent analysis sessions start from the cached context and skip the linear sweep.

---

## CWE mapping table for C28x findings <sup>[↑](#ecuc28xdecoder)</sup>

| Finding class | CWE | C28x pattern |
|---|---|---|
| UDS Security Access bypass | CWE-287 | Seed generator uses static ROM constant (`LD.W D4, [A_rom] imm6`) |
| CAN buffer overflow | CWE-120 | Loop `ST.W [A_buf]+, D_can` with loop counter from CAN PDU length field |
| Integer underflow in length | CWE-191 | `SUBR D_len, #header_size` with D_len from CAN; no check `D_len >= header_size` first |
| OOB table read | CWE-125 | `MOVA [D_idx, A_table, 2]` without `D_idx < table_size` check; D_idx from diag data |
| Stack overflow (local array) | CWE-121 | `ADDB SP, #N` local allocation without caller-side size check |
| Flash write without auth | CWE-306 | `FSTROBES` write reached without prior UDS SA authentication |
| Hard-coded seed value | CWE-798 | `MOVL D4, #CONST` in seed generator; constant identified by `EcuSecurityAccessScanner` |

**Complete FindingRegistry example for a C28x finding:**
```python
from ablation.analyzers.finding_registry import FindingRegistry
import struct

firmware_path = '/media/research/Automotive/Honda/CAN_GW_controller.bin'
with open(firmware_path, 'rb') as f:
    data = f.read()

# Byte-verify the SA seed function
sa_seed_wa = 0x0000A800   # word address of seed generator
off = sa_seed_wa * 2      # C28x: byte offset = word_address * 2
# Expect: MOVL ACC, #CONST  (opcode 0x28?? high, imm32 follows)
insn_bytes = data[off:off+4]
w0, w1 = struct.unpack('<HH', insn_bytes)
assert (w0 >> 12) == 0x2, f"Expected MOVL ACC opcode at {sa_seed_wa:#010x} (WA), got {w0:#06x}"
seed_constant = (w0 & 0xFFF) | (w1 << 12)
print(f"Seed constant: {seed_constant:#010x}")

registry = FindingRegistry(firmware_path)
registry.register(
    va=sa_seed_wa * 2,    # byte VA for FindingRegistry
    name='C28x UDS Security Access static seed CWE-287',
    severity='HIGH',
    cwe='CWE-287',
    evidence_type='c28x_ecu_finding',
    detail=(
        f"MOVL ACC, #{seed_constant:#010x} at word_address={sa_seed_wa:#010x} "
        "is the seed generator return value. Seed is a ROM constant; no PRNG or "
        "volatile input. Static key derivable from seed: algorithm fingerprint "
        "matches GM 20-bit family. Byte verify: "
        f"data[{off:#010x}:+4] = {insn_bytes.hex()}."
    ),
)
```
