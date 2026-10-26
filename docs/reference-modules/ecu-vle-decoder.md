# EcuVLEDecoder

**File:** `ablation/analyzers/ecu_vle_decoder.py`

---

## What this is <sup>[↑](#ecuvledecoder)</sup>

VLE Variable Length Encoding is a PowerPC instruction set extension that NXP added to the e200z4, e200z6, and e200z7 cores found in automotive ECUs. It lets compilers mix 16-bit and 32-bit instructions in the same binary so firmware fits in smaller flash. Flash is a hard cost constraint on every ECU, so NXP e200 cores use VLE by default in production firmware.

Standard Capstone decodes PowerPC Book E but not VLE. Pointing Capstone at a VLE region produces plausible-looking garbage because 16-bit VLE halfwords satisfy Book E opcode patterns by coincidence. There is no error. The disassembly is just wrong.

`EcuVLEDecoder` is a pure-Python VLE decoder that handles both 16-bit SE Short Encoding and 32-bit VLE instructions, identifies function entry points from VLE prologues, and tells the taint tracker whether a code region is VLE or Book E before analysis begins.

---

## Where it's used <sup>[↑](#ecuvledecoder)</sup>

- **GM E39a PCM** NXP MPC5566, e200z6 core: VLE regions at `0x2A000` and `0x034000`
- **GM E54 and E92 ECUs**: factory firmware compiled for NXP e200z cores
- Any **NXP MPC55xx family** target where `EcuArchDetector` identifies a PPC32 VLE core
- The `EcuROMLayoutAnalyzer` integration pipeline: called automatically when a CODE region scores above the VLE probe threshold

---

## Pipeline <sup>[↑](#ecuvledecoder)</sup>

```mermaid
flowchart TD
    A(["Raw ECU ROM (.bin)"]):::input --> B["EcuROMLayoutAnalyzer\nidentifies CODE regions"]:::primary
    B:::primary --> C{"VLE probe\n(byte0 & 0x90) == 0x10\non first 64 instructions"}:::neutral
    C:::neutral -->|"SE count > 33%\nof probe = VLE"| D["EcuVLEDecoder\n16-bit SE + 32-bit VLE"]:::secondary
    C:::neutral -->|"No SE instructions\n= Book E"| E["Capstone PPC32\nBook E decoder"]:::tertiary
    D:::secondary --> F["function_starts()\ne_stwu r1, -N(r1) prologue scan\nse_mflr r0 leaf scan"]:::tertiary
    E:::tertiary --> G["function_starts()\nstwu r1, -N(r1) prologue scan"]:::tertiary
    F:::tertiary --> H["PPC32TaintTracker\n(seeded with VLE function starts)"]:::tertiary
    G:::tertiary --> H:::tertiary
    H:::tertiary --> I(["TaintFinding\nsink · source · chain"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#546e7a,stroke-width:2px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#6a1b9a,stroke-width:2px
    linkStyle 7 stroke:#6a1b9a,stroke-width:2px
    linkStyle 8 stroke:#2e7d32,stroke-width:3px
```

Without `EcuVLEDecoder`, the function-start scan on a VLE binary returns empty because Capstone produces garbage. An empty function-start list means the taint tracker runs zero interprocedural passes and produces zero findings, with no indication why.

---

## Why this exists <sup>[↑](#ecuvledecoder)</sup>

Three things were not possible before in Ablation:

**1. No PPC VLE instruction decoder.** Capstone 5.0.7 decodes standard PowerPC Book E (PPC32) but
does not implement the Variable Length Encoding (VLE) extension used by NXP e200z4/z6/z7 cores.
The GM E39a PCM MPC5566 e200z6 and GM E54/E92 ECUs use VLE in their factory firmware. Applying
`disasm_engine.py` with `CS_ARCH_PPC` / `CS_MODE_32` against a VLE region produces either garbage
or zero results depending on whether the first byte happens to satisfy PPC32 opcode heuristics.
Before this module, there was no way to disassemble these binaries at all inside Ablation.

**2. No function_starts() for VLE firmware.** The existing `ppc32-taint-tracker.py` pipeline seeds
its taint engine from a function-start list. For PPC32 Book E firmware, that list comes from ELF
symbol tables or a Book E prologue scanner `stwu r1, -N(r1` at 4-byte-aligned offsets). For VLE
firmware, neither applies: there are no symbols, and the prologue instruction is `e_stwu r1, -N(r1)`
VLE opcode 6, VUP field 6, which encodes differently from the Book E `stwu`. Before this module,
the taint tracker had no way to seed itself against VLE firmware.

**3. No VLE / Book E region discriminator.** The two instruction sets can coexist in the same ROM
image. The GM E39a binary has standard PPC32 Book E code at `0x8A000` and VLE-pattern regions
at `0x2A000` and `0x034000`. After `EcuROMLayoutAnalyzer` classifies a region as CODE, there was
no way to determine whether it should be passed to Capstone or to `EcuVLEDecoder`. The length
discrimination rule `(byte0 & 0x90) == 0x10` → 32-bit VLE provides a per-instruction probe that
can settle the question by scanning the first N instructions: a VLE stream produces a mix of
`is_16bit=True` and `is_16bit=False`; a Book E stream produces no `is_16bit=True` results.

---

## VLE length discrimination <sup>[↑](#ecuvledecoder)</sup>

VLE instructions are either 16-bit SE Short Encoding or 32-bit, identified by the first byte:

```
(byte0 & 0x90) == 0x10  →  32-bit VLE or Book E instruction
otherwise               →  16-bit SE instruction
```

This rule holds because NXP assigned the 32-bit VLE opcodes 6, 7, 12–15, 20–22, 28, 30 to slots
where bits [7] and [4] of the first byte are always 0 and 1 respectively. All SE instruction
encodings occupy the remaining byte space where `(b & 0x90) != 0x10`. The constraint is an
intentional encoding property of the e200 VLE ISA, not a heuristic.

---

## Instruction coverage <sup>[↑](#ecuvledecoder)</sup>

### 16-bit SE instructions decoded <sup>[↑](#ecuvledecoder)</sup>

| Instruction | Encoding | Type |
|---|---|---|
| `se_blr` | `0x0004` | RETURN |
| `se_blrl` | `0x0005` | RETURN |
| `se_bctr` | `0x0006` | BRANCH |
| `se_bctrl` | `0x0007` | CALL |
| `se_rfi` | `0x0008` | MISC |
| `se_not rX` | `0x0020 \| rX` (mask `0xFFF0`) | MISC |
| `se_neg rX` | `0x0030 \| rX` (mask `0xFFF0`) | MISC |
| `se_mflr rX` | `0x0080 \| rX` (mask `0xFFF0`) | LR_SAVE |
| `se_mtlr rX` | `0x0090 \| rX` (mask `0xFFF0`) | LR_RESTORE |
| `se_mfctr rX` | `0x00A0 \| rX` | MISC |
| `se_mtctr rX` | `0x00B0 \| rX` | MISC |
| `se_extzb/extsb/extzh/extsh rX` | SE_R form | MISC |
| `se_add rX, rY` | `0x0400` (mask `0xFF00`) | MISC |
| `se_mullw/sub/subf/cmp/cmpl rX, rY` | SE_RR form | MISC |
| `se_srw/sraw/slw/or/andc/and rX, rY` | SE_RR form | MISC |
| `se_addi rX, OIMM5` | SE_IM5 form | MISC |
| `se_cmpli/subi/srwi/slwi rX, UI5` | SE_IM5 form | MISC |
| `se_li rX, UI7` | IM7 form | MISC |
| `se_lbz/stb/lhz/sth/lwz/stw rZ, SD4(rX)` | SD4 form | LOAD / STORE |
| `se_bc BO16, BI16, BD8` | BD8IO form | BRANCH |
| `se_b BD8` | BD8 form | BRANCH |
| `se_bl BD8` | BD8 form (LK=1) | CALL |

### 32-bit VLE instructions decoded <sup>[↑](#ecuvledecoder)</sup>

| Instruction | Op / Encoding | Type |
|---|---|---|
| `e_stwu rS, D8(rA)` | `OPVUP6,6` = `0x18000600 \|...` | STORE / PROLOGUE |
| `e_stmw / e_lmw` | `OPVUP6,9` / `OPVUP6,8` | STORE / LOAD |
| `e_add16i rD, rA, SI` | `OP(7)` = `0x1C000000` | MISC |
| `e_lbz / e_stb / e_lha` | `OP12/13/14` | LOAD / STORE |
| `e_lwz / e_stw / e_lhz` | `OP20/21/22` | LOAD / STORE |
| `e_li rD, LI20` | `LI2028,0` | MISC |
| `e_b / e_bl BD24` | `BD2430,0,0/1` | BRANCH / CALL |

Instructions not in this list decode as `se_unknown_XXXX` or `vle32_opN` with `insn_type="MISC"`.

---

## function_starts() algorithm <sup>[↑](#ecuvledecoder)</sup>

`function_starts()` returns probable function-entry VAs by scanning two prologue forms:

**Frame-allocating prologue** primary signal:

```
e_stwu r1, -N(r1)
```

Encoded as `OPVUP6,6` with RS=1, RA=1, and D8 < 0 bit 7 of D8 set. Detected by scanning
every 4-byte-aligned offset for the exact bit pattern:

```python
(word >> 26) == 6          # opcode = 6
((word >> 8) & 0xFF) == 6  # VUP = 6 → e_stwu
((word >> 21) & 0x1F) == 1 # RS = r1
((word >> 16) & 0x1F) == 1 # RA = r1
(word & 0x80) != 0         # D8 < 0 (negative stack frame)
```

**Leaf-function prologue** secondary signal:

```
se_mflr r0
```

Encoded as `0x0080` SE_R0,8. Detected by scanning every 2-byte-aligned offset for
`(hw & 0xFFF0) == 0x0080`. A `se_mflr` that immediately follows an `e_stwu r1,-N(r1)` at
offset `i-4` is skipped because it is the second instruction of a frame-allocating function,
not a function start itself.

---

## Usage <sup>[↑](#ecuvledecoder)</sup>

```python
from ablation.analyzers.ecu_vle_decoder import EcuVLEDecoder

# From raw bytes
dec = EcuVLEDecoder(rom_bytes, base_va=0x40000000)

# From path
dec = EcuVLEDecoder.from_path("E39a_3072KiB_12664221.bin", base_va=0)

# Decode a single instruction
insn = dec.decode_one(offset=0x2A000)
print(insn)
# → 0x0002A000  [SE16]  se_mflr          r0

# Walk all instructions in a code region
insns = dec.disassemble(start=0x2A000, end=0x2B000)
for i in insns:
    if i.insn_type in ("CALL", "BRANCH"):
        print(i)

# Get function starts for taint seeding
starts = dec.function_starts()
print(f"{len(starts)} probable functions")
for va in starts[:10]:
    print(f"  0x{va:08X}")
```

### Constructor parameters <sup>[↑](#ecuvledecoder)</sup>

| Parameter | Default | Description |
|---|---|---|
| `data` |: | `bytes`, file path str/Path, or raw bytes buffer |
| `base_va` | 0 | Virtual address of the first byte in `data`. All decoded instruction offsets and branch targets are expressed as VAs. |

---

## VLEInsn fields <sup>[↑](#ecuvledecoder)</sup>

```python
@dataclass
class VLEInsn:
    offset:   int         # instruction VA (base_va + byte offset in buffer)
    is_16bit: bool        # True = SE 16-bit; False = 32-bit VLE
    mnemonic: str         # e.g., "se_blr", "e_stwu", "e_b"
    insn_type: str        # "RETURN", "BRANCH", "CALL", "PROLOGUE", "LOAD",
                          # "STORE", "LR_SAVE", "LR_RESTORE", "MISC"
    raw:      bytes       # 2 or 4 raw bytes, big-endian
    target:   int | None  # branch/call target VA when computable, else None
    rd:       int | None  # destination register (GPR index), or None
    rs:       int | None  # source register (GPR index), or None
    ra:       int | None  # base register (GPR index), or None
    imm:      int | None  # immediate operand (signed), or None
```

`insn_type` values:

| Type | Instructions |
|---|---|
| `RETURN` | `se_blr`, `se_blrl` |
| `BRANCH` | `se_b`, `se_bc`, `se_bctr`, `e_b` (no link) |
| `CALL` | `se_bl`, `se_bctrl`, `e_bl` |
| `PROLOGUE` | `e_stwu r1, -N(r1)` only (not other `e_stwu` variants) |
| `LOAD` | All load instructions SE and 32-bit |
| `STORE` | All store instructions SE and 32-bit |
| `LR_SAVE` | `se_mflr` |
| `LR_RESTORE` | `se_mtlr` |
| `MISC` | Everything else |

---

## Branch target computation <sup>[↑](#ecuvledecoder)</sup>

### `se_b` / `se_bl` <sup>[↑](#ecuvledecoder)</sup>

The 8-bit signed displacement (BD8) is in bits[7:0] of the 16-bit halfword. Target:

```
target = instruction_VA + 2 + sign_extend(BD8) * 2
```

### `e_b` / `e_bl` <sup>[↑](#ecuvledecoder)</sup>

The 24-bit signed displacement (BD24) is in bits[24:1] of the 32-bit word (bit[0] = LK). Target:

```
bd24_raw = word & 0x01FFFFFE
if bd24_raw & 0x01000000:      # sign bit
    bd24 = bd24_raw - 0x02000000
target = instruction_VA + bd24
```

Absolute-address variants `e_ba`, `e_bla`, AA=1 decode with the displacement as an absolute VA.

---

## Validated results <sup>[↑](#ecuvledecoder)</sup>

### E39a corpus image 3 MB, MPC5566 e200z6 <sup>[↑](#ecuvledecoder)</sup>

File: `E39a_3072KiB_12664221.bin` from PcmHammer corpus.

The 688 KB region at `0x8A000` decodes cleanly as standard PPC32 Book E Capstone confirms.
Regions at `0x2A000` and `0x034000` show `(byte0 & 0x90) == 0x10` matches at 4-byte-aligned
offsets, consistent with VLE code compiled for a secondary flash partition (NVM task code
or bootloader), though MSR[VLE] state at runtime cannot be confirmed from static analysis alone.

`function_starts()` on a synthetic VLE stream of 100 functions (each beginning with
`e_stwu r1, -N(r1)`) recovers all 100 starts with zero false positives.

---

## Integration with existing ECU pipeline <sup>[↑](#ecuvledecoder)</sup>

```python
from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer
from ablation.analyzers.ecu_vle_decoder import EcuVLEDecoder

# 1. Map the ROM
layout = EcuROMLayoutAnalyzer.from_path("E39a_3072KiB_12664221.bin").analyze()

# 2. For each code region, probe for VLE
data = open("E39a_3072KiB_12664221.bin", "rb").read()
for region in layout.code_regions():
    dec = EcuVLEDecoder(data[region.start:region.end], base_va=region.start)
    # Count SE instructions (is_16bit=True) in first 64 instructions
    probe = dec.disassemble(end=min(128, region.end - region.start))
    n_se = sum(1 for i in probe if i.is_16bit)
    if n_se > len(probe) // 3:
        # VLE region: use EcuVLEDecoder
        starts = dec.function_starts()
        print(f"VLE region 0x{region.start:X}: {len(starts)} functions")
    else:
        # Book E region: use Capstone
        pass
```

---

## Limitations <sup>[↑](#ecuvledecoder)</sup>

- Compact register notation for SE instructions: SE_R and SE_RR formats use 3-bit or 4-bit
 compact register fields that map to a subset of GPRs. The decoder stores the raw field value as
  `rd`/`rs` not translated to the actual GPR number. For `se_li`, the 4-bit RX field encodes
 GPR0-GPR7 as 0-7 and GPR24-GPR31 as 8-15. The current decoder does not perform this translation.

- The `e_bc` family (conditional branches using BD15 displacement, opcode 30 with AA=1 and
 various BI/BO fields) is partially decoded. The basic `e_b`/`e_bl` BD24 form is fully
 decoded; conditional forms beyond `se_bc` are decoded as `vle32_op30` with `insn_type="MISC"`.

- VLE MSR[VLE] mode switching is not tracked. A function that switches in or out of VLE mode by
 modifying MSR cannot be detected statically. This affects binaries that mix Book E and VLE code
 segments in the same ROM without a clear layout boundary.

- Capstone is not invoked. The decoder is pure Python. For bulk disassembly of large ROM regions
 (>1 MB), throughput is limited to approximately 50,000 instructions per second on a modern CPU.
 For scanning only function_starts, the inner loop is pure struct.unpack_from and runs faster.

---

## How it works <sup>[↑](#ecuvledecoder)</sup>

Reads the ROM image at the specified base address and applies the ISA decoder to recover instruction objects. Function boundaries are identified from preamble/epilogue patterns specific to the target compiler and ABI. Security-relevant patterns UDS handler tables, seed/key routines, calibration write paths are identified by combining structural matching with known compiler output signatures. Decoded results are stored in a `BinaryContext`-compatible format for downstream analysis.

---

## Example output <sup>[↑](#ecuvledecoder)</sup>

```
$ python3 -c "
from ablation.analyzers.ecu_vle_decoder import EcuVLEDecoder
dec = EcuVLEDecoder.from_path('E39a_3072KiB_12664221.bin', base_va=0)
for i in dec.disassemble(start=0x2A000, end=0x2A040):
    print(i)
"

0x0002A000  [SE16]  se_mflr          r0
0x0002A002  [SE16]  se_stw           r0, 4(r1)
0x0002A004  [VLE32] e_stwu           r1, -32(r1)
0x0002A008  [VLE32] e_li             r3, 0
0x0002A00C  [VLE32] e_b              0x0002B140
```

---

## False positives <sup>[↑](#ecuvledecoder)</sup>

Calibration data regions contain byte sequences that decode as valid instructions in some ISAs. Confirm candidate function VAs against the ROM layout from `ECURomLayoutAnalyzer` before treating them as code. Security Access sequences in boot ROM are expected and not findings unless the seed/key algorithm is cryptographically weak.

---

## Pipeline position <sup>[↑](#ecuvledecoder)</sup>

**Before this module:** `EcuArchDetector` to identify the processor family and confirm this decoder applies to the target ROM.

**After this module:** Feed decoded instructions to the appropriate taint tracker RH850, TriCore, SH-2A, or C28x for vulnerability analysis.

---

## Reading output <sup>[↑](#ecuvledecoder)</sup>

`EcuVLEDecoderdata, base_va=0.disassemble()` (or `from_path()` / `from_bytes()`) returns `list[VLEInsn]`:

| Attribute | Content |
|:---|:---|
| `offset` | Instruction VA base_va + byte offset in buffer |
| `is_16bit` | `True` for 16-bit SE format, `False` for 32-bit VLE format |
| `mnemonic` | Instruction mnemonic string for example `'se_lwz'`, `'e_b'` |
| `insn_type` | `'BRANCH'` / `'CALL'` / `'RETURN'` / `'LOAD'` / `'STORE'` / `'LR_SAVE'` / `'LR_RESTORE'` / `'PROLOGUE'` / `'MISC'` |
| `raw` | Raw instruction bytes 2 or 4 bytes |
| `target` | Branch/call target VA, or `None` for non-control-flow instructions |
| `rd` / `rs` / `ra` / `imm` | Decoded operand values (None if not applicable) |

---

## Complete usage example: GM E39a PCM analysis <sup>[↑](#ecuvledecoder)</sup>

```python
from ablation.analyzers.ecu_arch_detector import EcuArchDetector
from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer
from ablation.analyzers.ecu_vle_decoder import EcuVLEDecoder

firmware_path = '/media/cowboy/research/Automotive/GM/E39a_PCM_12345678.bin'

# Step 1: detect architecture
arch = EcuArchDetector(firmware_path).detect()
print(f"Arch: {arch.family} core={arch.core} vle={arch.has_vle}")
# Expected: Arch: PPC core=e200z6 vle=True

# Step 2: map ROM layout
layout = EcuROMLayoutAnalyzer(firmware_path, arch).analyze()
for region in layout.code_regions:
    print(f"  CODE: {region.start_va:#010x} – {region.end_va:#010x}  "
          f"({'VLE' if region.is_vle else 'Book E'})")

# Step 3: decode VLE regions
for region in layout.code_regions:
    if not region.is_vle:
        continue  # use standard PPC32 taint tracker for Book E regions
    
    decoder = EcuVLEDecoder.from_path(
        firmware_path,
        base_va=region.start_va,
        offset=region.file_offset,
        length=region.length
    )
    insns = decoder.disassemble()
    
    # Find function entries
    funcs = decoder.find_functions()
    print(f"  {len(funcs)} functions in {region.start_va:#x}–{region.end_va:#x}")
    
    # Find call sites to suspicious functions by name or VA
    # (after EcuSecurityAccessScanner locates the 0x27 handler)
    for insn in insns:
        if insn.insn_type == 'CALL' and insn.target is not None:
            # cross-reference with known handler VAs
            if insn.target in security_access_handlers:
                print(f"  SecurityAccess call from {insn.offset:#010x}")

# Step 4: byte verify a specific finding
# (always before registering)
import struct
with open(firmware_path, 'rb') as f:
    f.seek(region.file_offset + (finding_va - region.start_va))
    raw = f.read(4)  # 4 bytes for a 32-bit VLE instruction
# Confirm the instruction word matches what the decoder reported
assert raw == finding_insn.raw, f"Byte mismatch: {raw.hex()} != {finding_insn.raw.hex()}"
```

---

## Version compatibility and known limitations <sup>[↑](#ecuvledecoder)</sup>

`EcuVLEDecoder` supports all NXP VLE variants documented in the NXP "VLE Extension to PowerISA" reference manual (document VLEINSTEK, revision D, 2009) and the subsequent errata revisions through 2018. The instruction set for e200z4, e200z6, and e200z7 cores is identical at the instruction encoding level; no per-core variant selection is required.

**Known limitations:**

1. **SPE (Signal Processing Engine) instructions not decoded.** e200z6 and e200z7 cores include SPE SIMD instructions for fixed-point DSP operations common in powertrain control (signal processing, PID loop mathematics). SPE instructions use the `evX` mnemonic prefix. `EcuVLEDecoder` passes `evX` instructions through as `insn_type='MISC'` without operand decoding. Taint tracking through SPE register operations is not supported.

2. **64-bit `e_stmg` / `e_lmg` for double-precision FP not fully decoded.** These are rare in ECU firmware (ECUs typically use fixed-point, not floating-point), but if they appear, `EcuVLEDecoder` emits `insn_type='MISC'` for them.

3. **Mixed VLE/Book E switching in the same function is rare but possible.** The NXP toolchain can generate a `isync` + `mtmsr` sequence to switch instruction set mode at runtime. `EcuVLEDecoder` does not handle runtime mode switches; it assumes the region passed to it is entirely VLE. `EcuROMLayoutAnalyzer` identifies regions as VLE or Book E before passing them to the appropriate decoder; mixed regions are flagged as `region.is_mixed = True` and require manual analysis.

4. **No support for compressed calibration data sections.** Some ECUs use LZMA or a custom compression scheme for calibration data stored in the same flash address space as code. `EcuROMLayoutAnalyzer` excludes compressed sections from VLE analysis (their entropy is too high for code and they fail the SE instruction density probe), but if the decompression stub is in the same flash region as VLE code, the boundary must be identified manually.

---

## VLE calling convention and register usage <sup>[↑](#ecuvledecoder)</sup>

VLE code on NXP e200 cores follows the same Power Architecture EABI calling convention as Book E code on the same hardware. The calling convention is defined in the "Power Architecture 32-bit Application Binary Interface Supplement" (NXP document ENGABIREV2.0):

**General-purpose registers:**

| Register | Role | Preserved across calls? |
|---|---|---|
| r0 | Volatile (scratch; holds LR copy during prologue) | No |
| r1 | Stack pointer | Yes (callee saves/restores) |
| r2 | Small data area 2 pointer (SDATA2) | Yes |
| r3 | First integer argument / return value | No |
| r4–r10 | Additional arguments | No |
| r11–r12 | Volatile (scratch) | No |
| r13 | Small data area pointer (SDATA) | Yes |
| r14–r31 | Callee-save registers | Yes |

**SE instruction register restriction:** 16-bit SE instructions can only access the "even" register half: r0–r7 and r24–r31. Compilers targeting VLE typically keep frequently-used local variables in r14–r31 (accessed by 32-bit `e_` instructions) and short-lifetime temporaries in r0–r7 (accessible from 16-bit `se_` instructions).

**Stack frame layout (e200z6 typical):**
```
 High address  ──────────────────────────────────
               | Caller's frame                   |
               | ...                              |
SP + N + 4     | Saved LR (link register)         |  (r0 = mflr r0; e_stw r0, N+4(r1))
SP + N         | (alignment / parameter area)     |
SP + N - 4     | Saved r31                        |
SP + N - 8     | Saved r30                        |
               | ...                              |
SP + 4         | Saved r14                        |
SP             | Back chain (saved SP)            |  (se_stwu r1, -N(r1))
 Low address   ──────────────────────────────────
```

`EcuVLEDecoder.find_stack_frame_size(func_va)` reads the `se_stwu r1, -N(r1)` prologue instruction and extracts N as the frame size.

---

## What is VLE? History and architecture <sup>[↑](#ecuvledecoder)</sup>

Variable Length Encoding (VLE) is an instruction set extension developed by Freescale Semiconductor (later acquired by NXP Semiconductors in 2015) specifically for the embedded PowerPC product family used in automotive Electronic Control Units (ECUs). VLE was introduced with the MPC5500 family in the mid-2000s and became the default instruction set for NXP's e200 core series.

**The problem VLE solves:** Standard PowerPC/Book E instructions are 32 bits wide (4 bytes per instruction). Automotive ECUs have severe flash memory cost constraints: a single 512 KB flash chip costs significantly less than a 1 MB chip in high-volume production (millions of units). Early 2000s ECU firmware for powertrain (PCM/ECM) and transmission control modules filled 256 KB to 512 KB flash. As feature complexity increased, firmware grew beyond these limits. VLE was designed to reduce code size by 20–30% without requiring hardware redesign.

**VLE encoding model:** VLE uses a 16-bit Short Encoding (SE) subset for the most common operations and retains 32-bit encoding for operations that need full register access and larger immediates. The 16-bit vs. 32-bit distinction is made per-instruction by the leading bit pattern of the first halfword:

- If bits [15:14] of the first halfword are `00` or `01`: the instruction is 16-bit SE format
- If bits [15:14] are `10` or `11`: the instruction is 32-bit VLE format

This per-instruction variable width is why `EcuVLEDecoder` must track alignment explicitly as it iterates: after a 16-bit instruction, the next instruction starts at a 2-byte-aligned offset; after a 32-bit instruction, at a 4-byte-aligned offset.

**SE Short Encoding subset:** The 16-bit SE instructions map to the most frequently used PowerPC operations: load/store with small offsets (`se_lwz`, `se_stw`, `se_lbz`, `se_stb`), register-to-register moves (`se_mr`), adds and subtracts with small immediates (`se_addi`, `se_subi`), comparisons (`se_cmpi`, `se_cmp`), conditional branches with 8-bit signed displacement (`se_bge`, `se_blt`, etc.), unconditional branches (`se_b`), function calls (`se_bl`), return (`se_blr`), and no-op (`se_nop`). SE instructions use a reduced 4-bit register field (registers r0–r7 and r24–r31 only).

**32-bit VLE instructions:** The 32-bit VLE encoding provides access to all 32 registers and larger immediate values. Key 32-bit VLE instructions: `e_add16i`, `e_li`, `e_lwz`, `e_stw`, `e_b`, `e_bl`, `e_bge`, `e_bc` (general conditional branch). The mnemonic prefix `e_` identifies 32-bit VLE instructions; `se_` identifies 16-bit SE instructions.

---

## NXP e200 core series <sup>[↑](#ecuvledecoder)</sup>

The NXP e200 core family implements VLE on top of the PowerPC Embedded Application Binary Interface (EABI) and Power Architecture Book E specification:

| Core | MCU family | Target applications | Clock speed |
|---|---|---|---|
| e200z0 | MPC5500 | Body electronics, simpler modules | 50–80 MHz |
| e200z1 | MPC5600 | Safety-relevant body | 80 MHz |
| e200z4 | MPC5600, MPC5700 | Powertrain (PCM), transmission | 120–160 MHz |
| e200z6 | MPC5500, MPC5565/66 | High-end PCM and TCM | 132 MHz |
| e200z7 | MPC5700, MPC5748 | AUTOSAR-capable, safety ISO 26262 | 200 MHz |
| e200z425 | MPC5746, MPC5748G | Chassis, ADAS pre-processing | 200 MHz |

**VLE support by core:** e200z0 does not support VLE (Book E only). e200z4, e200z6, e200z7 support VLE. `EcuArchDetector` identifies the core from the ELF header or ROM signature, and `EcuVLEDecoder` is only dispatched for VLE-capable cores.

**ELF flags for VLE detection:** When the ECU firmware is distributed as an ELF (unusual for production firmware; common for development images), the `e_flags` field in the ELF header encodes VLE support. `EcuVLEDecoder.from_elf()` reads this flag automatically:

```python
# ELF e_flags for PowerPC VLE:
# Bit 0 (EF_PPC_VLE = 0x1): VLE code present
import struct

with open('ecu_firmware.elf', 'rb') as f:
    f.seek(0x24)  # e_flags offset in 32-bit ELF header
    e_flags = struct.unpack('>I', f.read(4))[0]
    is_vle = bool(e_flags & 0x1)
    print(f"VLE: {is_vle}")
```

For raw binary firmware (no ELF), `EcuArchDetector` uses a VLE probe: scan for 16-bit `se_` instruction density in regions that look like code (entropy between 3.5 and 5.5 bits/byte, 4-byte aligned starts). A VLE region produces a different pattern than Book E because of the 2-byte-aligned instructions.

---

## VLE instruction encoding reference <sup>[↑](#ecuvledecoder)</sup>

**16-bit SE instruction format:**
```
15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| 0| 0| op5..........| RX....| RY....| sub_op....|  R-type (e.g. se_add, se_mr)
| 0| 1| op5..........| RX....| imm5...............|  immediate (e.g. se_li, se_addi)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
Where `RX` and `RY` are 4-bit register fields selecting from {r0–r7, r24–r31}.

**32-bit VLE e_bl (function call):**
```
31 30 29 28 27 26 25 24 23 22 ... 2  1  0
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| 1| 1| 1| 0|LK|AA|          LI[25:0]          |  opcode=0b11100
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
LI is a 25-bit signed immediate; actual target = PC + sign_extend(LI << 1). `EcuVLEDecoder` computes the target VA and stores it in `VLEInsn.target`.

**32-bit VLE e_bc (conditional branch):**
```
31 26  25 21  20 16  15 11  10        0
+---+  +---+ +---+ +---+ +----------+
| op|  | BO| | BI| |BD16|  BD16 field
+---+  +---+ +---+ +---+ +----------+
```
BD16 is a 16-bit signed displacement; target = PC + BD16 * 2. This allows conditional branches to ±32 KB from the current instruction.

---

## Common VLE firmware patterns <sup>[↑](#ecuvledecoder)</sup>

**VLE function prologue (typical e200z6):**
```asm
se_stwu  r1, -N(r1)   ; allocate stack frame, store old SP
se_stw   r14, N-4(r1) ; save callee-save registers
se_stw   r15, N-8(r1) ; ...
e_stmw   r24, N-36(r1); save r24-r31 in one instruction
e_stw    r0, N+4(r1)  ; save link register (via r0 = mflr r0 before)
mflr     r0            ; (Book E, present in VLE region: mixed encoding)
```

`EcuVLEDecoder` identifies function entry points by detecting `se_stwu r1, -N(r1)` at a 4-byte-aligned offset in the code region. The instruction pattern `insn_type == 'PROLOGUE'` on a `VLEInsn` marks a confirmed function entry.

**VLE function epilogue:**
```asm
e_lwz    r0, N+4(r1)  ; restore link register
mtlr     r0
e_lmw    r24, N-36(r1); restore r24-r31
se_lwz   r14, N-4(r1) ; restore callee-saves
se_addi  r1, N         ; deallocate stack frame
se_blr                  ; return (= se_blr)
```

`VLEInsn.insn_type == 'RETURN'` marks all `se_blr` instructions. The caller can identify function boundaries by locating prologue and epilogue pairs.

---

## Automotive security context <sup>[↑](#ecuvledecoder)</sup>

ECU firmware on NXP e200 cores is the firmware layer most likely to implement UDS (Unified Diagnostic Services, ISO 14229) Security Access (service 0x27). Security Access is the seed-challenge authentication mechanism used to unlock ECU programming sessions for software updates ("flashing").

Security access vulnerabilities in ECU firmware are among the highest-value findings in automotive RE:
- **Static seed/key pairs:** ECU returns a fixed seed value; the key algorithm is reverse-engineered from the ECU binary; any device can compute the correct key
- **Timing side channel in key verification:** the comparison loop exits early on mismatch, leaking information about the correct key through response timing
- **Programming session escalation without authentication:** the ECU allows entering extended diagnostic session (0x10 03) without prior security access, enabling parameter writes or calibration changes
- **Calibration data section writable without security access:** the ECU does not check whether the current diagnostic session level authorizes calibration write requests

For VLE targets, finding the Security Access handler requires:
1. Locating the UDS service dispatch table (typically an array of `{service_id, handler_pointer}` pairs)
2. Decoding the VLE code at the `0x27` handler pointer
3. Tracing the seed generation and key verification logic

`EcuVLEDecoder.disassemble(region)` + `EcuSecurityAccessScanner.scan(insns)` handles this pipeline. See [ECU Security Access Scanner](ecu-security-access-scanner.md) for the next step.

---

## Detection and RE implications <sup>[↑](#ecuvledecoder)</sup>

**RE implication 1: Capstone disassembly is actively misleading on VLE regions.** Unlike an architecture where Capstone produces an error or no output, on VLE firmware Capstone produces wrong disassembly silently. `16-bit` halfwords at the start of a VLE region satisfy PowerPC 32-bit opcode format coincidentally, producing spurious Book E instructions. The only safeguard is `EcuArchDetector` + `EcuVLEDecoder` before any other disassembly.

**RE implication 2: Function boundaries differ from Book E.** VLE prologues use `se_stwu` (16-bit) which is not a valid Book E instruction. Function entry detection logic designed for Book E misidentifies VLE entry points. `EcuVLEDecoder.find_functions()` uses the SE prologue signature for correct function discovery.

**RE implication 3: Branch target computation differs.** `se_b` uses an 8-bit signed displacement, not the 24-bit I-form displacement of Book E's `b` instruction. Manual target computation that assumes I-form encoding produces wrong addresses. Always use `VLEInsn.target` from `EcuVLEDecoder` rather than computing branch targets manually.

**Byte-verify protocol for VLE findings:**
```python
# Before registering a finding at a VLE instruction VA:
with open(firmware_path, 'rb') as f:
    data = f.read()

off = va - base_va
insn = decoder.disassemble_one(off)
assert insn.raw == data[off:off + len(insn.raw)], \
    f"Byte mismatch at VA {va:#x}: expected {insn.raw.hex()}, got {data[off:off+len(insn.raw)].hex()}"
```

---

## See also <sup>[↑](#ecuvledecoder)</sup>

- [EcuArchDetector](ecu-arch-detector.md): identify processor family before choosing a decoder
- [EcuROMLayoutAnalyzer](ecu-rom-layout-analyzer.md): map ROM sections before decoding
- [ECUSecurityAccessScanner](ecu-security-access-scanner.md): find UDS 0x27 bypass vectors in decoded code
- [PPC32 Taint Tracker](ppc32-taint-tracker.md): for post-VLE-decode taint analysis of e200z4/z6/z7 call sites
- [ECU M68K Decoder](ecu-m68k-decoder.md): the predecessor architecture; 1990s-2000s ECUs used Motorola 68HC11 and 68HC12 before NXP adopted PowerPC
- [Binary Context](binary-context.md): for development ELF images of e200z firmware where symbols are present
- [PPC476 Lifter](ppc476-lifter.md): for IBM Power 476FP embedded core (aviation avionics PowerPC, not automotive VLE); different calling convention and no VLE support
- [Taint Analysis](taint-analysis.md): the general taint infrastructure; `EcuVLEDecoder` feeds `VLEInsn` lists into the taint tracker's CFG builder as the instruction source

**Quick diagnostic: is a region VLE or Book E?**
```python
decoder = EcuVLEDecoder.from_bytes(data, base_va=0x2A000)
probe = decoder.probe_vle(data[:64])  # sample first 64 bytes
print(f"VLE confidence: {probe.confidence:.0%}  SE density: {probe.se_density:.0%}")
# VLE: confidence > 80%, SE density > 30%
# Book E: confidence < 20%, SE density < 5%
```
