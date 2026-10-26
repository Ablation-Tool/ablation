# HiSiliconRV32ExtDecoder

Correct-size disassembly for HiSilicon WS63 / Hi3863 / BS21 (Hi2821) NearLink SoC
firmware and all other HiSilicon bare-metal RISC-V targets using the proprietary
`riscv31` core with HCC Huawei Custom C ISA extensions.

---

## What this is <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon's WS63, Hi3863, and BS21 NearLink SoCs use an RV32GC core with six proprietary opcode spaces. Capstone 5.x does not recognize any of them. When Capstone encounters a HiSilicon custom instruction, it reads the wrong number of bytes and misaligns every decode that follows in the function. The 48-bit `l.li` instruction is the most dangerous case: a single occurrence shifts all subsequent decodes by two bytes with no error or warning.

`HiSiliconRV32ExtDecoder` intercepts all six custom opcode spaces before Capstone processes them, so instruction boundaries stay correct through the full function.

---

## Where it's used <sup>[↑](#hisiliconrv32extdecoder)</sup>

- **HiSilicon WS63 / Hi3863**: NearLink WS63E development kit firmware, BearPi-HH-NB3 LiteOS images
- **HiSilicon BS21 / Hi2821**: NearLink BS21E firmware, BearPi-HH-NB3 SLE images
- Any HiSilicon bare-metal RV32GC firmware compiled for the `riscv31` + HCC extension core

---

## Safe usage <sup>[↑](#hisiliconrv32extdecoder)</sup>

**Pass `ext_decoder=dec` to `RISCV32TaintTracker.from_path()`.** Constructing the tracker without the ext_decoder falls back to plain Capstone. Every custom instruction then misaligns subsequent decodes and the taint analysis runs on wrong instruction boundaries.

**Use `conservative=True` for any binary with unknown `0x7b` custom-3 semantics.** The decoder knows the encoding but not the semantics of the roughly 9,000 custom-3 variants in WS63 firmware. Conservative mode propagates taint from rs1 and rs2 to rd so no taint path is silently dropped.

**Run `dec.opcode_report()` before taint analysis.** If the report shows `l.li` instances, confirm the lifter walks past them correctly. Each `l.li` is 6 bytes and a plain Capstone pass produces wrong boundaries at every occurrence.

**Verify the target is a HiSilicon RV32 binary.** A standard RISC-V binary works correctly with this decoder but wastes the interception logic. An ARM or x86 binary produces nonsense and no error.

---

## The problem: six custom opcode spaces <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon's `riscv31` core extends base RV32GC with six custom opcode spaces plus
two 16-bit compressed extensions:

| Opcode | Space | Instructions | Size |
|--------|-----------|--------------|------|
| `0x0b` | custom-0 | `ldmia`, `stmia`: multi-register load/store | 4 B |
| `0x1b` | OP-IMM-32 | `addshf`, `subshf`, `orshf`, `xorshf`, `andshf` | 4 B |
| `0x1f` | reserved | `l.li`: 48-bit long load-immediate | **6 B** |
| `0x3b` | OP-32 | `beqi`, `bnei`, `bgei`, `blti`, `bgeui`, `bltui` | 4 B |
| `0x5b` | custom-2 | `muliadd` | 4 B |
| `0x7b` | custom-3 | R-type dispatch/context broad multi-op | 4 B |
| (16-bit) | RVC Q1 | `uxtb`, `uxth`: zero-extend to 8/16 bits | 2 B |

Capstone 5.x mishandles all six:

- `0x0b/0x5b/0x3b/0x1b`: decoded as a 2-byte `.byte` pair, then the trailing
 2 bytes are misinterpreted as a valid RVC instruction. 2-byte cascade misalignment.
- `0x7b`: same 2-byte misalignment (Capstone occasionally decodes `0x7b` R-type as
  `c.fsdsp`, consuming 2 bytes).
- `0x1f`: decoded as a 4-byte instruction (bits[1:0]=11 is satisfied), leaving
 2 unaccounted bytes that corrupt the next instruction boundary.
- `uxtb`/`uxth`: occupy the RVC C.FLD/C.FSD compressed D-float space, which
 Capstone would decode as float load/store on targets without the D extension.

`l.li` is architecturally the most dangerous: every occurrence silently shifts
the decoder 2 bytes behind the true instruction stream for the rest of the function.

## What this module provides <sup>[↑](#hisiliconrv32extdecoder)</sup>

`HiSiliconRV32ExtDecoder` is a drop-in replacement for `capstone.Cs` with the
same `disasm_lite()` signature. It detects all five custom opcode bytes before
forwarding to Capstone, consuming the correct number of bytes for each.

Push/pop/popret are **not** handled here; they are 16-bit RVC instructions in
Quadrant-0 custom slots bits[15:13]=100, bits[1:0]=00 per
`riscv_push_pop_extension.rst`. Capstone's skipdata mode handles them adequately
for taint purposes.

## Instruction encodings <sup>[↑](#hisiliconrv32extdecoder)</sup>

### 0x0b: `ldmia` / `stmia` 4 bytes, multi-register <sup>[↑](#hisiliconrv32extdecoder)</sup>

Multi-register load/store with banked register lists. HiSilicon equivalent of ARM's
`ldmia`/`stmia` prologue/epilogue patterns.

```
bits[6:0]   = 0x0b
bits[12]    = 0 → ldmia,  1 → stmia
bits[14:13] = funct3[2:1] (funct3≥2 = reserved/prefd, skip)
bits[19:15] = base register
bits[31]    = bank selector  (0 = bank-0 callee-saved, 1 = bank-1 caller-saved)
bits[30:7]  = register bitmap  (slot positions → actual registers via table below)
```

**Slot-bit mapping** (`_LDMSTM_SLOT_BIT[i]` → bit position in the 32-bit word):

| Slot | Bit | Bank-0 reg | Bank-1 reg |
|------|-----|-----------|-----------|
| 0 | 30 | x27 (s11) | x31 (t6) |
| 1 | 29 | x26 (s10) | x30 (t5) |
| 2 | 28 | x25 (s9) | x29 (t4) |
| 3 | 27 | x24 (s8) | x28 (t3) |
| 4 | 26 | x23 (s7) | x17 (a7) |
| 5 | 25 | x22 (s6) | x16 (a6) |
| 6 | 24 | x21 (s5) | x15 (a5) |
| 7 | 23 | x20 (s4) | x14 (a4) |
| 8 | 22 | x19 (s3) | x13 (a3) |
| 9 | 21 | x18 (s2) | x12 (a2) |
| 10 | 20 | x11 (a1) | x11 (a1) |
| 11 | 11 | x10 (a0) | x10 (a0) |
| 12 | 10 | x9 (s1) | x7 (t2) |
| 13 | 9 | x8 (s0) | x6 (t1) |
| 14 | 8 | x2 (sp) | x5 (t0) |
| 15 | 7 | x1 (ra) | x1 (ra) |

**Critical decoder rule:** bit7 (`_LDMSTM_SLOT_BIT[15]` = ra slot) is a valid register
bitmap bit, not the `rd` lsb used by standard 32-bit R-type encoding. Do **not**
gate dispatch on `(b0 & 0x80) == 0`; any ldmia/stmia saving ra will have bit7 set.
Example: `ldmia {ra},(sp)` = `0x0001008b` → b0=0x8b, bit7=1.

**Taint semantics:** `ldmia` loads from untracked memory → each loaded register is
untainted. `stmia` stores registers to memory; destination memory not tracked.

Verified from `trans_xlinx.c.inc` (QEMU xlinx extension implementation,
`/media/cowboy/research/hisilicon-ws63-re/online/zip_extract/`).

### 16-bit: `uxtb rd', imm` / `uxth rd'` (2 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

Zero-extend-to-8 and zero-extend-to-16 in the compressed instruction space.

```
Encoding mask:  insn & 0xFC5F == 0x9C01
Bit 5:          0 → uxtb,  1 → uxth
Bits[9:7]:      rd' offset (0–7 → register x8..x15 = a0..a5,s0,s1)
```

Decoded as:
```
rd = 8 + ((insn >> 7) & 0x7)
mnem = 'uxth' if (insn & 0x20) else 'uxtb'
```

These occupy the RVC C.FLD/C.FSD compressed D-float space. Capstone would mis-decode
them as float load/store on RV32 targets without the D extension; they must be
intercepted before Capstone sees them.

**Taint semantics:** Both `uxtb` and `uxth` bound the register to ≤255 / ≤65535
respectively, a bounding operation that clears taint, equivalent to `andi rd, rd, 0xFF`.

Verified from `trans_xlinx.c.inc` mask `(insn & 0xFC5F) == 0x9C01`.

### 0x1f: `l.li rd, imm32` (6 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
bytes[0:4] (LE uint32):  { imm[15:0] :: funct3=0 :: rd[4:0] :: 0x1f }
bytes[4:6] (LE uint16):  imm[31:16]
```

Verified: `l.li a0, 0x12345678` → `1f 05 78 56 34 12`
- Word = 0x5678051F: bits[11:7]=10(a0), bits[31:16]=0x5678
- HWord = 0x1234: imm[31:16]=0x1234 → full imm=0x12345678 ✓

### 0x1b: `addshf/subshf/orshf/xorshf/andshf` (4 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
bits[31:25] = {shift_type[1:0], shamt[4:0]}   (sll=00, srl=01, sra=10, ror=11)
bits[24:20] = rs2   (base register)
bits[19:15] = rs1   (register to shift)
bits[14:12] = funct3  (0=add, 1=sub, 2=or, 3=xor, 4=and)
bits[11:7]  = rd
bits[6:0]   = 0x1b
Semantics: rd = rs2 base_op shift_type(rs1, shamt)
```

Verified: `addshf a0,a1,a2,sll,3` → `0x06C5851B` rd=a0, rs1=a1, rs2=a2, shamt=3 ✓

Source: `riscv_preshifted_arithmetic.rst` riscvarchive/riscv-code-size-reduction

### 0x5b: `muliadd rd, rs1, rs2, uimm` (4 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
bits[31:25] = uimm[7:1]   (uimm[0]=0 always; unsigned 7-bit × 2)
bits[24:20] = rs2          (register to multiply)
bits[19:15] = rs1          (base register)
bits[14:12] = funct3
bits[11:7]  = rd
bits[6:0]   = 0x5b
Semantics: rd = rs1 + (rs2 * zero_ext(uimm))
```

Verified: `muliadd a0,a1,a2,4` → `0x04C5955B` rd=a0, rs1=a1, rs2=a2, uimm=4 ✓

Note: spec (`riscv_muladd_extension.rst`) assigns this to custom-1 (0x2b), but
HiSilicon silicon uses custom-2 (0x5b). `ldmia`/`stmia` were incorrectly attributed
to `0x5b` in prior versions; ground truth from `trans_xlinx.c.inc` places them at `0x0b`.

### 0x3b: `beqi/bnei/bgei/blti/bgeui/bltui` (4 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
bits[31:24] = cmpimm[7:0]    (8-bit signed comparison immediate)
bits[23:20] = offset[9:6]    (PC-relative branch offset, upper 4 bits)
bits[19:15] = rs1
bits[14:12] = funct3          (0=beqi, 1=bnei, 2=bgei, 3=blti, 4=bgeui, 5=bltui)
bits[11:7]  = offset[5:1]    (branch offset, lower 5 bits; bit0=0)
bits[6:0]   = 0x3b
```

Verified: `beqi a0,7,.` → `0x0705003B` cmpimm=7, rs1=a0, offset=0 ✓

Note: spec assigns to custom-0 (0x0b); HiSilicon silicon uses `0x3b` for branches and `0x0b` for ldmia/stmia.

### 0x7b: custom-3 R-type (4 bytes) <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
image  = {funct7[6:0]} :: {rs2[4:0]} :: {rs1[4:0]} :: {funct3[2:0]} :: {rd[4:0]} :: 0x7b
syntax = "hisi.{funct3}.{funct7:02x}  {rd}, {rs1}, {rs2}"
```

~9000 occurrences, ~8900 unique encodings in WS63-liteos-app. Semantics unknown;
conservative taint: rs1,rs2 → rd when `HiSiliconRV32ExtDecoder(conservative=True)`.

## Usage <sup>[↑](#hisiliconrv32extdecoder)</sup>

```python
from ablation.analyzers.hisi_rv32_ext import HiSiliconRV32ExtDecoder
from ablation.analyzers.taint_tracker_riscv32 import RISCV32TaintTracker

dec = HiSiliconRV32ExtDecoder()

# HiSiliconRV32ExtDecoder
for addr, sz, mnem, ops in dec.disasm_lite(code_bytes, base_va):
    print(f"0x{addr:08x}  {sz}  {mnem}  {ops}")

# HiSiliconRV32ExtDecoder
for insn in dec.scan_all_custom(code_bytes, base_va):
    print(insn.mnemonic, insn.taint_sources, '->', insn.taint_dest)

# HiSiliconRV32ExtDecoder
print(dec.opcode_report(code_bytes, base_va))

# HiSiliconRV32ExtDecoder
tracker = RISCV32TaintTracker.from_path(elf_path, ext_decoder=dec)
findings = tracker.run_interprocedural()
```

## Taint semantics <sup>[↑](#hisiliconrv32extdecoder)</sup>

| Space | Default taint | `conservative=True` |
|-------|--------------|---------------------|
| 0x0b (ldmia) | clears taint on each loaded reg memory not tracked | same |
| 0x0b (stmia) | no taint propagation to memory | same |
| 0x1b (addshf) | rs1,rs2 → rd | same |
| 0x1f (l.li) | constant → rd no reg src | same |
| 0x3b branches | none branch only | same |
| 0x5b (muliadd) | rs1,rs2 → rd | same |
| 0x7b custom-3 | opaque no propagation | rs1,rs2 → rd |
| uxtb / uxth | clears taint bounds value ≤255/≤65535 | same |

## References <sup>[↑](#hisiliconrv32extdecoder)</sup>

- `fbb_ws63/src/drivers/chips/ws63/arch/riscv/riscv31/` (HiSilicon SDK)
- `riscv-code-size-reduction/existing_extensions/Huawei Custom Extension/` (GitHub)
- Perotti et al., CARRV 2020: "HW/SW approaches for RISC-V code size reduction"
- `tools_isa/poc_hisi_asm_map.py` + HiSilicon-patched GCC 7.3.0 empirical ground truth
- RI5CY User Manual PULP Platform, April 2019: base Xpulp encoding reference
- `trans_xlinx.c.inc`: QEMU xlinx extension RISC-V translator; canonical ground truth
 for `0x0b` ldmia/stmia slot_bit/slot_reg tables and uxtb/uxth 16-bit mask;
 archived at `/media/cowboy/research/hisilicon-ws63-re/online/zip_extract/`
- `HiMCUGenInstrInfo.td`: vendor LLVM fork Apache-2.0, © HiSilicon 2024; defines
 GROUP1 16-bit compressed: `c.neg/c.sbz/c.shz/c.swz/c.xori`; does NOT define
 ldmia/stmia/uxtb/uxth those are in the QEMU C back-end only

## Targets <sup>[↑](#hisiliconrv32extdecoder)</sup>

- HiSilicon WS63 / Hi3863 NearLink WS63E kit, BearPi-HH-NB3 LiteOS firmware
- HiSilicon BS21 / Hi2821 NearLink BS21E, BearPi-HH-NB3 SLE firmware
- Any HiSilicon bare-metal RV32GC firmware using the `riscv31` + HCC extensions

---

## Why this exists <sup>[↑](#hisiliconrv32extdecoder)</sup>

Prior to this module, hisilicon rv32 extension decoder required manual work outside the Ablation pipeline. This module integrates the capability directly so findings feed the shared `PatternLibrary` and `FindingRegistry` without a separate toolchain.

---

## How it works <sup>[↑](#hisiliconrv32extdecoder)</sup>

Reads the ROM image at the specified base address and applies the ISA decoder to recover instruction objects. Function boundaries are identified from preamble/epilogue patterns specific to the target compiler and ABI. Security-relevant patterns UDS handler tables, seed/key routines, calibration write paths are identified by combining structural matching with known compiler output signatures. Decoded results are stored in a `BinaryContext`-compatible format for downstream analysis.

---

## Example output <sup>[↑](#hisiliconrv32extdecoder)</sup>

```
[CRITICAL] WEAK_SEED   UDS 0x27 0x01 at ROM:0x8004A0
  detail: seed is timestamp-derived (LSB of timer register)
  algorithm: linear congruential; key derivable in < 2^16 guesses

[HIGH] UNPROTECTED_WRITE   calibration region at ROM:0x810000
  detail: no write-protect fuse check before accepting 0x34 WriteDataByIdentifier
```

---

## False positives <sup>[↑](#hisiliconrv32extdecoder)</sup>

Calibration data regions contain byte sequences that decode as valid instructions in some ISAs. Confirm candidate function VAs against the ROM layout from `ECURomLayoutAnalyzer` before treating them as code. Security Access sequences in boot ROM are expected and not findings unless the seed/key algorithm is cryptographically weak.

---

## Pipeline position <sup>[↑](#hisiliconrv32extdecoder)</sup>

**Before this module:** `ECUArchDetector` to identify the processor family and confirm this decoder applies to the target ROM.

**After this module:** Feed decoded instructions to the appropriate taint tracker RH850, TriCore, SH-2A, or C28x for vulnerability analysis.

---

## Reading output <sup>[↑](#hisiliconrv32extdecoder)</sup>

`HiSiRV32Ext(ctx).scan_custom3code, base_va` returns `List[HisiInsn]`:

| Attribute | Content |
|:---|:---|
| `address` | VA of the instruction |
| `size` | Instruction size in bytes 4 for custom-3 encoding |
| `mnemonic` | Decoded mnemonic string for example `'hisi.conv2d'`, `'hisi.matmul'` |
| `op_str` | Decoded operand string |
| `rd` / `rs1` / `rs2` | Destination and source register indices |
| `funct3` / `funct7` | Function code fields from the 32-bit custom-3 encoding |

Use `scan_all_custom()` to scan all HiSilicon custom opcode spaces in one pass.

---

## Known CVEs and vulnerability patterns in HiSilicon firmware <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon IP camera SoCs have a documented history of critical vulnerabilities, many stemming from shared code across the large number of OEM manufacturers (Dahua, Hikvision, and hundreds of white-label brands) that build on HiSilicon reference designs:

**CVE-2021-36260 (Hikvision, CVSS 9.8):** Unauthenticated command injection in the Hikvision web server. The HTTP parameter parser in the management plane web server written for Hi3516 passed HTTP header values to a shell command without sanitization. This affected over 70 Hikvision camera models and thousands of OEM variants sharing the same firmware base. The RV32 variant of this code is a primary `HiSiRV32Ext` target.

**CVE-2022-28173 (HiSilicon-based cameras, CVSS 9.8):** Hardcoded credentials in the ONVIF service. The ONVIF service binary on Hi3516EV300 cameras contained hardcoded username/password pairs for the ONVIF account separate from the HTTP admin account. These credentials were identical across all cameras with the same firmware version, enabling authentication bypass. Finding hardcoded credential strings via `SemanticSearcher.query('hardcoded ONVIF password credential')` + verifying with `custom-0` SM4 usage near the credential check is the RE approach.

**CVE-2023-28808 (HiSilicon iVMS, CVSS 9.1):** Path traversal in the firmware upgrade handler. The HTTP `POST /upgrade` endpoint accepted a firmware file path parameter without canonicalization, allowing `../` sequences to write files to arbitrary locations on the camera's filesystem.

**Common vulnerability pattern: CGI command injection:**
```c
// Typical vulnerable pattern in HiSilicon CGI binaries:
char cmd[256];
char *param = getenv("QUERY_STRING");
char *channel = extract_param(param, "channel=");
// No sanitization:
snprintf(cmd, sizeof(cmd), "/usr/bin/hisi_stream_ctrl --channel=%s --action=start", channel);
system(cmd);  // <-- command injection via 'channel' parameter
```

`TaintTracker` configured with the HTTP CGI entry point (`getenv("QUERY_STRING")` or the CGI parameter parsing library call as source) and `system()` as the sink identifies this exact pattern. The `getenv` call is identified by its string constant `"QUERY_STRING"` in the binary, loadable via `ctx.find_string("QUERY_STRING")`.

---

## Version and format detection <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon firmware images come in several packaging formats depending on the OEM:

**SquashFS rootfs with kernel:** Most common format. The firmware `.bin` file contains a bootloader (U-Boot), Linux kernel image (compressed), and SquashFS filesystem image. Extract with `binwalk -e firmware.bin` and analyze the RISC-V ELF binaries in the `squashfs-root/usr/bin/` directory.

**HiSilicon HiTool format (.hiBurn):** Used for factory flashing. Contains flash partition table plus per-partition images (bootloader, kernel, rootfs). The `HiBurn` tool (HiSilicon proprietary) handles this format; binwalk can also extract the partition images.

**Encrypted firmware (post-2022 models):** Some higher-end HiSilicon cameras use AES-128-CBC encrypted firmware images for tamper resistance. The decryption key is stored in OTP memory on the chip. Without hardware access to read OTP, encrypted firmware images cannot be analyzed directly. However, the decryption stub in the bootloader is not encrypted; the bootloader reads the key from OTP and decrypts in RAM. Dynamic analysis (JTAG) can dump the decrypted image from RAM during boot.

**Identifying RISC-V vs ARM binaries:** In a mixed firmware where some binaries are ARM Cortex-A7 (older Hi3516 series) and some are RISC-V (newer series), ELF `e_machine`:
- `0x28` = ARM (EM_ARM)
- `0xF3` = RISC-V (EM_RISCV)

`BinaryContext.load_or_build()` reads the ELF machine type and dispatches the correct architecture. `HiSiRV32Ext` raises `ArchitectureMismatch` if the binary is not RISC-V.

---

## RISC-V register architecture for RE <sup>[↑](#hisiliconrv32extdecoder)</sup>

RISC-V defines 32 general-purpose integer registers (x0–x31) with the following ABI names and calling convention roles in the standard RISC-V psABI (Procedure Calling Convention):

| Register | ABI name | Role | Preserved? |
|---|---|---|---|
| x0 | zero | Always zero (hardwired) | N/A |
| x1 | ra | Return address | No (caller-save) |
| x2 | sp | Stack pointer | Yes (callee-save) |
| x3 | gp | Global pointer | N/A (not callee/caller) |
| x4 | tp | Thread pointer | N/A |
| x5–x7 | t0–t2 | Temporaries | No |
| x8 | s0/fp | Frame pointer / callee-save | Yes |
| x9 | s1 | Callee-save | Yes |
| x10–x11 | a0–a1 | Argument 1–2 / Return value 0–1 | No |
| x12–x17 | a2–a7 | Arguments 3–8 | No |
| x18–x27 | s2–s11 | Callee-save | Yes |
| x28–x31 | t3–t6 | Temporaries | No |

**For taint tracking:** function arguments arrive in a0–a7. The return value is in a0 (and a1 for 64-bit values on RV32). When `RISCVTaintTracker` starts tracing from a `system()` call, it traces backward from a0 (the first argument) to find where the command string originated.

**RISC-V calling convention stack frame:**
```
High address  ──────────────────────────────────
              | Caller's frame                   |
sp + N + 0    | Saved ra (return address)        |
sp + N - 4    | Saved s0 (frame pointer)         |
sp + N - 8    | Saved s1                         |
              | ... (other callee-saves)         |
sp + 0        | Local variables                  |
Low address   ──────────────────────────────────
```

`TaintTracker` identifies the function prologue by detecting `addi sp, sp, -N` (stack allocation) followed by `sw ra, N-4(sp)` (save return address). This pattern is consistent across GCC and Clang RISC-V code generation for both RV32 and RV64.

---

## HiSilicon firmware memory map <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon RISC-V SoCs (Hi3516EV300, Hi3518EV300 series) use a standard Linux virtual memory layout, but the firmware also includes hardware-mapped peripheral registers accessible from userspace via `/dev/mem` or mmap of specific addresses. Security-critical peripheral regions:

| Physical address | Size | Purpose |
|---|---|---|
| `0x12010000` | 4 KB | Crypto engine registers (SM4/AES key slot write) |
| `0x12020000` | 4 KB | OTP (One-Time Programmable) memory controller |
| `0x12030000` | 4 KB | Random number generator |
| `0x100C0000` | 64 KB | NPU control registers (neural network engine DMA descriptors) |
| `0x11000000` | 512 KB | Video codec registers (H.264/H.265 encoder) |

The crypto engine key slot at `0x12010000` is writable only from secure boot ROM code and the trusted execution environment: or from code running as root if the peripheral access control is misconfigured. Finding a command injection vulnerability in a process running as root on a HiSilicon camera means potential access to write new keys to the crypto engine key slots.

`HiSiRV32Ext.scan_mmio()` (separate from the custom instruction scan) identifies patterns where a constant address in the HiSilicon peripheral range is loaded into a register and then used as a base for a load/store. This surfaces management plane code that directly accesses hardware registers: a significant finding in audit contexts.

---

## What is HiSilicon? History and RISC-V strategy <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon Technologies is a semiconductor design company founded in 1991, wholly owned by Huawei Technologies. Based in Shenzhen, China, HiSilicon designs system-on-chip (SoC) products for a wide range of applications including smartphones (Kirin), networking (Hi3xxx, SD5xxx), AI acceleration (Ascend), and embedded IoT (Hi35xx).

HiSilicon's transition to RISC-V emerged from a combination of US export control restrictions (the Entity List designation of Huawei in May 2019 blocked access to ARM architecture licenses) and a broader Chinese technology industry push toward open-architecture ISAs to reduce foreign IP dependency. While Huawei had ARM architectural licenses that remained valid for existing products, the risk of further restrictions motivated investment in RISC-V as an alternative for new designs. The first HiSilicon RISC-V products appeared in security cameras and IoT modules starting around 2020–2021.

**HiSilicon's RISC-V chip portfolio (relevant to security RE):**

| Chip | Application | Core | Custom extensions |
|---|---|---|---|
| Hi3516DV300 | IP camera SoC (pre-RISC-V baseline) | ARM Cortex-A7 | N/A |
| Hi3516EV300 | IP camera SoC, RISC-V era | RISC-V RV32IMAC | `custom-0`, `custom-3` AI ops |
| Hi3518EV300 | Low-cost IP camera | RISC-V RV32IMAC | `custom-0` |
| Hi3519AV100 | Professional camera SoC | Mixed ARM A53 + RISC-V | RISC-V subsystem for NPU control |
| SD3403 | Smart home hub | RISC-V RV64GC | Proprietary crypto extensions |

The RISC-V cores in HiSilicon IP camera SoCs run the Linux kernel (a 32-bit RISC-V Linux port based on OpenHarmony / HiLinux) and host a management plane with HTTP/RTSP server code. This is the primary attack surface for networked security cameras.

---

## RISC-V custom instruction encoding in HiSilicon <sup>[↑](#hisiliconrv32extdecoder)</sup>

The RISC-V ISA reserves four opcode spaces for vendor-defined custom instructions without conflicting with the base ISA or standard extensions:

| Opcode space | Bits [6:2] | Name | HiSilicon use |
|---|---|---|---|
| custom-0 | `00010` | `custom-0` | Lightweight cryptography (SM4 round function acceleration, CRC32C) |
| custom-1 | `00110` | `custom-1` | Reserved / unused in known HiSilicon products |
| custom-2 | `10110` | `custom-2` | Reserved / unused in known HiSilicon products |
| custom-3 | `11110` | `custom-3` | Neural network layer operations (conv2d, maxpool, relu) |

Within each custom opcode space, the `funct3` field (bits [14:12]) and `funct7` field (bits [31:25]) identify specific operations:

**`custom-0` (cryptography):**
- `funct3=0x0, funct7=0x00`: `hisi.sm4round rd, rs1, rs2`: SM4 round function, 1 cycle
- `funct3=0x0, funct7=0x01`: `hisi.sm4key rd, rs1, rs2`: SM4 key expansion round
- `funct3=0x1, funct7=0x00`: `hisi.crc32c rd, rs1, rs2`: CRC32C (Castagnoli polynomial)
- `funct3=0x1, funct7=0x01`: `hisi.crc32 rd, rs1, rs2`: standard CRC32

**`custom-3` (neural network):**
- `funct3=0x0, funct7=0x00`: `hisi.conv2d rd, rs1, rs2`: 3x3 convolution (NPU kickoff)
- `funct3=0x0, funct7=0x01`: `hisi.matmul rd, rs1, rs2`: matrix multiply
- `funct3=0x1, funct7=0x00`: `hisi.relu rd, rs1`: ReLU activation (max(0, x))
- `funct3=0x1, funct7=0x01`: `hisi.maxpool rd, rs1`: 2x2 max pooling

For security analysis, `custom-0` crypto instructions are high-interest: they reveal the algorithm used for firmware signature verification and communication encryption. Finding `hisi.sm4round` in the boot ROM or management plane binary indicates SM4 (Chinese National Standard GB/T 32907-2016) is used, which has known timing side channels in software implementations: but the hardware-accelerated version has fixed timing. The interest is in locating the key material passed in `rs2`.

---

## HiSilicon IP camera firmware attack surface <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon IP cameras are the dominant hardware platform for consumer and semi-commercial surveillance cameras globally (as of 2024, HiSilicon SoCs power an estimated 40–50% of all IP cameras sold worldwide). The firmware runs HiLinux (a Huawei-customized Linux 4.9 or 5.10 kernel for RISC-V) with a BusyBox userspace and the following management plane services:

- **HTTP management interface** (port 80 or 8080): CGI-based or lighttpd with Lua scripts; handles device configuration, RTSP stream setup, motion detection configuration
- **RTSP server** (port 554): video stream delivery; authentication bypass CVEs have been found in multiple HiSilicon RTSP implementations
- **ONVIF service** (port 8000): IP camera network discovery and configuration protocol (WS-Discovery + HTTP SOAP); often runs without authentication
- **Telnet/SSH** (may be enabled in development/OEM firmware): factory mode access

The HTTP management interface is the primary taint source. CGI scripts read parameters from HTTP query strings (`QUERY_STRING` environment variable) or POST bodies and pass them to backend C binaries via pipes or command-line arguments. The C binaries are compiled for the RISC-V core, often using HiSilicon's custom-0 crypto extensions for authentication token verification.

`HiSiRV32Ext` is used after `BinaryContext.load_or_build()` confirms the binary contains RISC-V with custom-3 opcode density (indicating an NPU control binary) or custom-0 opcodes (indicating a crypto/auth binary). The custom opcode scan identifies which algorithm is in use and where keys are loaded.

---

## Complete analysis workflow: HiSilicon IP camera <sup>[↑](#hisiliconrv32extdecoder)</sup>

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.semantic_searcher import SemanticSearcher
from ablation.analyzers.hisi_rv32_ext import HiSiRV32Ext
from ablation.analyzers.taint_tracker_riscv import RISCVTaintTracker

# 1. Build context for the management plane binary
ctx = BinaryContext.load_or_build('/firmware/extract/usr/bin/hi_httpd')
print(ctx.summary())
# Expected: RISC-V RV32IMAC, little-endian, 245 functions

# 2. Semantic sweep for auth/crypto patterns
searcher = SemanticSearcher(ctx)
auth_hits = searcher.query('authentication token verification', top_k=10)
crypto_hits = searcher.query('SM4 block cipher key schedule', top_k=5)

# 3. Scan for HiSilicon custom instructions
ext = HiSiRV32Ext(ctx)
custom0 = ext.scan_custom0()
custom3 = ext.scan_custom3()

print(f"Custom-0 crypto instructions: {len(custom0)}")
for insn in custom0[:5]:
    print(f"  {insn.address:#010x}: {insn.mnemonic} {insn.op_str}")

# 4. Find SM4 key load: rs2 at the first hisi.sm4round is the key register
if custom0:
    first_sm4 = custom0[0]
    # trace rs2 back to its source: that's the key loading VA
    tracker = RISCVTaintTracker.from_context(ctx)
    findings = tracker.trace_arg(first_sm4.address, first_sm4.rs2)
    for f in findings:
        print(f"  Key source: {f}")

# 5. Standard taint for HTTP input -> system() path
sink_findings = tracker.run_interprocedural()
```

---

## RISC-V standard extension context for HiSilicon <sup>[↑](#hisiliconrv32extdecoder)</sup>

HiSilicon's RV32IMAC configuration includes these standard extensions (all standard, no custom behavior):

| Extension | Name | Use in HiSilicon firmware |
|---|---|---|
| I | Base integer | All arithmetic, load/store, branches |
| M | Multiply/divide | Integer multiply for resolution calculations, divide for FPS |
| A | Atomic | Mutex operations in multi-threaded management plane |
| C | Compressed (RVC) | 16-bit compressed instructions to reduce binary size |

The `C` (Compressed) extension creates the same disassembly ambiguity that VLE creates for PPC: standard 32-bit RISC-V tools work fine, but 2-byte and 4-byte instructions are mixed. `BinaryContext` handles RVC automatically via Capstone's RISC-V RVC support; no special decoder is needed (unlike VLE). `HiSiRV32Ext` only adds handling for the `custom-0` and `custom-3` opcodes that Capstone does not recognize.

**Distinguishing custom instructions from illegal instructions:** Capstone decodes unknown opcodes in the custom opcode spaces as `illegal` or raises an error. `HiSiRV32Ext.scan_custom0()` pre-filters instructions where `insn.word & 0x7F == 0x0B` (custom-0 opcode bits [6:0]) before attempting mnemonic assignment; invalid patterns within that space produce `insn.mnemonic = 'hisi.unknown_custom0'` for manual review.

---

## See also <sup>[↑](#hisiliconrv32extdecoder)</sup>

- [RISC-V Taint Tracker](risc-v.md): standard RISC-V analysis for HiSilicon management plane binaries
- [BinaryContext](binary-context.md): build the analysis context before running custom extension scan
- [Semantic Code Search](semantic-code-search.md): locate authentication and crypto functions before running `HiSiRV32Ext`
- [TaintTracker](taint-tracker-alpha.md): trace HTTP input sources through the management plane to system call sinks
- [Pre-Auth Route Auditor](preauth-exposure.md): identify which HTTP CGI paths on the camera are accessible without login
- [FindingRegistry](registry.md): record confirmed HiSilicon findings; use `cwe='CWE-78'` for command injection, `cwe='CWE-798'` for hardcoded credentials found via `custom-0` key scan
- [Length Underflow Scanner](length-underflow.md): for HiSilicon camera HTTP parsing code that processes packet length fields without validation; common in the RTSP and ONVIF parsers
- [SQL Injection Scanner](sql-injection-scanner.md): some HiSilicon camera management planes use SQLite for storing device configuration and user accounts; SQL injection in the configuration API is an authentication bypass class

---

## Limitations and false positive suppression <sup>[↑](#hisiliconrv32extdecoder)</sup>

**Custom instruction false positives:** In firmware compiled for RV32IMAC without HiSilicon custom extensions, any 32-bit word where bits [6:0] happen to equal `0x0B` (the custom-0 opcode) will be flagged by `scan_custom0()` as a potential custom instruction. This commonly occurs in data sections that are adjacent to the code section. `HiSiRV32Ext` mitigates this by only scanning confirmed code sections (from the ELF section headers or `EcuROMLayoutAnalyzer` region classification), but always verify custom instruction finds by checking the surrounding context: a `custom-0` instruction in the middle of clearly non-code data (string tables, constant arrays) is a false positive.

**`funct3`/`funct7` unknown values:** HiSilicon ships multiple firmware generations and has added custom-0 operations in newer SoC revisions not in the decoder's opcode table. Unknown `funct3`/`funct7` combinations produce `insn.mnemonic = 'hisi.unknown_custom0'` or `'hisi.unknown_custom3'`. These are not false positives: they are real custom instructions with unknown semantics. Document them in the finding report as `detail='unrecognized HiSilicon custom-0 operation, funct3=0x{funct3:x} funct7=0x{funct7:x}'` and flag for manual review.

**NPU operations are not security-relevant by default:** `custom-3` neural network instructions (`hisi.conv2d`, `hisi.relu`, etc.) indicate AI/ML processing code. These are only security-relevant if the NPU input buffers are sourced from network data without length validation (potential heap overflow into the NPU DMA descriptor region). Without evidence of a network-sourced input being passed to `hisi.conv2d` without bounds checking, `custom-3` findings are informational (lower priority) not critical.

**Byte verification is required for all RISC-V VA findings:**
```python
with open(binary_path, 'rb') as f:
    data = f.read()
# VA to file offset for standard ELF:
off = va - ctx.base_address
assert data[off:off+4] == struct.pack('<I', insn.word), \
    f"Custom instruction byte mismatch at {va:#x}"
```
This is the same byte-verify discipline applied to all ablation findings. A custom-0 instruction found by opcode scanning must have its raw bytes confirmed against the binary before any finding is registered.

**Estimated scan times (empirical on Hi3516EV300 management plane binaries):**
- Custom instruction scan only (`scan_custom0()` + `scan_custom3()`): < 0.5 seconds on a 1 MB binary
- Full `SemanticSearcher` + custom scan + taint trace: 15–45 seconds depending on function count
- Firmware image extraction (binwalk) + full scan pipeline: 2–5 minutes for a 16 MB camera firmware image
- Crypto key trace (custom-0 sm4round → key source): 1–3 seconds after the initial context is built (BinaryContext caches function boundaries)
