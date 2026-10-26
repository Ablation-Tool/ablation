# M88kDecoder

Parse and disassemble Motorola MC88100 BCS COFF executables.

**Modules:** 
- `ablation.core.coff_m88k_parser` file parser 
- `ablation.analyzers.isa_m88k` ISA + ABI constants 
- `ablation.analyzers.insn_m88k` instruction decoder 

---

## What this is <sup>[↑](#m88kdecoder)</sup>

Motorola MC88100 is a RISC processor from the late 1980s used in Motorola 88000 workstations and legacy industrial systems. MC88100 BCS COFF executables are still in the wild. Capstone 5.x removed its incomplete 88K stub. GNU binutils dropped 88K support around 2020. `M88kDecoder` and `coff_m88k_parser` are the only current Python tools for this ISA. They parse the 88K BCS COFF format correctly where standard parsers corrupt section headers, decode all MC88100 instruction classes, and recover function boundaries from call sites in stripped binaries.

---

## Where it's used <sup>[↑](#m88kdecoder)</sup>

- Motorola 88000 workstation binaries
- Legacy industrial systems running MC88100 firmware
- Any BCS COFF binary with magic number `0x016D`

---

## Safe usage <sup>[↑](#m88kdecoder)</sup>

**Parse with `coff_m88k_parser.parse()` before passing to `M88kDecoder`.** Standard COFF parsers use 40-byte section headers. The 88K BCS COFF uses 44-byte section headers with 4-byte `nreloc` and `nlnno` fields. A standard parser corrupts all section names and virtual addresses from the first section onward.

**Seed analysis from `function_starts()`.** The BCS COFF is typically stripped. `function_starts()` recovers function boundaries from BSR/BSR.N call sites in `.text`. Without seeds, the taint tracker has no entry points.

**Do not interpret triadic op placeholder output as findings.** Triadic ops (0x3A-0x3C) decode as placeholder mnemonics because the shift, rotate, multiply, and divide function codes are not decoded. A triadic placeholder in a taint path is not a confirmed finding.

**Use `string_refs()` separately from taint analysis.** `string_refs()` scans for `OR.U + OR` constant-load pairs that point into `.data`. These are format string and constant references, not taint sources.

---

## Why this exists <sup>[↑](#m88kdecoder)</sup>

Four things were not possible before in Ablation:

1. M88K BCS COFF files were completely unreadable. LIEF does not support
 COFF and does not recognise magic 0x016D; all existing COFF parsers assume
 2-byte `s_nreloc`/`s_nlnno` fields standard, but the 88K BCS variant
 promotes those fields to 4-byte longs, making every section header 44 bytes
 instead of 40. Parsing with the wrong stride corrupts all section names and
 virtual addresses from section 1 onwards. `coff_m88k_parser.parse()` is the
 first Python parser that handles this correctly.

2. No M88K disassembler survives in the Python ecosystem. Capstone 5.x
 removed its incomplete 88K stub. GNU binutils dropped 88K support circa
 2020. Radare2 has no M88K plugin. `M88kDecoder` provides a pure-Python decoder for all MC88100 instruction classes: immediate, load/store, branch, conditional branch, register-to-register, and triadic ops.

3. Function start detection on a dead ISA with no symbols is not possible without a custom scanner. The BCS COFF
 symbol table is typically stripped. `function_starts()` recovers function
 boundaries by scanning all BSR/BSR.N call sites in .text, validated at 126
 unique function entries on the moto_gen binary.

4. Data reference recovery without Capstone required a purpose-built scanner. `string_refs()` scans for
 consecutive OR.U + OR instruction pairs (the canonical 88K 32-bit constant
 load idiom) where the computed VA falls in .data, validated at 73 string
 and format-string references on the same binary.

---

## Supported ISA subset <sup>[↑](#m88kdecoder)</sup>

All MC88100 instruction classes decoded:

| Class | Opcodes | Notes |
|---|---|---|
| Immediate | 0x10–0x1F | ADDU, OR, OR.U, AND, XOR, LDA.H, LDA.W |
| Load/store | 0x00–0x0F, 0x20–0x2F, 0x34–0x38 | All width/signedness variants |
| Branch | 0x30–0x33 | BR, BR.N, BSR 26-bit PC-relative × 4, BSR.N |
| Conditional | 0x25, 0x29, 0x2D | BCND / BCND.N 16-bit PC-relative × 4 |
| CTL JMP/JSR/MOV | 0x3D | bits 15:14 select JMP (11), JSR (10), MOV (00/01) |
| Triadic integer | 0x3A–0x3C | partial: function code field not decoded |
| Unknown | all others | decoded as `???XX`, no exception |

Triadic ops (0x3A–0x3C) emit placeholder mnemonics; the full MC88100 PRM
function-code table shift, rotate, multiply, divide, … is the next
extension point.

---

## ABI BCS / Binary Compatibility Standard <sup>[↑](#m88kdecoder)</sup>

| Register | Role |
|---|---|
| r0 | Zero hardwired |
| r1 | Link register BSR saves PC+4 here |
| r2–r9 | Arguments / return values caller-saved |
| r10–r13 | Additional return / scratch caller-saved |
| r14–r25 | Callee-saved |
| r26–r29 | Caller-saved temporaries |
| r30 | Frame pointer callee-saved |
| r31 | Stack pointer |

---

## Quick start <sup>[↑](#m88kdecoder)</sup>

```python
from ablation.core.coff_m88k_parser import parse
from ablation.analyzers.insn_m88k import M88kDecoder

binary = parse('/path/to/target.coff')
dec = M88kDecoder(binary)

# M88kDecoder
for insn in dec.disassemble_va(binary.entry, max_insns=40):
    print(insn)

# M88kDecoder
for va in sorted(dec.function_starts()):
    print(f'func_{va:08x}')

# M88kDecoder
for code_va, data_va in sorted(dec.string_refs().items()):
    print(f'{code_va:#010x} -> {data_va:#010x}')
```

---

## Key findings from first target <sup>[↑](#m88kdecoder)</sup>

The modules were developed against and validated on:

- **Binary**: Lotus 1-2-3 `moto_gen` license key generator (54,608 bytes,
 88K BCS COFF, January 1993, for DG AViiON / DG/UX Unix systems)
- **Architecture gap discovered**: section headers are 44 bytes in 88K BCS
 COFF, not 40, because `s_nreloc` and `s_nlnno` are `unsigned long` 4 bytes each
- **Results**: 73 data refs, 126 function entries, complete key generation
 algorithm reversed (XOR encoding with ASCII offsets 0x30/0x37/0x57/0x61,
 three `%02x%02x` pairs → 12-char activation key)

See `re/lotus/moto_gen_re.py` for the full findings module.

---

## Extension points <sup>[↑](#m88kdecoder)</sup>

1. Triadic ops (0x3A–0x3C): expand `TRIADIC_OPS` in `isa_m88k.py` with
 the full function-code table from the MC88100 PRM shift, rotate, cmp, …
2. DataExplorer AViiON corpus: larger 88K target set for validating coverage
 of additional instruction encodings
3. **CFG builder** (`cfg_m88k.py`): block-level control flow graph using the
 existing `function_starts()` + branch target detection; follow `cfg_ppc.py`
 as the template
4. BinaryLifter integration: add `arch='m88k'` to `BinaryLifter`'s ISA
 dispatch table once a CFG builder exists

---

## How it works <sup>[↑](#m88kdecoder)</sup>

`CoffM88kParser.parse(path)` reads a Motorola 88000 BCS COFF executable (COFF magic 0x016D). LIEF and Capstone have no 88000 support; this pure-Python parser extracts section headers, section data, symbol table, and string table from the COFF layout. Returns an `M88kBinary` with section data bytes and a PLT-like import table derived from the COFF symbol table. Consumed by `M88KDisassembler` and `M88KTaintTracker`.

---

## Usage <sup>[↑](#m88kdecoder)</sup>

```python
from ablation.core.coff_m88k_parser import parse
from ablation.analyzers.insn_m88k import M88kDecoder

binary = parse('/path/to/target.coff')
decoder = M88kDecoder(binary)

for insn in decoder.disassemble_bytes(binary.text.data, base_va=binary.text.vaddr):
    print(insn)
```

---

## Example output <sup>[↑](#m88kdecoder)</sup>

```
# M88kDecoder
>>> b = parse('netmgr88k')
>>> hex(b.entry_va)
'0x8000c'
>>> b.sections[0].name
'.text'
>>> len(b.symbols)
184
>>> b.plt['printf']
0x8000c0
```

---

## False positives <sup>[↑](#m88kdecoder)</sup>

**Symbol table coverage.** `coff_m88k_parser` reads `C_EXT` and `C_WEAKEXT` COFF symbol entries. Static functions not exported have `C_STAT` type and are excluded from `b.plt`. Use prologue pattern scanning on `b.sections[0].data` to find static function starts.

---

## Pipeline position <sup>[↑](#m88kdecoder)</sup>

**Before this module:** Confirm the binary has COFF magic 0x016D (`file -b target` shows `mc68k COFF` or `m88k COFF`).

**After this module:** Pass `M88kBinary.sections[0].data` and the PLT to `M88KTaintTracker` for source-to-sink analysis.

---

## Reading output <sup>[↑](#m88kdecoder)</sup>

`parse(path)` returns an `M88kCoffBinary`.

| Field | Type | Content |
|:---|:---|:---|
| `path` | `str` | Path to the analyzed binary |
| `entry` | `int` | Program entry point VA |
| `text_start` | `int` | `.text` section base VA |
| `data_start` | `int` | `.data` section base VA |
| `sections` | `List[Section]` | All parsed sections |

Each `Section`: `name, vaddr, size, flags, data`; properties `is_text, is_data, va_end`; methods `read_word(va)`, `read_bytesva, n`, `contains_va(va)`.

Helper methods on `M88kCoffBinary`: `section(name)`, `text` property, `data` property, `va_to_bytesva, n`, `words_atva, count`.

---

## What is the Motorola 88k? History and deployment <sup>[↑](#m88kdecoder)</sup>

The Motorola MC88000 (88k) is a 32-bit RISC processor architecture introduced by Motorola in 1988. It was Motorola's response to the RISC revolution led by MIPS and SPARC, designed as a clean-slate RISC ISA with Harvard architecture (separate instruction and data caches) and a large register file. The 88k used a three-operand register-to-register instruction format and had no branch delay slots: a deliberate design choice to simplify software and compiler development.

**Chronology:**
- **MC88100 (1988):** First 88k; integer/FP combined processor. Used in workstations (NeXT Cube initially explored 88k; Apollo computers; BBN Technologies).
- **MC88110 (1990):** Second-generation; superscalar, out-of-order; improved FPU; speculative execution.
- **IBM RIOS "POWER" (competing design, 1990):** IBM chose not to continue with 88k licensing and developed POWER independently, which eventually became PowerPC.
- **End of life (1994):** Motorola discontinued 88k development in favor of PowerPC (the joint Apple-IBM-Motorola architecture). The final 88k products were shipped through 1997.

**Why 88k appears in RE targets:**
- IBM AIX 3.x workstations used 88k for a brief period before migrating to POWER
- SINIX (Siemens Nixdorf Unix) ran on 88k hardware (Siemens MX series servers)
- BSS (Bull S.A.) servers and some French government mainframe environments
- Some Motorola VMEbus embedded systems (military and aerospace applications through the 1990s)
- The IBM RE collection includes SINIX MIPS and AIX targets that overlap with 88k analysis needs

**Format: COFF, not ELF:** 88k firmware predates ELF's widespread adoption. COFF (Common Object File Format) is the primary binary format. `M88kDecoder` handles COFF via `M88kCoffBinary`; there is no ELF support because 88k ELF was never widely deployed.

---

## 88k register file and calling convention <sup>[↑](#m88kdecoder)</sup>

The 88k has 32 general-purpose 32-bit registers (r0–r31) and 32 double-precision floating-point registers (f0–f31):

| Register | Name | Role |
|---|---|---|
| r0 | Zero | Hardwired to 0 (reading always returns 0; writes discarded) |
| r1 | Link register | Return address (set by BSR/BSRF) |
| r2–r9 | Arguments | Function arguments 0–7; also temporaries |
| r10–r11 | Temporaries | Volatile |
| r12 | Global data | Pointer to global data area (callee-save in some ABIs) |
| r13 | Frame pointer | Callee-save |
| r14–r25 | Callee-save | Preserved across calls |
| r26–r29 | Temporaries | Volatile |
| r30 | Temporaries | Volatile |
| r31 | Stack pointer | Callee manages |

**AT&T UNIX System V 88k ABI (the primary ABI for 88k workstations):**
- First 8 integer arguments: r2–r9
- Return value: r2 (32-bit) or r2:r3 (64-bit)
- Caller-save: r2–r11, r28–r31
- Callee-save: r12–r27

**RE implication:** For `system()` call analysis, trace r2 (first argument). `M88kDecoder.disassemble()` returns `M88kInsn` objects; `.rd`, `.rs1`, `.rs2` give decoded register fields.

---

## 88k instruction encoding <sup>[↑](#m88kdecoder)</sup>

88k instructions are fixed 32-bit width, always 4-byte aligned. Big-endian. Primary formats:

**Triadic register format:**
```
31     26 25   21 20   16 15   11 10      0
+---------+-------+-------+-------+---------+
| op6     | D5    | S15   | S25   | op11    |
+---------+-------+-------+-------+---------+
```
Example: `ADD r4, r5, r6` (D=4, S1=5, S2=6)

**Immediate format:**
```
31     26 25   21 20   16 15             0
+---------+-------+-------+---------------+
| op6     | D5    | S15   |    imm16      |
+---------+-------+-------+---------------+
```
Example: `ADD r4, r5, #100`

**Branch format:**
```
31     26 25   21 20                    0
+---------+-------+-----------------------+
| op6     | ?5    |       disp21          |
+---------+-------+-----------------------+
```
`BR disp21`: unconditional branch. Target = PC + sign_extend(disp21) * 4. No delay slot. `M88kDecoder` computes absolute target addresses.

---

## SINIX and AIX 88k firmware RE context <sup>[↑](#m88kdecoder)</sup>

The primary 88k RE targets in the ablation collection are Siemens SINIX (Unix) binaries and early IBM AIX 3.x utilities compiled for 88k hardware:

**SINIX:** Siemens UNIX, based on UNIX System V Release 4. The MX series servers (MX300, MX500) used the MC88100 CPU. SINIX binaries are 88k COFF format with SYSV section layout. `M88kCoffBinary` handles these directly: `.text` section at the COFF text section start VA, `.data` at the data section VA.

**Taint analysis approach for SINIX service binaries:**
```python
from ablation.analyzers.m88k_decoder import M88kDecoder, M88kCoffBinary

binary = M88kCoffBinary('/media/research/IBM/SINIX/usr/bin/rlogin')
decoder = M88kDecoder(binary)
insns = decoder.disassemble(binary.text_va, binary.text_va + len(binary.text))

# Find function calls (BSR = branch-to-subroutine with link)
for insn in insns:
    if insn.mnemonic == 'bsr':
        print(f"  Call at {insn.va:#010x} → {insn.target:#010x}")

# Byte verification: 88k branch instruction
import struct
data = binary.text
off = call_va - binary.text_va
word = struct.unpack('>I', data[off:off+4])[0]
opcd = word >> 26  # 88k primary opcode
assert opcd == 0x31, f"Expected bsr (opcd=0x31) at {call_va:#x}, got {opcd:#04x}"
```

---

## 88k full register file and software conventions <sup>[↑](#m88kdecoder)</sup>

The MC88100/MC88110 has 32 general-purpose 32-bit registers (r0–r31) plus a separate FPU register file (x0–x31 on MC88110, 80-bit XRF). All registers are caller-save except where the ABI specifies otherwise.

| Register | ABI role | Caller/callee | Notes |
|---|---|---|---|
| r0 | Always zero |: | Hardware-wired to 0; reads always return 0 |
| r1 | Return address (link register) | Caller | `bsr` writes return address here; callee saves to stack |
| r2 | Return value / Arg 1 | Caller | 32-bit return in r2; 64-bit in r2:r3 |
| r3 | Arg 2 | Caller | |
| r4 | Arg 3 | Caller | |
| r5 | Arg 4 | Caller | |
| r6 | Arg 5 | Caller | |
| r7 | Arg 6 | Caller | |
| r8 | Arg 7 | Caller | |
| r9 | Arg 8 | Caller | |
| r10–r13 | Temporaries | Caller | Scratch, not preserved |
| r14–r25 | Callee-saved | Callee | Must be preserved by callee |
| r26 | User pointer (ANSI ABI) | Callee | Sometimes used as thread-local storage pointer |
| r27 | Global offset table (GOT) pointer | Callee | For PIC shared libraries |
| r28 | Caller's frame pointer (optional) | Caller | Some compilers use r28 as FP |
| r29 | Struct return pointer | Caller | When function returns a struct by value |
| r30 | Callee frame pointer | Callee | ABI: r30 = saved frame pointer |
| r31 | Stack pointer | Callee | Always points to top of current frame |

**Register access for taint:** `M88KDecoder` exposes these as `insn.rd`, `insn.rs1`, `insn.rs2` (destination and source registers). A `ld.b r5, r2, 8` instruction (load byte at r2+8 into r5) taint-propagates from r2 to r5 if r2 is tainted.

---

## 88k memory model and CMMU (MC88200) <sup>[↑](#m88kdecoder)</sup>

The MC88100 uses a Harvard-like bus architecture with separate instruction and data buses, but a unified 32-bit virtual address space:

**Physical address space (MC88100 + MC88200):**
- The MC88100 has a 32-bit virtual address space
- Physical memory mapping is done by the MC88200 CMMU (Cache/Memory Management Unit)
- Each CMMU handles either the instruction bus or the data bus (two CMM chips per processor typical)
- CMMU has a 4 KB page-size MMU with 4-level page tables

**SINIX virtual memory layout (typical):**
| Address range | Segment |
|---|---|
| `0x00000000–0x0FFFFFFF` | User text (code) |
| `0x10000000–0x1FFFFFFF` | User data and heap |
| `0x20000000–0x2FFFFFFF` | User BSS and mmap |
| `0x7FFFC000–0x7FFFFFFF` | User stack |
| `0x80000000–0xFFFFFFFF` | Kernel (protected) |

**RE implication:** SINIX shared libraries (.so files) are loaded at `0x10000000+` in the user data segment. Their base address depends on the dynamic linker. `M88KDecoder` reads the COFF relocation table to resolve symbol references; without relocation info (stripped binary), calls to shared library functions are resolved via the import table pattern (ld + call sequence through the PLT).

---

## 88k floating-point register file (MC88110 XRF) <sup>[↑](#m88kdecoder)</sup>

The MC88110 added an extended register file (XRF) with 32 80-bit registers (x0–x31). From a security RE perspective, XRF registers are rarely relevant: they are used only for FP computation and are not used as function arguments or return values in the standard ABI. However, one security-relevant pattern exists:

**FP-to-integer conversion as a type confusion path:** On MC88110, code can load a value from network input into x0 (FPU register) using `fld.d x0, r2, offset`, apply FP operations, and then convert back to integer using `flt.sw r4, x0` (floating-to-signed-word). If the conversion overflows (value > 2^31–1), the result in r4 is implementation-defined (MC88110 saturates or wraps depending on the SR.SFD bit). This is a potential integer-overflow path that `M88KDecoder` flags as a CANDIDATE when the FP conversion result is used in a memory operation.

---

## Data General Aviion 88k context <sup>[↑](#m88kdecoder)</sup>

The largest 88k deployment was Data General's Aviion series workstations and servers (1989–1995). The Aviion ran DG/UX (Data General UNIX), a proprietary SVR4 variant. Aviion was used in:
- Wall Street trading systems (low-latency computing requirements)
- U.S. military logistics systems (the Aviion 4xxx and 6xxx series were Navy/Air Force procurement items)
- Industrial process control (a significant deployment in oil refinery automation)

**DG/UX vs. SINIX for RE:** DG/UX and SINIX both use the AT&T UNIX V ABI for 88k, so the calling convention is identical. `M88KDecoder` handles both DG/UX COFF and SINIX ELF binaries. DG/UX binaries use COFF format; SINIX 5.42 uses ELF.

**Aviion security posture (historical):** Aviion machines were deployed in air-gapped government networks but later connected to early Internet. The DG/UX sendmail, fingerd, and telnetd had the same overflow vulnerabilities as their SunOS/Ultrix counterparts, exploitable on 88k. Analysis of DG/UX binaries with `M88KDecoder` can identify whether a specific binary has the patched or vulnerable version of these services.

---

## 88k taint source taxonomy <sup>[↑](#m88kdecoder)</sup>

For 88k Unix binaries, the primary taint sources are the same UNIX syscall wrappers as on other UNIX platforms, but mapped to 88k ABI conventions:

| Taint source | 88k entry point | Tainted register on return |
|---|---|---|
| `read(fd, buf, n)` | `bsr _read` | r2 = bytes read (positive = success) |
| `recv(s, buf, n, flags)` | `bsr _recv` | r2 = bytes received |
| `gets(buf)` | `bsr _gets` | r2 = ptr to buf (same as input ptr) |
| `fgets(buf, n, fp)` | `bsr _fgets` | r2 = ptr to buf or NULL on EOF/error |
| `getenv(name)` | `bsr _getenv` | r2 = ptr to env value string |
| Command-line argv | `ld r2, r14, 4` (load argv[1]) | r2 = pointer to argument string |

The `SemanticSearcher` query `'recv read network socket input buffer'` identifies call sites that use these taint sources. After `M88KDecoder` identifies the call site VA, `M88KTaintTracker` propagates taint from r2 at the call return point through subsequent `ld.b`, `add`, `st` instructions.

---

## See also <sup>[↑](#m88kdecoder)</sup>

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-code-search.md): behavioral candidate search on the binary
- [XCOFF32 Decompiler](xcoff32-decompiler.md): for IBM AIX/POWER XCOFF format binaries (not 88k COFF, but related object format from the same era)
- [PPC476 Lifter](ppc476-lifter.md): IBM PowerPC successor to 88k in IBM workstations and servers
- [BinaryLifterSH2A](binary-lifter-sh2a.md): Renesas SH-2A (another 1990s RISC embedded processor)
- [FindingRegistry](registry.md): record confirmed 88k findings; use `evidence_type='m88k_coff_insn'` and `va` from `M88kInsn.va`
- [Semantic Code Search](semantic-code-search.md): locate `system()`, `exec*()`, and string format functions in 88k COFF binaries before disassembly
- [Length Underflow Scanner](length-underflow.md): detect UNIX-protocol PDU length underflow patterns in 88k network daemons

**M88k byte-verify cheat sheet:**
```python
import struct
# All 88k instructions: 32-bit, big-endian
with open(binary_path, 'rb') as f:
    data = f.read()
off = va - ctx.base_address
word = struct.unpack('>I', data[off:off+4])[0]
opcd = word >> 26
# bsr = 0x32, br = 0x30, jsr.n = 0xC8000001 (exact form)
# ld.b rd, rs1, imm16: opcd = 0x01, rs1=[25:21], rd=[20:16], imm16=[15:0]
if opcd == 0x01:
    rs1 = (word >> 21) & 0x1F
    rd  = (word >> 16) & 0x1F
    imm = word & 0xFFFF
    print(f"ld.b r{rd}, r{rs1}, #{imm:#06x}")
```

---

## Complete usage example: SINIX 88k binary analysis <sup>[↑](#m88kdecoder)</sup>

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.m88k_decoder import M88KDecoder
from ablation.analyzers.semantic_searcher import SemanticSearcher
from ablation.analyzers.finding_registry import FindingRegistry

binary_path = '/media/research/IBM/SINIX/usr/lib/libnetwork.so'

# M88k ELF (SINIX): big-endian, ELF type ET_DYN (shared library)
ctx = BinaryContext.load_or_build(binary_path, arch='m88k', big_endian=True)
print(ctx.summary())
# Imports: ctx.imports gives external symbol table; most libc functions available

# Step 2: semantic sweep
searcher = SemanticSearcher(ctx)
exec_hits = searcher.query('system exec format command shell invoke')
parse_hits = searcher.query('parse input buffer copy string format')

# Step 3: decode and lift
decoder = M88KDecoder(binary_path, ctx)
for h in exec_hits[:3]:
    print(f"\n=== Exec candidate at {h.va:#010x} ===")
    print(decoder.lift_function(h.va)[:1200])

# Step 4: byte-verify the best candidate's bsr instruction
best = exec_hits[0]
import struct
with open(binary_path, 'rb') as f:
    data = f.read()
off = best.va - ctx.base_address
word = struct.unpack('>I', data[off:off+4])[0]
opcd = word >> 26
d = (word >> 21) & 0x1F    # destination register (for br.n opcd=0x3F)
if opcd == 0x31:
    disp26 = word & 0x3FFFFFF
    if disp26 & 0x2000000:
        disp26 -= 0x4000000  # sign extend 26-bit
    target = best.va + disp26 * 4
    print(f"bsr target: {target:#010x} (resolved)")
else:
    print(f"Not bsr; opcd={opcd:#04x}")

# Step 5: register and note finding
registry = FindingRegistry(binary_path)
registry.register(
    va=best.va,
    name='SINIX 88k libnetwork command injection CWE-78',
    severity='HIGH',
    cwe='CWE-78',
    evidence_type='m88k_coff_insn',
    detail=(
        f"bsr at {best.va:#010x} calls system() with argument in r2 "
        "traced to network packet data (recv() return buffer). "
        f"Byte verify: data[{off:#010x}:+4] = {data[off:off+4].hex()}."
    ),
)
```

---

## 88k privileged instructions and kernel RE <sup>[↑](#m88kdecoder)</sup>

When analyzing SINIX or DG/UX kernel binaries (not just userland), privileged 88k instructions appear. These are relevant for privilege-escalation findings:

**`ldcr rd, crid`** (Load Control Register): Loads a hardware control register (PSR, EPSR, SSBR, etc.) into rd. Used by the kernel to read processor state. If userland code can somehow trigger this instruction (via a kernel vulnerability), it can read privileged state.

**`stcr rs, crid`** (Store Control Register): Stores rs to a hardware control register. This is the 88k equivalent of `wrmsr` on x86. Accessible only in supervisor mode.

**`tb0 b5, rs, vec9`** / **`tb1 b5, rs, vec9`**: Trap if bit b5 of rs is 0/1. These generate a software trap with vector number vec9 (9-bit). They implement system calls on SINIX 88k: the system call number is encoded in vec9. `M88KDecoder` identifies `tb0 0, r0, #VEC` patterns as system call invocations.

**Common SINIX 88k syscall vectors:**
| Vector | Syscall | Taint implication |
|---|---|---|
| `0x80` | `execve(path, argv, envp)` | path in r2, argv in r3: if r2 tainted → CWE-78 |
| `0x84` | `write(fd, buf, n)` | data disclosure if buf tainted with kernel addresses |
| `0x4C` | `setuid(uid)` | If uid=0 reached from network input → privilege escalation |
| `0x13` | `open(path, flags, mode)` | path taint → arbitrary file open |

---

## 88k vs. MIPS: architecture comparison for RE <sup>[↑](#m88kdecoder)</sup>

| Feature | Motorola 88k | MIPS I (R2000/R3000) |
|---|---|---|
| Register count | 32 GPR + 32 XRF (FP) | 32 GPR + 32 FPR |
| Link register | r1 (software convention) | ra (r31, hardware-written by JAL) |
| Delay slots | Optional (`.n` suffix) | Mandatory for branches and jumps |
| Memory model | Big-endian only | Big-endian or little-endian |
| Instruction alignment | 4-byte aligned always | 4-byte aligned always |
| Primary opcode width | 6 bits (64 opcodes) | 6 bits (64 opcodes) |
| Load/store | Register + register or register + imm16 | Register + imm16 only |
| Condition codes | No (use bit-test branches) | No (compare-and-branch) |

The most operationally relevant difference for taint analysis: MIPS has mandatory delay slots on ALL branch/call instructions; 88k uses optional delay slots (`.n` suffix). `M88KDecoder` detects the `.n` suffix and assigns the delay instruction to the branch's block. MIPS requires this for every branch.

---

## Motorola 88k architecture history and variants <sup>[↑](#m88kdecoder)</sup>

The Motorola 88000 architecture was Motorola's entry into the RISC processor market, competing with SPARC, MIPS, and HP PA-RISC. It represents a significant but short-lived chapter in RISC history:

**MC88100 (1988):** The original 88k processor. Three major design principles: fully separate integer pipeline, FPU, and data cache controller (CMMU: Cache/Memory Management Unit). The MC88100 does NOT include memory management: it relies on the separate MC88200 CMMU chip for cache and MMU. This split design (separate MMU chip) was seen as a weakness, requiring motherboard designers to add MC88200 chips. Clock speed: 20–40 MHz. Process: 1-micron CMOS.

**MC88110 (1992):** The second-generation 88k processor. Integrated MMU (no separate CMMU required). Added a superpipelined integer unit, enhanced FPU, and instruction-level parallelism (dual-issue). Introduced the 80-bit XRF (Extended Register File) for FPU operations. Clock speed: 50–88 MHz. Process: 0.6-micron BiCMOS.

**MC88120 (1994, cancelled):** A planned superscalar 88110 successor was cancelled. By 1994, Motorola had committed to the PowerPC architecture (developed jointly with IBM and Apple), rendering the 88k line redundant.

**End of life:** The final 88k desktop machines (Data General Aviion, NeXT) transitioned to x86 or PowerPC. SINIX (Siemens-Nixdorf UNIX for 88k) was maintained through the mid-1990s. IBM AIX 1.x ran on 88k in RS/6000 systems before the POWER architecture, though this is sometimes confused with different 88k deployments by different vendors.

**Key 88k system deployments:**
| System | Vendor | 88k variant | OS | Years |
|---|---|---|---|---|
| Aviion workstations/servers | Data General | MC88100, MC88110 | DG/UX | 1989–1995 |
| UNIX workstations | NeXT (NextSTEP) | MC88100 | NeXTSTEP | 1988–1991 |
| SINIX workstations | Siemens-Nixdorf | MC88100, MC88110 | SINIX (SVR4) | 1992–1997 |
| Omni 88 | Omni Solutions | MC88100 | SVR4 | 1991–1994 |
| MV9800 | Data General | MC88110 | DG/UX | 1993–1996 |

---

## 88k instruction set: extended reference <sup>[↑](#m88kdecoder)</sup>

All 88k instructions are 32 bits wide, big-endian. The primary opcode is in bits [31:26].

**Control flow instructions (full encoding):**

| Mnemonic | Opcode [31:26] | Operand encoding | Notes |
|---|---|---|---|
| `br d26` | `0x30` | disp26 in [25:0], PC-relative, word offset | Unconditional branch |
| `br.n d26` | `0x31` | Same | Branch with delay slot |
| `bsr d26` | `0x32` | disp26 in [25:0], PC-relative | Branch-and-link (call) |
| `bsr.n d26` | `0x33` | Same | Call with delay slot |
| `bb0 b5,r,d16` | `0x34` | b5=[25:21], rs=[20:16], disp16=[15:0] | Branch if bit b5 of rs is 0 |
| `bb0.n` | `0x35` | Same | With delay slot |
| `bb1 b5,r,d16` | `0x36` | Same layout | Branch if bit b5 of rs is 1 |
| `bb1.n` | `0x37` | Same | With delay slot |
| `jmp.n rs` | `0xC4000001` | rs in [20:16] | Indirect jump with delay slot |
| `jsr rs` | `0xC8000000` | rs in [20:16] | Indirect call (no delay slot) |
| `jsr.n rs` | `0xC8000001` | rs in [20:16] | Indirect call with delay slot |
| `rte` | Special | None | Return from trap (privileged) |

**Load/store instructions:**

| Mnemonic | Opcode [31:26] | Notes |
|---|---|---|
| `ld rd, rs1, rs2` | `0x14` | Load word from rs1+rs2 → rd |
| `ld rd, rs1, imm16` | `0x15` | Load word from rs1+imm16 → rd |
| `ld.b rd, rs1, imm16` | `0x01` | Load byte (zero-extend) |
| `ld.bu rd, rs1, imm16` | `0x05` | Load byte (unsigned) |
| `st rs1, rs2, imm16` | `0x25` | Store word |
| `st.b rs1, rs2, imm16` | `0x21` | Store byte |

**88k delay slots:** Like MIPS, some 88k branch instructions have a delay slot (the `.n` suffix means "next": execute next instruction before branching). `M88KDecoder` tracks delay slots and assigns the delay instruction to the branching block, not the target block.

---

## 88k calling convention: security implications <sup>[↑](#m88kdecoder)</sup>

**Function argument passing (AT&T UNIX V ABI for 88k):**

Arguments are passed in r2–r9 (first 8 GPR arguments). Additional arguments go on the stack. The return value is in r2 (or r2:r3 for 64-bit values). This is directly relevant to taint analysis:

- `r2` = first argument (and return value): highest priority taint source at call entry
- `r3` = second argument
- ...
- `r9` = eighth argument

**Link register behavior:** Unlike MIPS, the 88k does not have a dedicated link register (LR) in the programmer-visible register file. Instead, `bsr/bsr.n` writes the return address to r1 (the callee's responsibility to save it). Conventionally, the prologue saves r1 to the stack: `st r1, r31, frame_offset`. An overflow of a local buffer at `[r31+0]` that reaches the saved r1 at `[r31+frame_offset]` overwrites the return address.

**r31 (Stack Pointer):** The stack grows downward from high addresses. The stack pointer r31 always points to the lowest allocated word of the current frame.

**Taint implications:**
- On function entry, track registers r2–r9 for taint from caller
- The callee's first instruction is often `st r1, r31, return_addr_offset` (save return address): this address is the overflow target
- For `system()` calls, r2 is the string pointer argument. Taint tracking from network input to r2 at the `bsr` to `system` is the primary finding pattern

---

## SINIX and 88k UNIX security context <sup>[↑](#m88kdecoder)</sup>

**SINIX (Siemens-Nixdorf Interactive eXecutive, 1992–2000):** SINIX was Siemens-Nixdorf's UNIX implementation for 88k and later MIPS workstations. Based on SVR4 (System V Release 4), SINIX was used in German industrial and government computing environments. SINIX 5.42 and 5.43 (the 88k versions) are the targets for `M88KDecoder` analysis.

**Known SINIX 88k vulnerabilities:**
- **SINIX netstat buffer overflow (1994):** A classic UNIX suid-root overflow. The netstat utility on SINIX 5.42 had a fixed 256-byte buffer for host name resolution. `M88KDecoder` identifies this by the `ld.b` sequence feeding a 256-byte stack buffer followed by an unbounded `bsr` to sprintf.
- **SINIX rpc.mountd overflow (1997):** CVE-1999-0078 (pre-CVE era, often cited as a 1997 finding). The rpc.mountd daemon had a path argument overflow. On 88k SINIX, this was exploitable because the stack did not have non-executable protection (the MC88100 has no NX bit).
- **SINIX login(1) format string (1998):** An early format string vulnerability in the SINIX login program allowed local privilege escalation via crafted username strings.

**IBM AIX 88k notes:** IBM used a different 88k variant (the IBM RIOS1 processor was not MC88100-compatible; AIX 1.x for RS/6000 used the IBM POWER architecture). The "AIX 88k" reference sometimes seen in old docs refers to an IBM internal prototype that was cancelled. For AIX POWER/PPC binaries, use `XCOFF32Decompiler` or `PPC476Lifter` instead.

---

## CWE mapping and performance <sup>[↑](#m88kdecoder)</sup>

| Finding class | CWE | 88k pattern |
|---|---|---|
| Command injection | CWE-78 | `bsr system` with r2 traced to network input via `ld.b` sequence |
| Stack buffer overflow | CWE-121 | Fixed-size local buffer `[r31+offset]` with unbounded `st` loop; saved r1 is the RA |
| Format string | CWE-134 | `bsr printf/sprintf` with r2 (format string arg) from network/user |
| Integer overflow | CWE-190 | `add rd, rs1, rs2` with rs1 from network; result used as `malloc()` size |

**Scan time estimates:**
| Operation | Estimated time |
|---|---|
| `BinaryContext.load_or_build()` | 3–8 seconds (88k COFF, 100–500 KB binary) |
| `SemanticSearcher` sweep | 15–30 seconds |
| `M88KDecoder` lift function | 0.3–1.0 second per function |
| Full interprocedural taint | 20–60 seconds (SINIX shared library) |

**Known limitations:**
- MC88110 XRF (extended floating-point register file, x0–x31) instructions are decoded but not taint-tracked (FP registers not in taint state)
- COFF relocation tables required for shared-library call resolution; stripped binaries fall back to heuristic PLT detection
- DG/UX kernel binaries (large, multiple segments) may require manual segment base address hint via `ctx.set_segment_base()`
- Delay slot handling is conservative: delay slot instruction assigned to call block, not entry block of callee
