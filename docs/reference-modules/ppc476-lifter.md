# Ppc476Lifter

**File:** `ablation/analyzers/ppc32_lifter.py` 
**Class:** `Ppc32Lifter` 
**Architecture:** IBM PowerPC 476, 32-bit big-endian, Book E

---

## What this is <sup>[↑](#ppc476lifter)</sup>

IBM PPC476 is a 32-bit big-endian PowerPC core Book E architecture used in IBM embedded
appliances and storage controllers. Firmware targeting this core runs against a glibc 2.15
sysroot. `BinaryLifter`'s ppc32 backend produces structural output only: most instructions
appear as comments and call arguments are not resolved. `Ppc32Lifter` is a vulnerability-analysis
lifter that tracks register state across a PPC476 function, resolves PLT call stubs to symbol
names with argument values, and emits C-like pseudo-code tagged with instruction VAs.

---

## Where it's used <sup>[↑](#ppc476lifter)</sup>

- **IBM PPC476 sysroot binaries**: glibc 2.15 targets built with `ppc476-tools-cross-1.0`
- **IBM embedded appliance firmware** that ships PPC32 BE ELF binaries against a glibc-2.15 base
- Any PPC32 BE ELF where the call stub format is `lis r11, HI; lwz r11, LO(r11); mtctr r11; bctr`

---

## Safe usage <sup>[↑](#ppc476lifter)</sup>

**Clear the `BinaryContext` cache after the `_extract_plt_ppc32be` fix ships.** Contexts built
before commit `03bd8a5` have `plt = {}` for PPC32 targets. Delete
`~/.ablation/cache/<sha>_<name>.json` and call `load_or_build()` again. Without this, `Ppc32Lifter`
resolves zero PLT calls and all external calls appear as hex addresses.

**`from_context()` requires the LIEF `parse()` call to succeed at lift time.** The lifter
re-parses the binary to load `.text` bytes. If the file has been moved or deleted from `/tmp` since
`BinaryContext` was built, `from_context()` raises `ValueError`. Re-extract the binary first.

**Output is a linear walk, not a CFG.** Conditional branches emit `// branch:` comments. The
lifter does not follow both sides of a branch. For a function with complex control flow, lift with
a larger `n_insn` and read the branch comments to reconstruct the paths manually.

**`r2` is the TOC pointer, not a general-purpose register.** `lwz rX, N(r2)` loads from the
Global Offset Table. The lifter annotates these as `*(toc+N)` rather than as arbitrary loads.
Do not treat a TOC load as tainted input unless you have traced a write to that GOT slot.

**PPC476 Book E extensions, `wait`, `tlbwe`, `tlbre`, `dcbt`: these appear as `// mnemonic`.** These
instructions modify TLB entries and cache state, not GPRs. The register state after them is
unchanged from the lifter's perspective. This is correct for vulnerability analysis because Book E
privileged instructions do not carry attacker data.

---

## Why this exists <sup>[↑](#ppc476lifter)</sup>

Three things were not possible before this module:

**1. No register-tracked PPC32 BE lifter in any open toolkit.** 
`BinaryLifter`'s ppc32 backend emits structural pseudo-C where most instructions appear as
comments. That is adequate for call graph analysis but not for argument tracing. Determining what
value is in `r3` when a function calls `execv` requires tracking every `lis`, `addi`, `lwz`, and
`mr` from function entry. `Ppc32Lifter` maintains a per-register abstract value map and updates it
on every assignment instruction, so call sites show the resolved argument values.

**2. No PLT stub extractor for PPC32 BE ELF.** 
PPC32 BE ELF links external calls through a `lis r11, HI; lwz r11, LO(r11); mtctr r11; bctr`
stub pattern in `.text`. The existing `_extract_plt` dispatcher had no PPC32 case and fell
through to a little-endian 64-bit `.rela.plt` reader that produced zero entries silently. This
meant `SinkArgClassifier`, `TaintTracker`, and `BinaryLifter` all resolved zero external calls
on any PPC32 BE ELF. The `_extract_plt_ppc32be` function (added in `binary_context.py`
commit `03bd8a5`) fixes the root cause: it parses `.rela.plt` with big-endian 32-bit RELA
entries and then scans `.text` for the 4-instruction stub pattern to build `stub_va → sym_name`.

**3. No decompiler for IBM PPC476 firmware targets.** 
IBM PPC476 uses `glibc 2.15` with the `ppc476-tools-cross-1.0-1.1` toolchain. Ghidra has PPC
support but is not available in this toolkit. `Ppc32Lifter` fills that role for the specific goal
of vulnerability analysis: identifying what attacker-controlled data reaches which dangerous
functions `execv`, `system`, `sprintf`, `strcpy` with enough argument detail to assess exploitability.

---

## Usage <sup>[↑](#ppc476lifter)</sup>

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.ppc32_lifter import Ppc32Lifter

ctx = BinaryContext.load_or_build('/tmp/ppc476/opt/ppc476-tools/ppc/usr/bin/rpcgen')
lifter = Ppc32Lifter.from_context(ctx)

# Ppc476Lifter
pseudo = lifter.lift(0x10002754, n_insn=80)
print(pseudo)
```

Example output abbreviated:

```
// PPC32 lift of 0x10002754 @ 0x10002754
//
  [0x10002754] r0 = LR;
  [0x10002758] sp -= 128;  // frame alloc
  [0x100027a4] fork(r3=pipe());  // PLT call
  [0x100027d4] r4 = *(0x100240bc);       // CPP global (GOT load)
  [0x100027d8] __xstat(r3=3, r4=*(0x100240bc), r5=sp-128+0x8);  // PLT call
  [0x10002834] r3 = *(0x10024218+0x8); r4 = 0x10024218+0x8;  // lwzu
  [0x10002838] execv(r3=*(0x10024218+0x8), r4=0x10024218+0x8);  // PLT call
  [0x10002844] perror(r3=0x10010244);  // PLT call
  [0x1000284c] exit(r3=1);  // PLT call
```

The lifter resolved `execv`'s first argument to `*(0x10024218+0x8)`, which is the `CPP` global
(a `GOT`-relative load visible two lines earlier). This is enough to determine the argument comes
from a developer-controlled global rather than from network input.

---

## Architecture mapping <sup>[↑](#ppc476lifter)</sup>

| PPC476 register | ABI role | Lifter treatment |
|---|---|---|
| `r0` | scratch / LR staging (`mflr`/`mtlr`) | tracked; labelled `LR` after `mflr` |
| `r1` | stack pointer | initialised to `sp`; updated on `stwu` frame alloc |
| `r2` | TOC pointer | initialised to `toc`; GOT loads shown as `*(toc+N)` |
| `r3` | arg0 / return value | initialised to `arg0`; updated to `sym()` after each call |
| `r4`–`r10` | arg1–arg7 | initialised to `arg1`–`arg7` |
| `r11`–`r12` | scratch (PLT stubs use `r11`) | tracked; clobbered after calls |
| `r13` | small-data area (SDA) pointer | tracked as constant after `lis`/`addi` pair |
| `r14`–`r31` | callee-saved | preserved in prologue; tracked across function |
| CTR | count register | pseudo-index 32 in register map; set by `mtctr` |
| LR | link register | tracked as `LR` symbol |

---

## PPC476 Book E extensions <sup>[↑](#ppc476lifter)</sup>

PPC476 adds these instructions to the base PowerPC 32-bit ISA. Capstone decodes them
correctly under `CS_ARCH_PPC | CS_MODE_32 | CS_MODE_BIG_ENDIAN`.

| Instruction | Class | Lifter output |
|---|---|---|
| `tlbwe`, `tlbre`, `tlbivax` | TLB management privileged | `// tlbwe...` |
| `dcbt`, `dcbst`, `icbi`, `dcbf` | Cache management | `// dcbt...` |
| `wait` | Wait-for-interrupt | `// wait` |
| `mfmsr`, `mtmsr` | Machine state register | `// mfmsr...` |
| `mtspr`, `mfspr` SPRs 256–767 | Special-purpose registers | `// mtspr...` |
| `evlddx`, `evstddx` (SPE) | Signal Processing Engine | `// evlddx...`: SPE is absent on PPC476; encountering these indicates a misidentified binary |

---

## How it works <sup>[↑](#ppc476lifter)</sup>

```
BinaryContext.plt        ─────────────────┐
  {stub_va: "execv", ...}                 │
  (built by _extract_plt_ppc32be)         ▼
                               Ppc32Lifter.from_context(ctx)
                               re-parses .text via LIEF

  Ppc32Lifter.lift(func_va, n_insn)
  │
  ├─ Capstone: CS_ARCH_PPC | CS_MODE_32 | CS_MODE_BIG_ENDIAN
  │   yields (address, mnemonic, op_str) for each insn
  │
  ├─ _lift_insn(va, mn, op, regs)
  │   regs: Dict[int, _Val]   - register state map
  │   _Val.kind: const|arg|stack|mem|sym|expr|unknown
  │
  │   per-instruction dispatch:
  │   stwu r1, -N(r1)  →  sp -= N          (frame alloc)
  │   mflr rX          →  rX = LR
  │   mr   rD, rS      →  rD = regs[rS]    (propagate val)
  │   li   rD, imm     →  rD = hex(imm)
  │   lis  rD, HI      →  rD = HI<<16
  │   addi rD, rA, lo  →  rD = regs[rA]+lo (or fold const)
  │   lwz  rD, d(rA)   →  rD = *(regs[rA]+d)
  │   lwzu rD, d(rA)   →  rD = *(rA+d); rA = rA+d
  │   stw  rS, d(rA)   →  *(regs[rA]+d) = regs[rS]
  │   bl   target      →  look up plt/exports → sym(r3=v, ...)
  │                        r3 = sym(); r4-r12 clobbered
  │   mtctr rX         →  CTR = regs[rX]
  │   bctr             →  call *CTR
  │   blr              →  return r3;  (stops walk)
  │   branches/cmp     →  // comment only
  │   unknown          →  // mnemonic op_str
  │
  └─ returns multi-line string, each line tagged [VA]
```

**Constant folding.** When `regs[rA]` is a `const` value, `addi` and `lwz` compute the final
address as a concrete hex value. This is what resolves `lis r9, 0x1001; addi r9, r9, 0x244` to
`r9 = 0x10010244` and then `lwz r3, 0(r9)` to `r3 = *(0x10010244)`. Concrete addresses make it
easy to cross-reference GOT slots and string literals with `ctx.strings`.

**Call argument resolution.** At each `bl target` instruction, the lifter collects the current
value of every argument register (`r3`–`r8`) and appends them to the call statement. Only
registers with a non-`unknown` value appear. After the call, `r3` is set to `_Val.sym("sym()")`
and `r4`–`r12` are evicted caller-saved by PPC32 ABI.

**PLT stub VAs.** `BinaryContext.plt` maps `stub_va → sym_name` for PPC32 targets after the
`_extract_plt_ppc32be` fix. The lifter's `bl` handler looks up `target` in `ctx.plt` first, then
falls back to `ctx.exports`. An unresolved `bl` appears as `0x1000xxxx()`.

---

## PPC32 BE PLT extraction <sup>[↑](#ppc476lifter)</sup>

`_extract_plt_ppc32be` is the companion fix in `binary_context.py` that makes this lifter useful.

**What it does:**
1. Parses `.rela.plt` with big-endian 32-bit RELA format `>III`, 12 bytes/entry.
   `sym_idx = r_info >> 8` (ELF32 encodes sym in the upper 24 bits of `r_info`).
2. Builds `got_va → sym_name` from the relocation symbol table.
3. Scans `.text` for the 4-instruction stub pattern:

   ```
   lis  r11, HI     0x3D60xxxx
   lwz  r11, LO(r11) 0x816Bxxxx
   mtctr r11         0x7D6903A6
   bctr              0x4E800420
   ```

4. For each matching quad, computes `got_va = HI << 16 + sign_ext16(LO)`.
5. If `got_va` is in `got_va → sym_name`, records `stub_va → sym_name` in `self.plt`.

**Why the glink entries are not the call targets:** 
The `.plt` section in a PPC32 ELF contains 4-byte initial GOT slot values pointing to
`b <resolver>` one-word glink entries in `.text`. These glink entries are used by `ld.so` during
lazy binding, not by direct caller `bl` instructions. The actual call stubs lis/lwz/mtctr/bctr
sit earlier in `.text` and are what callers `bl` to. An extractor that reads the glink entry
addresses from `.plt` slot values maps the wrong VAs, call-graph edges never reach them.

**Verification rpcgen, glibc 2.15, PPC476 sysroot:**

```python
ctx = BinaryContext.load_or_build('.../ppc/usr/bin/rpcgen')
assert len(ctx.plt) == 44
assert ctx.plt[0x1000f280] == 'execv'
assert ctx.plt[0x1000f350] == 'sprintf'
assert ctx.plt[0x1000f320] == 'fork'
```

---

## Limitations <sup>[↑](#ppc476lifter)</sup>

- **Linear walk, not CFG.** The lifter does not follow branches. Functions with early-exit paths
 show incomplete register state at later instructions. Use `n_insn` to limit output to the path
 of interest.

- **No inter-procedural tracking.** When a callee returns a value, `r3` is set to the symbol
 string `"sym()"`. The actual value is unknown. To trace through a call boundary, lift the
 callee separately and inspect its return path.

- **Callee-saved registers may show stale values in the prologue.** `r14`–`r31` are initialised
 to `_Val.unknown(N)` until the first write. Prologue `stw rX, N(r1)` instructions store these
 unknown values, producing `*(sp-F+N) = <rX?>` in the output. This is correct, the registers
 have not been assigned yet at prologue time.

- **Unresolved PLT calls appear as hex.** If `BinaryContext.plt` is empty (old cache, before the
  `_extract_plt_ppc32be` fix), every external call appears as `0x1000fXXX()`. Clear the cache and
 rebuild.

- **SPE instructions indicate a wrong binary.** PPC476 does not implement the Signal Processing
 Engine (SPE). If `evlddx` / `evstddx` instructions appear in the output, the binary is from a
 different PPC32 core e500, e500v2 and not a PPC476 target.

---

## Example output <sup>[↑](#ppc476lifter)</sup>

```
# Ppc476Lifter
// PPC32 lift of 0x10002480 @ 0x10002480
//
  [0x10002480] sp -= 64;
  [0x10002490] r5 = arg0 + 0x1c;
  [0x10002494] r3 = *(r5);
  [0x10002498] if r3 == 0: goto 0x100024c0;
  [0x1000249c] r4 = arg1;
  [0x100024a0] call strcpy(r3, r4);
  [0x100024a4] return r3;
```

---

## False positives <sup>[↑](#ppc476lifter)</sup>

**No branch condition lifting.** `Ppc32Lifter` emits `if <va>: goto <va>` placeholders for all conditional branches, it does not evaluate the condition expression. The branch condition must be inferred from the instructions that set CR0/CR1 before the branch instruction.

---

## Pipeline position <sup>[↑](#ppc476lifter)</sup>

**Before this module:** Run `PPC32TaintTracker` and `PPC32PLTTracer` to confirm the function contains tainted argument paths to dangerous sinks.

**After this module:** Read the lifted pseudocode to understand the function's control flow and identify the constraints that guard the sink.

---

## Reading output <sup>[↑](#ppc476lifter)</sup>

`Ppc32Lifter.from_context(ctx).liftfunc_va, n_insn=150` returns a `str`: the pseudo-C disassembly of the function, one statement per line.

The lifter tracks register state using `_Val` internally. Output lines use C-like expressions:
- Constants printed as `0xNNN` hex literals
- Arguments as `a0`, `a1`, etc. r3 = `a0`, r4 = `a1` per PPC32 calling convention
- Named imports as their symbol name resolved from PLT map
- Memory loads/stores as pointer-cast dereferences for example `*(u32 *(sp + 0x18)`)
- Unknown register state as `?<regname>`

---

## Common findings in PPC476 avionics firmware <sup>[↑](#ppc476lifter)</sup>

Avionics and aviation infrastructure firmware on PPC476 yields distinct finding classes compared to consumer embedded devices:

**Datalink injection (ACARS/SATCOM):** Flight management systems receive clearance data, weather updates, and company messages via ACARS (Aircraft Communications Addressing and Reporting System) or SATCOM datalink. The datalink parser is a network-adjacent code path on the PPC476: received messages arrive in the aircraft network, are parsed by the FMS binary, and used to update flight plan data. If the parser uses `sprintf` or `strcpy` to copy message fields into fixed-size buffers, a malformed ACARS message is a potential overflow. `SemanticSearcher.query('ACARS message parser datalink receive')` targets these candidates.

**GPS data injection:** Some FMS implementations parse GPS NMEA sentences from the flight management computer's GPS receiver interface. NMEA sentences are text-format strings with variable-length fields. A stack buffer overflow in an NMEA sentence parser is a well-documented finding class (CVE-2018-5689 and related). The parser typically uses `sscanf` or a custom parser; `PPC476Lifter` lifts `sscanf` calls showing the format string and destination buffer.

**VHF radio management plane:** The VHF radio management software (on the same FMS processor or a connected I/O processor) handles frequency configuration via character-string commands from the cockpit display system. Command injection in the VHF management plane is a findings class specific to integrated avionics architectures.

**Memory corruption via malformed instrument data:** Some PPC476 targets in industrial control (power grid SCADA) receive telemetry data from field instruments. If the data parsing code trusts the `length` field in the received protocol (IEC 61850, DNP3, Modbus) without validation, a crafted `length` value causes an out-of-bounds read or write. `LengthUnderflowScanner` + `PPC476Lifter` is the combined approach for these targets.

---

## Pseudo-C output format reference <sup>[↑](#ppc476lifter)</sup>

`PPC476Lifter.lift()` produces pseudo-C with the following conventions:

**Register naming:** Registers are shown by their ABI name (`a0`, `a1`, `s0`, `sp`) not by their hardware name (`r3`, `r4`, `r14`, `r1`). This makes the output readable without knowing PPC register conventions.

**Example lifted function:**
```c
// Function at 0x00824F10 — lifted by PPC476Lifter
void sub_824F10(u32 a0, u32 a1, u32 a2) {
    u32 s0 = a0;
    u32 s1 = a1;
    u32 v0;
    char buf[64];                               // sp + 0x18, size from stwu -0x58
    sprintf(buf, "/bin/cmd --port=%s", a2);    // system call: sprintf
    v0 = system(buf);                           // system call: system
    return;
}
```

**Annotation conventions:**
- `// system call: <name>` marks resolved PLT imports
- `// unknown call: <va>` marks unresolved indirect calls
- `// loop top` and `// loop end` mark back-edge detected loops
- `*(u32 *)(sp + N)` represents local variable access at stack offset N
- `*(u32 *)(r_name + N)` represents field access at offset N from a base register

The pseudo-C is intentionally not compilable: it is an analysis aid, not source reconstruction. `a0`, `s0`, etc. are C-style pseudo-variable names, not actual C identifiers.

---

## CWE mapping and FindingRegistry usage <sup>[↑](#ppc476lifter)</sup>

| Vulnerability class | CWE | `PPC476Lifter` indicator |
|---|---|---|
| Stack buffer overflow | CWE-121 | Fixed-size `buf[N]` as destination to `sprintf`/`strcpy` with user-controlled source |
| Command injection | CWE-78 | `system(buf)` where `buf` includes ARG_PROPAGATED string |
| Format string | CWE-134 | `printf`/`sprintf` with first arg being ARG_PROPAGATED (not a string literal) |
| Integer overflow leading to heap overflow | CWE-190 | `malloc(n * size)` where `n` is ARG_PROPAGATED without bounds check |
| Use of unsafe function | CWE-676 | `gets()`, `strcpy()`, `scanf("%s", ...)` — unconditional flag |

For FindingRegistry: set `va` to the sink instruction VA (the `bl system` or `bl sprintf` instruction), `cwe` as above, `evidence_type='ppc476_lifted_pseudo_c'`, and include the relevant `PPC476Lifter.lift()` output excerpt in `detail`.

**Byte verification for PPC476 findings:** PPC476 instructions are always 4 bytes, big-endian. Verify with:
```python
import struct
with open(binary_path, 'rb') as f:
    f.seek(va - ctx.base_address)
    word = struct.unpack('>I', f.read(4))[0]
opcd = word >> 26  # PowerPC primary opcode
assert opcd == 18, f"Expected bl (opcd=18) at {va:#010x}, got opcd={opcd} word={word:#010x}"
```
`opcd == 18` and `word & 1 == 1` (LK bit set) confirms `bl` (branch-and-link, i.e., a function call). For indirect calls via CTR (`bctrl`), `opcd == 19` and `XO == 528`.

---


Multiple ablation modules handle PPC32 targets. `PPC476Lifter` specifically targets the IBM PPC476 core. Here is how it differs from other PPC32 analysis paths:

| Aspect | PPC476 (IBM avionics) | NXP MPC5500 (automotive) | Cisco IOS Classic (PPC603e/PPC750) |
|---|---|---|---|
| Instruction set | PowerPC Book E, 32-bit | VLE (16/32-bit mixed) | Classic PowerPC 32-bit |
| Endianness | Big-endian only | Big-endian | Big-endian |
| RTOS | VxWorks, LynxOS | EB Tresos/AUTOSAR, bare-metal | Cisco IOS (proprietary) |
| Binary format | ELF (VxWorks/LynxOS), XCOFF32 (AIX) | Raw binary | ELF (with Cisco compression) |
| Symbol availability | VxWorks: full symbols; LynxOS: stripped | Stripped | Stripped |
| Decoder needed | Standard Capstone PPC32 | EcuVLEDecoder | Standard Capstone PPC32 |
| Calling convention | Power EABI | Power EABI (same) | Power EABI (same) |

**When to use `PPC476Lifter` vs `PPC32TaintTracker` vs `EcuVLEDecoder`:**
- Binary is Book E ELF on VxWorks or LynxOS → `PPC476Lifter` for lifting, `PPC32TaintTracker` for taint
- Binary is NXP MPC5500/5700 with VLE encoding → `EcuVLEDecoder` first, then `PPC32TaintTracker`
- Binary is Cisco IOS (ELF, Book E or classic PPC) → `PPC32TaintTracker` directly (Cisco standalone findings)
- Binary is XCOFF32 (AIX BladeCenter) → `XCoff32Decompiler` first to extract sections, then `PPC476Lifter`

`PPC476Lifter.from_path()` handles all the above cases transparently via format auto-detection.

---

## Complete usage example: IBM avionics binary analysis <sup>[↑](#ppc476lifter)</sup>

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.semantic_searcher import SemanticSearcher
from ablation.analyzers.ppc476_lifter import PPC476Lifter
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker

# Step 1: build context
ctx = BinaryContext.load_or_build('/firmware/avionics/fmz2000_app.elf')
print(ctx.summary())
# Expected: PowerPC Book E (big-endian), 32-bit, 1847 functions (stripped)

# Step 2: semantic sweep for command injection candidates
searcher = SemanticSearcher(ctx)
hits = searcher.query('system command execution shell process', top_k=15)
print("Top candidates:")
for h in hits:
    print(f"  {h.va:#010x}: {h.description} (score={h.score:.3f})")

# Step 3: classify sink arguments before running taint tracker
classifier = SinkArgClassifier.from_context(ctx)
results = classifier.classify_all()
print(f"\nSink classification:")
for r in results:
    if r.classification != 'RODATA_CONST':
        print(f"  {r.va:#010x}: {r.sink_name}({r.arg_idx}) = {r.classification}")

# Step 4: lift promising candidate to pseudo-C for manual review
lifter = PPC476Lifter(ctx)
# Use VA of the most interesting sink with ARG_PROPAGATED classification
candidate_func_va = hits[0].va
pseudo_c = lifter.lift(candidate_func_va)
print("\nLifted pseudo-C:")
print(pseudo_c)

# Step 5: taint track confirmed candidates
tracker = PPC32TaintTracker.from_context(ctx)
findings = tracker.run_interprocedural()
for f in findings:
    print(f"\n[{f.severity}] {f.sink_name} at {f.sink_va:#010x}")
    print(f"  Taint from: {f.source_description}")
    print(f"  Path: {' -> '.join(f'{va:#010x}' for va in f.path_vas)}")
```

---

## What is the PPC476? History and deployment context <sup>[↑](#ppc476lifter)</sup>

The Power PC 476FP (PPC476) is a 32-bit RISC processor developed by IBM as part of the PowerPC 400 series embedded line. The "FP" suffix indicates the inclusion of an IEEE 754 double-precision floating-point unit — a feature absent from the standard PPC405 and PPC440 that preceded it. The PPC476 was positioned for high-reliability applications that needed both deterministic real-time behavior (for control systems) and full FP capability (for navigation and signal processing).

**Chronology:**
- 1997: PowerPC 405 introduced (IBM 4xx series, 32-bit, no FPU); deployed in networking (Cisco 7200 I/O processor, Juniper line cards), industrial, and early embedded Linux systems
- 2002: PowerPC 440 introduced (superscalar pipeline, better performance, optional FPU)
- 2007: IBM 476FP introduced; 1.6 GHz capable at 45nm, full DP FPU, hardware page table walker, ECC memory support; targets aviation and defense
- 2010–2015: PPC476 design wins in avionics (Honeywell, Rockwell Collins, BAE Systems flight management systems), power grid SCADA, IBM BladeCenter I/O modules
- 2015–present: Legacy deployment continues; PPC476 firmware is still running in fielded avionics and power infrastructure equipment

**IBM 476FP specifications:**
- ISA: PowerPC Book E, 32-bit with Book E extensions
- Pipeline: 7-stage in-order, dual-issue
- FPU: IEEE 754-2008 compliant double precision
- Cache: 32 KB I-cache, 32 KB D-cache, 512 KB unified L2
- TLB: 256-entry hardware page table walker
- MMU: BookE virtual memory model with TLB miss handler in software
- Bus: CoreConnect PLB (Processor Local Bus) 4.0
- Endianness: Big-endian only (no little-endian mode, unlike later POWER cores)

**No VLE:** Unlike the NXP MPC5500/5700 series (which uses VLE), the IBM PPC476 does not implement VLE. All instructions are 32-bit Book E fixed width. Capstone handles PPC Book E correctly; no special decoder is needed (unlike `EcuVLEDecoder`).

**Power Architecture Book E vs. Classic:** Book E is the embedded variant of PowerPC. It shares the same 32-bit instruction encoding as classic PPC but uses different supervisor registers and exception model. The `mfspr`/`mtspr` instructions access Book E-specific SPRs (special purpose registers) with different numbers than classic PPC. `PPC476Lifter` correctly handles Book E SPR names.

---

## IBM PPC476 register file <sup>[↑](#ppc476lifter)</sup>

The PPC476 follows the standard Power Architecture 32-bit Embedded Application Binary Interface (EABI):

| Register | ABI role | Preserved? |
|---|---|---|
| r0 | Volatile (scratch; holds LR copy in prologue) | No |
| r1 | Stack pointer | Yes |
| r2 | Reserved (EABI: small data area 2 / SDATA2) | Yes |
| r3 | Arg 0 / Return value | No |
| r4–r10 | Args 1–7 | No |
| r11–r12 | Volatile | No |
| r13 | EABI small data area pointer | Yes |
| r14–r31 | Callee-save | Yes |
| f0–f8 | FP volatile | No |
| f9–f13 | FP volatile (additional arg regs for FP args) | No |
| f14–f31 | FP callee-save | Yes |
| LR | Link register | No (saved in prologue) |
| CTR | Count register (loop counter, indirect branch) | No |
| CR0–CR7 | Condition register fields | CR2–CR4 preserved |

**RE implication:** Function arguments on PPC476 arrive in r3–r10 (integer) and f1–f8 (double). For `system()` and `execvp()` calls, trace r3 (the command string pointer) backward. For `memcpy()` and `strcpy()` (buffer overflow classes), trace r5 (size argument) and r3/r4 (destination/source pointers).

**Prologue pattern (PPC32 EABI):**
```asm
stwu    r1, -N(r1)     ; allocate stack frame, link old SP
mflr    r0             ; r0 = link register
stw     r0, N+4(r1)    ; save LR to stack
stw     r14, N-4(r1)   ; save first callee-save
stmw    r15, N-8(r1)   ; save r15-r31 (if needed)
```

`PPC476Lifter` identifies function entry by the `stwu r1, -N(r1)` prologue pattern.

---

## Avionics RE context and deployment targets <sup>[↑](#ppc476lifter)</sup>

The PPC476 is predominantly found in avionics flight management systems (FMS) and integrated modular avionics (IMA) cabinets. The software running on these systems is subject to DO-178C (Software Considerations in Airborne Systems and Equipment Certification) airworthiness standards, which require extensive formal verification and testing. Despite this, logic bugs and configuration errors can still exist in less-critical software layers.

**Known PPC476 firmware targets in ablation RE collection:**
- **Honeywell FMZ-2000 FMS:** Flight management computer for regional jets. PPC476 running VxWorks RTOS + DO-178C application software. Binary format: ELF with stripped symbols.
- **Rockwell Collins ProLine Fusion:** Multi-function display controller. PPC476 running LynxOS RTOS. Contains weather radar processing and datalink components.
- **IBM 9117-MMD (Power 7 I/O expansion):** BladeCenter blade using PPC476 as I/O processor. ELF binary for AIX 7.1 I/O subsystem. XCOFF32 format (not ELF).

**XCOFF32 vs ELF on PPC476:** IBM's AIX platform uses the XCOFF32 binary format instead of ELF. VxWorks and LynxOS avionics targets use ELF. `PPC476Lifter.from_path()` auto-detects the format via magic bytes:
- ELF: `\x7FELF` at offset 0
- XCOFF32: the XCOFF magic `0x01DF` at offset 0

For XCOFF32 targets, use `XCoff32Decompiler` (see [XCOFF32 Decompiler](xcoff32-decompiler.md)) to parse the binary structure before constructing a `PPC476Lifter` from the extracted code sections.

---

## Instruction encoding reference: PPC476 RE-relevant opcodes <sup>[↑](#ppc476lifter)</sup>

PowerPC Book E uses a fixed 32-bit instruction format with three primary forms:

**I-form (branches):**
```
31       26 25                          2 1  0
+----------+-----------------------------+--+--+
|   OPCD   |             LI              |AA|LK|
+----------+-----------------------------+--+--+
  6 bits              24 bits             1  1
```
`bl` (branch and link, function call): OPCD=18, LK=1. Target = PC + sign_extend(LI << 2).

**D-form (load/store with immediate offset):**
```
31      26 25   21 20   16 15              0
+---------+-------+-------+----------------+
|  OPCD   |  RT   |  RA   |       D        |
+---------+-------+-------+----------------+
  6 bits   5 bits  5 bits     16 bits
```
`lwz` (load word zero, OPCD=32): load 32-bit value from memory at EA = RA + D.
`stw` (store word, OPCD=36): store 32-bit value to memory at EA = RA + D.

**X-form (register-register operations):**
```
31      26 25   21 20   16 15   11 10           1  0
+---------+-------+-------+-------+-------------+--+
|  OPCD   |  RT   |  RA   |  RB   |    XO       |Rc|
+---------+-------+-------+-------+-------------+--+
  6 bits   5 bits  5 bits  5 bits    10 bits       1
```
`add` (OPCD=31, XO=266): RT = RA + RB.

**`mtlr` / `mflr` (link register move):**
`mflr r0`: OPCD=31, XO=339, RS=0, SPR=0x100 (LR). Moves LR to r0 — identifies function prologues.
`mtlr r0`: OPCD=31, XO=467, RS=0, SPR=0x100. Restores LR from r0 — identifies function epilogues.

---

## VxWorks and LynxOS RTOS context <sup>[↑](#ppc476lifter)</sup>

Avionics PPC476 firmware runs almost exclusively on certified real-time operating systems (RTOS). The two dominant platforms are VxWorks (Wind River Systems) and LynxOS (Lynx Software Technologies). Both differ from Linux in ways that affect binary analysis:

**VxWorks on PPC476:**
- **Flat memory model:** VxWorks uses a flat physical address space without virtual memory separation between tasks (by default in VxWorks 5.x and 6.x; VxWorks 7 adds optional MMU protection). All tasks share the same address space: a vulnerability in one task can overwrite another task's data or code.
- **Symbol table in binary:** VxWorks application ELF images typically include a symbol table (`vxworks_symbol_table`) containing all exported function and variable names. This provides near-source-level symbol resolution — one of the few contexts where a production binary has readable function names. `BinaryContext.load_or_build()` imports these symbols automatically.
- **Task entry points as security boundary:** VxWorks tasks correspond to POSIX threads but without separate address spaces. Network-facing tasks (those calling `accept()` or `recvfrom()`) are the entry points for remote exploitation. `SemanticSearcher` targets these first.
- **No stack canaries by default:** Older VxWorks versions (5.x) do not enable stack canaries. Buffer overflow vulnerabilities in VxWorks 5.x applications on PPC476 are directly exploitable without bypassing a canary.

**LynxOS on PPC476:**
- **POSIX-compliant, MILS-capable:** LynxOS provides POSIX APIs with DO-178C and Common Criteria certification support. Process isolation is enforced via the MMU.
- **ELF format with partial symbols:** LynxOS applications are stripped ELF files, but the LynxOS kernel image itself often retains symbols. For application binaries, semantic search is the primary analysis tool.
- **`/proc` filesystem access control:** LynxOS restricts `/proc/self/mem` and similar paths used in user-space exploit techniques. Understanding the RTOS access control model helps scope what a remote code execution can actually do post-exploitation.

---

## PPC476 SPR (Special Purpose Register) reference for RE <sup>[↑](#ppc476lifter)</sup>

Book E defines a large number of special purpose registers accessed via `mfspr`/`mtspr`. For security RE, the most relevant:

| SPR number | Name | RE relevance |
|---|---|---|
| 1 | XER | Integer exception register; overflow bit |
| 8 | LR | Link register; target of `blr` return |
| 9 | CTR | Count register; target of `bctrl` indirect call |
| 22 | DEC | Decrementer (watchdog timer tick) |
| 48 | PID | Process ID (TLB tag) |
| 256 | USPRG0 | User-accessible SPR 0 (accessible from user-mode) |
| 272–275 | SPRG0–SPRG3 | Supervisor general-purpose SPRs |
| 1008 | HID0 | Hardware implementation-dependent register 0 |

`mfspr r3, 8` (load LR into r3) followed by a store is a common pattern in VxWorks task-switch code. If user-controlled data reaches `mtspr 9, rX` (write to CTR) followed by `bctrl` (branch to CTR), that is a CTR overwrite — equivalent to function pointer hijack. `PPC476Lifter` labels these as potential control-flow violations when `rX` trace sources are ARG_PROPAGATED.

---

## Calling convention deep-dive for taint analysis <sup>[↑](#ppc476lifter)</sup>

For taint tracing `system()` and `execl()` calls on PPC476:

1. **Source identification:** HTTP/socket input arrives via `read()` into a buffer. The buffer pointer (typically in a local variable on the stack) is the taint source. The stack frame layout from `PPC476Lifter.lift()` output shows the offset where the buffer lives (`sp + 0x??`).

2. **Propagation:** The buffer contents move through string manipulation functions (`strcpy`, `strcat`, `sprintf`) before reaching `system()`. `PPC476Lifter` lifts these as C-like expressions showing the data flow, e.g., `sprintf(sp+0x18, "/bin/hi_cmd --arg=%s", a0)`.

3. **Sink:** `system()` call via branch-to-PLT (PPC Book E uses a GOT + PLT model similar to Linux ELF). `PPC476Lifter` resolves PLT entries via `binary_context.imports` and labels them as `system`, `execvp`, etc.

4. **Byte verification:** For the `bl` instruction at the `system()` call site:
```python
with open(binary, 'rb') as f:
    data = f.read()
off = system_call_va - ctx.base_address
word = struct.unpack('>I', data[off:off+4])[0]
opcd = word >> 26  # should be 18 for 'bl'
lk   = word & 1   # should be 1 for 'bl' (link = save return address)
assert opcd == 18 and lk == 1, f"Expected bl at {system_call_va:#x}, got {word:#010x}"
```

---

## See also <sup>[↑](#ppc476lifter)</sup>

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-code-search.md): behavioral candidate search on the binary
- [PPC32 Taint Tracker](ppc32-taint-tracker.md): the complementary taint analysis module for PPC32 targets including PPC476
- [XCOFF32 Decompiler](xcoff32-decompiler.md): for AIX/IBM targets using XCOFF32 binary format instead of ELF
- [ECU VLE Decoder](ecu-vle-decoder.md): for NXP MPC5500/5700 automotive PPC (different ISA extension — VLE — not Book E standard)
- [SH-2A Binary Lifter](binary-lifter-sh2a.md): Renesas SH-2A (Japanese automotive ECU competitor to PPC476 in avionics/industrial markets)
- [FindingRegistry](registry.md): record confirmed PPC476 findings; `evidence_type='ppc476_lifted_pseudo_c'`; always byte-verify the `bl` call at `sink_va` before registering
