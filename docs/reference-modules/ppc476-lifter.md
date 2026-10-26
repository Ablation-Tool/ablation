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

## See also <sup>[↑](#ppc476lifter)</sup>

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
