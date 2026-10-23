# PEF ABI Clobber Scanner

**File:** `ablation/analyzers/pef_abi_clobber_scanner.py`

Detects ABI register clobber violations in PPC32 PEF code sections: call sites
where an argument register is clobbered by an intermediate `bl` instruction
between the last write and the sink call.

Built on `encoding_dag.Template` / `Field` for correct bitfield extraction.
The three bugs that affected the hand-written OpenTransport scanner are
structurally impossible here; see **Design notes** below.

---

## Quick start

```python
from ablation.analyzers.pef_abi_clobber_scanner import PEFABIClobberScanner

scanner = PEFABIClobberScanner.from_bytes(code_bytes, base_va=0)

# OTStrCat / OTStrCopy: check r4 (string source arg)
findings = scanner.scan(
    sink_vas=[0x01690, 0x01774],
    check_regs=[4],
)
print(scanner.report(findings))
# PEFABIClobberScanner: 2 site(s): PLAUSIBLE=2  SAFE=0
#
# [PLAUSIBLE] 0x001690  r4  call_clobber @ 0x001684
# [PLAUSIBLE] 0x001774  r4  call_clobber @ 0x001768

# OTMemcpy: check r4 (source) and r5 (size)
findings = scanner.scan(
    sink_vas=[0x06e24],
    check_regs=[4, 5],
)
# [PLAUSIBLE] 0x006e24  r4  call_clobber @ 0x006e08
# [PLAUSIBLE] 0x006e24  r5  call_clobber @ 0x006e08
```

---

## Construction

```python
PEFABIClobberScanner.from_bytes(code: bytes, base_va: int = 0)
```

`code` is the raw bytes of the PEF code section.  `base_va` is the virtual
address of the first byte (offset 0 in `code`). All sink VAs and stop VAs in
results are relative to `base_va`.

---

## scan()

```python
findings = scanner.scan(
    sink_vas: List[int],
    check_regs: Optional[List[int]] = None,   # default [4]
    window: int = 32,                          # max instructions to walk back
) -> List[ABIClobberFinding]
```

For each (sink_va, check_reg) pair, walks backward from the BL instruction at
`sink_va`.  The walk stops as soon as one of four conditions is met:

| Stop condition | Verdict | `stop_reason` |
|---|---|---|
| Found an instruction that writes `check_reg` | `SAFE` | `reg_written` |
| Found a `bl` (clobbers r3-r12) | `PLAUSIBLE` | `call_clobber` |
| Found an unconditional `b` / `ba` | `PLAUSIBLE` | `uncond_branch` |
| Found a `blr` | `PLAUSIBLE` | `return` |
| Window exhausted | `PLAUSIBLE` | `window_exhausted` |

---

## ABIClobberFinding

```python
@dataclass
class ABIClobberFinding:
    site_va:     int    # VA of the sink BL instruction
    check_reg:   int    # register examined
    verdict:     str    # "PLAUSIBLE" or "SAFE"
    stop_va:     int    # VA where backward walk stopped
    stop_reason: str    # one of the stop conditions above
```

`finding.fmt()` returns a single formatted line suitable for display.

---

## report()

```python
PEFABIClobberScanner.report(findings: List[ABIClobberFinding]) -> str
```

Static method. Returns a multi-line string summary: count header followed by
one `fmt()` line per finding, sorted by (site_va, check_reg).

---

## PPC32 instruction coverage

The scanner correctly classifies the following instruction forms. Each uses
its own `Template`; no shared field extractor assumes a fixed position.

### Register-write opcodes

| Opcode(s) | Form | Dest field | Instructions |
|---|---|---|---|
| 12, 13, 14, 15 | D-arith | RT=bits[25:21] | addic, addic., addi/li, addis/lis |
| 32–35, 40–43 | D-arith | RT=bits[25:21] | lwz, lbz, lhz, lha (+ update forms) |
| 46 | D-arith | RT=bits[25:21] | lmw (range: RT..r31) |
| 24–29 | D-logical | RA=bits[20:16] | ori/mr, oris, xori, xoris, andi., andis. |
| 20, 21, 23 | M-form | RA=bits[20:16] | rlwimi, rlwinm/slwi/srwi, rlwnm |
| 31 + XO=RT | X-form | RT=bits[25:21] | add, sub, mul, div, mflr, lwzx, lbzx, … |
| 31 + XO=RA | X-form | RA=bits[20:16] | or/mr, and, slw, srw, extsh, extsb, … |

### Block-terminating instructions

| Opcode | Condition | Semantic | Effect on walk |
|---|---|---|---|
| 18 | LK=1 | bl / bla | PLAUSIBLE (call_clobber) |
| 18 | LK=0 | b / ba | PLAUSIBLE (uncond_branch) |
| 19 | XO=16, BO=20 | blr | PLAUSIBLE (return) |

Conditional branches (opcode 16) are transparent; the walk continues through
them. This is conservative: it may find a write that is only on one branch of
a conditional, which a full CFG analysis would flag.

---

## Design notes

Three bugs in the hand-written OpenTransport scanner are structurally fixed.

**1. D-form arithmetic vs. logical dest-field asymmetry**

```
addi r4, r3, 0    → opcode 14  D-arith  dest=RT=bits[25:21]=4   ✓ write detected
ori  r4, r3, 0    → opcode 24  D-logical dest=RA=bits[20:16]=4  ✓ write detected
ori  r3, r4, 0    → opcode 24  D-logical dest=RA=bits[20:16]=3  ✓ not r4: SAFE preserved
```

The old scanner used `(word >> 21) & 0x1f` for all opcodes. For `ori r4, r3, 0`
it extracted RS=3 (the source) instead of RA=4 (the destination) and missed the
write. For `ori r3, r4, 0` it extracted RS=4 and falsely treated it as a write
to r4. Two separate `Template` objects with different field names resolve this
at the structural level.

**2. addic (opcode 12) not in detection list**

The old scanner detected opcodes 14 and 15 but not 12 (addic) or 13 (addic.).
`_PRIMARY_WRITE` is a dict keyed on primary opcode; opcodes 12 and 13 are
explicit entries. There is no implicit "other" path.

**3. Unconditional branch not treated as basic-block boundary**

The old scanner's backward walk crossed `b target` (opcode 18, LK=0) without
stopping, entering the preceding basic block or function. `classify()` returns
`_UNCOND` for opcode 18 with LK=0; the scanner returns PLAUSIBLE immediately on
seeing `_UNCOND`.

---

## Limitations

- **PEF only**: designed for Mac OS 8/9 CFM PEF code sections. For ELF PPC32,
 use `PPC32TaintTracker` (handles GOT2 PIC, import stubs, linked `.so` binaries).
- **Intra-block only**: the backward walk does not build a CFG. It stops at
 any block-terminating instruction. A full CFG pass (not yet implemented) would
 handle paths where the register is set on all predecessor blocks.
- **No memory taint**: the scanner checks whether the register was *written*, not
 whether the written value is tainted / network-controlled. A SAFE verdict means
 the register has a defined value; it does not certify that value is safe.
- **Update-form RA writes**: `lwzu` (opcode 33), `lhzu` (41), `lhau` (43),
  `lbzu` (35) also write RA (base register update).  These update writes are not
 currently tracked; only RT is tracked for these opcodes. This is a
 conservative under-approximation (may produce PLAUSIBLE when RA was in fact
 written). Add RA tracking for update-form opcodes if this causes false positives.

---

## Why this exists

Prior to this module, pef abi clobber scanner required manual work outside the Ablation pipeline. This module integrates the capability directly so findings feed the shared `PatternLibrary` and `FindingRegistry` without a separate toolchain.

---

## How it works

`PEFABIClobberScanner.from_bytes(code, base_va)` takes raw PPC32 code bytes from a PEF (Classic Mac OS Portable Executable Format) binary. `scan()` decodes each instruction using a lightweight PPC32 word classifier (`classify(word)`), no Capstone, no func_starts. It tracks callee-saved register state (r13–r31, f14–f31, CR2–CR4) across the instruction stream. `_check_site()` flags sites where a callee-saved register is written before being saved or is read after being clobbered by a prior write without an intervening save.

---

## Usage

```python
from ablation.analyzers.pef_abi_clobber_scanner import PEFABIClobberScanner

import lief
binary = lief.parse('/path/to/classic_macos.pef')
code_sec = binary.get_section('__TEXT')
code = bytes(code_sec.content)
base_va = code_sec.virtual_address

# Identify sink call VAs (e.g. bl OTStrCat) from symbol table or sweep
sink_vas = [0x1234, 0x5678]   # VAs of bl instructions targeting sink functions

scanner = PEFABIClobberScanner.from_bytes(code, base_va=base_va)
findings = scanner.scan(sink_vas=sink_vas)
for f in findings:
    print(f.fmt())
```

---

## Example output

```
PEFABIClobberScanner: 2 site(s): PLAUSIBLE=2  SAFE=0

[PLAUSIBLE] 0x001690  r4  call_clobber @ 0x001684
[PLAUSIBLE] 0x001774  r4  call_clobber @ 0x001768
```

---

## False positives

Conditional branches (opcode 16) are transparent: the backward walk does not stop at `beq`/`bne`. A PLAUSIBLE verdict may result when the register is written on only one branch of a conditional; a full CFG analysis (not implemented) would distinguish this. Inspect the PLAUSIBLE site and trace whether all predecessor blocks write the register before the sink call.

---

## Pipeline position

**Before this module:** Identify sink call VAs: BL instructions targeting dangerous functions for example OTStrCat, OTStrCopy, OTMemcpy. Use `SemanticSearcher.query()` or the PEF symbol table.

**After this module:** Manually verify PLAUSIBLE sites. A PLAUSIBLE verdict means the register may be undefined at the sink call; confirm by inspecting the specific call path from the source VAs in `stop_va`.

---

## Reading findings

`PEFABIClobberScanner.from_context(ctx).scan(sink_vas, check_regs)` returns `List[ABIClobberFinding]`:

| Attribute | Content |
|:---|:---|
| `site_va` | VA of the sink `bl` instruction |
| `check_reg` | Register index examined (e.g., `4` for `r4`) |
| `verdict` | `'PLAUSIBLE'`: argument register was last written before the intermediate call, leaving it clobbered; `'SAFE'`: register was re-written after all calls before reaching the sink |
| `stop_va` | VA where the backward walk stopped |
| `stop_reason` | `'reg_written'` / `'call_clobber'` / `'uncond_branch'` / `'return'` / `'window_exhausted'` |

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
