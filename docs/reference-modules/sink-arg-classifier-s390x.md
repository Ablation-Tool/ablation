# SinkArgClassifierS390X

Classify exec-class sink argument provenance on s390 (31-bit) and s390x (64-bit) big-endian ELFs — bypassing `BinaryContext`'s broken s390x PLT detection to recover exec-class imports on IBM mainframe Linux binaries.

---

## Why this exists

1. **`BinaryContext` misidentifies s390x binaries as x86-64.** For `e_machine=0x0016` (EM_S390), `BinaryContext` falls through to its x86-64 PLT parser, which returns `plt=0` on every s390x binary. `SinkArgClassifier` is then called with an empty PLT map and produces 0 results — not because the binary is safe, but because the architecture detection is broken. Gap ID: `S390-GAP-001`.

2. **The gap affects real IBM targets.** Confirmed on: IBM ClearCase `linux_390` (`cleartool`, 20516 bytes), IBM Rational BuildForge 7.1.1.3 `bfagent` (s390x), IBM XL C/C++ Compiler 1.2.0 runtime for s390x. All three returned `BinaryContext.arch='x86_64'` with `plt=0` before this module existed.

3. **The module bypasses BinaryContext entirely.** `SinkArgClassifierS390X.from_path()` uses LIEF directly for DYNSYM enumeration and Capstone `CS_ARCH_SYSZ` for disassembly, completely bypassing the broken `BinaryContext` s390x path.

---

## How it works

```
SinkArgClassifierS390X.from_path(ctx.path)
         │
         ├── LIEF parse: enumerate .rela.plt → got_to_sym map
         ├── Walk .plt section: locate PLT stubs → plt_rev map
         ├── Scan .rodata for string ranges
         ├── Discover snprintf PLT VAs for SNPRINTF_RODATA detection
         │
         └── classify_all()
             └── For each func_va in LIEF symbols:
                 ├── Capstone CS_ARCH_SYSZ disassembly
                 ├── _find_call_sites(): BRASL/BASR targeting sink stub
                 └── _trace_arg(): backward scan from call site

```

**`_trace_arg` patterns — s390x System V ABI:**

| Instruction | Classification |
|:---|:---|
| `larl %rX, addr` | `RODATA_CONST` if `addr` in `.rodata` |
| `lghi %rX, imm` / `lhi %rX, imm` | `RODATA_CONST` (immediate) |
| `lgfi %rX, imm` | `RODATA_CONST` (32-bit sign-extended immediate) |
| `lgr %rX, %rY` / `lr %rX, %rY` | `ARG_PROPAGATED` if rY in `r2–r6`; recurse otherwise |
| `la %rX, N(%r15)` / `lay %rX, N(%r15)` | Stack slot address → snprintf back-track |
| `lgrl %rX, addr` | Load 64-bit from PC-relative → `RODATA_CONST` if target in `.rodata` |
| `lg %rX, N(%rY)` / `l %rX, N(%rY)` | Load from memory — `ARG_PROPAGATED` if rY in `r2–r6` |

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.sink_arg_classifier_s390 import SinkArgClassifierS390X

ctx = BinaryContext.load_or_build('/path/to/bfagent')

# Bypass BinaryContext PLT gap: always use from_path on s390x
clf = SinkArgClassifierS390X.from_path(ctx.path)

clf.add_sink('cleartool_exec', arg_pos=0)
results = clf.classify_all()
print(clf.report(results))

flagged = [r for r in results if r.verdict not in ('RODATA_CONST', 'SNPRINTF_RODATA')]
```

**Typical output:**
```
SinkArgClassifierS390X: 8 results
  RODATA_CONST      system(arg0)    func=0x40004abc call=0x40004b20  larl r2 → 0x400a1000 in .rodata
  ARG_PROPAGATED    popen(arg0)     func=0x40008200 call=0x40008280  lgr r2, r2 (entry arg)
  UNKNOWN           execve(arg0)    func=0x4000c400 call=0x4000c450  lg r2, 0x40(r11)

Summary: ARG_PROPAGATED=1 | RODATA_CONST=5 | UNKNOWN=2
```

---

## Calling convention (s390x System V ABI)

```
r2   argument 0 / return value
r3   argument 1
r4   argument 2
r5   argument 3
r6   argument 4
r15  stack pointer
```

Both 31-bit s390 and 64-bit s390x use this layout. The module handles both word sizes (31-bit and 64-bit pointer arithmetic).

---

## Limitations

**`from_path()` required; `from_context()` is not safe.** `BinaryContext` misclassifies s390x binaries as x86-64 and returns `plt=0`. Always call `SinkArgClassifierS390X.from_path(ctx.path)`, never `SinkArgClassifierS390X.from_context(ctx)`.

**LIEF required.** Without LIEF the module cannot enumerate DYNSYM and returns 0 results. Verify `lief` is installed before running on s390x targets.

**No snprintf upgrade for mainframe stack conventions.** The `%r15`-based stack format argument classification is present but limited to detecting the stack slot address pattern. `TaintedStringTracker` does not yet support s390x.

---

## Pipeline position

**Architecture detection:** Check `ctx.arch == 's390x'` or `e_machine == 0x0016` before using this module. The `sac_for_context()` dispatcher routes s390/s390x automatically.

**After:** Filter out `RODATA_CONST`. Pass `ARG_PROPAGATED` and `UNKNOWN` to manual `WindowAnalyzer` trace — no s390x `TaintTracker` variant exists yet.

---

## See also

- [Sink Arg Classifier](sink-arg-classifier.md) — x86-64 baseline and full verdict reference
- [SAC Arch Dispatch](sac-arch-dispatch.md) — auto-selects this module for s390/s390x
- [Window Analyzer](window-analyzer.md) — disassemble call sites for manual UNKNOWN resolution
