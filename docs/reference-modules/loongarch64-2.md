# LoongArch64 Compiler Bug Detection

Detect the GCC 12.3.1.7 LoongArch64 `min`-to-`max` code generation bug: identifying the four-instruction branchless sequence where swapped `masknez`/`maskeqz` order produces the maximum of two values instead of the minimum, and determine whether the wrong (maximum) value flows into a memory sink on the same taint path.

---

## Why this exists

1. **GCC 12.3.1.7-1.tl4 for LoongArch64 emits `maxa, b` when the source calls `mina, b`.** The branchless min/max pattern uses `masknez`/`maskeqz` to select one of two values; correct `min` requires `maskeqz` to select `Ra` when `Ra < Rb` and `masknez` to select `Rb` otherwise. GCC 12.3.1.7 emits the inverted order, producing `max`. This bug appears in TencentOS 4.6 kernel 6.6.119-52.9.tl4 and any other LoongArch64 target compiled with this GCC version.

2. A second variant uses immediate-compare instructions (`sltui`/`slti`) with a constant: `minx, CONSTANT` where the bug produces `maxx, CONSTANT`. This is the higher-severity variant: when `CONSTANT` is a buffer size or allocation limit, the wrong (larger) value passed to a memory sink produces a heap overflow. `LA64MaxNotMinScanner.scan()` detects both the register-compare and immediate-compare variants.

3. `LA64MaxNotMinScanner.from_pe32plus()` supports PE32+ (Windows on LoongArch): enabling analysis of LoongArch64 Windows kernel drivers compiled with the same buggy GCC toolchain. This covers LoongArch64 IoT and industrial targets that ship Windows-based firmware.

---

## How it works

```mermaid
flowchart TD
    A(["LA64MaxNotMinScanner.from_path(path)\n  or .from_pe32plus(data, image_base)"]):::input --> B["scan() → List[LA64MaxNotMinFinding]\n  Pattern 1: register-compare variant\n    sltu  Rcond, Ra, Rb\n    masknez Rtmp1, Rb, Rcond   ← wrong order → max\n    maskeqz Rtmp2, Ra, Rcond\n    or Rout, Rtmp2, Rtmp1\n    (correct min would swap masknez/maskeqz)\n  Pattern 2: immediate-compare variant\n    sltui/slti Rcond, Ra, N\n    masknez Rtmp1, Rconst, Rcond\n    maskeqz Rtmp2, Ra, Rcond\n    or Rout, Rtmp2, Rtmp1\n  For each match: check if Rout flows to memory sink\n    → LA64MaxNotMinFinding"]:::primary
    B:::primary --> C["LA64MaxNotMinFinding:\n  func_va: int\n  pattern_va: int  (VA of slt/sltu)\n  result_name: str  (ABI reg name)\n  sink_va: int\n  sink_name: str  (PLT symbol)\n  sink_arg: str\n  fp_class: str  ('' | 'vec_growth' | 'copy_limit')\n  compare_op: str  ('sltu' | 'slt')"]:::secondary
    C:::secondary --> D(["report(findings) → str"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner

scanner = LA64MaxNotMinScanner.from_path('/path/to/tencentos_kernel.elf')
findings = scanner.scan()

for f in findings:
    print(f"  {f.pattern_va:#x}  {f.result_name} → {f.sink_name} @ {f.sink_va:#x}")
    if f.fp_class:
        print(f"    ELIMINATED: {f.fp_class}")
    else:
        print(f"    REAL: {f.compare_op} integer truncation → {f.sink_name}({f.sink_arg})")

print(scanner.report(findings))
```

---

## Example output

The following illustrates the LoongArch64 compiler bug detection output format. Actual addresses are binary-specific.

```
LA64MaxNotMinScanner: tencentos_kernel.elf

Findings: <N>

LA64_MAX_NOT_MIN  pattern@<pattern_va>  a0 -> memcpy(count)@<sink_va>  [sltu...]
  REAL: sltu integer truncation → memcpy(count) — max used as copy length

LA64_MAX_NOT_MIN  pattern@<pattern_va>  a1 -> kmalloc(size)@<sink_va>
  [vec_growth]: ELIMINATED
```

---

## False positives

**The four-instruction pattern may appear in code that legitimately computes `max()`**: a correct `maxa, b` implementation uses exactly this pattern with the correct `masknez`/`maskeqz` order. `LA64MaxNotMinScanner` detects the `max` pattern as a potential bug only when the source context function name containing `min`, `clamp`, `limit`, or `bound` suggests `min` was intended. Validate with source code review if available.

**`from_pe32plus()` requires a valid image base**: providing an incorrect `image_base` will produce incorrect VAs in findings. Verify the image base from the PE's `Optional Header.ImageBase` field before calling.

---

## Pipeline position

Run `LA64MaxNotMinScanner` on any LoongArch64 ELF or PE binary. Prioritize `CRITICAL` findings flows to sink for immediate taint verification. The `LoongArch64TaintTracker` can confirm the path from the `max` result to the sink.

---

## Reading findings

`LA64MaxNotMinScanner.scan()` returns `List[LA64MaxNotMinFinding]`:

| Attribute | Type | Content |
|:---|:---|:---|
| `func_va` | `int` | VA of the enclosing function 0 if unknown |
| `pattern_va` | `int` | VA of the `slt`/`sltu` instruction starting the 4-insn sequence |
| `result_reg` | `int` | Register number of the incorrect result |
| `result_name` | `str` | ABI name of `result_reg` for example `a0` |
| `sink_va` | `int` | VA of the `bl` to the sink function |
| `sink_name` | `str` | PLT symbol name of the sink for example `memcpy` |
| `sink_arg` | `str` | Argument label showing which argument receives the wrong value |
| `context` | `str` | Disassembly snippet empty string if not available |
| `fp_class` | `str` | `""` = real finding; `"vec_growth"` = eliminated; `"copy_limit"` = plausible-low |
| `compare_op` | `str` | `"sltu"` unsigned or `"slt"` (signed) |

---

## See also

- [LoongArch64 Taint Analysis](taint-analysis-2.md): `TaintTrackerLA64` for full dataflow verification of scanner findings
- [LoongArch64 KASAN-Aware Decoding](hisilicon-risc-v-extensions.md): `LoongArchDecoderV2` for debug kernel analysis
