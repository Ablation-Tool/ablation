# StaticLinkSinkScanner

Locate exec-class sink implementations in statically linked ELFs and classify all their call sites: filling the gap where `SinkArgClassifier` returns 0 results because there is no PLT to scan.

---

## Why this exists

1. **`SinkArgClassifier` requires a PLT.** It finds call sites by locating PLT stub VAs for `system`, `popen`, `execve`, etc. Statically linked binaries compile libc directly in, there are no PLT stubs, and `BinaryContext.plt` is empty. `SinkArgClassifier.classify_all()` returns 0 results and the binary appears safe when it is not.

2. **The gap affects real targets.** IBM POWER tools: `BTT52iFix` (static x86_64), `VE/UninstallAssistantLinux` (static x86_32), `HMC-V11/img2a` (static ppc64le), many IBM XL C runtime tools. All returned SAC=0 before this module. Gap IDs: `SAC-STATIC-001` (system), `SAC-STATIC-002` (popen), `SAC-STATIC-003` (strcpy/strcat).

3. **glibc's `system()` has a reliable signature.** `system()` always passes `"/bin/sh"` as a literal string argument to `execve()`. Locating `"/bin/sh"` in `.rodata`, then finding every function that loads that address with a LEA/MOV and also calls `execve()`, identifies `system()` implementation VAs with high confidence. All BL/CALL instructions targeting those VAs become `system()` call sites.

---

## How it works

```
StaticLinkSinkScanner.from_context(ctx)
         │
         ├── _find_binsh(): scan .rodata bytes for b'/bin/sh\x00'
         │
         └── scan_system()
             ├── For each /bin/sh occurrence at string_va:
             │   ├── Find all functions that LEA/MOV the string_va (xref scan)
             │   ├── Verify: does that function contain a CALL to execve()?
             │   └── Record candidate as system_impl_va
             │
             ├── Find all call sites to system_impl_va:
             │   ├── x86_64/x86_32: scan for CALL rel32 (0xE8) targeting impl_va
             │   ├── ppc64/ppc32:   scan for BL/BLA instructions targeting impl_va
             │   └── s390x:         scan for BRASL targeting impl_va
             │
             └── For each call site: classify arg0 provenance
                 ├── RODATA_CONST   — arg is a .rodata literal
                 ├── ARG_PROPAGATED — arg traces to entry register
                 └── UNKNOWN-STATIC — cannot resolve within lookback window
```

Note: `UNKNOWN-STATIC` differs from `UNKNOWN`. It signals that the scan found a real call site to a statically-linked sink implementation, but could not determine argument provenance, not that the result is unreliable.

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.static_link_sink_scanner import StaticLinkSinkScanner

ctx = BinaryContext.load_or_build('/path/to/static_binary')
scanner = StaticLinkSinkScanner.from_context(ctx)

results = scanner.scan_system()
print(scanner.report(results))

# Filter to actionable verdicts
flagged = [r for r in results if r.verdict != 'RODATA_CONST']
for r in flagged:
    print(f'0x{r.call_va:x}  {r.verdict}  {r.sink_name}  impl@0x{r.sink_impl_va:x}')
    print(f'  {r.arg_evidence}')
    print(f'  byte_verified={r.byte_verified}')
```

**Typical output:**
```
StaticLinkSinkScanner: 14 call sites to system (impl@0x426800)
  RODATA_CONST      system  call=0x412340  impl=0x426800  LEA rdi, [rip+0x...] → /bin/ls
  ARG_PROPAGATED    system  call=0x41a080  impl=0x426800  MOV rdi, rdi (entry arg)
  UNKNOWN-STATIC    system  call=0x41b200  impl=0x426800  MOV rdi, [rbp-0x30]
  UNKNOWN-STATIC    system  call=0x41c400  impl=0x426800  rdi write not found in window

Summary: 1 RODATA_CONST, 1 ARG_PROPAGATED, 12 UNKNOWN-STATIC
```

---

## Result fields (StaticSinkResult)

| Field | Type | Content |
|:---|:---|:---|
| `call_va` | `int` | VA of the CALL/BL instruction that calls the sink implementation |
| `sink_name` | `str` | `'system'`, `'popen'`, `'strcpy'`, `'strcat'` |
| `sink_impl_va` | `int` | VA of the statically-linked function implementation (found via `/bin/sh` xref) |
| `verdict` | `str` | `RODATA_CONST`, `ARG_PROPAGATED`, or `UNKNOWN-STATIC` |
| `arg_evidence` | `str` | Human-readable backward trace of argument classification |
| `byte_verified` | `bool` | True if the bytes at `call_va` match the expected CALL encoding for the architecture |

---

## Architecture coverage

| Architecture | System detection | Call scan |
|:---|:---|:---|
| x86_64 | `/bin/sh` xref + execve CALL | CALL rel32 (`0xE8`) |
| x86_32 | `/bin/sh` xref + execve CALL | CALL rel32 i386 |
| ppc64 / ppc32 | `/bin/sh` xref | BL / BLA instruction encoding |
| s390x | `/bin/sh` xref | BRASL instruction |
| Other | `/bin/sh` xref only | `UNKNOWN-STATIC` (no call scan) |

---

## Limitations

**`byte_verified=False` means double-check manually.** The call site scan uses a backward byte search for the CALL/BL encoding. If the binary has been modified or the function boundary estimate is incorrect, `call_va` may point to data bytes rather than a real instruction. Always verify that `data[call_va - base]` matches the expected opcode before treating the finding as confirmed.

**`strcpy` and `strcat` classification is heuristic.** glibc uses SSE2/AVX2 for x86_64 `strcpy`, making byte-pattern matching unreliable. The scanner identifies strcpy candidates by locating functions that call `memcpy` or use `rep movsb` with `rdi` as the first argument. These are flagged `UNKNOWN-STATIC`. Use `BinaryContext.str_xrefs` to add context.

**One `/bin/sh` string per binary.** If the binary has no `.rodata` or if the `/bin/sh` string was placed in a non-standard section, `scan_system()` returns 0 results even when `system()` is present.

---

## Pipeline position

**Check first:** `ctx.plt` being empty is the signal to use this module. If `len(ctx.plt) == 0` and `ctx.arch` is in the supported list, run `StaticLinkSinkScanner` instead of `SinkArgClassifier`.

**After:** `UNKNOWN-STATIC` results warrant `WindowAnalyzer.dump_text(call_va)` for manual argument trace. `ARG_PROPAGATED` results can feed into `TaintTracker`.

---

## See also

- [Sink Arg Classifier](sink-arg-classifier.md): PLT-based SAC for dynamically linked binaries
- [RelDynPc32Scanner](rel-dyn-pc32-scanner.md): for i386 PIC shared objects that use `.rel.dyn` instead of PLT
- [Window Analyzer](window-analyzer.md): manual trace for UNKNOWN-STATIC results
