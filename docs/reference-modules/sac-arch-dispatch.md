# sac_for_path(): Architecture-aware SAC factory

## Why this exists

`SinkArgClassifier.from_path()` hardcodes x86-64 because it initialises Capstone with `CS_ARCH_X86` and `CS_MODE_64`. Calling it on an i386, ppc32 BE, or s390x ELF produces SAC=0 for every call site. The binary is not necessarily safe; the classifier cannot read the correct registers.

Gap IDs resolved: **IBM-ARCH-001** for i386 cdecl, **IBM-ARCH-002** for ppc32 BE r3, and **S390-GAP-001** for s390x r2.

## Usage

```python
from ablation.analyzers.sink_arg_classifier import sac_for_path

clf = sac_for_path('/tmp/extract/bin/linux/doorsd')   # auto-detects i386
for r in clf.classify_all():
    print(f"{r.sink_name}@0x{r.call_va:x}: {r.verdict}")
```

## Dispatch table

| e_machine | Architecture | Returns |
|---|---|---|
| `0x0003` | i386 cdecl | `SinkArgClassifierX86_32` |
| `0x0014` | ppc32 BE | `SinkArgClassifierPPC32` |
| `0x0016` | s390 or s390x | `SinkArgClassifierS390` |
| anything else | x86-64 default | `SinkArgClassifier` |

## API contract

All returned objects expose the same three methods:

- `.classify_all()` returns `List[SinkClassification]`
- `.classify_sink()` takes a sink name and argument position, returns `List[SinkClassification]`
- `.add_sink()` takes a sink name and argument position

## Notes

The function reads 20 bytes from the ELF header before dispatching. It falls back to `SinkArgClassifier.from_path()` on `OSError` or non-ELF magic. ARM32 and AARCH64 route through the main `SinkArgClassifier` class and do not pass through `sac_for_path()`.
