# Debug metadata recovery

Recover LoongArch function boundaries from.eh_frame, DWARF and BTF where available.

---

## What it does

Recover LoongArch function boundaries from.eh_frame, DWARF and BTF where available.

---

## Implementation

- [`i386_absolute_xref_scanner.py`](../../ablation/analyzers/i386_absolute_xref_scanner.py)
- [`dwarf_loongarch64.py`](../../ablation/analyzers/dwarf_loongarch64.py)

---

## See also

- [Core](core.md) — module-level reference with constructor patterns and usage examples
