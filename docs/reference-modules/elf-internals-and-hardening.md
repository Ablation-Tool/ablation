# ELF internals and hardening

Parse ELF32/64 program/section headers, symbols, dependencies, RPATH/RUNPATH and GOT/PLT; inspect NX, PIE, RELRO and canary indicators.

---

## What it does

Parse ELF32/64 program/section headers, symbols, dependencies, RPATH/RUNPATH and GOT/PLT; inspect NX, PIE, RELRO and canary indicators.

---

## Implementation

- [`binary_parser.py`](../../ablation/core/binary_parser.py)
- [`elf_parser.py`](../../ablation/core/elf_parser.py)

---

## See also

- [Binary Context](binary-context.md) — module-level reference with constructor patterns and usage examples
