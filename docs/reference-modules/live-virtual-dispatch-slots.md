# Live virtual-dispatch slots

Find x86-64 indirect-call slot uses and distinguish referenced slots from unobserved ones.

---

## What it does

Find x86-64 indirect-call slot uses and distinguish referenced slots from unobserved ones.

---

## Implementation

- [`vtable_resolver.py`](../../ablation/analyzers/vtable_resolver.py)
- [`elf_vtable_reconstructor.py`](../../modules/elf_vtable_reconstructor.py)

---

## See also

- [Vtable X86 64](vtable-x86-64.md) — module-level reference with constructor patterns and usage examples
