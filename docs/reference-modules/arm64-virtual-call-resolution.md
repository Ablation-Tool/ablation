# ARM64 virtual-call resolution

Infer vtables, constructor vptr writes and supported BLR targets.

---

## What it does

Infer vtables, constructor vptr writes and supported BLR targets.

---

## Implementation

- [`vtable_resolver.py`](../../ablation/analyzers/vtable_resolver.py)
- [`elf_vtable_reconstructor.py`](../../modules/elf_vtable_reconstructor.py)

---

## See also

- [Vtable X86 64](vtable-x86-64.md) — module-level reference with constructor patterns and usage examples
