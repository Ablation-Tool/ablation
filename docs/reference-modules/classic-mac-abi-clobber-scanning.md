# Classic Mac ABI clobber scanning

Detect supported PPC32 PEF argument-register clobbers across intervening calls.

---

## What it does

Detect supported PPC32 PEF argument-register clobbers across intervening calls.

---

## Implementation

- [`ppc32_plt_tracer.py`](../../ablation/analyzers/ppc32_plt_tracer.py)
- [`ppc64_elfv1_resolver.py`](../../ablation/analyzers/ppc64_elfv1_resolver.py)

---

## See also

- [Ppc32 Plt Tracer](ppc32-plt-tracer.md) — module-level reference with constructor patterns and usage examples
