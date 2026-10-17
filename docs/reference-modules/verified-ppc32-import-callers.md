# Verified PPC32 import callers

Trace PLT thunk calls while checking the caller's active GOT2 base.

---

## What it does

Trace PLT thunk calls while checking the caller's active GOT2 base.

---

## Implementation

- [`ppc32_plt_tracer.py`](../../ablation/analyzers/ppc32_plt_tracer.py)
- [`ppc64_elfv1_resolver.py`](../../ablation/analyzers/ppc64_elfv1_resolver.py)

---

## See also

- [Ppc32 Plt Tracer](ppc32-plt-tracer.md) — module-level reference with constructor patterns and usage examples
