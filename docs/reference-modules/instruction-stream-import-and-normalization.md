# Instruction-stream import and normalization

Convert supported Capstone, objdump or hand-written listings into common per-ISA instruction/operand objects; normalize aliases and x86 syntax.

---

## What it does

Convert supported Capstone, objdump or hand-written listings into common per-ISA instruction/operand objects; normalize aliases and x86 syntax.

---

## Implementation

- [`insn_x86.py`](../../ablation/analyzers/insn_x86.py)
- [`insn_arm32.py`](../../ablation/analyzers/insn_arm32.py)

---

## See also

- [Core](core.md) — module-level reference with constructor patterns and usage examples
