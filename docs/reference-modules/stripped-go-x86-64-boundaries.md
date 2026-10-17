# Stripped Go x86-64 boundaries

Recover function entries from pclntab when conventional symbols/debug info are absent.

---

## What it does

Recover function entries from pclntab when conventional symbols/debug info are absent.

---

## Implementation

- [`go_string_resolver.py`](../../ablation/analyzers/go_string_resolver.py)
- [`go_subprocess_scanner.py`](../../ablation/analyzers/go_subprocess_scanner.py)

---

## See also

- [Go Binary Re](go-binary-re.md) — module-level reference with constructor patterns and usage examples
