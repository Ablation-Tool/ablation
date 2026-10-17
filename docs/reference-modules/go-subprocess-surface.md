# Go subprocess surface

Find os/exec call sites and recover static command-path arguments where possible.

---

## What it does

Find os/exec call sites and recover static command-path arguments where possible.

---

## Implementation

- [`go_string_resolver.py`](../../ablation/analyzers/go_string_resolver.py)
- [`go_subprocess_scanner.py`](../../ablation/analyzers/go_subprocess_scanner.py)

---

## See also

- [Go Binary Re](go-binary-re.md) — module-level reference with constructor patterns and usage examples
