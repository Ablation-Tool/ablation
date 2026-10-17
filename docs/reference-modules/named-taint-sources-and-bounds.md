# Named taint sources and bounds

Preserve source labels and supported bounds on attacker-controlled contributions rather than a single boolean taint flag.

---

## What it does

Preserve source labels and supported bounds on attacker-controlled contributions rather than a single boolean taint flag.

---

## Implementation

- [`taint_tracker_x86_labeled.py`](../../ablation/analyzers/taint_tracker_x86_labeled.py)
- [`taint_tracker_arm32_labeled.py`](../../ablation/analyzers/taint_tracker_arm32_labeled.py)

---

## See also

- [Taint Analysis](taint-analysis.md) — module-level reference with constructor patterns and usage examples
