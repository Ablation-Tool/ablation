# Frame, pointer and memory-range state

Track supported frame slots, spilled pointers, constants, memory ranges and register aliases across instruction streams.

---

## What it does

Track supported frame slots, spilled pointers, constants, memory ranges and register aliases across instruction streams.

---

## Implementation

- [`taint_tracker_x86_labeled.py`](../../ablation/analyzers/taint_tracker_x86_labeled.py)
- [`taint_tracker_arm32_labeled.py`](../../ablation/analyzers/taint_tracker_arm32_labeled.py)

---

## See also

- [Taint Analysis](taint-analysis.md) — module-level reference with constructor patterns and usage examples
