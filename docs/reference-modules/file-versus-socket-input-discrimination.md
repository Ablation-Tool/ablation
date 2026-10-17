# File-versus-socket input discrimination

Classify ARM64 fgets sources using FILE-pointer provenance to reduce configuration-file false positives.

---

## What it does

Classify ARM64 fgets sources using FILE-pointer provenance to reduce configuration-file false positives.

---

## Implementation

- [`sink_propagator.py`](../../ablation/analyzers/sink_propagator.py)
- [`sanitizer_detector.py`](../../ablation/analyzers/sanitizer_detector.py)

---

## See also

- [Sink Propagator](sink-propagator.md) — module-level reference with constructor patterns and usage examples
