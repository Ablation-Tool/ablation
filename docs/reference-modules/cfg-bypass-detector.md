# CFGBypassDetector

## Why this exists

Three things were not possible before in Ablation:

1. **No CFG table inspection.** Before this module, Ablation had no way to read `IMAGE_LOAD_CONFIG.GuardFlags` or the CFG protected function table from a Windows PE. The only CFG-related path was `pe_sweep.py`, which flagged missing CFG at a coarse level but could not identify *which specific exports* slip through when export suppression is enabled; these are the precise bypass targets an attacker needs.

2. **No export-vs-table cross-reference.** A PE with CFG enabled and export suppression enabled (`IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION`) still has individual exports that are absent from the protected function table. Finding those required manually comparing the export directory against the CFG function table entry by entry. There was no automated path for that.

3. **No XFG / entry stride awareness.** Extended Flow Guard (`IMAGE_GUARD_XFG_ENABLED`) changes the semantics of the protected function table and adds per-call-site type tokens. The `entry_stride` field (`4 + (GuardFlags >> 28)`) affects how entries are read. Without accounting for this, a reader would misparse entries on any binary compiled with `/guard:xtfg`.

This module closes all three gaps. It is the entry point for CFG bypass surface analysis on any Windows PE.

---

## What it does

`CFGBypassDetector` parses `IMAGE_LOAD_CONFIG.GuardFlags` and the CFG function table using LIEF, then cross-references the PE export table to find:

- CFG completely absent (`IMAGE_GUARD_CF_INSTRUMENTED` not set): every indirect call target is unprotected.
- CFG table not populated (`IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT` not set): the runtime check passes every address.
- Export suppression missing: all exported functions are valid CFG targets, expanding the gadget surface to the full export table.
- Individual exports not in the CFG table when export suppression is enabled: these are the specific bypass targets an attacker would use.

A secondary scan counts `call reg` / `jmp reg` instructions in code sections to estimate the size of the indirect call surface.

---

## Usage

```python
from ablation.analyzers.cfg_bypass_detector import CFGBypassDetector

det = CFGBypassDetector.from_path('ntdll.dll')
findings = det.scan()
print(CFGBypassDetector.report(findings))

cfg = det.cfg_config()
print(f"CFG enabled: {cfg.cfg_enabled}")
print(f"Export suppression: {cfg.export_suppression}")
print(f"Protected functions: {cfg.function_count}")
print(f"Entry stride: {cfg.entry_stride} bytes")
print(f"XFG: {cfg.xfg_enabled}")
```

---

## Findings

| Severity | Category | Trigger |
|---|---|---|
| HIGH | `cfg_disabled` | `IMAGE_GUARD_CF_INSTRUMENTED` not set |
| HIGH | `cfg_table_absent` | CFG enabled but function table flag absent |
| MEDIUM | `no_export_suppression` | `IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION` not set |
| MEDIUM | `export_not_in_cfg_table` | Specific export absent from CFG table (per export) |
| INFO | `indirect_call_stats` | Count of indirect call/jmp sites |

CWE: CWE-693 (Protection Mechanism Failure) on all HIGH/MEDIUM findings.

---

## Dependencies

- `lief >= 0.14.0` (PE parsing, exports, `IMAGE_LOAD_CONFIG`)
- `capstone >= 5.0` (indirect call counting in code sections)

---

## Key constants

| Flag | Value | Meaning |
|---|---|---|
| `IMAGE_GUARD_CF_INSTRUMENTED` | `0x100` | CFG enabled |
| `IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT` | `0x400` | Table populated |
| `IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION` | `0x8000` | Exports excluded from targets |
| `IMAGE_GUARD_XFG_ENABLED` | `0x800000` | Extended Flow Guard active |
| Entry stride | `4 + (GuardFlags >> 28)` | Bytes per CFG table entry |

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Example output

```
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading findings

`CFGBypassDetector.from_path(path).scan()` returns `List[CFGBypassFinding]`:

| Attribute | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `category` | `cfg_disabled` / `cfg_table_absent` / `no_export_suppression` / `export_not_in_table` / `indirect_call_stats` |
| `title` | Short description of the bypass opportunity |
| `location` | Human-readable location string (function name, export name, or PE header field) |
| `description` | Detailed explanation of why this is a bypass surface |
| `va` | VA of the relevant instruction or table entry (0 if not applicable) |
| `cwe` | CWE identifier (e.g., `CWE-693`) |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
