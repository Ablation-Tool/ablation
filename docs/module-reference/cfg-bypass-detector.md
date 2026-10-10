# CFGBypassDetector

## Why this exists

3 things that weren't possible before in Ablation:

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
