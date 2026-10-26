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
| MEDIUM | `export_not_in_cfg_table` | Specific export absent from CFG table per export |
| INFO | `indirect_call_stats` | Count of indirect call/jmp sites |

CWE: CWE-693 Protection Mechanism Failure on all HIGH/MEDIUM findings.

---

## Dependencies

- `lief >= 0.14.0` PE parsing, exports, and `IMAGE_LOAD_CONFIG`
- `capstone >= 5.0` indirect call counting in code sections

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

`CFGBypassDetector.from_path()` opens the PE with LIEF and reads `IMAGE_LOAD_CONFIG.GuardFlags`. The flags are tested against four masks:

1. `IMAGE_GUARD_CF_INSTRUMENTED` (0x100): if absent, emits a HIGH `cfg_disabled` finding immediately; no further CFG checks apply.
2. `IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT` (0x400): if absent, emits HIGH `cfg_table_absent` the runtime check passes every address regardless of the table.
3. `IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION` (0x8000): if absent, emits MEDIUM `no_export_suppression`; all exported functions are valid indirect call targets.
4. Export-vs-table cross-reference: when export suppression is enabled, reads all named exports from `PE.exports` and checks each against the CFG function table. Exports absent from the table emit individual MEDIUM `export_not_in_cfg_table` findings.

The `entry_stride` for the CFG function table is `4 + (GuardFlags >> 28)`: standard CFG uses 4 bytes per entry, XFG uses 8 bytes. Entries are read at stride intervals from the table RVA.

A secondary Capstone pass over all code sections counts `call reg` / `jmp reg` instructions and emits an INFO `indirect_call_stats` finding with the total count.

---

## Example output

The following illustrates `CFGBypassDetector.report()` output format. Actual values are binary-specific.

```
CFGBypassDetector: ntdll.dll

Findings: 2 high/critical  3 medium  1 info

  [MEDIUM] no_export_suppression
    location : IMAGE_LOAD_CONFIG.GuardFlags
    category : no_export_suppression
    cwe      : CWE-693
    Export suppression not enabled — all 437 exports are valid CFG indirect call targets.

  [MEDIUM] export_not_in_cfg_table
    location : LdrLoadDll
    category : export_not_in_cfg_table
    cwe      : CWE-693
    Export 'LdrLoadDll' at VA 0x7FF800A31234 is not in the CFG protected function table.

  [INFO] indirect_call_stats
    location : .text
    category : indirect_call_stats
    Indirect call sites (call reg / jmp reg): 212
```

---

## False positives

**Delay-load imports expand the bypass surface:** The Capstone `call reg` / `jmp reg` count includes delay-load thunks, which dispatch to the OS loader. These are legitimate indirect calls, not bypass vectors. Subtract IAT thunk addresses from the indirect call count when sizing the actual attacker-reachable surface.

**`export_not_in_cfg_table` on non-callable exports:** DLL exports that are data symbols not functions are never in the CFG table. Distinguish function vs. data exports by checking `lief.PE.Export.Entry.function_rva` vs. data RVAs, or filter to exports whose RVA falls inside a code section.

**XFG type-token mismatch not detected:** When XFG is enabled, the runtime also validates a per-call-site type token. A function present in the CFG table may still be blocked by XFG type mismatch. `CFGBypassDetector` reports presence/absence in the table only; it does not analyze XFG type compatibility.

---

## Pipeline position

**Before this module:** Use on any Windows PE kernel module, system DLL, or userland binary. No `BinaryContext` required: `from_path()` uses LIEF directly. Run before any exploit feasibility analysis to confirm whether CFG restricts indirect call targets.

**After this module:** Feed `export_not_in_cfg_table` findings into exploit chain construction, these are the specific exports usable as gadget pivots. Use `va` from each finding for exact address confirmation with `BinaryContext` or WinDbg.

---

## Reading findings

`CFGBypassDetector.from_path(path).scan()` returns `List[CFGBypassFinding]`:

| Attribute | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `category` | `cfg_disabled` / `cfg_table_absent` / `no_export_suppression` / `export_not_in_table` / `indirect_call_stats` |
| `title` | Short description of the bypass opportunity |
| `location` | Human-readable location string function name, export name, or PE header field |
| `description` | Detailed explanation of why this is a bypass surface |
| `va` | VA of the relevant instruction or table entry 0 if not applicable |
| `cwe` | CWE identifier such as `CWE-693` |

---

## See also

- [PE Sweep](pe-sweep.md): coarse Windows PE security feature check DEP, ASLR, SafeSEH, and CFG; `CFGBypassDetector` extends CFG analysis to per-export bypass surface
- [BinaryContext](binary-context.md): load PE for further analysis after identifying bypass targets
- [FindingRegistry](registry.md): register confirmed bypass findings with CWE attribution
