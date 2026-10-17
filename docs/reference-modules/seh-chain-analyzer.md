# SEHChainAnalyzer

## Why this exists

Two things were not possible before in Ablation:

1. **No SafeSEH table inspection.** Ablation had no module that read `IMAGE_LOAD_CONFIG.SEHandlerTable` and `SEHandlerCount` from an x86 PE. `pe_sweep.py` detected `/GS` cookie presence via the `__security_cookie` import, but SafeSEH is a separate mechanism; a binary can have `__security_cookie` and still lack SafeSEH entirely. Without reading the handler table, there was no way to tell whether an x86 binary compiled without `/SAFESEH` was vulnerable to SEH overwrite exploitation.

2. **No runtime SEH frame scanning.** Even when SafeSEH is enabled, individual functions install SEH frames dynamically with `push handler; push FS:[0]; mov FS:[0], esp`. If the handler address used in the push is not in the SafeSEH table (for example because it was computed dynamically or was added by a third-party library linked without `/SAFESEH`), that handler is a bypass target. Before this module, finding those mis-registered frames required manual disassembly of each function.

---

## What it does

`SEHChainAnalyzer` operates on x86 (32-bit) PE binaries only. It rejects x64 PE input with a `ValueError` because x64 uses table-based EH via `.pdata`, not the stack-based SEH chain.

For x86 PE input, it:

1. Reads `IMAGE_LOAD_CONFIG.SEHandlerTable` and `SEHandlerCount` to determine if SafeSEH is active and enumerate registered handler RVAs.
2. Scans all code sections with Capstone for the canonical SEH frame installation sequence: `push <handler_va>` followed within four instructions by a memory access via `FS:` (the `FS:[0]` chain pointer).
3. Cross-references each found frame handler VA against the SafeSEH table.
4. Reports handlers that are referenced in code but absent from the table.

---

## Usage

```python
from ablation.analyzers.seh_chain_analyzer import SEHChainAnalyzer

ana = SEHChainAnalyzer.from_path('legacy_service.exe')
findings = ana.scan()
print(SEHChainAnalyzer.report(findings))

handlers = ana.safe_seh_handlers()
print(f"SafeSEH table has {len(handlers)} handler(s)")

frames = ana.seh_frames()
unsafe = [f for f in frames if not f.in_safe_seh]
print(f"{len(unsafe)} frame(s) use handlers not in SafeSEH table")
```

---

## Findings

| Severity | Category | Trigger |
|---|---|---|
| HIGH | `safesh_disabled` | No `IMAGE_LOAD_CONFIG`, or `SEHandlerTable`/`SEHandlerCount` is zero |
| MEDIUM | `handler_not_in_table` | Handler installed in code but absent from SafeSEH table |
| INFO | `safesh_enabled` | SafeSEH active with N registered handlers |
| INFO | `seh_frame_count` | N SEH frame installations found in code |

CWE: CWE-693 (Protection Mechanism Failure) on HIGH/MEDIUM.

---

## Dependencies

- `lief >= 0.14.0` (x86 PE parsing, `IMAGE_LOAD_CONFIG`)
- `capstone >= 5.0` (x86 32-bit SEH frame pattern scan)

---

## Scope

x86 (I386) PE only. Calling `from_path()` on an x64 or ARM PE raises `ValueError`.

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

`SEHChainAnalyzer.from_path(path).scan()` returns `List[SEHFinding]`:

| Attribute | Content |
|:---|:---|
| `severity` | `'HIGH'` / `'MEDIUM'` / `'LOW'` / `'INFO'` |
| `category` | `'safeseh_disabled'` / `'no_handlers'` / `'handler_not_in_table'` / `'seh_frame_count'` / `'dynamic_handler_count'` |
| `title` | Short finding title |
| `location` | PE path or section name |
| `description` | Human-readable explanation |
| `va` | VA of the relevant `push handler_va` instruction (0 if not applicable) |
| `cwe` | CWE identifier string (e.g., `'CWE-693'`) |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
