# TI NNC Scanner — FORGE Audit + DEV & TEST ORCHESTRATION PLAN

**Module:** `ablation/analyzers/ti_nnc_scanner.py`  
**Version:** v2.69.0  
**Date:** 2026-10-10  
**Auditor:** Claude Sonnet 4.6  

---

## SAFE CODE 10-Section Audit

### §1 Input Validation
- `from_path(path)`: accepts `str | Path`, stores as `str(path)`, passes to `lief.parse()`.
  lief handles corrupt/missing files gracefully (returns `None`, warns to stderr). **PASS**
- `_extract_floats/_extract_int32s`: guard `va == 0`, `size < 4`, content length before unpack. **PASS**
- Symbol name access: guarded with `if not name: continue`. **PASS**

### §2 Command Injection
No subprocess, os.system, Popen, eval, or exec calls anywhere in the module. **PASS**

### §3 Path Traversal
Path is passed only to `lief.parse()`. No `open()` calls on user-supplied path. **PASS**

### §4 Secret/Credential Exposure
No credentials, API keys, or secrets in the module. **PASS**

### §5 Integer Overflow / Underflow
`count = size // 4` — floor division, always non-negative. `content[:count * 4]` — safe slice. **PASS**

### §6 Memory Safety
Pure Python. No ctypes, no C extensions invoked directly by this module. **PASS**

### §7 Error Handling
- `lief.parse()` returns `None` for bad input; checked before attribute access.
- `isinstance(binary, lief.ELF.Binary)` guard prevents MACHO/PE attribute errors.
- `_extract_floats/_extract_int32s`: bare `except Exception` catches all lief content-read errors.
- `_binding_str`: bare `except Exception` catches lief enum access errors on older lief versions.
- **PASS**: no unhandled exceptions that propagate to caller.

### §8 Data Leakage
No network calls, no file writes, no logging statements. **PASS**

### §9 Dependencies
- `lief>=0.14.0` — already in `pyproject.toml`. No new dependency introduced. **PASS**
- `struct`, `re`, `dataclasses`, `pathlib`, `typing` — stdlib. **PASS**

### §10 Logic Correctness
- Symbol iteration: `binary.symbols` may include both `.symtab` and `.dynsym` entries in lief.
  Duplicates would overwrite `run_syms[model]` with the same `(va, sym)` — no semantic issue.
- `_infer_mode`: uses `finished_syms` membership to detect NPU HW mode — correct per NNC spec §3.5.
- Float extraction uses `'<f'` (little-endian). All TI MCU NNC targets are LE. **PASS**
- Minor: big-endian ARM builds would misparse floats. Not a practical risk (no TI MCU NNC target is BE).
- **PASS**

**gate_passed: True** — 0 HIGH, 0 CRITICAL findings.

---

## DEV & TEST ORCHESTRATION PLAN

### Test 1 — Import smoke test
```python
from ablation.analyzers.ti_nnc_scanner import TiNNCScanner, TiNNCScanResult
```
Expected: no ImportError.

### Test 2 — Missing file graceful handling
```python
scanner = TiNNCScanner.from_path('/nonexistent.elf')
result = scanner.scan()
assert result.modules == []
assert result.findings == []
```
Expected: empty result, lief warning to stderr, no exception.

### Test 3 — Non-ELF input (COFF/PE)
Build or find a PE binary. Expected: `isinstance` guard returns empty result.

### Test 4 — ARM ELF with no tvmgen symbols
Any standard ARM ELF firmware without NNC content. Expected: empty result.

### Test 5 — Synthetic ELF with tvmgen symbols (positive test)
Craft an ELF with:
- `tvmgen_default_run` (GLOBAL binding)
- `tvmgen_default_bias_data` (WEAK binding, size=12, 3 floats in .rodata)
- `tvmgen_default_scale_data` (WEAK binding, size=4, 1 float)
- `tvmgen_default_shift_data` (WEAK binding, size=4, 1 int32)
- `tvmgen_default_finished` (GLOBAL)
- `TI_NPU_init` (GLOBAL)

Expected findings:
- 3x TINCC-001 (one per weak norm symbol)
- 1x TINCC-002 (NPU async flag)
- 1x TINCC-004 (skip-normalize)
Module: name='default', execution_mode='npu_hw', has_finished_flag=True

### Test 6 — Multi-model NPU contention
Craft ELF with `tvmgen_a_run`, `tvmgen_a_finished`, `tvmgen_b_run`, `tvmgen_b_finished`.
Expected: TINCC-003 fires once for models [a, b].

### Test 7 — Soft-mode model (no finished flag)
Craft ELF with `tvmgen_default_run` only, no `finished` flag, no `TI_NPU_init`.
Expected: execution_mode='npu_soft', no TINCC-002.

### Test 8 — Report formatting
`TiNNCScanner.report(result)` on a populated result.
Expected: ASCII table with all findings, sorted HIGH→MEDIUM→INFO.

---

## Known limitations

- C28x firmware: cl2000 emits COFF, not ELF. Scanner returns empty result. Requires Gap 1.
- BNORM sequence detection in disassembled code: not implemented. Future work.
- Tensor shape extraction: not implemented (would require parsing the .h header or .rodata structs).
